# *Hunt for ADWS requests from unknown devices*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1119 | Automated Collection | https://attack.mitre.org/techniques/T1119/ |
| T1087.002 | Account Discovery - Domain Account | https://attack.mitre.org/techniques/T1087/002/ |
| T1069.002 | Permission Groups Discovery - Domain Groups | https://attack.mitre.org/techniques/T1069/002/ |
| T1201 | Password Policy Discovery | https://attack.mitre.org/techniques/T1201/ |
| T1482 | Domain Trust Discovery | https://attack.mitre.org/techniques/T1482/ |
| T1021.002 | Remote Services - SMB/Windows Admin Shares | https://attack.mitre.org/techniques/T1021/002/ |
| T1018 | Remote System Discovery | https://attack.mitre.org/techniques/T1018/ |
| T1135 | Network Share Discovery | https://attack.mitre.org/techniques/T1135/ |

#### Description
This hunting rule searches for incomming ADWS connections on Domain Controllers (DC's need to be onboarded in Defender for Endpoint) from IP Addresses that cannot be linked to MDE onboarded devices.

#### Risk
Adversary tools used to enumerate Active Directory over ADWS instead of using LDAP are becoming more popular, since they often stay under the radar of most monitoring tools. In the references you can find two detections provided by FalconForce on how you can detect ADWS connections from an unexpected binary, when the source device is onboarded in Microsoft Defender for Endpoint. But if somehow an unmanaged device was able to to connect via ADWS to domain controllers, we are not able to use these detections. Because of this, you should hunt for unknown devices performing ADWS connections and treat them as suspicious. 

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://falconforce.nl/soaphound-tool-to-collect-active-directory-data-via-adws/
- https://github.com/FalconForceTeam/FalconFriday/blob/master/Discovery/ADWS_Connection_from_Unexpected_Binary-Win.md
- https://github.com/FalconForceTeam/FalconFriday/blob/master/Discovery/ADWS_Connection_from_Process_Injection_Target-Win.md
- https://cyberlandsec.com/soapy-the-ultimate-stealthy-active-directory-enumeration-tool-via-adws/
- https://github.com/FalconForceTeam/SOAPHound

## Defender XDR
```KQL
let device_info = (
    // Get device network info from last 7 days
    DeviceNetworkInfo
    | where Timestamp > ago(7d)
    // Expand the IP Addresses of the devices
    | mv-expand todynamic(IPAddresses)
    | extend IPAddress = tostring(IPAddresses.IPAddress)
    // Distinct IP address for each device
    | distinct DeviceName, DeviceId, IPAddress
    // Search for each device if it is onboarded or not
    | join kind=inner (
        DeviceInfo 
        | where Timestamp > ago(7d)
        | distinct DeviceName, DeviceId, OnboardingStatus
        // Get the first timestamp the device was seen
        | join kind=inner (
            DeviceInfo
            | where Timestamp > ago(30d)
            | summarize FirstSeen = arg_min(Timestamp, DeviceId) by DeviceId
        ) on DeviceId
        | project-away DeviceId1, DeviceId2
    ) on DeviceId, DeviceName
    | project-away DeviceName1, DeviceId1
);
// Get incomming traffic on ADWS port and save unique remote IP addresses
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType != "ListeningConnectionCreated"
| where InitiatingProcessFolderPath == @"c:\windows\adws\microsoft.activedirectory.webservices.exe"
| where LocalPort == "9389"
| summarize ConnectionTimes=make_list(Timestamp) by RemoteIP, DeviceName
// Get device information of remote IP addresses, results for IP we do not find information for are allowed
| join kind=leftouter device_info on $left.RemoteIP == $right.IPAddress
| project-away IPAddress
// Check if the remote IPs are onboarded devices or not
| where OnboardingStatus != "Onboarded"
// Make output better
| project DeviceName, ConnectionTimes, RemoteIP, RemoteDeviceName = DeviceName1, RemoteDeviceId = DeviceId, RemoteOnboardingStatus = OnboardingStatus, RemoteDeviceFirstSeen = FirstSeen
```

## Sentinel
```KQL
let device_info = (
    // Get device network info from last 7 days
    DeviceNetworkInfo
    | where TimeGenerated > ago(7d)
    // Expand the IP Addresses of the devices
    | mv-expand todynamic(IPAddresses)
    | extend IPAddress = tostring(IPAddresses.IPAddress)
    // Distinct IP address for each device
    | distinct DeviceName, DeviceId, IPAddress
    // Search for each device if it is onboarded or not
    | join kind=inner (
        DeviceInfo 
        | where TimeGenerated > ago(7d)
        | distinct DeviceName, DeviceId, OnboardingStatus
        // Get the first timestamp the device was seen
        | join kind=inner (
            DeviceInfo
            | where TimeGenerated > ago(30d)
            | summarize FirstSeen = arg_min(TimeGenerated, DeviceId) by DeviceId
        ) on DeviceId
        | project-away DeviceId1, DeviceId2
    ) on DeviceId, DeviceName
    | project-away DeviceName1, DeviceId1
);
// Get incomming traffic on ADWS port and save unique remote IP addresses
DeviceNetworkEvents
| where TimeGenerated > ago(30d)
| where ActionType != "ListeningConnectionCreated"
| where InitiatingProcessFolderPath == @"c:\windows\adws\microsoft.activedirectory.webservices.exe"
| where LocalPort == "9389"
| summarize ConnectionTimes=make_list(TimeGenerated) by RemoteIP, DeviceName
// Get device information of remote IP addresses, results for IP we do not find information for are allowed
| join kind=leftouter device_info on $left.RemoteIP == $right.IPAddress
| project-away IPAddress
// Check if the remote IPs are onboarded devices or not
| where OnboardingStatus != "Onboarded"
// Make output better
| project DeviceName, ConnectionTimes, RemoteIP, RemoteDeviceName = DeviceName1, RemoteDeviceId = DeviceId, RemoteOnboardingStatus = OnboardingStatus, RemoteDeviceFirstSeen = FirstSeen
```