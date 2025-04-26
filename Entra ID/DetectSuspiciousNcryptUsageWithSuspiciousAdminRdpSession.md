# *Detect Suspicious ncrypt.dll usage on admin device with RDP connections to non TPM protected device*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1555.004 | Credentials from Password Stores: Windows Credential Manager | https://attack.mitre.org/techniques/T1555/004/ |
| T1606 | Forge Web Credentials | https://attack.mitre.org/techniques/T1606/ |
| T1021.001 | Remote Services: Remote Desktop Protocol | https://attack.mitre.org/techniques/T1021/001/ |

#### Description
This detection rule uses a WDAC audit policy to ingest missing DeviceImageLoad events in MDE, and check for suspicious processes using the ncrypt.dll and admin devices performing RDP connection to unmanaged or non-TPM devices. More information on the attack scenario this is detection is applicable for can be found in the references.

#### Risk
By using this detections, we can try to detect an attacker using the hellopoc.ps1 script in RoadTools to generate an assertion, and export the Windows Hello for Business keys using an RDP session. 

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com/detecting-non-privileged-windows-hello-abuse/
- https://github.com/dirkjanm/ROADtools/blob/master/winhello_assertion/hellopoc.ps1

## Defender XDR
```KQL
let time_lookback = 30d;
let admin_users = toscalar(
    IdentityInfo
    | where Timestamp > ago(7d)
    | where CriticalityLevel != "" or AccountDisplayName contains "Admin"
    | summarize make_set(AccountDisplayName)
);
let devices_with_admin_accounts = (
    ExposureGraphEdges
    // Get edges where source is a device and destination is a admin user
    | where SourceNodeLabel == "device" and TargetNodeLabel == "user"
    | where TargetNodeName in (admin_users)
    // Check which devices have the credentials of the admin user
    | make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
    | graph-match (SourceNode)-[hasCredentialsOf]->(TargetNode)
        project IncomingNodeName = SourceNode.NodeName, OutgoingNodeName = TargetNode.NodeName, CriticalityLevel = TargetNode.NodeProperties.rawData.criticalityLevel.criticalityLevel, CriticalityRuleNames = TargetNode.NodeProperties.rawData.criticalityLevel.ruleNames
    | summarize make_set(IncomingNodeName)
);
let no_tpm_devices = (
    ExposureGraphNodes
    // Get device nodes with their inventory ID
    | where NodeLabel == "device"
    | mv-expand EntityIds
    | where EntityIds.type == "DeviceInventoryId"
    // Get interesting properties
    | extend OnboardingStatus = tostring(parse_json(NodeProperties)["rawData"]["onboardingStatus"]),
        TpmSupported = tostring(parse_json(NodeProperties)["rawData"]["tpmData"]["supported"]),
        TpmEnabled = tostring(parse_json(NodeProperties)["rawData"]["tpmData"]["enabled"]),
        TpmActivated = tostring(parse_json(NodeProperties)["rawData"]["tpmData"]["activated"]),
        DeviceName = tostring(parse_json(NodeProperties)["rawData"]["deviceName"]),
        DeviceId = tostring(EntityIds.id)
    // Search for distinct devices
    | distinct DeviceId, DeviceName, OnboardingStatus, TpmSupported, TpmEnabled, TpmActivated
    // Get Unmanaged devices and device not supporting a TPM
    | where OnboardingStatus != "Onboarded" or (TpmSupported != "true" and TpmActivated != "true" and TpmEnabled != "true")
    | extend TpmSupported = iff(TpmSupported == "", "unknown", TpmSupported),
        TpmActivated = iff(TpmActivated == "", "unknown", TpmActivated),
        TpmEnabled = iff(TpmEnabled == "", "unknown", TpmEnabled)
);
let no_tpm_device_info = (
    DeviceNetworkInfo
    | where Timestamp > ago(7d)
    // Get latest network info for each device ID
    | summarize arg_max(Timestamp, *) by DeviceId
    | mv-expand todynamic(IPAddresses)
    | extend IPAddress = tostring(IPAddresses.IPAddress)
    // Find no TPM devices and join with their network information
    | join kind=inner no_tpm_devices on DeviceId
    | project DeviceId, DeviceName, MacAddress, IPAddress, OnboardingStatus, TpmActivated, TpmEnabled, TpmSupported
);
let dangerous_rdp_sessions = (
    DeviceNetworkEvents
    | where Timestamp > ago(time_lookback)
    // Only flag admin devices
    | where DeviceName in (devices_with_admin_accounts)
    // Exclude MDI RDP Connections (known for NNR)
    | where InitiatingProcessFileName !~ "microsoft.tri.sensor.exe"
    // Search for RDP connections to non-tpm devices
    | where ActionType == "ConnectionSuccess"
    | where RemotePort == 3389
    | join kind=inner no_tpm_device_info on $left.RemoteIP == $right.IPAddress
    | project-rename RemoteDeviceId = DeviceId1, 
        RdpRemoteDeviceName = DeviceName1, 
        RdpRemoteMacAddress = MacAddress, 
        RdpRemoteDeviceOnboardingStatus = OnboardingStatus, 
        RdpRemoteDeviceTpmActivated = TpmActivated, 
        RdpRemoteDeviceTpmEnabled = TpmEnabled, 
        RdpRemoteDeviceTpmSupported = TpmSupported,
        RdpTimeGenerated = Timestamp,
        RdpInitiatingProcessFileName = InitiatingProcessFileName
    | project-away IPAddress
);
// Get all possible nonce requests
let nonce_requests = (
    DeviceNetworkEvents
    | where Timestamp > ago(time_lookback)
    | where ActionType == "ConnectionSuccess"
    | where RemoteUrl =~ "login.microsoftonline.com"
    | project-rename NonceRequestTimestamp = Timestamp
);
// Get suspicious ncrypt.dll usage via WDAC audit policy
DeviceEvents
| where Timestamp > ago(time_lookback)
// Only flag admin devices
| where DeviceName in (devices_with_admin_accounts)
| where ActionType startswith "AppControl" and FileName =~ "ncrypt.dll"
// Check if the same initiating process is doing a nonce request
| join kind=inner nonce_requests on InitiatingProcessId, DeviceId
// Only flag when nonce was request 10min before of after ncrypt usage
| where Timestamp between (todatetime(NonceRequestTimestamp - 10m) .. todatetime(NonceRequestTimestamp + 10m))
// Check if the same device is doing RDP Connections
| join kind=inner dangerous_rdp_sessions on DeviceId
// Whitelist known good processes
| where InitiatingProcessFileName !in ("backgroundtaskhost.exe","svchost.exe")
// Project interesting columns
| extend WdacPolicyName = parse_json(AdditionalFields)["PolicyName"]
| project Timestamp, DeviceName, ActionType, FileName, InitiatingProcessSHA1, InitiatingProcessFileName, 
    InitiatingProcessId, InitiatingProcessAccountName, InitiatingProcessParentFileName, WdacPolicyName, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP,
    NonceRequestTimestamp, RdpTimeGenerated, RdpInitiatingProcessFileName, RdpRemoteDeviceName, RdpRemoteMacAddress, RdpRemoteDeviceOnboardingStatus,
    RdpRemoteDeviceTpmActivated, RdpRemoteDeviceTpmEnabled, RdpRemoteDeviceTpmSupported
```

## Sentinel
```KQL
let time_lookback = 30d;
let admin_users = toscalar(
    IdentityInfo
    | where TimeGenerated > ago(7d)
    | where CriticalityLevel != "" or AccountDisplayName contains "Admin"
    | summarize make_set(AccountDisplayName)
);
let devices_with_admin_accounts = (
    ExposureGraphEdges
    // Get edges where source is a device and destination is a admin user
    | where SourceNodeLabel == "device" and TargetNodeLabel == "user"
    | where TargetNodeName in (admin_users)
    // Check which devices have the credentials of the admin user
    | make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
    | graph-match (SourceNode)-[hasCredentialsOf]->(TargetNode)
        project IncomingNodeName = SourceNode.NodeName, OutgoingNodeName = TargetNode.NodeName, CriticalityLevel = TargetNode.NodeProperties.rawData.criticalityLevel.criticalityLevel, CriticalityRuleNames = TargetNode.NodeProperties.rawData.criticalityLevel.ruleNames
    | summarize make_set(IncomingNodeName)
);
let no_tpm_devices = (
    ExposureGraphNodes
    // Get device nodes with their inventory ID
    | where NodeLabel == "device"
    | mv-expand EntityIds
    | where EntityIds.type == "DeviceInventoryId"
    // Get interesting properties
    | extend OnboardingStatus = tostring(parse_json(NodeProperties)["rawData"]["onboardingStatus"]),
        TpmSupported = tostring(parse_json(NodeProperties)["rawData"]["tpmData"]["supported"]),
        TpmEnabled = tostring(parse_json(NodeProperties)["rawData"]["tpmData"]["enabled"]),
        TpmActivated = tostring(parse_json(NodeProperties)["rawData"]["tpmData"]["activated"]),
        DeviceName = tostring(parse_json(NodeProperties)["rawData"]["deviceName"]),
        DeviceId = tostring(EntityIds.id)
    // Search for distinct devices
    | distinct DeviceId, DeviceName, OnboardingStatus, TpmSupported, TpmEnabled, TpmActivated
    // Get Unmanaged devices and device not supporting a TPM
    | where OnboardingStatus != "Onboarded" or (TpmSupported != "true" and TpmActivated != "true" and TpmEnabled != "true")
    | extend TpmSupported = iff(TpmSupported == "", "unknown", TpmSupported),
        TpmActivated = iff(TpmActivated == "", "unknown", TpmActivated),
        TpmEnabled = iff(TpmEnabled == "", "unknown", TpmEnabled)
);
let no_tpm_device_info = (
    DeviceNetworkInfo
    | where TimeGenerated > ago(7d)
    // Get latest network info for each device ID
    | summarize arg_max(TimeGenerated, *) by DeviceId
    | mv-expand todynamic(IPAddresses)
    | extend IPAddress = tostring(IPAddresses.IPAddress)
    // Find no TPM devices and join with their network information
    | join kind=inner no_tpm_devices on DeviceId
    | project DeviceId, DeviceName, MacAddress, IPAddress, OnboardingStatus, TpmActivated, TpmEnabled, TpmSupported
);
let dangerous_rdp_sessions = (
    DeviceNetworkEvents
    | where TimeGenerated > ago(time_lookback)
    // Only flag admin devices
    | where DeviceName in (devices_with_admin_accounts)
    // Exclude MDI RDP Connections (known for NNR)
    | where InitiatingProcessFileName !~ "microsoft.tri.sensor.exe"
    // Search for RDP connections to non-tpm devices
    | where ActionType == "ConnectionSuccess"
    | where RemotePort == 3389
    | join kind=inner no_tpm_device_info on $left.RemoteIP == $right.IPAddress
    | project-rename RemoteDeviceId = DeviceId1, 
        RdpRemoteDeviceName = DeviceName1, 
        RdpRemoteMacAddress = MacAddress, 
        RdpRemoteDeviceOnboardingStatus = OnboardingStatus, 
        RdpRemoteDeviceTpmActivated = TpmActivated, 
        RdpRemoteDeviceTpmEnabled = TpmEnabled, 
        RdpRemoteDeviceTpmSupported = TpmSupported,
        RdpTimeGenerated = Timestamp,
        RdpInitiatingProcessFileName = InitiatingProcessFileName
    | project-away IPAddress
);
// Get all possible nonce requests
let nonce_requests = (
    DeviceNetworkEvents
    | where TimeGenerated > ago(time_lookback)
    | where ActionType == "ConnectionSuccess"
    | where RemoteUrl =~ "login.microsoftonline.com"
    | project-rename NonceRequestTimestamp = TimeGenerated
);
// Get suspicious ncrypt.dll usage via WDAC audit policy
DeviceEvents
| where TimeGenerated > ago(time_lookback)
// Only flag admin devices
| where DeviceName in (devices_with_admin_accounts)
| where ActionType startswith "AppControl" and FileName =~ "ncrypt.dll"
// Check if the same initiating process is doing a nonce request
| join kind=inner nonce_requests on InitiatingProcessId, DeviceId
// Only flag when nonce was request 10min before of after ncrypt usage
| where TimeGenerated between (todatetime(NonceRequestTimestamp - 10m) .. todatetime(NonceRequestTimestamp + 10m))
// Check if the same device is doing RDP Connections
| join kind=inner dangerous_rdp_sessions on DeviceId
// Whitelist known good processes
| where InitiatingProcessFileName !in ("backgroundtaskhost.exe","svchost.exe")
// Project interesting columns
| extend WdacPolicyName = parse_json(AdditionalFields)["PolicyName"]
| project TimeGenerated, DeviceName, ActionType, FileName, InitiatingProcessSHA1, InitiatingProcessFileName, 
    InitiatingProcessId, InitiatingProcessAccountName, InitiatingProcessParentFileName, WdacPolicyName, InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP,
    NonceRequestTimestamp, RdpTimeGenerated, RdpInitiatingProcessFileName, RdpRemoteDeviceName, RdpRemoteMacAddress, RdpRemoteDeviceOnboardingStatus,
    RdpRemoteDeviceTpmActivated, RdpRemoteDeviceTpmEnabled, RdpRemoteDeviceTpmSupported
```