# *Hunt for RDP sessions to unmanaged and non TPM devices*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.001 | Remote Services: Remote Desktop Protocol | https://attack.mitre.org/techniques/T1021/001/ |

#### Description
This query can help you find devices performing RDP sessions to unmanaged or non-TPM protected devices.  

#### Risk
This can be a risk to expose Windows Hello for Business credentials when Windows Hello for Business is being used as authentication method for the RDP session, since the keys will not be protected on the destination device by a TPM.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com/detecting-non-privileged-windows-hello-abuse/

## Defender XDR
```KQL
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
DeviceNetworkEvents
// Search for RDP connections to non-tpm devices
| where Timestamp > ago(1h)
| where ActionType == "ConnectionSuccess"
| where RemotePort == 3389
// Exclude MDI RDP Connections (known for NNR)
| where InitiatingProcessFileName !~ "microsoft.tri.sensor.exe"
| join kind=inner no_tpm_device_info on $left.RemoteIP == $right.IPAddress
| project-rename RemoteDeviceId = DeviceId1, RemoteDeviceName = DeviceName1, RemoteMacAddress = MacAddress, RemoteDeviceOnboardingStatus = OnboardingStatus, RemoteDeviceTpmActivated = TpmActivated, RemoteDeviceTpmEnabled = TpmEnabled, RemoteDeviceTpmSupported = TpmSupported
| project-away IPAddress
```

## Sentinel
```KQL
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
DeviceNetworkEvents
// Search for RDP connections to non-tpm devices
| where TimeGenerated > ago(1h)
| where ActionType == "ConnectionSuccess"
| where RemotePort == 3389
// Exclude MDI RDP Connections (known for NNR)
| where InitiatingProcessFileName !~ "microsoft.tri.sensor.exe"
| join kind=inner no_tpm_device_info on $left.RemoteIP == $right.IPAddress
| project-rename RemoteDeviceId = DeviceId1, RemoteDeviceName = DeviceName1, RemoteMacAddress = MacAddress, RemoteDeviceOnboardingStatus = OnboardingStatus, RemoteDeviceTpmActivated = TpmActivated, RemoteDeviceTpmEnabled = TpmEnabled, RemoteDeviceTpmSupported = TpmSupported
| project-away IPAddress
```