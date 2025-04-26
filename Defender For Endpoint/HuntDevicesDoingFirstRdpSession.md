# *Hunt for devices doing first RDP session*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.001 | Remote Services: Remote Desktop Protocol | https://attack.mitre.org/techniques/T1021/001/ |

#### Description
This hunting query can help you find devices doing an RDP connection for the first time in 30 days. While this can be normal behavior, it might be interesting to look at why this device is suddenly doing an RDP connection. 

#### Risk
By investigating these devices, you might find an attacker performing lateral movement over RDP from an end-user device.

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
let historic_rdp_devices = toscalar(
    DeviceNetworkEvents
    | where Timestamp > ago (30d)
    | where ActionType == "ConnectionSuccess"
    | where RemotePort == 3389
    | summarize make_set(DeviceId)
);
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType == "ConnectionSuccess"
| where RemotePort == 3389
| where DeviceId !in (historic_rdp_devices)
```

## Sentinel
```KQL
let historic_rdp_devices = toscalar(
    DeviceNetworkEvents
    | where TimeGenerated > ago (30d)
    | where ActionType == "ConnectionSuccess"
    | where RemotePort == 3389
    | summarize make_set(DeviceId)
);
DeviceNetworkEvents
| where TimeGenerated > ago(1h)
| where ActionType == "ConnectionSuccess"
| where RemotePort == 3389
| where DeviceId !in (historic_rdp_devices)
```