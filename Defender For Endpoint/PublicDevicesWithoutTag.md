# *Hunt for public facing devices via DeviceNetworkEvents*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1190 | Exploit Public-Facing Application | https://attack.mitre.org/techniques/T1190/ |

#### Description
Find public facing devices via the DeviceNetworkEvents table.

#### Risk
When a proxy solution is in front of the public facing device, the devices will not be included in this query.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com/analyzing-mde-network-inspections/

## Defender XDR
```KQL
DeviceNetworkEvents
| where ActionType contains "InboundConnection"
| where RemoteIPType == "Public"
| distinct DeviceName
```

## Sentinel
```KQL
N/A
```