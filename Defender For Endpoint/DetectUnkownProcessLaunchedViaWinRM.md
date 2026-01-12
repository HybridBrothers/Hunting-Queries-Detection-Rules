# *Detect Unknown process launched via WinRM*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.006 | Remote Services: Windows Remote Management | https://attack.mitre.org/techniques/T1021/006/ |

#### Description
When an unknown process is being launched from the WinRM service on a server, this might indicate a malicious actor spreading malware on various servers via the WinRM protocol.

#### Risk
This detection tries to detect malware being dropped over the WinRM protocol.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://thecollective.eu/

## Defender XDR
```KQL
DeviceProcessEvents
| where InitiatingProcessFileName contains "wsmprovhost.exe"
| invoke FileProfile(SHA1)
| where GlobalPrevalence < 1000
| join kind=leftouter (
    DeviceNetworkEvents
    | where ActionType == "InboundConnectionAccepted"
    | where LocalPort in ("5985", "5986")
    | distinct RemoteIP, DeviceId
) on DeviceId
| project-away DeviceId1
```
