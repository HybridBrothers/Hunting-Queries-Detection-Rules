# *Detect Unknown process using SMB or WinRM*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | https://attack.mitre.org/techniques/T1021/002/ |
| T1021.006 | Remote Services: Windows Remote Management | https://attack.mitre.org/techniques/T1021/006/ |

#### Description
WinRM and SMB are popular network protocols to perform lateral movement by adversaries (while there are some others as well). When an unknown process is performing SMB or WinRM network connections, this might indicate that a malware process is trying to move laterally to other devices in your network. 

> [!WARNING]
> This detection rule is the base for the detection. You will need to add environment specific finetuning in order to limit the BP detections on legitimate processes

#### Risk
This detection tries to detect malware performing lateral movement over SMB and WinRM.

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
DeviceNetworkEvents
| where TimeGenerated > ago(1h)
| where RemotePort in ("5985", "5986", "445")
| where ActionType in~ ("ConnectionSuccess", "ConnectionAttempt",
"ConnectionFailed", "ConnectionRequest")
| where isnotempty(InitiatingProcessSHA256)
| invoke FileProfile(InitiatingProcessSHA256)
| where isnotempty(GlobalPrevalence) and GlobalPrevalence < 1000
```
