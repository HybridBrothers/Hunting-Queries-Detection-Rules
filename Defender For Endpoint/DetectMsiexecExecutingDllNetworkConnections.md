# *Detect Msiexec executing DLL network connections*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1218.007 | System Binary Proxy Execution: Msiexec | https://attack.mitre.org/techniques/T1218/007/ |

#### Description
Adversaries regularly use Msiexec (or other lolbins) to execute their malicious programs with. A common way to do this is more specifically using Msiexec to execute beacons encapsulated in DLL files. While this happens a lot in legitimate cases, a DLL file loaded via Msiexec starting network connections may indicate a beacon running. 

> [!WARNING]
> You might need to add environment specific finetuning to this rule in order to reduce BP detections from legitimate processes.

#### Risk
This detection tries to detect beacons in DLL files that are loaded via the Msiexec lolbin. 

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
| where InitiatingProcessParentFileName =~ "msiexec.exe"
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(3d)
    | where InitiatingProcessFileName =~ "msiexec.exe"
) on DeviceId, 
    $left.InitiatingProcessParentId == $right.InitiatingProcessId,
    $left.InitiatingProcessParentCreationTime == $right.InitiatingProcessCreationTime
| where InitiatingProcessCommandLine1 has_any ("/y", "-y", "/z", "-z")
```
