# *Detect executable drops via Azure ARC custom script extension*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.008 | Remote Services: Direct Cloud VM Connections | https://attack.mitre.org/techniques/T1021/008/ |
| T1651 | Cloud Administration Command | https://attack.mitre.org/techniques/T1651/ |


#### Description
This detection rule flags when the Azure Arc service on a machine is dropping executable files. This might indicate that an actor is trying to drop malware or beacons via a compromised cloud admin account. In the most legitimate cases administrators are pushing only PowerShell or Shell scripts, although these can also contain malicious content. Be aware of this gap in the below detection rule. 

#### Risk
This rule triest to mitigate the risk of malicious actors trying to deploy malware or beacons via Azure Arc.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://thecollective.eu/

## Defender XDR
```kql
// Executable extensions we want to flag (you can also add .ps1 and .sh)
let win_executable_extensions = dynamic([".dll", ".exe", ".msi", ".bat", ".cmd", ".com", ".vbs", ".wsf", ".scr", ".cpl"]);
let linux_executable_extensions = dynamic([".bin", ".run", ".py", ".pl", ".out", ".appimage", ".deb", ".rpm"]);
DeviceFileEvents
| where TimeGenerated > ago(1h)
// Search for file created events by Arc Custom Script Handler
| where ActionType == "FileCreated"
| where InitiatingProcessFileName =~ "customscripthandler.exe"
// Get the file type
| extend FileType = tostring(parse_json(AdditionalFields).FileType)
// Flag on extension or executable file type
| where FileName has_any (win_executable_extensions) or 
    FileName has_any (linux_executable_extensions) or 
    FileType contains "Executable"
```