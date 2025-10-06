# *Detect process drops via Azure ARC performing lateral movement*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.008 | Remote Services: Direct Cloud VM Connections | https://attack.mitre.org/techniques/T1021/008/ |
| T1651 | Cloud Administration Command | https://attack.mitre.org/techniques/T1651/ |
| T1021 | Remote Services | https://attack.mitre.org/techniques/T1021/ |


#### Description
This detection rule spots processes that where dropped via Azure Arc on a machine and are now performing lateral movement. A common procedures for attackers when they compromised one machine is to move laterally to other machines via common protocols such as RDP, SSH, VNC, WMI, RPC, etc. It is not very common in an environment that Azure Arc is being used for this. 

#### Risk
This detection rule tries to mitigate the risk of Azure Arc being used to compromise servers and move laterally through the environment.

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
let process_drop_via_arc = (
    DeviceFileEvents
    | where TimeGenerated > ago(7d)
    // Search for file created events by Arc Custom Script Handler
    | where ActionType == "FileCreated"
    | where InitiatingProcessFileName =~ "customscripthandler.exe"
    | where isnotempty(SHA256)
    | distinct SHA256
);
DeviceNetworkEvents
| where TimeGenerated > ago(1h)
| join kind=inner process_drop_via_arc on $left.InitiatingProcessSHA256 == $right.SHA256
| where RemotePort in ("5985", "5986", "445", "3389", "22", "5900", "135")
| where ActionType in~ ("ConnectionSuccess", "ConnectionAttempt", 
"ConnectionFailed", "ConnectionRequest")
```