# *Detect first time Arc Custom Script or Run Command deployment*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.008 | Remote Services: Direct Cloud VM Connections | https://attack.mitre.org/techniques/T1021/008/ |
| T1651 | Cloud Administration Command | https://attack.mitre.org/techniques/T1651/ |


#### Description
This detection rule flags using UEBA of Defender XDR and Microsoft Sentinel if it is the first time that an account is deploying Custom Scripts or Run Commands on Azure Arc machines. Since UEBA uses a baseline of 180 days, it might indicate that an account is being abused to compormise Azure Arc machines.  

#### Risk
This rule tries to mitigate the risk of cloud admin accounts being abused to compromised Azure Arc machines while Custom Scripts or Run Commands are not really used in the environment.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://learn.microsoft.com/en-us/azure/sentinel/ueba-reference?tabs=log-analytics#action-performed
- https://thecollective.eu/

## Defender XDR
```kql
BehaviorAnalytics
| where TimeGenerated > ago(1h)
| extend ActivityInsights = parse_json(ActivityInsights)
| where ActivityInsights.EventMessage has_any ('runCommand/action', 'extensions/write')
| where ActivityInsights.FirstTimeUserPerformedAction == "True"
```