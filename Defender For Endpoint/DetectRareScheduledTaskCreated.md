# *Detect Rare scheduled task created*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1053.005 | Scheduled Task/Job: Scheduled Task | https://attack.mitre.org/techniques/T1053/005/ |

#### Description
Persistence via Scheduled Tasks is a well-known technique used by adversaries to make sure their malware programs keep running an the compromised device. With this detection rule, you can search for scheduled tasks being created by processes that did not performed this before.

> [!WARNING]
> This detection rule is the base for the detection. You will need to add environment specific finetuning in order to limit the BP detections on legitimate processes

#### Risk
This detection tries to detect malware making itself persistent via scheduled tasks.

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
let lolbins = toscalar(externaldata(FileName:string, Description:string, Author:string, Date:datetime, Command:string, CommandDescription:string, CommandUsecase:string, CommandCategory:string)
    ["https://lolbas-project.github.io/api/lolbas.csv"] with(format="csv", ignoreFirstRecord=true)
    | extend FileName = tolower(FileName)
    | summarize make_set(FileName)
);
// Setting up the rare ones.
let rareScheduledTaskRegistrations = toscalar(
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where ProcessCommandLine has_all ("schtasks",  "/create")
    | summarize count() by ProcessCommandLine
    | where count_ < 5
    | summarize make_set(ProcessCommandLine)
);
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessCommandLine has_all ("schtasks",  "/create")
| extend ProcessCommandLine = replace_regex(ProcessCommandLine, @"C:\\Users\\[^\\]+", "C:\\Users\\<USERNAME>")
// Only take the ones in the last day we find rare within the organization.
| where ProcessCommandLine in (rareScheduledTaskRegistrations)
| invoke FileProfile(InitiatingProcessSHA256, 1000)
| where not(GlobalPrevalence > 1000 and tolower(InitiatingProcessFileName) !in (lolbins))
```
