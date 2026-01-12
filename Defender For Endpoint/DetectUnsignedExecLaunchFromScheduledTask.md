# *Detect Unsigned executable launch from scheduled task*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1053.005 | Scheduled Task/Job: Scheduled Task | https://attack.mitre.org/techniques/T1053/005/ |

#### Description
Persistence via Scheduled Tasks is a well-known technique used by adversaries to make sure their malware programs keep running an the compromised device. With this detection rule, you can search for unknown executables being launched from scheduled tasks.

> [!WARNING]
> This detection rule is the base for the detection. You will need to add environment specific finetuning in order to limit the BP detections on legitimate processes

#### Risk
This detection tries to detect malware being launched from scheduled tasks

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
let scheduled_binaries = (
    DeviceProcessEvents
    | where ActionType !contains "aggregated"
    | where Timestamp > ago(1h)
    | where InitiatingProcessCommandLine == "svchost.exe -k netsvcs -p -s Schedule"
    | distinct SHA1
);
let untrusted_binaries = (
    scheduled_binaries
    | join kind=leftanti (
        DeviceFileCertificateInfo 
        | where Timestamp > ago(1h) 
        | summarize max_trusted=max(IsTrusted) by SHA1 
        | where max_trusted==1
    ) on SHA1
);
untrusted_binaries
| invoke FileProfile(SHA1,1000)
| where IsCertificateValid != 1 // Exclude signed binaries
| where (isnotempty(GlobalPrevalence) and GlobalPrevalence < 1000)
| join (
    DeviceProcessEvents 
    | where ActionType !contains "aggregated"
    | where InitiatingProcessCommandLine == "svchost.exe -k netsvcs -p -s Schedule"
) on SHA1
```
