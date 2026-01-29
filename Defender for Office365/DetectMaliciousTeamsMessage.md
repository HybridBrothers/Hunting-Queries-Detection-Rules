# *Detect Malicious Teams Message*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |

#### Description

#### Risk


#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References


## Defender XDR
```KQL
// Malicious messages detection
MessageEvents
| where ThreatTypes != ""
| join kind=leftouter MessageUrlInfo on TeamsMessageId
```