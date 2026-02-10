# *Detect Malicious Teams Message*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1204.001 | User Execution: Malicious Link | https://attack.mitre.org/techniques/T1204/001/ |
| T1566.002 | Phishing: Spearphishing Link | https://attack.mitre.org/techniques/T1566/002/ |

#### Description
This detection rule detects Microsoft Teams messages where MDO detected a threat in the message.

#### Risk
Malicious messages being send to users can be the beginning of an Initial Access.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com
- https://thecollective.eu

## Defender XDR
```KQL
// Malicious messages detection
MessageEvents
| where ThreatTypes != ""
| join kind=leftouter MessageUrlInfo on TeamsMessageId
```