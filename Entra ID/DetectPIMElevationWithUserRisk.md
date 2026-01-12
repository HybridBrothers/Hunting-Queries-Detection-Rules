# *Detect PIM elevation with user risk*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1548 | Abuse Elevation Control Mechanism | https://attack.mitre.org/techniques/T1548/ |

#### Description
When an account with eligible roles in Entra ID is compromised, the attacker will probably escalate their privileges via Microsoft PIM. With this rule you can detect when a risky user is elevating their privileges with PIM.

#### Risk
Detect a compromised account with eligible roles. 

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com/

## Microsoft Sentinel
```KQL
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName contains "PIM activation" and OperationName contains "completed"
| extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| join kind=inner (AADUserRiskEvents | where TimeGenerated > ago(1d)) on UserPrincipalName
```

## Defender XDR
```KQL
CloudAppEvents
| where TimeGenerated > ago(1h)
| where ActionType == "Add member to role."
| extend UserPrincipalName = tostring(RawEventData.ObjectId)
| join kind=inner (AADUserRiskEvents | where TimeGenerated > ago(1d)) on UserPrincipalName
```