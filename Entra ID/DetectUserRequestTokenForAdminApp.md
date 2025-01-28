# *Detect non-admin requesting token for admin applications*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1651 | Cloud Administration Command | https://attack.mitre.org/techniques/T1651/ |

#### Description
This rule detects sign-in attempts from non-admin users to admin applications in Entra ID. 

#### Risk
When for example RoadTx is used without modifications, it will request tokens for Azure AD PowerShell. This can easily be detected when done on a non-admin account. 

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com/device-to-entraid/

## Defender XDR
```KQL
N/A
```

## Sentinel
```KQL
let ITAccounts=(_GetWatchlist('ITAccounts') | summarize make_set(ITAccounts));
// Materialize Dataset
let DataSetMat= materialize (SigninLogs
| where TimeGenerated > ago(1h)
| where AppDisplayName has_any ("PowerShell", "CLI", "Command Line", "Management Shell")
// Get successful and failed due to no assignment logins
| where ResultType in ("0", "50105")
| summarize max(TimeGenerated) by UserPrincipalName, AppDisplayName, IPAddress, UserId, ResultType
// join IdentityInfo to get more information
| join kind=leftouter (IdentityInfo | where TimeGenerated > ago(14d) | summarize arg_max(TimeGenerated, *) by AccountObjectId ) on $left.UserId == $right.AccountObjectId
// exclude Accounts with Assigned Roles
| where array_length(AssignedRoles) == 0
// exclude known IT personnel Departments
| where Department !has "it" and Department !has "ict" and Department !has "operations"
// exclude service accounts
| where JobTitle != "Service Account");
// exclude IT accounts
let FIL= (DataSetMat
| extend ITAccounts= toscalar(ITAccounts)
| mv-expand ITAccounts
| where AccountUPN contains ITAccounts or AccountDisplayName contains ITAccounts);
DataSetMat
// exclude service accounts
| join kind=leftanti FIL on AccountUPN
| distinct  max_TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, JobTitle, Department, UserId, ResultType
```