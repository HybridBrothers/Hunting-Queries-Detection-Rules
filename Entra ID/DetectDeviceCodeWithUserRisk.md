# *Detect device code login with user risk*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078.004 | Valid Accounts: Cloud Accounts | https://attack.mitre.org/techniques/T1078/004/ |

#### Description
Threat actors regularly use Device Code authentication to login into compromised accounts. Popular attacks for this are using device code phishing attacks for example. Even though **every organization should block device code authentication in conditional access**, you can create a fall-back detection rule to flag device code logins by risky users. 

#### Risk
Detect attackers login into an account after a device code phishing attack.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://www.microsoft.com/en-us/security/blog/2025/05/29/defending-against-evolving-identity-attack-techniques/

## Microsoft Sentinel
```KQL
union SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(1h)
| where ResultSignature =~ "SUCCESS"
| where AuthenticationProtocol =~ "deviceCode"
| join kind=inner (AADUserRiskEvents | where TimeGenerated > ago(1d)) on UserPrincipalName
```