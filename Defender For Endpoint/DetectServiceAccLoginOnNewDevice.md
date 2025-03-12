# *Detect service account login on new device*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.001 | Remote Services: Remote Desktop Protocol | https://attack.mitre.org/techniques/T1021/001/ |
| T1021.002 | Remote Services: SMB/Windows Admin Shares | https://attack.mitre.org/techniques/T1021/002/ |
| T1021.003 | Remote Services: Distributed Component Object Model | https://attack.mitre.org/techniques/T1021/003/ |
| T1021.006 | Remote Services: Windows Remote Management | https://attack.mitre.org/techniques/T1021/006/ |

#### Description
This detection rule tries to flag suspicious logins on devices from service accounts, for which these service accounts did not login into those devices for the last 14 days. This might indicate that the service account is compromised and is being used for lateral movement into the environment.

Most service accounts have a fearly static set of devices they authenticate to. Because of this, it is easier to flag deviations for service accounts compared to user accounts. However, some service accounts are known to dynamically log into devices based on observed events (susch as the MDI service accounts). Because of this some environment specific finetuning might be needed to reduce BP detections.

#### Risk
This detections tries to cover the risk of service account compromise being used for lateral movement.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References

## Defender XDR
```KQL
// Get all enabled service accounts
let service_acc = (
    IdentityInfo
    | where Timestamp > ago(7d)
    | where Type == "ServiceAccount" and IsAccountEnabled == 1
    | distinct AccountName = tolower(AccountName)
);
// Get the history service account logins
let historic_events = (
    DeviceLogonEvents
    | where Timestamp between (ago(14d) .. ago(1h))
    | where ActionType == "LogonSuccess"
    | extend AccountName = tolower(AccountName)
    | join kind=inner service_acc on AccountName
    | summarize HistoricLogins = make_set(DeviceName) by AccountName
);
// Get the account logins done over Network
DeviceLogonEvents
| where Timestamp > ago(1h)
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| extend AccountName = tolower(AccountName)
// Join inner to only get known service account logins
| join kind=inner service_acc on AccountName
// Join inner to get a list of the historic device logins for the service accounts
| join kind=inner historic_events on AccountName
// Only get sign-ins where Device is not in the history logins
| extend HistoricLogins = tostring(HistoricLogins)
| where HistoricLogins !contains DeviceName
// Make output better
| project-away AccountName1, AccountName2
// Exclude MDI Service Account - CHANGE IF DIFFERENT FOR YOUR ORG
| where AccountName != "gsma_mdi$"
// Environment specific finetuning - begin
// Environment specific finetuning - end
```

## Sentinel
```KQL
// Get all enabled service accounts
let service_acc = (
    IdentityInfo
    | where TimeGenerated > ago(7d)
    | where Type == "ServiceAccount" and IsAccountEnabled == 1
    | distinct AccountName = tolower(AccountName)
);
// Get the history service account logins
let historic_events = (
    DeviceLogonEvents
    | where TimeGenerated between (ago(14d) .. ago(1h))
    | where ActionType == "LogonSuccess"
    | extend AccountName = tolower(AccountName)
    | join kind=inner service_acc on AccountName
    | summarize HistoricLogins = make_set(DeviceName) by AccountName
);
// Get the account logins done over Network
DeviceLogonEvents
| where TimeGenerated > ago(1h)
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| extend AccountName = tolower(AccountName)
// Join inner to only get known service account logins
| join kind=inner service_acc on AccountName
// Join inner to get a list of the historic device logins for the service accounts
| join kind=inner historic_events on AccountName
// Only get sign-ins where Device is not in the history logins
| extend HistoricLogins = tostring(HistoricLogins)
| where HistoricLogins !contains DeviceName
// Make output better
| project-away AccountName1, AccountName2
// Exclude MDI Service Account - CHANGE IF DIFFERENT FOR YOUR ORG
| where AccountName != "gsma_mdi$"
// Environment specific finetuning - begin
// Environment specific finetuning - end
```