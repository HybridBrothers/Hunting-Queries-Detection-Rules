# *Detect changes to Connect Sync Application*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098 | Account Manipulation | https://attack.mitre.org/techniques/T1098/ |
| T1078.004 | Valid Accounts: Cloud Accounts | https://attack.mitre.org/techniques/T1078/004/ |
| T1556.007 | Modify Authentication Process: Hybrid Identity | https://attack.mitre.org/techniques/T1556/007/ |

#### Description
This detection flags any changes happening on the Connect Sync Application in Entra ID. Since this is a very interesting account for attackers to abuse when moving laterally between AD DS and Entra ID, any change to the account should be investigated. We try to exclude legitimate certificate renewal processes, and a new account onboarding in the detection rule. 

#### Risk
This detection tries to cover the risk of an attacker trying to manipulate the Connect Sync Application.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://specterops.io/blog/2025/06/09/update-dumping-entra-connect-sync-credentials/

## Defender XDR
```KQL
// Flag everything except a renewal process and onboarding
let base = materialize (
    AuditLogs
    // Search events happening on the Sync Account
    | extend AppName = tostring(TargetResources[0].displayName)
    | where AppName startswith "ConnectSyncProvisioning_"
    // Only get cretificate or secret changes
    | where OperationName contains "Update application – Certificates and secrets management"
    // Expand the target resources and modified properties, and only use events ralted to KeyDescription
    | mv-expand TargetResources
    | extend ModifiedProperties = TargetResources.modifiedProperties
    | mv-expand ModifiedProperties
    | where ModifiedProperties.displayName == "KeyDescription"
    // Save the old and new values of the secrets on the application
    | extend OldValue = tostring(ModifiedProperties.oldValue), 
        NewValue = tostring(ModifiedProperties.newValue)
    // Save the old and new credential names in an array
    | extend OldCredentialNames = extract_all(@"DisplayName=([^\]]+)", dynamic([1]), OldValue),
        NewCredentialNames = extract_all(@"DisplayName=([^\]]+)", dynamic([1]), NewValue)
);
let newCredsAdd = (
    base
    // Flag when there are more new credentials than old ones
    | where array_length(OldCredentialNames) < array_length(NewCredentialNames)
    | project-rename NewCredAddTimeGenerated = TimeGenerated
);
let credRemove = (
    base
    // Get events where credentials are being removed
    | where array_length(OldCredentialNames) > array_length(NewCredentialNames)
    | project-rename CredRemoveTimeGenerated = TimeGenerated
);
let credRenewal = (
    // Find legitimate credential renewals
    newCredsAdd
    | join kind=leftouter credRemove on AppName
    | where CredRemoveTimeGenerated - NewCredAddTimeGenerated <= 1m
);
AuditLogs
| extend AppName = tostring(TargetResources[0].displayName)
| where AppName startswith "ConnectSyncProvisioning_"
| join kind=leftanti credRenewal on CorrelationId
// Exclude cred removes (duplicate / not interesting)
| join kind=leftanti credRemove on CorrelationId
// Exclude new deployment
| where OperationName !in ("Add service principal", "Add application")
```

## Sentinel
```KQL
// Flag everything except a renewal process and onboarding
let base = materialize (
    AuditLogs
    // Search events happening on the Sync Account
    | extend AppName = tostring(TargetResources[0].displayName)
    | where AppName startswith "ConnectSyncProvisioning_"
    // Only get cretificate or secret changes
    | where OperationName contains "Update application – Certificates and secrets management"
    // Expand the target resources and modified properties, and only use events ralted to KeyDescription
    | mv-expand TargetResources
    | extend ModifiedProperties = TargetResources.modifiedProperties
    | mv-expand ModifiedProperties
    | where ModifiedProperties.displayName == "KeyDescription"
    // Save the old and new values of the secrets on the application
    | extend OldValue = tostring(ModifiedProperties.oldValue), 
        NewValue = tostring(ModifiedProperties.newValue)
    // Save the old and new credential names in an array
    | extend OldCredentialNames = extract_all(@"DisplayName=([^\]]+)", dynamic([1]), OldValue),
        NewCredentialNames = extract_all(@"DisplayName=([^\]]+)", dynamic([1]), NewValue)
);
let newCredsAdd = (
    base
    // Flag when there are more new credentials than old ones
    | where array_length(OldCredentialNames) < array_length(NewCredentialNames)
    | project-rename NewCredAddTimeGenerated = TimeGenerated
);
let credRemove = (
    base
    // Get events where credentials are being removed
    | where array_length(OldCredentialNames) > array_length(NewCredentialNames)
    | project-rename CredRemoveTimeGenerated = TimeGenerated
);
let credRenewal = (
    // Find legitimate credential renewals
    newCredsAdd
    | join kind=leftouter credRemove on AppName
    | where CredRemoveTimeGenerated - NewCredAddTimeGenerated <= 1m
);
AuditLogs
| extend AppName = tostring(TargetResources[0].displayName)
| where AppName startswith "ConnectSyncProvisioning_"
| join kind=leftanti credRenewal on CorrelationId
// Exclude cred removes (duplicate / not interesting)
| join kind=leftanti credRemove on CorrelationId
// Exclude new deployment
| where OperationName !in ("Add service principal", "Add application")
```