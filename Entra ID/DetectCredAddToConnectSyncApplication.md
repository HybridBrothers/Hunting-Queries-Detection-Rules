# *Detect credential add to Connect Sync Application*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1098 | Account Manipulation | https://attack.mitre.org/techniques/T1098/ |
| T1098.001 | Account Manipulation: Additional Cloud Credentials | https://attack.mitre.org/techniques/T1098/001/ |
| T1078.004 | Valid Accounts: Cloud Accounts | https://attack.mitre.org/techniques/T1078/004/ |
| T1556.007 | Modify Authentication Process: Hybrid Identity | https://attack.mitre.org/techniques/T1556/007/ |

#### Description
This detection specifically flags credentials being added to the Connect Sync Application in Entra ID, a technique known to have persistance from On-premise AD DS to Entra ID. It tries to look at both certificate, client secret, and federated credentials being added, and tries to remove legitimate renewal processes. Since the legitimate renewal process first adds a new certificate only te remove the old one short after, we by default allow for a maximum of 1 minute between the certificate create and delete events.

#### Risk
This detection tries to cover the risk of an attacker trying to persist access to Entra ID via a compromised Entra ID Connector account, as exlplained in the SpecterOps blogpost which can be found in the references. 


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
// Flag adding credential that does not look like a renewal
let base = materialize (
    AuditLogs
    // Search events happening on the Sync Account
    | extend AppName = tostring(TargetResources[0].displayName)
    | where AppName startswith "ConnectSyncProvisioning_"
    // Only get cretificate or secret changes
    | where OperationName has_any ("Add service principal", "Certificates and secrets management", "Update application")
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
// Only flag when credentials are added without another being removed for the same application within a small time window
// This excludes a normal renewal process
newCredsAdd
| join kind=leftouter credRemove on AppName
| where CredRemoveTimeGenerated - NewCredAddTimeGenerated > 1m
| project NewCredAddTimeGenerated, CredRemoveTimeGenerated, OperationName, AdditionalDetails, InitiatedBy, AppName, ModifiedProperties, OldCredentialNames, NewCredentialNames
```

## Sentinel
```KQL
// Flag adding credential that does not look like a renewal
let base = materialize (
    AuditLogs
    // Search events happening on the Sync Account
    | extend AppName = tostring(TargetResources[0].displayName)
    | where AppName startswith "ConnectSyncProvisioning_"
    // Only get cretificate or secret changes
    | where OperationName has_any ("Add service principal", "Certificates and secrets management", "Update application")
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
// Only flag when credentials are added without another being removed for the same application within a small time window
// This excludes a normal renewal process
newCredsAdd
| join kind=leftouter credRemove on AppName
| where CredRemoveTimeGenerated - NewCredAddTimeGenerated > 1m
| project NewCredAddTimeGenerated, CredRemoveTimeGenerated, OperationName, AdditionalDetails, InitiatedBy, AppName, ModifiedProperties, OldCredentialNames, NewCredentialNames
```
