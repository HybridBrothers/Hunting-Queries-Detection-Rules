# *Detect suspicious conditional access policy modifications*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1556.009 | Modify Authentication Process: Conditional Access Policies | https://attack.mitre.org/techniques/T1556/009/ |

#### Description
This detection rule flags events where conditional access policies are getting weaker, when modifications to CA inclusion or exclusion groups are happening, or when the effectiveness of a policy is disabled.

#### Risk
By using this detections, we try to cover the risk of a malicious actor changing authorization policies in Entra ID.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com/suspicious-conditional-access-modifications/

## Defender XDR
```KQL
N/A
```

## Sentinel
```KQL
// !! TO DO: CHANGE TO YOUR CA GROUP NAMING CONVENTION !!
let ca_include_naming_convention = "CA-Include";
let ca_exclude_naming_convention = "CA-Exclude";
// OPTIONAL - Get PIM activations with justifications for CA changes
let ca_pim_activations = AuditLogs
    // Get PIM activations
    | where TimeGenerated > ago(24h)
    | where OperationName contains "completed (PIM activation)"
    // Parse details
    | parse AdditionalDetails with * "{\"key\":\"StartTime\",\"value\":\"" PimStartTime "\"" * "{\"key\":\"ExpirationTime\",\"value\":\"" PimExpirationTime "\"" * "{\"key\":\"Justification\",\"value\":\"" PimJustification "\"" *
    // Only get CA related PIM justifications
    | where PimJustification has_any ("Conditional Access", "CA", "Trusted", "Named", "Location")
    // Extend and projects
    | extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
    | project OperationName, PimJustification, PimStartTime, PimExpirationTime, UserPrincipalName;
// Get suspicious policy changes
let policy_changes = AuditLogs
    // Get CA updates
    | where TimeGenerated > ago(24h)
    | where OperationName in ("Update conditional access policy", "Delete conditional access policy")
    // Expand Target resources and the modified properties
    | mv-expand TargetResources
    | mv-expand TargetResources.modifiedProperties
    // Save the new and old values
    | extend NewValueConditions = parse_json(tostring(parse_json(TargetResources_modifiedProperties.newValue))).conditions
    | extend OldValueConditions = parse_json(tostring(parse_json(TargetResources_modifiedProperties.oldValue))).conditions
    | extend NewValueGrandControls = parse_json(tostring(parse_json(TargetResources_modifiedProperties.newValue))).grantControls
    | extend OldValueGrandControls = parse_json(tostring(parse_json(TargetResources_modifiedProperties.oldValue))).grantControls
    | extend NewValueSessionControls = parse_json(tostring(parse_json(TargetResources_modifiedProperties.newValue))).sessionControls
    | extend OldValueSessionControls = parse_json(tostring(parse_json(TargetResources_modifiedProperties.oldValue))).sessionControls
    | extend NewState = parse_json(tostring(parse_json(TargetResources_modifiedProperties.newValue))).state
    | extend OldState = parse_json(tostring(parse_json(TargetResources_modifiedProperties.oldValue))).state
    // Count the new inlude arrays
    | extend CountNewUserIncludes = array_length(NewValueConditions.users.includeUsers),
        CountNewRoleIncludes = array_length(NewValueConditions.users.includeRoles),
        CountNewGroupIncludes = array_length(NewValueConditions.users.includeGroups),
        CountNewUserActionIncludes = array_length(NewValueConditions.applications.inlcudeUserActions),
        CountNewAuthContextIncludes = array_length(NewValueConditions.applications.includeAuthenticationContextClassReferences),
        CountNewApplicationIncludes = array_length(NewValueConditions.applications.inlcudeApplications),
        CountNewLocationIncludes = array_length(NewValueConditions.locations.includeLocations),
        CountNewPlatformIncludes = array_length(NewValueConditions.platforms.includePlatforms)
    // Count the old inlude arrays
    | extend CountOldUserIncludes = array_length(OldValueConditions.users.includeUsers),
        CountOldRoleIncludes = array_length(OldValueConditions.users.includeRoles),
        CountOldGroupIncludes = array_length(OldValueConditions.users.includeGroups),
        CountOldUserActionIncludes = array_length(OldValueConditions.applications.inlcudeUserActions),
        CountOldAuthContextIncludes = array_length(OldValueConditions.applications.includeAuthenticationContextClassReferences),
        CountOldApplicationIncludes = array_length(OldValueConditions.applications.inlcudeApplications),
        CountOldLocationIncludes = array_length(OldValueConditions.locations.includeLocations),
        CountOldPlatformIncludes = array_length(OldValueConditions.platforms.includePlatforms)
    // Count the new exclude arrays
    | extend CountNewUserExcludes = array_length(NewValueConditions.users.excludeUsers),
        CountNewRoleExcludes = array_length(NewValueConditions.users.excludeRoles),
        CountNewGroupExcludes = array_length(NewValueConditions.users.excludeGroups),
        CountNewApplicationExcludes = array_length(NewValueConditions.applications.excludeApplications),
        CountNewLocationExcludes = array_length(NewValueConditions.locations.excludeLocations),
        CountNewPlatformExcludes = array_length(NewValueConditions.platforms.excludePlatforms)
    // Count the old exclude arrays
    | extend CountOldUserExcludes = array_length(OldValueConditions.users.excludeUsers),
        CountOldRoleExcludes = array_length(OldValueConditions.users.excludeRoles),
        CountOldGroupExcludes = array_length(OldValueConditions.users.excludeGroups),
        CountOldApplicationExcludes = array_length(OldValueConditions.applications.excludeApplications),
        CountOldLocationExcludes = array_length(OldValueConditions.locations.excludeLocations),
        CountOldPlatformExcludes = array_length(OldValueConditions.platforms.excludePlatforms)
    // Alert when includes are taken away and excludes are added, application filter changes, or AppType changes
    | extend Reasons = dynamic([])
    | extend Reasons = iff(CountNewUserIncludes < CountOldUserIncludes, array_concat(Reasons, dynamic(["User removed from include"])), Reasons)
    | extend Reasons = iff(CountNewRoleIncludes < CountOldRoleIncludes, array_concat(Reasons, dynamic(["Role removed from include"])), Reasons)
    | extend Reasons = iff(CountNewGroupIncludes < CountOldGroupIncludes, array_concat(Reasons, dynamic(["Group removed from include"])), Reasons)
    | extend Reasons = iff(CountNewUserExcludes > CountOldUserExcludes, array_concat(Reasons, dynamic(["User added to exclude"])), Reasons)
    | extend Reasons = iff(CountNewRoleExcludes > CountOldRoleExcludes, array_concat(Reasons, dynamic(["Role added to exclude"])), Reasons)
    | extend Reasons = iff(CountNewGroupExcludes > CountOldGroupExcludes, array_concat(Reasons, dynamic(["Group added to exclude"])), Reasons)
    | extend Reasons = iff(CountNewUserActionIncludes < CountOldUserActionIncludes, array_concat(Reasons, dynamic(["User action removed from include"])), Reasons)
    | extend Reasons = iff(CountNewAuthContextIncludes < CountOldAuthContextIncludes, array_concat(Reasons, dynamic(["Authentication context removed from include"])), Reasons)
    | extend Reasons = iff(CountNewApplicationIncludes < CountOldApplicationIncludes, array_concat(Reasons, dynamic(["Application removed from include"])), Reasons)
    | extend Reasons = iff(CountNewApplicationExcludes > CountOldApplicationExcludes, array_concat(Reasons, dynamic(["Application added to exclude"])), Reasons)
    | extend Reasons = iff(CountNewLocationIncludes < CountOldLocationIncludes, array_concat(Reasons, dynamic(["Locations removed from include"])), Reasons)
    | extend Reasons = iff(CountNewLocationExcludes > CountOldLocationExcludes, array_concat(Reasons, dynamic(["Locations added to exclude"])), Reasons)
    | extend Reasons = iff(CountNewPlatformIncludes < CountOldPlatformIncludes, array_concat(Reasons, dynamic(["Platforms removed from include"])), Reasons)
    | extend Reasons = iff(CountNewPlatformExcludes > CountOldPlatformExcludes, array_concat(Reasons, dynamic(["Platforms added to exclude"])), Reasons)
    // Flag general changes
    | extend Reasons = iff(tostring(NewValueConditions.applications.applicationFilter) != tostring(OldValueConditions.applications.applicationFilter), array_concat(Reasons, dynamic(["Application filter changed"])), Reasons)
    | extend Reasons = iff(tostring(NewValueConditions.clientAppTypes) != tostring(OldValueConditions.clientAppTypes), array_concat(Reasons, dynamic(["Client app type changed"])), Reasons)
    | extend Reasons = iff(tostring(NewValueConditions.userRiskLevels) != tostring(OldValueConditions.userRiskLevels), array_concat(Reasons, dynamic(["User risk levels changed"])), Reasons)
    | extend Reasons = iff(tostring(NewValueConditions.signInRiskLevels) != tostring(OldValueConditions.signInRiskLevels), array_concat(Reasons, dynamic(["Sign-in risk levels changed"])), Reasons)
    | extend Reasons = iff(tostring(NewValueConditions.servicePrincipalRiskLevels) != tostring(OldValueConditions.servicePrincipalRiskLevels), array_concat(Reasons, dynamic(["Service Principal risk levels changed"])), Reasons)
    | extend Reasons = iff(tostring(NewValueGrandControls) != tostring(OldValueGrandControls), array_concat(Reasons, dynamic(["Grant controls changed"])), Reasons)
    | extend Reasons = iff(tostring(NewValueSessionControls) != tostring(OldValueSessionControls), array_concat(Reasons, dynamic(["Session controls changed"])), Reasons)
    | extend Reasons = iff(tostring(NewValueConditions.devices) != tostring(OldValueConditions.devices), array_concat(Reasons, dynamic(["Device conditions changed"])), Reasons)
    // Flag Change from include 'all' to only include specifics (since this can evade the count detections)
    | extend Reasons = iff(tostring(OldValueConditions.locations.includeLocations) contains "all" and tostring(NewValueConditions.locations.includeLocations) !contains "all", array_concat(Reasons, dynamic(["Include locations changed from all to specific"])), Reasons)
    | extend Reasons = iff(tostring(OldValueConditions.platforms.includePlatforms) contains "all" and tostring(NewValueConditions.platforms.includePlatforms) !contains "all", array_concat(Reasons, dynamic(["Include platforms changed from all to specific"])), Reasons)
    | extend Reasons = iff(tostring(OldValueConditions.users.includeUsers) contains "all" and tostring(NewValueConditions.users.includeUsers) !contains "all", array_concat(Reasons, dynamic(["Include users changed from all to specific"])), Reasons)
    | extend Reasons = iff(tostring(OldValueConditions.applications.includeApplications) contains "all" and tostring(NewValueConditions.applications.includeApplications) !contains "all", array_concat(Reasons, dynamic(["Include applications changed from all to specific"])), Reasons)
    // Flag state change to inactive
    | extend Reasons = iff(tostring(OldState) == "enabled" and tostring(NewState) != "enabled", array_concat(Reasons, dynamic(["Policy was disabled"])), Reasons)
    // Flag policy deletion
    | extend Reasons = iff(OperationName == "Delete conditional access policy", array_concat(Reasons, dynamic(["Policy was deleted"])), Reasons);
// Get trusted named location changes
let named_locations = AuditLogs
    // Get named location changes
    | where TimeGenerated > ago(24h)
    | where OperationName in ("Add named location", "Update named location")
    // Expand Target resources and the modified properties
    | mv-expand TargetResources
    | mv-expand TargetResources.modifiedProperties
    // Always flag when the named location is trusted
    | extend NewValueIsTrusted = parse_json(tostring(parse_json(TargetResources_modifiedProperties.newValue))).isTrusted
    | where NewValueIsTrusted == "true"
    // Add reason
    | extend Reasons = dynamic([])
    | extend Reasons = iff(OperationName == "Add named location", array_concat(Reasons, dynamic(["Trusted named location was added"])), Reasons)
    | extend Reasons = iff(OperationName == "Update named location", array_concat(Reasons, dynamic(["Trusted named location was updated"])), Reasons);
// Get changes to groups used in CA policies
let remove_from_include_group = AuditLogs
    | where TimeGenerated > ago(24h)
    | where OperationName == "Remove member from group"
    // Expand Target resources and the modified properties
    | mv-expand TargetResources
    | mv-expand TargetResources.modifiedProperties
    // Search for the display name of the edited group and find groups with CA naming convention
    | where TargetResources_modifiedProperties.displayName == "Group.DisplayName" and TargetResources_modifiedProperties contains ca_include_naming_convention
    // Add reason
    | extend Reasons = dynamic([])
    | extend Reasons = dynamic(["Member removed from include group used in CA policy"]);
let add_to_exclude_group = AuditLogs
    | where TimeGenerated > ago(24h)
    | where OperationName == "Add member to group"
    // Expand Target resources and the modified properties
    | mv-expand TargetResources
    | mv-expand TargetResources.modifiedProperties
    // Search for the display name of the edited group and find groups with CA naming convention
    | where TargetResources_modifiedProperties.displayName == "Group.DisplayName" and TargetResources_modifiedProperties contains ca_exclude_naming_convention
    // Add reason
    | extend Reasons = dynamic([])
    | extend Reasons = dynamic(["Member added to exclude group used in CA policy"]);
// Union all detections
union policy_changes, named_locations, remove_from_include_group, add_to_exclude_group
// Check if reason array is empty
| where Reasons != "[]"
// Sorting and project
| sort by TimeGenerated desc
| project TimeGenerated, OperationName, InitiatedBy, LoggedByService, Result, TargetResources, AADOperationType, Reasons
| extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
// Look for PIM activations from the same user who performed changes
| join kind=leftouter ca_pim_activations on UserPrincipalName
| project-away UserPrincipalName1
// Check if PIM was justified for user, and only show non-justified PIMs
| extend JustifiedPIM = iff(isnotempty(PimStartTime) and isnotempty(PimExpirationTime) and TimeGenerated between (todatetime(PimStartTime) .. todatetime(PimExpirationTime)), true, false)
| where JustifiedPIM == false
```