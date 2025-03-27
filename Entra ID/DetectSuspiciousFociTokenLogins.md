# *Detect suspicious foci token logins*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1651 | Cloud Administration Command | https://attack.mitre.org/techniques/T1651/ |
| T1606 | Forge Web Credentials | https://attack.mitre.org/techniques/T1606/ |

#### Description
FOCI tokens (Family of Client IDs tokens) are special refresh tokens that allow multiple applications within the same "family" to share authentication tokens. This means that once a user authenticates with one application, they can access other applications in the same family without needing to re-authenticate. For adversaries, these are very interesting tokens to abuse since they can access a normal application (Microsoft Teams for example), and reuse that refresh token to access another application (like Azure CLI).

To detect a suspicious foci token combination, we look for all the logins using foci tokens and group them by Session ID (since these belong to the same session). Then we take the first login where no refresh token was provided, and look at the logins that used refresh tokens as incomming token types within that same session. If the second login application is one that is typically abused by adversaries and the application for the first login is a 'normal' application, we flag the event.

Some organizations have a high BP hit count on Microsoft Azure CLI. To limit those hits, you have three finetune options to enable in the query:
- Only alert when first and second login has X time between each other (default 90 minutes if enabled)
- Only alert on Microsoft Azure CLI when Global Administrator scope is used in token
- Only alert on Microsoft Azure CLI when Global Administrator scope is used in token and request came from a non-compliant device

#### Risk
With this detection rule we try to detect suspicious foci token usage.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://swisskyrepo.github.io/InternalAllTheThings/cloud/azure/azure-access-and-token/#foci-refresh-token
- https://github.com/secureworks/family-of-client-ids-research/tree/main

## Sentinel
```KQL
// TimeDiff threshold in minutes. Needed for some environments with a lot of BP hits on long time frames. Used in scenario where you expect adversary to quickly request new tokens after first token request.
let maxTimeDiff = 90;
// External lookup to get list of FOCI applications
let FociClientApplications = toscalar(externaldata(client_id: string)
    [@"https://raw.githubusercontent.com/secureworks/family-of-client-ids-research/refs/heads/main/known-foci-clients.csv"] with (format="csv", ignoreFirstRecord=true)
    //| project-rename FociClientId = client_id
    | summarize FociClientId = make_list(client_id)
    );
// Get all token requests for Foci clients
let FociTokenRequest = materialize (
    AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(6h)
    // Filter for sign-ins to home tenant only
    | where HomeTenantId == ResourceTenantId
    // Lookup for FOCI client
    | where AppId in (FociClientApplications)
    );
FociTokenRequest
// First get all initial logins without refresh tokens as incomming token type
| where IncomingTokenType == "none"
// Then get logins with refresh tokens for same session
| join kind=inner (
    FociTokenRequest
    | where IncomingTokenType != "none"
    | project-rename
        SecondAppDisplayName = AppDisplayName,
        SecondRequestTimeGenerated = TimeGenerated,
        SecondAppId = AppId
    )
    on SessionId, UserPrincipalName
// Exclude when First App ID and Second are the same
| where AppDisplayName != SecondAppDisplayName
// Only get requests where refresh token was used after first sign-in
| extend TimeDiff = datetime_diff('minute', SecondRequestTimeGenerated, TimeGenerated)
| where TimeDiff >= 0 //and TimeDiff <= maxTimeDiff // Remove from comment you want to apply time difference restriction
// Only project needed columns
| project
    FirstRequestTimeGenerated = TimeGenerated,
    FirstResult = ResultType,
    FirstResultDescription = ResultDescription,
    Identity,
    Location,
    FirstAppDisplayName = AppDisplayName,
    FirstAppId = AppId,
    ClientAppUsed,
    DeviceDetail,
    SecondDeviceDetail = DeviceDetail1,
    IPAddress,
    LocationDetails,
    UserAgent,
    SecondRequestTimeGenerated,
    SecondResult = ResultType,
    SecondResultDescription = ResultDescription1,
    SecondAppDisplayName,
    SecondAppId,
    SeconIncomingTokenType = IncomingTokenType1,
    SessionId,
    TimeDiff,
    AuthenticationProcessingDetails,
    SecondAuthenticationProcessingDetails = AuthenticationProcessingDetails1
// Flag logins to the following applications as second login (since they are very popular for attackers and we rather not see logins to these via foci tokens)
| where SecondAppDisplayName in ("Microsoft Azure CLI", "Microsoft Azure PowerShell", "Office 365 Management")
// ENVIRONMENT SPECIFIC FINETUNING - BEGIN
// Most BP triggers are mainly on Microsoft Azure CLI, so we provide two ways of handling these BP detections (strongly depends on environment)
// OPTION 1 - Flag login to Azure CLI using 'Global Administrator' ID in token scope
//| where (SecondAppDisplayName in ("Microsoft Azure PowerShell", "Office 365 Management") or (SecondAppDisplayName == "Microsoft Azure CLI" and SecondAuthenticationProcessingDetails contains "62e90394-69f5-4237-9190-012177145e10"))
// OPTION 2 - Flag login to Azure CLI using 'Global Administrator' ID in token scope from non compliant device
//| where (SecondAppDisplayName in ("Microsoft Azure PowerShell", "Office 365 Management") or (SecondAppDisplayName == "Microsoft Azure CLI" and SecondAuthenticationProcessingDetails contains "62e90394-69f5-4237-9190-012177145e10" and todynamic(SecondDeviceDetail).isCompliant != "true"))
// ENVIRONMENT SPECIFIC FINETUNING - END
```