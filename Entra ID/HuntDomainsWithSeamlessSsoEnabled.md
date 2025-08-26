# *Hunt domains with Seamless SSO enabled in Entra ID Connect*

## Query Information

#### MITRE ATT&CK Technique(s)

N/A

#### Description
With below KQL query you can search through the IdentityLogon events of Microsoft Defender for Identity to find users and devices still using Seamless SSO in Entra ID Connect. This feature has been marked by the community multiple times as a security risk, and should be disabled if not in use. The KQL query returns the domains where Seamless SSO is enabled, allong with the related users and devices. On top of that, devices get enriched to find their OS distribution, version, and join type and tells you if Seamless SSO is expected to be used for the related device or not. If there are no results or if all results are showing 'No' for the 'Seamless SSO Expected' column, it should be save to disable the feature in Entra ID connect.

!**Important**: This query relies on the Domain Controller EventID 4769 and Defender for Identity. Make sure the EventID is being logged and Defender for Identity is healthy. For more information see references!

#### Risk
See reference for impacted scenario's. 

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://nathanmcnulty.com/blog/2025/08/finding-seamless-sso-usage/#
- https://ourcloudnetwork.com/why-you-should-disable-seamless-sso-in-microsoft-entra-connect/

## Defender XDR
```KQL
// Get all device info we can find
let devices = (
    DeviceInfo
    // Search for 14 days
    | where TimeGenerated > ago(14d)
    // Normalize DeviceName 
    // --> if it is an IP Address we keep it
    // --> If it is not an IP Address we only use the hostname for correlation
    | extend DeviceName = iff(ipv4_is_private(DeviceName), DeviceName, tolower(split(DeviceName, ".")[0]))
    // Only get interesting data
    | distinct DeviceName, OSPlatform, OSVersion, DeviceId, OnboardingStatus, Model, JoinType
);
IdentityLogonEvents
// Get the last 30 days of logon events on Domain Controllers
| where TimeGenerated > ago(30d)
// Search for Seamless SSO events
| where Application == "Active Directory" and Protocol == "Kerberos"
| where TargetDeviceName == "AZUREADSSOACC"
// Save the domain name of the Domain Controller
| extend OnPremisesDomainName = strcat(split(DestinationDeviceName, ".")[-2], ".", split(DestinationDeviceName, ".")[-1])
// Normalize DeviceName 
// --> if it is an IP Address we keep it
// --> If it is not an IP Address we only use the hostname for correlation
| extend DeviceName = iff(ipv4_is_private(DeviceName), DeviceName, tolower(split(DeviceName, ".")[0]))
// Only use interesting data and find more info regarding the source device
| distinct AccountUpn, OnPremisesDomainName, DeviceName
| join kind=leftouter devices on DeviceName 
| project-away DeviceName1
// Check if Seamless SSO usage is expected
| extend ['Seamless SSO Expected'] = case(
    // Cases where we do not expect Seamless SSO to be used
    JoinType == "Hybrid Azure AD Join" or 
    JoinType == "AAD Joined" or
    JoinType == "AAD Registered", "No",
    // Cases where we do expect Seamless SSO to be used
    JoinType == "Domain Joined" or 
    (OSPlatform startswith "Windows" and toreal(OSVersion) < 10.0) , "Yes", 
    // Cases that need to be verified
    "Unknown (to verify)"
)
```