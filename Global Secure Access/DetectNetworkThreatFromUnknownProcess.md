

```KQL
NetworkAccessTraffic
| where TimeGenerated > ago(30d)
| where ThreatType !in ("NoneFound", "")
| project-rename AadDeviceId = DeviceId
// Enrich with Device Information
| join kind=leftouter (
    DeviceInfo
    | where TimeGenerated > ago(30d)
    | summarize arg_max(TimeGenerated, *) by DeviceId
    | project DeviceName, DevicePublicIP = PublicIP, OSPlatform, JoinType, OnboardingStatus, AadDeviceId, DeviceId
) on AadDeviceId
// Get more information on source process via MDE
| join kind=leftouter (
    DeviceNetworkEvents
    | where TimeGenerated > ago(30d)
    | extend FQDN = tostring(parse_url(RemoteUrl).Host)
    | project-away DeviceName, ActionType, Type, TimeGenerated
) on $left.DestinationFqdn == $right.FQDN, DeviceId
// Only flag if process is unknown or unsigned
| invoke FileProfile(InitiatingProcessSHA256)
| where not(GlobalPrevalence > 1000 and SignatureState =~ "SignedValid")
```