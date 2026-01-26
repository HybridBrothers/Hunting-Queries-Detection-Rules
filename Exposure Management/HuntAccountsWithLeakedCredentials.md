# *Hunt for accounts with leaked credentials*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| TA0006 | Credential Access | https://attack.mitre.org/tactics/TA0006/ |


#### Description
This query searches for accounts where Exposure Management detected leaked credentials. This query is correlated with the `IdentityInfo` table, mainly because you can easily created a detection of this rule if you would like to.


#### Risk
This hunting query helps you in finding accounts that have leaked credentials. This mitigates the risk of easy account compromise when an attacker is using known password lists.


#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References

## Defender XDR
```KQL
IdentityInfo
| summarize arg_max(TimeGenerated, AccountUpn, AccountDisplayName, AccountDomain, CriticalityLevel, DistinguishedName) by AccountObjectId
| join kind=inner (
    ExposureGraphNodes
    // Get accounts with Leaked Credentials
    | where NodeProperties.rawData.hasAdLeakedCredentials == "true" or NodeProperties.rawData.hasLeakedCredentials == "true"
    // Get the AAD Object ID
    | mv-expand EntityIds
    | where EntityIds.type == "AadObjectId"
    | extend AccountObjectId = extract('objectid=(.*)', 1, tostring(EntityIds.id))
    | extend HasAdLeakedCredentials = tostring(NodeProperties.rawData.hasAdLeakedCredentials),
        HasLeakedCredentials = tostring(NodeProperties.rawData.hasLeakedCredentials)
    | distinct NodeLabel, AccountObjectId, HasAdLeakedCredentials, HasLeakedCredentials
) on AccountObjectId
```