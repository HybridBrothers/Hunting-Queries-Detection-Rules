# *Hunt for Defender for Identity not installed but eligible*

## Query Information

#### MITRE ATT&CK Technique(s)

N/A

#### Description
This query shows you which servers are eligible for Defender for identity but does not have the Defender for Identity agent installed. The query seach the eligible servers via Defender for Endpoint (requirement for this query to work), and is based on the server roles that MDE recongnizes. 

#### Risk
If not alle eligible servers are onboarded in Defender for Identity, you have a detection gap.


#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- N/A


## Defender XDR
```KQL
let device_roles = dynamic(["EntraConnectServer", "AzureADConnectServer", "ActiveDirectoryCertificateServicesServer", "DomainController", "ADFS"]);
let mdi_servers = (
    DeviceTvmSoftwareInventory
    | where SoftwareName == "azure_advanced_threat_protection_sensor"
    | distinct MdiDeviceName=tolower(DeviceName)
);
let mdi_eligible_servers = (
    ExposureGraphNodes
    | extend DeviceRoles= parse_json(NodeProperties)["rawData"]["deviceRole"]
    | extend CriticalityRuleNames = parse_json(NodeProperties)["rawData"]["criticalityLevel"]["ruleNames"]
    | where DeviceRoles has_any (device_roles) or
        CriticalityRuleNames has_any (device_roles)
    | distinct NodeName=tolower(NodeName), tostring(DeviceRoles), tostring(CriticalityRuleNames)
);
mdi_servers
| join kind=rightouter mdi_eligible_servers on $left.MdiDeviceName == $right.NodeName
| extend Issue = iff(isempty(MdiDeviceName), "This server is eligible for MDI but does not have MDI installed", "None")
| where Issue != "None"
```

## Sentinel
```KQL
N/A
```