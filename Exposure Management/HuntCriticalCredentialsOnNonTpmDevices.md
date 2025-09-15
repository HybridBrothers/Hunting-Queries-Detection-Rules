# *Hunt for critical credentials on non-TPM enabled devices*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| TA0006 | Credential Access | https://attack.mitre.org/tactics/TA0006/ |


#### Description
This query searches for devices that does not have a TPM (Trusted Platform Module) enabled but contains critical credentials. The output shows for how many users each non-TPM device has credentials, together with the rules why each user is considered a critical user.


#### Risk
When critical credentials are stored on devices without a TPM enabled, it is more easy for adversaries to steal those credentials when the device is compromised. 


#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References

## Defender XDR
```KQL
let no_tpm_devices = (
    ExposureGraphNodes
    // Get device nodes with their inventory ID
    | mv-expand EntityIds
    | where EntityIds.type == "DeviceInventoryId"
    // Get interesting properties
    | extend OnboardingStatus = tostring(parse_json(NodeProperties)["rawData"]["onboardingStatus"]),
        TpmSupported = tostring(parse_json(NodeProperties)["rawData"]["tpmData"]["supported"]),
        TpmEnabled = tostring(parse_json(NodeProperties)["rawData"]["tpmData"]["enabled"]),
        TpmActivated = tostring(parse_json(NodeProperties)["rawData"]["tpmData"]["activated"]),
        DeviceName = tostring(parse_json(NodeProperties)["rawData"]["deviceName"]),
        DeviceId = tostring(EntityIds.id)
    // Search for distinct devices
    | distinct NodeId, DeviceName, OnboardingStatus, TpmSupported, TpmEnabled, TpmActivated
    // Get device with no TPM enabled
    | where TpmSupported != "true" and TpmActivated != "true" and TpmEnabled != "true"
    | extend TpmSupported = iff(TpmSupported == "", "unknown", TpmSupported),
        TpmActivated = iff(TpmActivated == "", "unknown", TpmActivated),
        TpmEnabled = iff(TpmEnabled == "", "unknown", TpmEnabled)
);
let critical_users = toscalar(
    // Search for critical users
    ExposureGraphNodes
    | where NodeLabel == "user"
    | extend CriticalityLevel = todynamic(NodeProperties).rawData.criticalityLevel.criticalityLevel
    | extend RuleNames = todynamic(NodeProperties).rawData.criticalityLevel.ruleNames
    | where CriticalityLevel == 0
    | distinct NodeName, NodeId, tostring(CriticalityLevel), tostring(RuleNames)
    | summarize make_set(NodeName)
);
// Make graph for max of 3 edges, where we start from a device and end with an user
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (SourceNode)-[anyEdge*1..3]->(TargetNode)
    where SourceNode.NodeLabel in ("device", "microsoft.compute/virtualmachines") and TargetNode.NodeLabel == "user" and TargetNode.NodeName in ( critical_users )
    project SourceNodeName = SourceNode.NodeName,
    SourceNodeId = SourceNode.NodeId,
    Edges = anyEdge.EdgeLabel,
    TargetNodeId = TargetNode.NodeId,
    TargetNodeName = TargetNode.NodeName,
    TargetNodeLabel = TargetNode.NodeLabel,
    TargetCriticalityLevel = TargetNode.NodeProperties.rawData.criticalityLevel.criticalityLevel,
    TargetRuleNames = TargetNode.NodeProperties.rawData.criticalityLevel.ruleNames
| distinct SourceNodeId, SourceNodeName, TargetNodeId, TargetNodeName, tostring(TargetCriticalityLevel), tostring(TargetRuleNames)
// Only return devices that does not have a TPM fully enabled
| join kind=inner no_tpm_devices on $left.SourceNodeId == $right.NodeId
// Make JSON of tpm data
| extend TpmState = tostring(bag_pack(
    'TpmSupported', TpmSupported,
    'TpmEnabled', TpmEnabled,
    'TpmActivated', TpmActivated
))
// Make JSON of users data
| extend Json = bag_pack(
    'User', TargetNodeName,
    'UserCriticalityLevel', TargetCriticalityLevel,
    'UserRuleNames', TargetRuleNames
)
// Make list of users per device
| summarize UserList = make_list(Json) by DeviceName, OnboardingStatus, TpmState
// Count amount of exposed users per device
| extend UserCount = array_length(UserList)
| sort by UserCount desc
```