# *Hunt for critical credentials on devices with non-critical accounts*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078/ |

#### Description
In most organizations normal user accounts or accounts with low risk permissions have less security controls enabled. This because there are less security controls needed in order to minize the risk vectors that come with these accounts. If these accounts are used on devices where critical account credentials are also present, the critical user account can be compromised more easily when the device is accessed by an adversary via the non-critical user account. 

Because of this, a Privileged Access Workstation should be used which serves as a dedicated workstation for the critical accounts. By doing this, the critical user account cannot be comprmised via a unhardened device.

#### Risk
When you know which devices are exposing critical credentials via access from non-critical accounts, you know which devices have the most risk to all for privilege escalation.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References

## Defender XDR
```KQL
// Search for all users and save their criticality level
let xspm_users = materialize(
    ExposureGraphNodes
    | where NodeLabel == "user"
    | extend CriticalityLevel = todynamic(NodeProperties).rawData.criticalityLevel.criticalityLevel
    | extend RuleNames = todynamic(NodeProperties).rawData.criticalityLevel.ruleNames
    | distinct NodeName, NodeId, tostring(CriticalityLevel), tostring(RuleNames)
);
// Make a list of all critical users
let critical_users = toscalar(
    xspm_users
    | where CriticalityLevel == 0
    | summarize make_set(NodeName)
);
// Make a list of all non critical users
let non_critical_users = toscalar(
    xspm_users
    | where CriticalityLevel != 0
    | summarize make_set(NodeName)
);
// Make graph for max of 3 edges, where we start from a device and end with an user
ExposureGraphEdges
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
| graph-match (SourceNode)-[anyEdge*1..3]->(TargetNode)
    where SourceNode.NodeLabel in ("device", "microsoft.compute/virtualmachines") and TargetNode.NodeLabel == "user"
    project SourceNodeName = SourceNode.NodeName,
    Edges = anyEdge.EdgeLabel,
    TargetNodeName = TargetNode.NodeName,
    TargetNodeLabel = TargetNode.NodeLabel
// Make a list of all users a device has credentials for
| summarize UserList = make_set(TargetNodeName) by SourceNodeName
// Only return devices with more than one credential
| where array_length(UserList) > 1
// Make new lists saving the critical users and non critical users per device
| extend CriticalUserList = set_intersect(UserList, critical_users),
    NonCriticalUserList = set_intersect(UserList, non_critical_users)
// Flag when a device has both critical and non critical users
| where array_length(CriticalUserList) > 0 and array_length(NonCriticalUserList) > 0
```