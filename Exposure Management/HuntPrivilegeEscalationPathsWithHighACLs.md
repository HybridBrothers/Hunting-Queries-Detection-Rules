# *Hunt for privilege escalation paths with high ACLs*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1078 | Valid Accounts | https://attack.mitre.org/techniques/T1078/ |

#### Description
When an adversary establishes data collection of an Active Directory domain, they regularly search for interesting accounts with privilege escalation paths using the genericWrite and genericAll ACL permissions on objects. When using BloodHound, it is very easy to get a visual overview of these paths in an Active Directory domain. This query tries to establish the same using Defender XDR Exposure Management. 

#### Risk
By knowing these paths you can effectivly remediate and lower the risk of privilege escalation paths in AD DS. 

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://www.hackingarticles.in/genericwrite-active-directory-abuse/
- https://bloodhound.specterops.io/resources/edges/generic-write
- https://bloodhound.specterops.io/resources/edges/generic-all

## Defender XDR
```KQL
let high_permissions = dynamic(["genericWrite", "genericAll"]);
let edge_labels = dynamic(["member of", "has permissions to", "can authenticate to", "can authenticate as", "has credentials of", "can impersonate as"]);
// Get users and groups with high ACL permissions on other objects
let HighPermissionLinks = (ExposureGraphEdges
    // Get edges related to roles
    | where EdgeLabel == "has role on"
    // Get edges containing high permission ACLs
    | extend Permissions = todynamic(EdgeProperties).rawData.acl.controlTypes
    | where Permissions has_any (high_permissions)
    // Exclude Domain and Enterprise Administrators as source node
    | where not(SourceNodeLabel == "group" and SourceNodeName in ("Domain Admins", "Enterprise Admins"))
    // Exclude Built-in administrator account
    | where not(SourceNodeLabel == "user" and SourceNodeName == "Administrator")
    | summarize TargetNodes = make_set(TargetNodeName), TargetNodeCount = count() by SourceNodeName, SourceNodeLabel, tostring(Permissions), TargetNodeLabel, SourceNodeId
);
let HighPermissionNodes = toscalar(
    HighPermissionLinks
    | summarize SourceNodes = make_set(SourceNodeName)
);
// Get edges for links to the high ACL permissions
ExposureGraphEdges
| where TargetNodeName in (HighPermissionNodes)
| make-graph SourceNodeId --> TargetNodeId with ExposureGraphNodes on NodeId
// Get between one and three relations
| graph-match (SourceNode)-[anyEdge*1..3]->(TargetNode)
    project IncomingNodeName = SourceNode.NodeName, 
    IncomingNodeLabel = SourceNode.NodeLabel,
    Edges = anyEdge.EdgeLabel, 
    OutgoingNodeName = TargetNode.NodeName,
    OutgoingNodeId = TargetNode.NodeId
// Filter for interesting edges
| where Edges has_any (edge_labels)
// Join the high permission ACLs
| join kind=inner HighPermissionLinks on $left.OutgoingNodeId == $right.SourceNodeId
// Exclude Domain and Enterprise Administrators as source node
| where not(IncomingNodeLabel == "group" and IncomingNodeName in ("Domain Admins", "Enterprise Admins"))
// Exclude Built-in administrator account
| where not(IncomingNodeLabel == "user" and IncomingNodeName == "Administrator")
| distinct IncomingNodeName, IncomingNodeLabel, tostring(Edges), OutgoingNodeName, OutgoingNodeLabel = SourceNodeLabel, tostring(Permissions), TargetNodeLabel, tostring(TargetNodes), TargetNodeCount
```