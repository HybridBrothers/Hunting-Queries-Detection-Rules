# *Hunt for critical credentials on non Credential Guard enabled devices*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| TA0006 | Credential Access | https://attack.mitre.org/tactics/TA0006/ |


#### Description
This query searches for devices that does not have Credential Guard enabled but contains critical credentials. The output shows for how many users each non Credential Guard device has credentials, together with the list of users being exposed.


#### Risk
When critical credentials are stored on devices without Credential Guard enabled, it is more easy for adversaries to steal those credentials when the device is compromised. This is because without Credential Guard Kerberos, NTLM, and Credential Manager secrets are stored in the Local Security Authority (LSA) process called `lsass.exe`, which can be dumped with various tools like MimiKatz. With Credential Guard enabled, these secrets are protected and isolated using Virtualization-based security (VBS).


#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References

## Defender XDR
```KQL

let no_credguard_devices = (
        ExposureGraphNodes
        // Get devices with credential guard misconfiguration
        | where array_length(NodeProperties.rawData.hasGuardMisconfigurations) > 0
        // Get interesting data
        | extend DeviceName = tostring(parse_json(NodeProperties)["rawData"]["deviceName"]),
            DeviceId = tostring(EntityIds.id)
        | extend DeviceName = iff(isempty(DeviceName), NodeName, DeviceName)
        // Search for distinct devices
        | distinct NodeId, DeviceName
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
    | join kind=inner no_credguard_devices on $left.SourceNodeId == $right.NodeId
    // Make list of users per device
    | summarize UserList = make_list(TargetNodeName) by DeviceName
    // Count amount of exposed users per device
    | extend UserCount = array_length(UserList)
    | sort by UserCount desc
```
