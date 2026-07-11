# *Hunt for local AI Agent activity with Agent Info*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |

#### Description
This query allows you to find the activity a local AI Agent performed via the `CloudAppEvents` table using the `AgentsInfo` and `ExposureGraphNodes` table.

#### Risk
With this query a SOC Analysts can find the events a local AI Agent performed.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com/posts/agentinfo-cloudappevents-correlation/

## Defender XDR
```KQL
// Fill in agent name or one of the Agent IDs you have found
let agent_name = "";
let some_agent_id = "";
AgentsInfo 
| where TimeGenerated > ago(1d)
| summarize arg_max(TimeGenerated, *) by AgentId
| where (isempty(some_agent_id) and Name =~ agent_name) or (isempty(agent_name) and * has some_agent_id)
// Take local AI Agents
| where Platform == "LocalAgents"
| distinct Name, Platform, SourceAgentId
// Join with Graph Nodes to get the ObservabilityID
| join kind=inner (
    ExposureGraphNodes
    | where NodeLabel == "ai-agent"
    | where parse_json(NodeProperties).rawData.aiAgentMetadata.platform == "LocalAgents"
    | extend SourceAIAgentId = extract("{\"type\":\"SourceAIAgentId\",\"id\":\"([^\"]+)\"}", 1, tostring(EntityIds))
    | extend A365RegistryAIAgentId = extract("{\"type\":\"A365RegistryAIAgentId\",\"id\":\"tenantid=([^;]+);titleid=([^\"]+)\"}", 2, tostring(EntityIds))
    | project SourceAIAgentId, A365RegistryAIAgentId
) on $left.SourceAgentId == $right.SourceAIAgentId
| extend ExtractedObservabilityID = iff(
    A365RegistryAIAgentId matches regex @"(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})",
    extract(@"(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})", 1, A365RegistryAIAgentId),
    A365RegistryAIAgentId
)
| join kind=inner (
    CloudAppEvents
    | where ActionType in ("InvokeAgent","InferenceCall","ExecuteToolBySDK","ExecuteToolByGateway","ExecuteToolByMCPServer")
    // Extract the platformIDs and ObservabilityID
    | extend PlatformAgentId = tostring(parse_json(RawEventData)["PlatformAgentId"]), 
        PlatformTargetAgentId = tostring(parse_json(RawEventData)["PlatformTargetAgentId"])
    | extend PlatformId = iff(isempty(PlatformAgentId) and isnotempty(PlatformTargetAgentId), PlatformTargetAgentId, PlatformAgentId)
    | extend ObservabilityID = iff(
        PlatformId matches regex @"(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})", 
        extract(@"(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})", 1, PlatformId),
        PlatformId
    )
) on $left.ExtractedObservabilityID == $right.ObservabilityID
```