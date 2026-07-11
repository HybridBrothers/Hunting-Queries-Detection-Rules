# *Hunt for AI Agent activity with Agent Info*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |

#### Description
This query allows you to find the activity an AI Agent performed via the `CloudAppEvents` table using the `AgentsInfo` table.

#### Risk
With this query a SOC Analysts can find the events an AI Agent performed.

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
// Skip local AI Agents
| where Platform != "LocalAgents"
| extend ExtractedObservabilityID = iff(
    ObservabilityID matches regex @"(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})",
    extract(@"(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})", 1, ObservabilityID),
    ObservabilityID
)
// Add fallback on titleId if ObservabilityID is empty
| extend ExtractedObservabilityID = iff(ExtractedObservabilityID == "", extract(@"(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})", 1, tostring(parse_json(RawAgentInfo).titleId)), ExtractedObservabilityID)
| project Name, Platform, ExtractedObservabilityID
| join kind=inner (
    CloudAppEvents
    | where TimeGenerated > ago(7d)
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