AgentsInfo 
| where TimeGenerated > ago(1d)
| summarize arg_max(TimeGenerated, *) by AgentId
// Skip local AI Agents
| where Platform != "LocalAgents"
| extend ExtractedObservabilityID = iff(
    ObservabilityID matches regex @"(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})",
    extract(@"(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})", 1, ObservabilityID),
    ObservabilityID
)
// Add fallback on titleId if ObservabilityID is empty
| extend ExtractedObservabilityID = iff(ExtractedObservabilityID == "", extract(@"(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})", 1, tostring(parse_json(RawAgentInfo).titleId)), ExtractedObservabilityID)
// Get raw info for rool information
| extend RawInfo = parse_json(RawAgentInfo)
| extend ImpactedSettings = RawInfo.impactedSettings,
    AppType = RawInfo.appType
// Focus on third-party tool usage
| where AppType =~ "thirdParty" or ImpactedSettings has "allowThirdPart"
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
