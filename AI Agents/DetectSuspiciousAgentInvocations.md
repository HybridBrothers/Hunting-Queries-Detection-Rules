let lookback = 1d;
let baseline = 14d;
// Per-agent baseline of caller countries
let GeoBaseline =
    CloudAppEvents
    | where Timestamp between (ago(baseline) .. ago(lookback))
    | where ActionType == "InvokeAgent"
    | extend rd = parse_json(tostring(RawEventData))
    | extend AgentName = coalesce(tostring(rd.TargetAgentName), tostring(rd.AgentName))
    | summarize KnownCountries = make_set(CountryCode) by AgentName;
CloudAppEvents
| where Timestamp > ago(lookback)
| where ActionType == "InvokeAgent"
| extend rd = parse_json(tostring(RawEventData))
| extend AgentName = coalesce(tostring(rd.TargetAgentName), tostring(rd.AgentName)),
         ClientIP = tostring(rd.ClientIP),
         CallerUpn = tostring(rd.UserId),
         CallerKey = tostring(rd.UserKey),
         Channel = tostring(rd.ChannelName)
| join kind=leftouter GeoBaseline on AgentName
| extend NewCountry = isnotempty(CountryCode) and not(set_has_element(KnownCountries, CountryCode))
| where IsAnonymousProxy == true or IsExternalUser == true or NewCountry
| project Timestamp, AgentName, CallerUpn, CallerKey, ClientIP, IPAddress, CountryCode, City, ISP,
          IsAnonymousProxy, IsExternalUser, NewCountry, Channel, ReportId
| order by Timestamp desc
