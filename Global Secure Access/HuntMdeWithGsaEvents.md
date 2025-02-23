# *Hunt MDE with GSA events*

## Query Information

#### MITRE ATT&CK Technique(s)

N/A

#### Description
This rule correlates the Microsoft Defender for Endpoint DeviceNetworkEvents table with the Global Secure Access NetworkAccessTraffic table. By doing this, you can enrich the MDE events which contains detailed process information with the GSA events that contains detailed HTTP header information and more. 

#### Risk
With this query you can reduce FP rates of existing detections, and try to create more accurate new detections by combining MDE and GSA logs. 

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com/correlating-defender-for-endpoint-and-global-secure-access-logs/

## Defender XDR
```KQL
let gsa_events = NetworkAccessTraffic
    // Join DeviceInfo to get MDE DeviceID
    | join kind=inner ( 
        DeviceInfo
        | distinct DeviceId, AadDeviceId
    ) on $left.DeviceId == $right.AadDeviceId
    // Remove Entra Device ID from GSA logs
    | project-away DeviceId
    // Rename MDE Device ID to DeviceId column
    | project-rename DeviceId = DeviceId1;
// Get all MDE network events
DeviceNetworkEvents
// Get HTTP details if HTTP connection is logged
| extend HttpStatus = toint(todynamic(AdditionalFields).status_code),
    BytesIn = toint(todynamic(AdditionalFields).response_body_len),
    BytesOut = toint(todynamic(AdditionalFields).request_body_len),
    HttpMethod = tostring(todynamic(AdditionalFields).method),
    UrlHostname = tostring(todynamic(AdditionalFields).host),
    UrlPath = tostring(todynamic(AdditionalFields).uri),
    UserAgent = tostring(todynamic(AdditionalFields).user_agent),
    HttpVersion = tostring(todynamic(AdditionalFields).version)
// Join GSA logs
| join kind=inner gsa_events on 
    DeviceId,
    $left.RemoteUrl == $right.DestinationFqdn,
    $left.RemotePort == $right.DestinationPort,
    $left.Protocol == $right.TransportProtocol,
    $left.InitiatingProcessFileName == $right.InitiatingProcessName
| project-rename TimeGeneratedGsa = TimeGenerated1, TimestampMde = Timestamp
| project-away Type, TenantId, TimeGenerated, TenantId1, Type1, DeviceId1, AadDeviceId
```

## Sentinel
```KQL
let gsa_events = NetworkAccessTraffic
    // Join DeviceInfo to get MDE DeviceID
    | join kind=inner ( 
        DeviceInfo
        | distinct DeviceId, AadDeviceId
    ) on $left.DeviceId == $right.AadDeviceId
    // Remove Entra Device ID from GSA logs
    | project-away DeviceId
    // Rename MDE Device ID to DeviceId column
    | project-rename DeviceId = DeviceId1;
// Get all MDE network events
DeviceNetworkEvents
// Get HTTP details if HTTP connection is logged
| extend HttpStatus = toint(todynamic(AdditionalFields).status_code),
    BytesIn = toint(todynamic(AdditionalFields).response_body_len),
    BytesOut = toint(todynamic(AdditionalFields).request_body_len),
    HttpMethod = tostring(todynamic(AdditionalFields).method),
    UrlHostname = tostring(todynamic(AdditionalFields).host),
    UrlPath = tostring(todynamic(AdditionalFields).uri),
    UserAgent = tostring(todynamic(AdditionalFields).user_agent),
    HttpVersion = tostring(todynamic(AdditionalFields).version)
// Join GSA logs
| join kind=inner gsa_events on 
    DeviceId,
    $left.RemoteUrl == $right.DestinationFqdn,
    $left.RemotePort == $right.DestinationPort,
    $left.Protocol == $right.TransportProtocol,
    $left.InitiatingProcessFileName == $right.InitiatingProcessName
| project-rename TimeGeneratedGsa = TimeGenerated2, TimestampMde = TimeGenerated
| project-away Type, TenantId, TimeGenerated, TenantId1, Type1, DeviceId1, AadDeviceId
```