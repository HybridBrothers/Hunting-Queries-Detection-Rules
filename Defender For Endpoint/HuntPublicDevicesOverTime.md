# *Hunt for public facing devices and exposed ports over time*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1190 | Exploit Public-Facing Application | https://attack.mitre.org/techniques/T1190/ |

#### Description
Find public facing devices over time via the public device tag in the DeviceInfo table.

#### Risk
Public facing identification is only supported for Windows operating systems with specific versions. For more details about the nuances, see the blogpost added in the references. 

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com/analyzing-mde-network-inspections/

## Defender XDR
```KQL
// Create a base function
let base = (){ 
    DeviceInfo
    | where Timestamp > ago(30d)
    | extend AdditionalFields = todynamic(AdditionalFields)
    | extend InternetFacingLastSeen = todatetime(AdditionalFields.InternetFacingLastSeen)
        , InternetFacingReason = tostring(AdditionalFields.InternetFacingReason)
        , InternetFacingLocalIp = tostring(AdditionalFields.InternetFacingLocalIp)
        , InternetFacingPublicScannedIp = tostring(AdditionalFields.InternetFacingPublicScannedIp)
        , InternetFacingLocalPort = tostring(AdditionalFields.InternetFacingLocalPort)
        , InternetFacingPublicScannedPort = tostring(AdditionalFields.InternetFacingPublicScannedPort)
        , InternetFacingTransportProtocol = tostring(AdditionalFields.InternetFacingTransportProtocol)
};
base()
// Get the latest resport
| summarize arg_max(InternetFacingLastSeen, *) by DeviceName, InternetFacingLocalIp, InternetFacingLocalPort, InternetFacingTransportProtocol
// Join with the earliest report
| join kind=inner ( base()
    | summarize arg_min(InternetFacingLastSeen, *) by DeviceName, InternetFacingLocalIp, InternetFacingLocalPort, InternetFacingTransportProtocol
) on DeviceName, InternetFacingLocalIp, InternetFacingLocalPort, InternetFacingTransportProtocol
// Make a data point for each day between earliest and latest report
| extend Range = range(bin(InternetFacingLastSeen1, 1d), bin(InternetFacingLastSeen, 1d), 1d)
// Now expand all datapoints for dates the ports have been active
| mv-expand Range
| where Range != ""
| summarize count() by InternetFacingLocalPort, bin(todatetime(Range), 1d)
| render linechart
```

## Sentinel
```KQL
N/A
```