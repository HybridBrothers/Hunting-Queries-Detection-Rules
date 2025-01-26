# *Hunt for public facing devices via public tag*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1190 | Exploit Public-Facing Application | https://attack.mitre.org/techniques/T1190/ |

#### Description
Find public facing devices via the public device tag in the DeviceInfo table. The internet facing reason is also included in this query.

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
DeviceInfo
| where Timestamp > ago(7d)
| extend AdditionalFields = todynamic(AdditionalFields)
| where todatetime(AdditionalFields.InternetFacingLastSeen) > ago(7d)
| extend InternetFacingLastSeen = tostring(AdditionalFields.InternetFacingLastSeen)
    , InternetFacingReason = tostring(AdditionalFields.InternetFacingReason)
    , InternetFacingLocalIp = tostring(AdditionalFields.InternetFacingLocalIp)
    , InternetFacingPublicScannedIp = tostring(AdditionalFields.InternetFacingPublicScannedIp)
    , InternetFacingLocalPort = tostring(AdditionalFields.InternetFacingLocalPort)
    , InternetFacingPublicScannedPort = tostring(AdditionalFields.InternetFacingPublicScannedPort)
    , InternetFacingTransportProtocol = tostring(AdditionalFields.InternetFacingTransportProtocol)
| summarize arg_max(InternetFacingLastSeen, *) by DeviceName, InternetFacingLocalIp, InternetFacingLocalPort, InternetFacingPublicScannedIp, InternetFacingPublicScannedPort, InternetFacingTransportProtocol, InternetFacingReason
| project InternetFacingLastSeen, DeviceName, InternetFacingLocalIp, InternetFacingLocalPort, InternetFacingPublicScannedIp, InternetFacingPublicScannedPort, InternetFacingTransportProtocol, InternetFacingReason
```

## Sentinel
```KQL
N/A
```