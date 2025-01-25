# *CEF to CommonSecurityLog normlization query*

## Query Information

#### MITRE ATT&CK Technique(s)

M/A

#### Description
This query can be used to normalize Syslog CEF data to the CommonSecurityLog table in Microsoft Sentinel. It extracts the CEF values via RegularExpressions, and add the values to new columns that allign with the CommonSecurityLog tables.

#### Risk
1. Be aware that the source schema is based on data comming from Logstash, which means you might have to alter the query a bit if your source schema is different. 
2. The CEF headers might differ based on the source that is sending the CEF messages (for example, CheckPoint CEF headers are different to the CEF headers of PaloAlto messages). Make sure to dubbel check your headers and change the query accordingly. 

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com/parsing-cef-messages-without-azure-monitor-agent/

## Defender XDR
```KQL
N/A
```

## Sentinel
```KQL
source
// Normalize to CommonSecurityLog schema
| parse message with CEF: string 
    "|"     DeviceVendor: string 
    "|"     DeviceProduct: string 
    "|"     DeviceVersion: string
    "|"     DeviceEventClassID: string
    "|"     Activity: string 
    "|"     LogSeverity: string
    "|"     AdditionalExtensions: string
// Extract fields
| extend
    DeviceAction = extract("act=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    ApplicationProtocol = extract("app=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceEventCategory = extract("cat=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    EventCount = toint(extract("cnt=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    DestinationDnsDomain = extract("destinationDnsDomain=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DestinationServiceName = extract("destinationServiceName=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DestinationTranslatedAddress = extract("destinationTranslatedAddress=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DestinationTranslatedPort = toint(extract("destinationTranslatedPort=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    CommunicationDirection = extract("deviceDirection=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceDnsDomain = extract("deviceDnsDomain=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    deviceExternalId = toint(extract("deviceExternalId=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    DeviceFacility = extract("deviceFacility=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceInboundInterface = extract("deviceInboundInterface=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceNtDomain = extract("deviceNtDomain=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceOutboundInterface = extract("deviceOutboundInterface=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DevicePayloadId = extract("devicePayloadId=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    ProcessName = extract("deviceProcessName=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceTranslatedAddress = extract("deviceTranslatedAddress=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DestinationHostName = extract("dhost=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DestinationMacAddress = extract("dmac=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DestinationNTDomain = extract("dntdom=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DestinationProcessId = toint(extract("dpid=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    DestinationUserPrivileges = extract("dpriv=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DestinationProcessName = extract("dproc=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DestinationPort = toint(extract("dpt=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    DestinationIP = extract("dst=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceTimeZone = extract("dtz=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DestinationUserId = extract("duid=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DestinationUserName = extract("duser=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceAddress = extract("dvc=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceName = extract("dvchost=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceMacAddress = extract("dvcmac=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    ProcessID = toint(extract("dvcpid=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    ExternalID = toint(extract("externalId=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    FileCreateTime = extract("fileCreateTime=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    FileHash = extract("fileHash=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    FileID = extract("fileId=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    FileModificationTime = extract("fileModificationTime=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    FilePath = extract("filePath=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    FilePermission = extract("filePermission=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    FileType = extract("fileType=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    FileName = extract("fname=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    FileSize = toint(extract("fsize=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    Computer = extract("host=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    ReceivedBytes = tolong(extract("in=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    Message = extract("msg=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    OldFileCreateTime = extract("oldFileCreateTime=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    OldFileHash = extract("oldFileHash=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    OldFileId = extract("oldFileId=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    OldFileModificationTime = extract("oldFileModificationTime=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    OldFileName = extract("oldFileName=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    OldFilePath = extract("oldFilePath=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    OldFilePermission = extract("oldFilePermission=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    OldFileSize = toint(extract("oldFileSize=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    OldFileType = extract("oldFileType=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    SentBytes = tolong(extract("out=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    EventOutcome = extract("outcome=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    Protocol = extract("proto=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    Reason = extract("reason=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    RequestURL = extract("request=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    RequestClientApplication = extract("requestClientApplication=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    RequestContext = extract("requestContext=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    RequestCookies = extract("requestCookies=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    RequestMethod = extract("requestMethod=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    ReceiptTime = extract("rt=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    SourceHostName = extract("shost=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    SourceMacAddress = extract("smac=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    SourceNTDomain = extract("sntdom=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    SourceDnsDomain = extract("sourceDnsDomain=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    SourceServiceName = extract("sourceServiceName=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    SourceTranslatedAddress = extract("sourceTranslatedAddress=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    SourceTranslatedPort = toint(extract("sourceTranslatedPort=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    SourceProcessId = toint(extract("spid=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    SourceUserPrivileges = extract("spriv=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    SourceProcessName = extract("sproc=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    SourcePort = toint(extract("spt=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    SourceIP = extract("src=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    SourceUserID = extract("suid=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    SourceUserName = extract("suser=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    EventType = toint(extract("type=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions))
// Extract custom fields
| extend
    DeviceCustomString1 = extract("cs1=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomString1Label = extract("cs1Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomString2 = extract("cs2=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomString2Label = extract("cs2Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomString3 = extract("cs3=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomString3Label = extract("cs3Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomString4 = extract("cs4=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomString4Label = extract("cs4Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomString5 = extract("cs5=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomString5Label = extract("cs5Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomString6 = extract("cs6=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomString6Label = extract("cs6Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomNumber1 = toint(extract("cn1=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    DeviceCustomNumber1Label = extract("cn1Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomNumber2 = toint(extract("cn2=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    DeviceCustomNumber2Label = extract("cn2Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomNumber3 = toint(extract("cn3=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    DeviceCustomNumber3Label = extract("cn3Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    FlexString1 = extract("flexString1=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    FlexString1Label = extract("flexString1Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    FlexString2 = extract("flexString2=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    FlexString2Label = extract("flexString2Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomIPv6Address1 = extract("c6a1=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomIPv6Address1Label = extract("c6a1Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomIPv6Address2 = extract("c6a2=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomIPv6Address2Label = extract("c6a2Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomIPv6Address3 = extract("c6a3=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomIPv6Address3Label = extract("c6a3Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomIPv6Address4 = extract("c6a4=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomIPv6Address4Label = extract("c6a4Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomFloatingPoint1 = toreal(extract("cfp1=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    deviceCustomFloatingPoint1Label = extract("cfp1Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomFloatingPoint2 = toreal(extract("cfp2=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    deviceCustomFloatingPoint2Label = extract("cfp2Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomFloatingPoint3 = toreal(extract("cfp3=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    deviceCustomFloatingPoint3Label = extract("cfp3Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomFloatingPoint4 = toreal(extract("cfp4=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    deviceCustomFloatingPoint4Label = extract("cfp4Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomDate1 = extract("deviceCustomDate1=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomDate1Label = extract("deviceCustomDate1Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomDate2 = extract("deviceCustomDate2=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    DeviceCustomDate2Label = extract("deviceCustomDate2Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    FlexDate1 = extract("flexDate1=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    FlexDate1Label = extract("flexDate1Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    FlexNumber1 = toint(extract("flexNumber1=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    FlexNumber1Label = extract("flexNumber1Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions),
    FlexNumber2 = toint(extract("flexNumber2=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)),
    FlexNumber2Label = extract("flexNumber2Label=(.*?)(\\s\\w+=|$)", 1, AdditionalExtensions)
| extend TimeGenerated = todatetime(ls_timestamp), Computer = tostring(host)
| project-away
    message,
    facility,
    facility_label,
    ls_version,
    priority,
    severity,
    severity_label,
    ['type'],
    CEF,
    ls_timestamp,
    host,
    tags
```