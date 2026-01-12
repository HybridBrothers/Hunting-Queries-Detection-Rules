# *Detect LolDriver drop or load from unknown or unsigned process*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1068 | Exploitation for Privilege Escalation | https://attack.mitre.org/techniques/T1068/ |

#### Description
Adversaries may use LolDrivers to elevate their privileges on a system. Regularly, their drop their own LolDrivers from their beacon process when the LolDriver is not yet present on the system. This is a detection use case to detect an unknown process dropping these LolDrivers.

#### Risk
This detection tries to detect malware dropping LolDrivers which they can then use for privilege escalation on the target system.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://thecollective.eu/

## Defender XDR
```KQL
let LOLDrivers = externaldata(Category:string, KnownVulnerableSamples:dynamic, Verified:string ) [h@"https://www.loldrivers.io/api/drivers.json"]
     with (
       format=multijson,
       ingestionMapping=@'[{"Column":"Category","Properties":{"Path":"$.Category"}},{"Column":"KnownVulnerableSamples","Properties":{"Path":"$.KnownVulnerableSamples"}},{"Column":"Verified","Properties":{"Path":"$.Verified"}}]'
     )
    | mv-expand KnownVulnerableSamples
    | extend SHA1 = tostring(KnownVulnerableSamples.SHA1), SHA256 = tostring(KnownVulnerableSamples.SHA256)
;
let SHA1List = toscalar(
    LOLDrivers
    | summarize make_set(SHA1)
);
let SHA256List = toscalar(
    LOLDrivers
    | summarize make_set(SHA256)
);
let device_events = (
    DeviceEvents
    | where Timestamp > ago(1h)
    | where ActionType == "DriverLoaded"
    | where SHA1 in ( SHA1List ) or SHA256 in ( SHA256List )
);
let device_file_events = (
    DeviceFileEvents
    | where Timestamp > ago(1h)
    | where ActionType == "FileCreated"
    | where SHA1 in ( SHA1List ) or SHA256 in ( SHA256List )
);
union device_events, device_file_events
| invoke FileProfile(InitiatingProcessSHA1)
| where GlobalPrevalence < 1000 or SignatureState =~ "Unsigned"
```
