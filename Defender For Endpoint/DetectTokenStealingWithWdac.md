# *Detect device token stealing with WDAC*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1212 | Exploitation for Credential Access | https://attack.mitre.org/techniques/T1212/ |
| T1606.001 | Forge Web Credentials: Web Cookies | https://attack.mitre.org/techniques/T1606/001/ |
| T1528 | Steal Application Access Token | https://attack.mitre.org/techniques/T1528/ |
| T1539 | Steal Web Session Cookie | https://attack.mitre.org/techniques/T1539/ |

#### Description
This rule uses a WDAC audit policy to ingest missing Microsoft Defender for Endpoint events. By doing this, we can detect PRT token stealing on a device when exploiting the MicrosoftAccountTokenProvider.dll. For more detailed information on the WDAC audit policy, see the blogpost added in the references.

#### Risk
Exploitation of the MicrosoftAccountTokenProvider.dll is something Defender for Endpoint does not detect by default. This makes this detection rule so important, since it fills a very important blind spot. 

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com/using-wdac-to-ingest-missing-mde-events/

## Defender XDR
```KQL
DeviceEvents
| where ActionType startswith "AppControl"
| where FileName =~ "MicrosoftAccountTokenProvider.dll"
| invoke FileProfile(InitiatingProcessSHA1, 1000)
| where GlobalPrevalence < 250
```

## Sentinel
```KQL
N/A
```