# *Detect entra token request via specific BOF (IOC based)*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1651 | Cloud Administration Command | https://attack.mitre.org/techniques/T1651/ |
| T1606 | Forge Web Credentials | https://attack.mitre.org/techniques/T1606/ |

#### Description
This might be one of the silliest detections I have created. But since there is a Beacon Object File out there which can be used to directly request Entra ID access tokens from an active beacon on a device using a specific User Agent, we can easily detect this beacon file by flagging the funny user agent and / or scope identifier that is used.

#### Risk
Detect token request via a specific BOF file.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://github.com/trustedsec/CS-Remote-OPs-BOF/blob/12850f1d9306ccdec21f2b4e9dd16f78b0b949a9/src/Remote/get_azure_token/entry.c#L260

## Sentinel
```KQL
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(5m)
| where UserAgent contains "ur mum" 
| where ResourceIdentity == "797f4846-ba00-4fd7-ba43-dac1f8f63013"
```