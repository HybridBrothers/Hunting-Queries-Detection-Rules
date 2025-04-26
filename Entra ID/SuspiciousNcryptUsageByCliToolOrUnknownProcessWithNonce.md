# *Suspicious ncrypt.dll usage by process requesting Entra ID Nonce*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1555.004 | Credentials from Password Stores: Windows Credential Manager | https://attack.mitre.org/techniques/T1555/004/ |
| T1606 | Forge Web Credentials | https://attack.mitre.org/techniques/T1606/ |

#### Description
This detection rule uses a WDAC audit policy to ingest missing DeviceImageLoad events in MDE, and check for suspicious processes using the ncrypt.dll and requesting an Entra ID Nonce. More information on the attack scenario this is detection is applicable for can be found in the references.

#### Risk
By using this detections, we can try to detect an attacker using the hellopoc.ps1 script in RoadTools to generate an assertion. 

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com/detecting-non-privileged-windows-hello-abuse/
- https://github.com/dirkjanm/ROADtools/blob/master/winhello_assertion/hellopoc.ps1

## Defender XDR
```KQL
let cli_tools = dynamic(["powershell", "python"]);
// Get all possible nonce requests
let nonce_requests = (
    DeviceNetworkEvents
    | where Timestamp > ago(1h)
    | where ActionType startswith "ConnectionSuccess"
    | where RemoteUrl =~ "login.microsoftonline.com"
    | project-rename NonceTimestamp = Timestamp
);
// Get suspicious ncrypt.dll usage via WDAC audit policy
DeviceEvents
| where Timestamp > ago(1h)
| where ActionType startswith "AppControl" and FileName =~ "ncrypt.dll"
// Check if the same initiating process is doing a nonce request
| join kind=inner nonce_requests on InitiatingProcessId, DeviceId
// Only flag when nonce was request 10min before of after ncrypt usage
| where Timestamp between (todatetime(NonceTimestamp - 10m) .. todatetime(NonceTimestamp + 10m))
| invoke FileProfile(InitiatingProcessSHA1, 1000)
| where (
    // Flag CLI tools
    InitiatingProcessFileName has_any (cli_tools) or 
    // Flag unknown processes
    GlobalPrevalence < 250
)
```

## Sentinel
```KQL
let cli_tools = dynamic(["powershell", "python"]);
// Get all possible nonce requests
let nonce_requests = (
    DeviceNetworkEvents
    | where TimeGenerated > ago(1h)
    | where ActionType startswith "ConnectionSuccess"
    | where RemoteUrl =~ "login.microsoftonline.com"
    | project-rename NonceTimestamp = TimeGenerated
);
// Get suspicious ncrypt.dll usage via WDAC audit policy
DeviceEvents
| where TimeGenerated > ago(1h)
| where ActionType startswith "AppControl" and FileName =~ "ncrypt.dll"
// Check if the same initiating process is doing a nonce request
| join kind=inner nonce_requests on InitiatingProcessId, DeviceId
// Only flag when nonce was request 10min before of after ncrypt usage
| where TimeGenerated between (todatetime(NonceTimestamp - 10m) .. todatetime(NonceTimestamp + 10m))
| invoke FileProfile(InitiatingProcessSHA1, 1000)
| where (
    // Flag CLI tools
    InitiatingProcessFileName has_any (cli_tools) or 
    // Flag unknown processes
    GlobalPrevalence < 250
)
```