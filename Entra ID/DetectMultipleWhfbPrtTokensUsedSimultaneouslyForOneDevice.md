# *Detect Multiple Hello for Business PRT tokens being used simultaneously for one device.*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1606 | Forge Web Credentials | https://attack.mitre.org/techniques/T1606/ |

#### Description
This detection rule tries to find multiple PRT tokens being used simultaneously for one device. This might indicate that an attacker was able to request a new PRT on a second device using exxported Windows Hello for Business keys. More information about the attack scenario can be found in the references.

#### Risk
By using this detections, we can try to detect an attacker requesting access tokens with a forged PRT token on a new device. 

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com/detecting-non-privileged-windows-hello-abuse/

## Defender XDR
```KQL
// Get the Sign-in logs we want to query
let base = materialize(
    SigninLogs
    | where Timestamp > ago(1d)
);
// Get all the WHfB signins by looking at the authentication method and incomming token
let whfb = (
    base
    // Get WHfB signins
    | mv-expand todynamic(AuthenticationDetails)
    | where AuthenticationDetails.authenticationMethod == "Windows Hello for Business"
    | where IncomingTokenType == "primaryRefreshToken"
    | extend DeviceID = tostring(DeviceDetail.deviceId), AuthenticationDateTime = todatetime(AuthenticationDetails.authenticationStepDateTime)
    // Remove empty Session and Device IDs
    | where SessionId != "" and DeviceID != ""
);
// Save the time frame for each WHfB PRT token
// We use the SessionID to identify a specific PRT token since the SessionID changes when a new refresh token is being used
let prt_timeframes = (
    whfb
    // Summarize the first and last PRT usage per device, by using the Session ID
    | summarize TimeMin = arg_min(AuthenticationDateTime,*), TimeMax=arg_max(AuthenticationDateTime,*) by DeviceID, SessionId
    | project DeviceID, SessionId, TimeMin, TimeMax
);
// Save all the Session IDs for the logins that came from a WHfB authentication method
let whfb_sessions = toscalar(
    whfb
    | summarize make_set(SessionId)
);
base
| mv-expand todynamic(AuthenticationDetails)
| extend DeviceID = tostring(DeviceDetail.deviceId), AuthenticationDateTime = todatetime(AuthenticationDetails.authenticationStepDateTime)
// Get all signins related to a WHfB Session
| where SessionId in (whfb_sessions)
// Join the access token requests comming from a WHfB session with all the PRT tokens used in the past for each device
| join kind=inner prt_timeframes on DeviceID
| extend CurrentSessionID = SessionId, OtherSessionID = SessionId1, OtherSessionTimeMin = TimeMin, OtherSessionTimeMax = TimeMax, DeviceName = tostring(DeviceDetail.displayName)
// Get logins where the current SessionID is not the same as another one
| where CurrentSessionID != OtherSessionID
// Check if the new Session ID is seen while other Session IDs are still active (only check first login of the current Session ID)
| summarize arg_min(AuthenticationDateTime, *) by DeviceID, CurrentSessionID
| where AuthenticationDateTime between (OtherSessionTimeMin .. OtherSessionTimeMax)
// Exclude Windows Sign In as application login since attackers will use the PRT to request access tokens for other applications (they do not need to signin into Windows anymore)
| where AppDisplayName != "Windows Sign In"
| project AuthenticationDateTime, UserPrincipalName, DeviceID, DeviceName, CurrentSessionID, OtherSessionID, OtherSessionTimeMin, OtherSessionTimeMax, AppDisplayName, ResourceDisplayName
```

## Sentinel
```KQL
// Get the Sign-in logs we want to query
let base = materialize(
    SigninLogs
    | where TimeGenerated > ago(1d)
);
// Get all the WHfB signins by looking at the authentication method and incomming token
let whfb = (
    base
    // Get WHfB signins
    | mv-expand todynamic(AuthenticationDetails)
    | where AuthenticationDetails.authenticationMethod == "Windows Hello for Business"
    | where IncomingTokenType == "primaryRefreshToken"
    | extend DeviceID = tostring(DeviceDetail.deviceId), AuthenticationDateTime = todatetime(AuthenticationDetails.authenticationStepDateTime)
    // Remove empty Session and Device IDs
    | where SessionId != "" and DeviceID != ""
);
// Save the time frame for each WHfB PRT token
// We use the SessionID to identify a specific PRT token since the SessionID changes when a new refresh token is being used
let prt_timeframes = (
    whfb
    // Summarize the first and last PRT usage per device, by using the Session ID
    | summarize TimeMin = arg_min(AuthenticationDateTime,*), TimeMax=arg_max(AuthenticationDateTime,*) by DeviceID, SessionId
    | project DeviceID, SessionId, TimeMin, TimeMax
);
// Save all the Session IDs for the logins that came from a WHfB authentication method
let whfb_sessions = toscalar(
    whfb
    | summarize make_set(SessionId)
);
base
| mv-expand todynamic(AuthenticationDetails)
| extend DeviceID = tostring(DeviceDetail.deviceId), AuthenticationDateTime = todatetime(AuthenticationDetails.authenticationStepDateTime)
// Get all signins related to a WHfB Session
| where SessionId in (whfb_sessions)
// Join the access token requests comming from a WHfB session with all the PRT tokens used in the past for each device
| join kind=inner prt_timeframes on DeviceID
| extend CurrentSessionID = SessionId, OtherSessionID = SessionId1, OtherSessionTimeMin = TimeMin, OtherSessionTimeMax = TimeMax, DeviceName = tostring(DeviceDetail.displayName)
// Get logins where the current SessionID is not the same as another one
| where CurrentSessionID != OtherSessionID
// Check if the new Session ID is seen while other Session IDs are still active (only check first login of the current Session ID)
| summarize arg_min(AuthenticationDateTime, *) by DeviceID, CurrentSessionID
| where AuthenticationDateTime between (OtherSessionTimeMin .. OtherSessionTimeMax)
// Exclude Windows Sign In as application login since attackers will use the PRT to request access tokens for other applications (they do not need to signin into Windows anymore)
| where AppDisplayName != "Windows Sign In"
| project AuthenticationDateTime, UserPrincipalName, DeviceID, DeviceName, CurrentSessionID, OtherSessionID, OtherSessionTimeMin, OtherSessionTimeMax, AppDisplayName, ResourceDisplayName
```