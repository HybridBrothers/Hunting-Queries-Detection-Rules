# *Hunt devices supporting MDE Containment*

## Query Information

#### MITRE ATT&CK Technique(s)

N/A

#### Description
This hunting query can help you finding which Defender for Endpoint enrolled devices support device containment. This is being done by looking at the client version and estimated time the version was available. 

#### Risk
The calculation to check if device containment is supported is done by checking the date of when an update is available. Microsoft documentation is not always clear about which versions contain which features, which makes this query an estimation query. More information can be found in below references.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://learn.microsoft.com/en-us/defender-endpoint/windows-whatsnew
- https://hybridbrothers.com/device-isolation-and-containment-strategies/

## Defender XDR
```KQL
// Paste your query here
// Gets the onboarded windows devices and checks containment support nuances
let onboardedWindows = DeviceInfo
| where OnboardingStatus == "Onboarded" and OSPlatform contains "Windows"
| distinct DeviceId, DeviceName, ClientVersion, OSPlatform
| parse ClientVersion with Major:int "." Minor:int "." Build:int "." Revision:int
// Reference: https://learn.microsoft.com/en-us/defender-endpoint/windows-whatsnew
| extend Date = case(
    Minor >= 8760, "July-2024", 
    Minor >= 8750, "May-2024",
    Minor >= 8735, "Feb-2024",
    Minor >= 8672, "Dec-2023",
    Minor >= 8560, "Sept-2023",
    Minor > 8295, "May-2023",
    Minor == 8295 and Revision >= 1023, "May-2023",
    Minor == 8295 and Revision between (1019 .. 1023), "Jan/Feb-2023",
    Minor > 8210, "Dec-2022", 
    Minor == 8210 and Build >= 22621 and Revision >= 1016, "Dec-2022", 
    Minor == 8210 and not(Build >= 22621 and Revision >= 1016), "Aug-2022", 
    "< Aug-2022"
)
// Containment without AH Audit supported from Nov-2022
// Containment with AH Audit supported from Mar-2023
| extend Containment = case(
    Minor >= 8295, "Supported with AH Audit",
    (Minor == 8210 and Build >= 22621 and Revision >= 1016) or Minor > 8210, "Supported without AH Audit",
    "Unsupported"
);
// Gets onboarded non-windows devices, since containment is not supported here
let onboardedNonWindows = DeviceInfo
| where OnboardingStatus == "Onboarded" and OSPlatform !contains "Windows"
| distinct DeviceId, DeviceName, ClientVersion, OSPlatform
| extend Containment = "Unsupported";
// Get not-onboarded Servers
let notOnboardedServers = DeviceInfo
| where OnboardingStatus != "Onboarded" and DeviceType == "Server"
| distinct DeviceId, DeviceName, ClientVersion, OSPlatform
| extend Containment = "Unsupported";
// Union all and show diagram
union onboardedNonWindows, onboardedWindows, notOnboardedServers
| summarize count() by Containment
| render piechart 
```

## Sentinel
```KQL
N/A
```