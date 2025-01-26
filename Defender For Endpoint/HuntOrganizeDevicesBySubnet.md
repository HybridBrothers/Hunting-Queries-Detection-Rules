# *Hunt for devices organized by subnet*

## Query Information

#### MITRE ATT&CK Technique(s)

N/A

#### Description
This rule helps you organize devices by subnet in your networks. By doing this, you can identify how many not-onboarded devices, devices not supporting MDE containment, and types of devices live in your subnet ranges.

#### Risk
- This query is rather big and can probably be optimized a bit. The result will in most cases contain a supernet, which you will have to filter out yourself if needed.
- The IsolateSupportedOS and ContainSupportedOS columns are calculated based on OS only. The correct agent version nuances as discussed earlier are not yet added.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com/device-isolation-and-containment-strategies/
## Defender XDR
```KQL
let isolationSupportedOS = dynamic(["Windows11", "Windows10", "WindowsServer2025", "WindowsServer2022", "WindowsServer2019", "WindowsServer2016", "WindowsServer2012R2", "Linux", "macOS"]);
let containmentSupportedOS = dynamic(["Windows11", "Windows10", "WindowsServer2025", "WindowsServer2022", "WindowsServer2019", "WindowsServer2016", "WindowsServer2012R2"]);
let base = DeviceNetworkInfo
    // Expand all IPs
    | mv-expand todynamic(IPAddresses)
    // Ignore IPv6 addresses
    | where tostring(IPAddresses.IPAddress) !contains ":"
    // Save the Prefix as an extra property and set it to /32 when empty
    | extend Prefix = iff(isnotempty(tostring(IPAddresses.SubnetPrefix)), tostring(IPAddresses.SubnetPrefix), "32");
let networks = base
    // Get network addresses with a non /32 prefix
    | where Prefix != "32"
    // Get the network address related to the IP
    | extend NetworkAddress = format_ipv4(tostring(IPAddresses.IPAddress), tolong(Prefix))
    // Build the IP and Network Address with the CIDR notation
    | extend IPAddress = strcat(tostring(IPAddresses.IPAddress), "/", Prefix)
    | extend NetworkAddress = strcat(NetworkAddress, "/", Prefix)
    // Join the Device Info information
    | join kind=inner DeviceInfo on DeviceId, ReportId
    // Ignore APIPA addresses
    | where NetworkAddress != "169.254.0.0/16"
    // Ignore merged device IDs
    | where MergedToDeviceId == ""
    // Make a set of all the Device Objects belonging to the same subnet
    | extend DeviceObj = pack(
        "DeviceName", DeviceName,
        "IPAddress", IPAddress,
        "DeviceType", DeviceType,
        "DeviceCategory", DeviceCategory,
        "IsInternetFacing", IsInternetFacing,
        "OnboardingStatus", OnboardingStatus,
        "OSDistribution", OSDistribution,
        "OSPlatform", OSPlatform
    )
    // Make a list of the objects in the same subnet
    | summarize make_set(DeviceObj) by NetworkAddress;
let device_with_host_prefix = base
    // Get network addresses with /32 Prefix to try and match other networks
    | where Prefix == "32"
    // Build the IP Address with the CIDR notation
    | extend IPAddress = strcat(tostring(IPAddresses.IPAddress), "/", Prefix)
    // Join the Device Info information
    | join kind=inner DeviceInfo on DeviceId, ReportId
    // Ignore merged device IDs
    | where MergedToDeviceId == ""
    // Make a set of all the Device Objects
    | extend DeviceObj = pack(
        "DeviceName", DeviceName,
        "IPAddress", IPAddress,
        "DeviceType", DeviceType,
        "DeviceCategory", DeviceCategory,
        "IsInternetFacing", IsInternetFacing,
        "OnboardingStatus", OnboardingStatus,
        "OSDistribution", OSDistribution,
        "OSPlatform", OSPlatform
    )
    | extend Joiner = 1;
let network_addresses = base
    // Get network addresses with a non /32 prefix
    | where Prefix != "32"
    // Get the network address related to the IP
    | extend NetworkAddress = format_ipv4(tostring(IPAddresses.IPAddress), tolong(Prefix))
    | extend NetworkAddress = strcat(NetworkAddress, "/", Prefix)
    // Create joiner to find host addresses related to certain networks
    | distinct NetworkAddress
    | extend Joiner = 1;
let networks2 = device_with_host_prefix
    // Try to join /32 IPs
    | join kind=inner network_addresses on Joiner
    // Check if IP is in the network range, and only return those IPs
    | extend InRange = ipv4_is_in_range(IPAddress, NetworkAddress)
    | where InRange == 1
    // Make a list of the objects in the same subnet
    | summarize make_set(DeviceObj) by NetworkAddress;
union networks, networks2
    // Expand the Device Objects
    | mv-expand set_DeviceObj
    // Save the DeviceType, DeviceCategory, and Onboarding Status
    | extend DeviceType = set_DeviceObj.DeviceType
    | extend DeviceCategory = set_DeviceObj.DeviceCategory
    | extend OnboardingStatus = set_DeviceObj.OnboardingStatus
    // Count how many servers, workstations, network devices, iot devices, and ot devices exists in a subnet, the onboarding estate, and OS Distribution
    | summarize Servers = countif(set_DeviceObj.DeviceType=="Server"),
        Workstations = countif(set_DeviceObj.DeviceType=="Workstation"),
        NetworkDevices = countif(set_DeviceObj.DeviceCategory=="NetworkDevice"),
        IoTDevices = countif(set_DeviceObj.DeviceCategory=="IoT"),
        OTDevices = countif(set_DeviceObj.DeviceCategory=="OT"),
        Onboarded = countif(set_DeviceObj.OnboardingStatus=="Onboarded"),
        NotOnboarded = countif(set_DeviceObj.OnboardingStatus!="Onboarded"),
        IsolateSupportedOS = countif((set_DeviceObj.OSDistribution has_any (isolationSupportedOS) or set_DeviceObj.OSPlatform == "Linux") and set_DeviceObj.OnboardingStatus == "Onboarded"),
        ContainSupportedOS = countif(set_DeviceObj.OSDistribution has_any (containmentSupportedOS) and set_DeviceObj.OnboardingStatus == "Onboarded") by NetworkAddress
    // Join the network subnets so we have the device objects again
    | join kind=leftouter networks on NetworkAddress
    | join kind=leftouter networks2 on NetworkAddress
    // Extend Array Concat
    | extend set_DeviceObj = array_concat(set_DeviceObj, set_DeviceObj1)
    // Remove duplicate columns
    | project-away NetworkAddress1, NetworkAddress2, set_DeviceObj1
    // Count how many IPs there are in one subnet
    | extend CountIPs = array_length(set_DeviceObj)
    | sort by CountIPs desc
```

## Sentinel
```KQL
N/A
```