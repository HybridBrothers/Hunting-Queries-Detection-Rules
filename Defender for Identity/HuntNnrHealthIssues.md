# *Hunt for Defender for Identity NNR issues*

## Query Information

#### MITRE ATT&CK Technique(s)

N/A

#### Description
This query can help you in finding Network Name Resolution health issues of Microsoft Defender for Identity. NNR is a critical component which is used to get more information on IP addresses seen by MDI. Without NNR proparly working, MDI can throw a lot of False Positive alerts.

#### Risk
High False Negative detections by MDI.


#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com/mdi-nnr-health/


## Defender XDR
```KQL
let networks = DeviceNetworkInfo
    // Expand all IPs
    | mv-expand todynamic(IPAddresses)
    // Get the network address related to the IP
    | extend NetworkAddress = format_ipv4(tostring(IPAddresses.IPAddress), tolong(IPAddresses.SubnetPrefix))
    // Build the IP with the CIDR notation
    | extend IPAddress = strcat(tostring(IPAddresses.IPAddress), "/", tolong(IPAddresses.SubnetPrefix))
    // Save the Prefix as an extra property
    | extend Prefix = tostring(IPAddresses.SubnetPrefix)
    // Make a set of all the IP's belonging to the same subnet
    | summarize make_set(IPAddress) by NetworkAddress, Prefix
    // Count how many IPs there are in one subnet
    | extend CountIPs = array_length(set_IPAddress)
    | extend Joiner = 1;
// Network Information
let network_info = DeviceNetworkInfo
    | mv-expand todynamic(IPAddresses)
    | extend IPAddress = tostring(IPAddresses.IPAddress);
// Ports used in NNR
let nnr_ports = dynamic(["3389", "135", "137"]);
let mdi_servers = dynamic([]);
// Query network connections
DeviceNetworkEvents
// Get events from Defender for Identity sensors - fill in mdi-servers variable for more complete results
| where InitiatingProcessFileName == "Microsoft.Tri.Sensor.exe" or DeviceName has_any (mdi_servers)
// Check traffic for NNR ports
| where RemotePort in (nnr_ports)
// Join the network info for more destination context
| join kind=inner network_info on $left.RemoteIP == $right.IPAddress
// Get distinct values
| project-rename RemoteDeviceName = DeviceName1
| distinct DeviceName, ActionType, RemoteIP, RemotePort, RemoteDeviceName
// Join all network addresses
| extend Joiner = 1
| join kind=inner networks on Joiner
// Check if remote ip is in a certain network address
| extend NetworkAddrPrefix = strcat(NetworkAddress, "/", Prefix)
| where ipv4_is_in_range(RemoteIP, NetworkAddrPrefix)
// Create Object to reuse later
| extend Obj = pack(
    "DeviceName", DeviceName,
    "NetworkAddrPrefix", NetworkAddrPrefix,
    "RemotePort", RemotePort,
    "RemoteIP", RemoteIP
)
// Count amount of failed and succeeded logins
| summarize FailedConnections = countif(ActionType == "ConnectionFailed"), 
    SucceededConnections = countif(ActionType == "ConnectionSuccess") by tostring(Obj)
// Extract the columns from the object again
| extend Obj = todynamic(Obj)
// Save the properties for later use
| extend DeviceName = tostring(Obj.DeviceName),
    NetworkAddrPrefix = tostring(Obj.NetworkAddrPrefix),
    RemotePort = tostring(Obj.RemotePort),
    RemoteIP = tostring(Obj.RemoteIP)
// Create a new object to save the amount of failed and succeeded attempts per IP
| extend Obj = pack(
    "RemoteIP", RemoteIP,
    "SucceededConnections", SucceededConnections,
    "FailedConnections", FailedConnections
)
// Create a list of the remote ips and their connections by MDI sensor, destination subnet and RemoteIP
// Subnets with only fails on both ports will fail in NNR
| summarize ConnectionDetails = make_set(Obj), 
    TotalSucceededConnections = sum(SucceededConnections), 
    TotalFailedConnections = sum(FailedConnections) by DeviceName, NetworkAddrPrefix, RemotePort
// Filter out /32 addresses
| where NetworkAddrPrefix !contains "/32"
// Sorting
| sort by TotalFailedConnections desc
// Reorder
| project-reorder DeviceName, NetworkAddrPrefix, RemotePort, TotalSucceededConnections, TotalFailedConnections, ConnectionDetails
```

## Sentinel
```KQL
N/A
```