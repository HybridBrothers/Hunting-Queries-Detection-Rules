# *Hunt Device Discovery Subnet Ranges*

## Query Information

#### MITRE ATT&CK Technique(s)

N/A

#### Description
This KQL query helps you identify which subnet ranges are behind the Microsoft Defender for Endpoint Device Discovery 'Monitored Networks' page. By using this query you can investigate if all of your corporate networks are being monitored and change monitored states effectivly. More information can be found in the references.

#### Risk
This query helps mitigating the risk that you do not perform Device Discovery on all monitored networks, which would result into an incomplete asset inventory list in Defender XDR.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com/mde-device-discovery-improving-the-monitored-network-page/

## Defender XDR
```KQL
// OPTIONAL - Device cap used to ignore network with less then X devices in them
let device_cap = 0;
DeviceNetworkInfo
| where Timestamp > ago(7d)
// Ignore empty networks
| where ConnectedNetworks  != ""
// Get networks data
| extend ConnectedNetworksExp = parse_json(ConnectedNetworks)
| mv-expand bagexpansion = array ConnectedNetworks=ConnectedNetworksExp
| extend NetworkName = tostring(ConnectedNetworks ["Name"]), NetworkDescription = tostring(ConnectedNetworks ["Description"]), NetworkCategory = tostring(ConnectedNetworks ["Category"])
// Get subnet data for IPv4 Addresses
| extend IPAddressesExp = parse_json(IPAddresses)
| mv-expand bagexpansion = array IPAddresses=IPAddressesExp
| extend IPAddress = tostring(IPAddresses ["IPAddress"]), SubnetPrefix = tolong(IPAddresses ["SubnetPrefix"])
| extend NetworkAddress = format_ipv4(IPAddress, SubnetPrefix)
| extend SubnetRange = strcat(NetworkAddress, "/", SubnetPrefix)
// Exclude IPv6 and APIPPA
| where SubnetPrefix <= 32
| where IPAddress !startswith "169.254"
// Ignore unidentified networks
| where not(NetworkName has_any ("Unidentified", "Identifying..."))
// Provide list
| distinct DeviceId, NetworkName, IPv4Dhcp, SubnetRange
| summarize Devices = count(), SubnetRanges = make_set(SubnetRange) by NetworkName, IPv4Dhcp
// Ignore network with very low device count
| where Devices >= device_cap
| sort by Devices desc
```

## Sentinel
```KQL
// OPTIONAL - Device cap used to ignore network with less then X devices in them
let device_cap = 0;
DeviceNetworkInfo
| where TimeGenerated > ago(7d)
// Ignore empty networks
| where ConnectedNetworks  != ""
// Get networks data
| extend ConnectedNetworksExp = parse_json(ConnectedNetworks)
| mv-expand bagexpansion = array ConnectedNetworks=ConnectedNetworksExp
| extend NetworkName = tostring(ConnectedNetworks ["Name"]), NetworkDescription = tostring(ConnectedNetworks ["Description"]), NetworkCategory = tostring(ConnectedNetworks ["Category"])
// Get subnet data for IPv4 Addresses
| extend IPAddressesExp = parse_json(IPAddresses)
| mv-expand bagexpansion = array IPAddresses=IPAddressesExp
| extend IPAddress = tostring(IPAddresses ["IPAddress"]), SubnetPrefix = tolong(IPAddresses ["SubnetPrefix"])
| extend NetworkAddress = format_ipv4(IPAddress, SubnetPrefix)
| extend SubnetRange = strcat(NetworkAddress, "/", SubnetPrefix)
// Exclude IPv6 and APIPPA
| where SubnetPrefix <= 32
| where IPAddress !startswith "169.254"
// Ignore unidentified networks
| where not(NetworkName has_any ("Unidentified", "Identifying..."))
// Provide list
| distinct DeviceId, NetworkName, IPv4Dhcp, SubnetRange
| summarize Devices = count(), SubnetRanges = make_set(SubnetRange) by NetworkName, IPv4Dhcp
// Ignore network with very low device count
| where Devices >= device_cap
| sort by Devices desc
```