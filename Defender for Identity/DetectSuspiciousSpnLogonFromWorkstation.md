# *Suspicious SPN logon from workstation (DumpGuard)*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1003.004 | OS Credential Dumping: LSA Secrets | https://attack.mitre.org/techniques/T1003/004/ |
| T1003 | OS Credential Dumping | https://attack.mitre.org/techniques/T1003/ |

#### Description
With the DumpGuard tool, attackers are able to dump credetials via Remote Credential Guard on devices that have Credential Guard enabled.
Since the DumpGuard tool needs to use an SPN enabled account (in the POC they use a machine account) for two exploitation scenario's, it is interesting to look for TGT requests happening from client devices for SPN enabled accounts. 

#### Risk
This detection tries to mitigate the risk of attackers bypassing Credential Guard on devices by using the DumpGuard tool. 

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://specterops.io/blog/2025/10/23/catching-credential-guard-off-guard/
- [Inspired by a BlueRaven query](https://www.linkedin.com/posts/bluraven_kql-threathunting-detectionengineering-activity-7387496098510319616-dGhE?utm_source=share&utm_medium=member_desktop&rcm=ACoAACz-oDsBI8pyHV8fT38Q6oiZQcBRxBPyw0I)

## Defender XDR
```KQL
let spn_accounts = toscalar(
    // Search for all SPNs we can find in historic logs
    IdentityLogonEvents
    | where TimeGenerated > ago(14d)
    | where Application == "Active Directory"
    | where isnotempty(AdditionalFields.Spns)
    | extend Spns = split(AdditionalFields.Spns, ",")
    | summarize make_set(Spns)
);
let workstation_subnets = toscalar(
    DeviceNetworkInfo
    | where TimeGenerated > ago(14d)
    // Filter out empty device names
    | where isnotempty(DeviceName)
    // Expand IP Addresses
    | mv-expand todynamic(IPAddresses)
    // Focus on device name and IP Address info
    | distinct DeviceName, tostring(IPAddresses)
    // Filter out IPv6 addresses, /32 addresses, and APIPA addresses
    | where todynamic(IPAddresses).IPAddress !contains ":"
    | where todynamic(IPAddresses).SubnetPrefix != "32"
    | where todynamic(IPAddresses).IPAddress !startswith "169.254"
    // Find Device Type of the device
    | join kind=inner (
        DeviceInfo
        | where TimeGenerated > ago(30d)
        | distinct DeviceName, DeviceType
    ) on DeviceName
    // Only focus on workstations
    | where DeviceType == "Workstation"
    // Create Network Address based on the host IP Address and create a distinct list
    | extend NetworkAddress = format_ipv4_mask(tostring(todynamic(IPAddresses).IPAddress), tolong(todynamic(IPAddresses).SubnetPrefix))
    | summarize make_set(NetworkAddress)
);
IdentityLogonEvents
| where TimeGenerated > ago(1h)
// Get AD TGT requests by looking for Kerberos requests to KRBTGT account
| where Application == "Active Directory"
| where Protocol == "Kerberos"
| where AdditionalFields.Spns contains "krbtgt"
// Check for requests to account names with SPNs
| where AccountName in (spn_accounts)
// Check if IP Address is from a client range
| where ipv4_is_in_any_range(IPAddress, workstation_subnets)
// Optional - Ignore failed logins
| where ActionType != "LogonFailed"
```
