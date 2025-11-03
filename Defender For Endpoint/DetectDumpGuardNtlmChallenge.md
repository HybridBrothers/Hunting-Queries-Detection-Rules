# *DumpGuard NTLM challenge detected*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1003.004 | OS Credential Dumping: LSA Secrets | https://attack.mitre.org/techniques/T1003/004/ |
| T1003 | OS Credential Dumping | https://attack.mitre.org/techniques/T1003/ |

#### Description
With the DumpGuard tool, attackers are able to dump credetials via Remote Credential Guard on devices that have Credential Guard enabled. The creator of the DumpGuard tool purposely used a hard-coded NTLMv1 challenge into the tool, for easy detection. 

> [!WARNING]
> Since the detection relies on a static IOC that can easily be changed in the source code, this detection has a low confidence score since it can be easily bypassed. However, if the detection hits it is almost 100% certain the alert will be TP.
> Also take into account that the `NetworkSignatureInspected` ActionType in MDE is sampled, which means not very event will be logged. 

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

## Defender XDR
```KQL
DeviceNetworkEvents
// Get NTLM Challenges
| where ActionType == "NetworkSignatureInspected"
| where tostring(todynamic(AdditionalFields).SignatureName) =~ "NTLM-Challenge"
// Extract the NTLM Sample Packet
| extend SamplePacketContent = extract('\\["(.+)"\\]', 1, tostring(todynamic(AdditionalFields).SamplePacketContent))
// Remove % values, since the '1122334455667788' is easy to find without conversions
| extend NewSamplePacketContent = strcat_array(split(SamplePacketContent, "%"), "")
| where NewSamplePacketContent contains "1122334455667788"
```
