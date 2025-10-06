# *Detect Custom Script or Run Command deployment by risky user*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1021.008 | Remote Services: Direct Cloud VM Connections | https://attack.mitre.org/techniques/T1021/008/ |
| T1651 | Cloud Administration Command | https://attack.mitre.org/techniques/T1651/ |


#### Description
This detection rule flags when a user with risk events in Entra ID Identity Protection is deploying Custom Scripts or Run Commands on Azure or Azure Arc machines. This may indicate a compromised cloud user that is now performaring lateral movement from the Azure control plane to Virtual Machines in other environments. 

#### Risk
This rule tries to mitigate the risk of compromised cloud admin accounts performing lateral movement via Azure or Azure Arc Custom Script or Run Command deployments.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://thecollective.eu/

## Defender XDR
```kql
AzureActivity 
| where TimeGenerated > ago(1h)
| where CategoryValue == "Administrative"
| where OperationNameValue =~ "Microsoft.Compute/virtualMachines/runCommand/action"
    or OperationNameValue =~ "MICROSOFT.COMPUTE/VIRTUALMACHINES/EXTENSIONS/WRITE"
| extend VMName = tostring(todynamic(Properties).resource)
| summarize make_list(ActivityStatusValue), TimeGenerated = max(TimeGenerated) by CorrelationId, CallerIpAddress, Caller, ResourceGroup, VMName
| join kind=inner (AADUserRiskEvents | where TimeGenerated > ago(14d) ) on $left.Caller == $right.UserPrincipalName
```