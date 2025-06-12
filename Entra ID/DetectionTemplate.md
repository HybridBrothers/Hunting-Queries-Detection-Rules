# *Hunt MSOL Azure AD Connect / Entra Sync servers*

## Query Information

#### MITRE ATT&CK Technique(s)

N/A

#### Description
Microsoft announced that starting from April 30 2025, Microsoft Entra Connect will need to have the minimal version of 2.4.18.0. If you want to identitify if you still have an AD Connect or Entra Sync server with a lower version, you can use below KQL query. 

#### Risk
See reference for impacted scenario's. 

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/harden-update-ad-fs-pingfederate
- https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-upgrade-previous-version

## Defender XDR
```KQL
DeviceTvmSoftwareInventory
| where SoftwareVendor == "microsoft"
| where SoftwareName in ("microsoft_entra_connect_sync", "microsoft_azure_ad_connect")
| distinct DeviceName, SoftwareName, SoftwareVendor, SoftwareVersion
| extend MSOnlineDepricationSafe = iff(
    parse_version(SoftwareVersion) < parse_version("2.4.18.0"),
    "No",
    "Yes"
)
```

## Sentinel
```KQL
DeviceTvmSoftwareInventory
| where SoftwareVendor == "microsoft"
| where SoftwareName in ("microsoft_entra_connect_sync", "microsoft_azure_ad_connect")
| distinct DeviceName, SoftwareName, SoftwareVendor, SoftwareVersion
| extend MSOnlineDepricationSafe = iff(
    parse_version(SoftwareVersion) < parse_version("2.4.18.0"),
    "No",
    "Yes"
)
```