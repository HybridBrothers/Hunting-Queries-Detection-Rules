# *Detect Direct Send phishing emails*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | https://attack.mitre.org/techniques/T1566/ |

#### Description
In May 2025, a campaign started using the Microsoft Exchange Direct Send feature to send phishing mails to organizations. This feature is designed for use by printers, scanners, cloud services and other devices that need to send messages on behalf of the company. This detection rule tries to detect the malicious mails being send via Direct Send using a couple of indicators:

    - Sender email is the same as Recipient email
    - SPF and DMARC both failed
    - Mail is not comming in via an Exchange connector
    - The sender IP address country is not a country that the user is known to login from

FYI, if you remove the country check (last line of the query), you can use the query to identify if there are legitimate mails as well. If not, you can disable the Direct Send feature in Exchange Online.


#### Risk
This detection tries to detect the Direct Send phsihing mails when you cannot disable Direct Send, especially when they are not being blocked by MDO. This allows you to ZAP the mails manually after delivery. 

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://www.bleepingcomputer.com/news/security/microsoft-365-direct-send-abused-to-send-phishing-as-internal-users/
- https://www.jumpsec.com/guides/microsoft-direct-send-phishing-abuse-primitive/
- https://techcommunity.microsoft.com/blog/exchange/introducing-more-control-over-direct-send-in-exchange-online/4408790?WT.mc_id=M365-MVP-9501

## Defender XDR
```KQL
let country_land_codes = (
    externaldata (Country:string,Alpha2:string,Alpha3:string,CountryCode:string,Iso3166:string,Region:string,SubRegion:string,IntermediateRegion:string,RegionCode:string,SubRegionCode:string,IntermediateRegionCode:string) 
    ['https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/refs/heads/master/all/all.csv'] with (format='csv', ignoreFirstRecord=true)
    | distinct Country, Alpha2
);
let login_locations = (
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where ResultSignature == 0
    | distinct UserId, UserPrincipalName, LandCode = tostring(LocationDetails.countryOrRegion)
    | where isnotempty(LandCode)
    | join kind=inner country_land_codes on $left.LandCode == $right.Alpha2
    | summarize UsageCountries = make_set(Country) by UserId, UserPrincipalName
);
EmailEvents
| where TimeGenerated > ago(30d)
// Find Direct Send mails
| where SenderMailFromAddress == RecipientEmailAddress
| extend AuthenticationDetails = parse_json(AuthenticationDetails)
| where AuthenticationDetails.SPF == "fail" and AuthenticationDetails.DMARC == "fail"
// Only flag mails not comming in via an exchange connector (these are legit mails)
| where isempty(Connectors)
// Exclude if detected as phish (since it is already remediated then)
| where DeliveryAction !in ("Junked", "Blocked")
| extend Location = parse_json(geo_info_from_ip_address(SenderIPv4))
| extend MailFromCountry = tostring(Location.country)
// Find the usage countries of the users
| join kind=leftouter login_locations on $left.SenderObjectId == $right.UserId
// Flag when sender country is not a usage country of the user
| where tostring(UsageCountries) !contains MailFromCountry
```

## Sentinel
```KQL
let country_land_codes = (
    externaldata (Country:string,Alpha2:string,Alpha3:string,CountryCode:string,Iso3166:string,Region:string,SubRegion:string,IntermediateRegion:string,RegionCode:string,SubRegionCode:string,IntermediateRegionCode:string) 
    ['https://raw.githubusercontent.com/lukes/ISO-3166-Countries-with-Regional-Codes/refs/heads/master/all/all.csv'] with (format='csv', ignoreFirstRecord=true)
    | distinct Country, Alpha2
);
let login_locations = (
    SigninLogs
    | where TimeGenerated > ago(7d)
    | where ResultSignature == 0
    | distinct UserId, UserPrincipalName, LandCode = tostring(LocationDetails.countryOrRegion)
    | where isnotempty(LandCode)
    | join kind=inner country_land_codes on $left.LandCode == $right.Alpha2
    | summarize UsageCountries = make_set(Country) by UserId, UserPrincipalName
);
EmailEvents
| where TimeGenerated > ago(30d)
// Find Direct Send mails
| where SenderMailFromAddress == RecipientEmailAddress
| extend AuthenticationDetails = parse_json(AuthenticationDetails)
| where AuthenticationDetails.SPF == "fail" and AuthenticationDetails.DMARC == "fail"
// Only flag mails not comming in via an exchange connector (these are legit mails)
| where isempty(Connectors)
// Exclude if detected as phish (since it is already remediated then)
| where DeliveryAction !in ("Junked", "Blocked")
| extend Location = parse_json(geo_info_from_ip_address(SenderIPv4))
| extend MailFromCountry = tostring(Location.country)
// Find the usage countries of the users
| join kind=leftouter login_locations on $left.SenderObjectId == $right.UserId
// Flag when sender country is not a usage country of the user
| where tostring(UsageCountries) !contains MailFromCountry
```