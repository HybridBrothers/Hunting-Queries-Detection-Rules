# *Detect external user sending suspicious link to multiple users*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |

#### Description

#### Risk


#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References


## Defender XDR
```KQL
// External user sending same link to multiple users via Teams
let threshold = 5;
MessageEvents
| where TimeGenerated > ago(1d)
// Focus on chat messsages
| where ThreadType == "chat"
// Only return external users sending messages
| join kind=leftanti (
    IdentityInfo
    | where TimeGenerated > ago(14d)
    | distinct AccountObjectId
) on $left.SenderObjectId == $right.AccountObjectId
// Only flag messages with Teams Links
| join kind=inner MessageUrlInfo on TeamsMessageId
// Exclude teams file thumbnails
| where Url !~ "http://dummy.jpg/"
// Make a set of the chats a user sends a specific URL to
| summarize ChatSet = make_set(ThreadId) by SenderEmailAddress, Url
// Count the amount of chats
| extend ChatCount = array_length(ChatSet)
| where ChatCount > threshold
```