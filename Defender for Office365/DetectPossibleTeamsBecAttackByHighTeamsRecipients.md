# *Detect Possible Teams BEC Attack by High Teams Recipients*

## Query Information

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    | Link    |
| ---  | --- | --- |
| T1566 | Phishing | https://attack.mitre.org/techniques/T1566/ |

#### Description
An external sender suddenly increasing the amount of internal users they are sending messages to, can indicate that external user being compromised and used for BEC Attacks. In these kind of attacks compromised accounts are used to send phishing links or attachments to users in business relationships.

#### Risk
When the external user is sending a lot of messages to different internal users at a small time frame, these messages might be malicious.

#### Author <Optional>
- **Name:** Robbe Van den Daele
- **Github:** https://github.com/RobbeVandenDaele
- **Twitter:** https://x.com/RobbeVdDaele
- **LinkedIn:** https://www.linkedin.com/in/robbe-van-den-daele-677986190/
- **Website:** https://hybridbrothers.com/

#### References
- https://hybridbrothers.com
- https://thecollective.eu

## Defender XDR
```KQL
// Possible BEC detection by high teams recipients 
let increase_percentage = 200;
let base = (
    MessageEvents
    | where TimeGenerated > ago(14d)
    // Focus on chat messsages
    | where ThreadType == "chat"
    // Only return external users sending messages
    | join kind=leftanti (
        IdentityInfo
        | where TimeGenerated > ago(14d)
        | distinct AccountObjectId
    ) on $left.SenderObjectId == $right.AccountObjectId
    // Make a set of all the chats they are posting to, for every day
    | summarize ChatSet = make_set(ThreadId) by SenderEmailAddress, bin(TimeGenerated, 1d)
    // Count the amount of chats they posted to for each day
    | extend ChatAmmount = array_length(ChatSet)
);
// Get the average of send chats per external user per day
let averageBySender = (
    base
    | summarize AverageChatsBySender = avg(ChatAmmount) by SenderEmailAddress
);
// Check if the sender dubbled their chats to internal users compared to their baseline
base
| where TimeGenerated > ago(1d)
| join kind=inner averageBySender on SenderEmailAddress
| where ChatAmmount > AverageChatsBySender * (increase_percentage / 100)
```