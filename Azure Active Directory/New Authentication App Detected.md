## Description:
This detection identifies newly seen or unusual Azure AD application sign-ins that may indicate the creation or use of malicious or unauthorized cloud applications. By comparing recent sign-in activity against a baseline of previously known apps, these queries highlight anomalous applications, external app usage, and potentially compromised cloud accounts aligned with MITRE ATT&CK technique T1078.004 (Valid Accounts: Cloud Accounts). This helps analysts quickly spot suspicious authentication patterns, risky third-party apps, and indicators of account or app abuse within Microsoft 365 and Azure AD environments.

## MITRE ATT&CK Technique(s)
Technique ID	Title	Link
T1078.004	Valid Accounts: Cloud Accounts	https://attack.mitre.org/techniques/T1078/004


## References
https://learn.microsoft.com/en-us/azure/active-directory/develop/reference-aadsts-error-codes
https://www.varonis.com/blog/using-malicious-azure-apps-to-infiltrate-a-microsoft-365-tenant
https://learn.microsoft.com/en-us/security/compass/incident-response-playbook-compromised-malicious-app
https://www.lares.com/blog/malicious-azure-ad-application-registrations/

## Defender XDR
let KnownApps = AADSignInEventsBeta
    // Adjust the timerange depending on the retention period
    | where Timestamp between (ago(30d) .. ago(2d))
    | distinct Application;
AADSignInEventsBeta
| where Timestamp > ago(2d)
| where not(Application in~ (KnownApps))
// If the AppID is empty then it is a third party App.
| extend IsExternalApp = iff(isempty(ApplicationId), 'True', 'False')
| project-reorder Timestamp, AccountUpn, ErrorCode, IsExternalApp, Application, AccountObjectId, IPAddress, ClientAppUsed


## Sentinel 

let KnownApps = SigninLogs
// Adjust the timerange depending on the retention period
| where TimeGenerated between (ago(90d) .. ago(2d))
| distinct AppDisplayName;
SigninLogs
| where TimeGenerated > ago(2d)
| where not(AppDisplayName in~ (KnownApps))
// If the AppID is empty then it is a third party App.
| extend IsExternalApp = iff(isempty(AppId), "True", "False")
| project-reorder TimeGenerated, UserPrincipalName, ResultType, IsExternalApp, AppDisplayName, Identity, IPAddress, ClientAppUsed
