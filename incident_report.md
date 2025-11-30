Incident Report – Unauthorized Privilege Escalation (Botsv3 Environment)

Report Version: 1.0
Date Created: [Insert today’s date]
Analyst: Yusuf Nazeer
Environment: Splunk Enterprise (Bots v3 Security Dataset)
Classification: Potential Privilege Escalation Attempt
Severity: Medium

** 1. Executive Summary

On the Botsv3 Windows endpoint FYODOR-L, multiple account-modification events occurred within seconds, involving the user account FyodorMalteskesko, including assignment to the Administrators group.

These events align with MITRE ATT&CK Privilege Escalation techniques (T1078, T1134) and may indicate an adversary escalating privileges after gaining initial access.

Although this is a lab dataset, the activity reflects a realistic attacker behavior pattern. This report analyzes the events, assesses impact, and provides recommended remediation.

2. Timeline of Events

(All times from Splunk where you saw them)

Timestamp (UTC)	Account_Name	Target_Account	Group_Name	Host
2018-08-20 05:08:35	FyodorMalteskesko	–	Administrators	FYODOR-L
2018-08-20 05:08:17	FyodorMalteskesko	–	Users	FYODOR-L
2018-08-20 05:08:17	FyodorMalteskesko	svcvnc	–	FYODOR-L
2018-08-20 05:08:17	FyodorMalteskesko	–	None	FYODOR-L

Observations

Four identity-related events occurred within 18 seconds.

One event shows addition to Administrators → highest privilege.

One event modifies svcvnc, which resembles a service login account.

This pattern is commonly consistent with rapid unauthorized privilege setup.

3. Detection Details
Detection Name: Unauthorized Privilege Modification
Splunk Query Used:
index=botsv3 (EventCode=4720 OR EventCode=4728 OR EventCode=4732)
| table _time, Account_Name, Target_Account, Group_Name, host
| sort -_time

Why This Query?

These Windows Security Event Codes detect:

4720 – New user account created

4728 – Added to security-enabled global group

4732 – Added to a local group

These are among the most reliable indicators of:
✔ Privilege escalation
✔ Credential misuse
✔ Unauthorized admin creation

4. MITRE ATT&CK Mapping
Technique	Name	How It Applies
T1078	Valid Accounts	Attacker used a legitimate account (Fyodor) to escalate privileges.
T1134	Access Token Manipulation / Privilege Assignment	Account added to Administrators, modifying authorization tokens.

These are top-tier SOC-relevant detections.

5. Analysis & Interpretation
* Account: FyodorMalteskesko

This account performed:

Group modifications

Direct assignment to Administrators

Alterations of another account (svcvnc)

* Key Indicators:

Speed (multiple privilege changes in seconds) indicates automated activity or an attacker with a script.

Administrators group modification is almost always malicious unless pre-authorized.

Target account “svcvnc” looks like a service-related account → common lateral movement tactic.

* Impact Assessment:

If this were a live environment, the attacker could now:

Disable antivirus

Dump credentials

Move laterally

Install backdoors

Exfiltrate data

6. Containment Recommendations

If this were real, the SOC should immediately:

1. Disable or lock the account “FyodorMalteskesko”

Prevent further misuse of escalated privileges.

2. Review “svcvnc” account activity

Ensure no scheduled tasks, services, or remote tools were installed.

3. Investigate login patterns

Look for:

Successful logons before the privilege change

Unusual hours

Logons from new hosts

4. Review group membership changes

Confirm no other hidden persistence (e.g., new users, SIDHistory changes).

7. Eradication & Recovery Actions

Revoke Administrator membership for affected accounts.

Require password resets for:

FyodorMalteskesko

svcvnc

Verify no new services, tasks, or registry-run keys were installed.

Patch and update endpoint.

Re-enable or reinstall EDR if it was tampered with.

8. Lessons Learned

This incident shows why SOC Tier 1 analysts must:

Know common Windows EventCodes

Detect privilege escalation patterns

Use Splunk to pivot between accounts, hosts, and timelines

Map detections to MITRE tactics

Build simple alerting logic for identity misuse

You can talk through all of this during interviews and sound highly competent.

9. Appendix
Raw Splunk Events (from your search)

(Copy/paste the exact 4 events here — screenshots recommended in GitHub)

Screenshots to Capture in Splunk (for GitHub):

You should screenshot all of the following:

The Splunk search box with executed query

The results table showing the 4 events

The timeline chart or events panel

Your created alert (if you built one)

Any dashboard visualizations
