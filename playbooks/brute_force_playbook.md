
**SOC Playbook: Privilege Escalation & Suspicious Logon Investigation**

1. Purpose
This playbook provides a standardized process for investigating and responding to suspicious authentication activity and potential privilege escalation within the monitored environment. It is designed for Tier 1 SOC analysts and aligned to industry best practices and MITRE ATT&CK techniques.


2. Scope
This playbook applies to the following detection types:

- New Local Admin / Privilege Escalation Events
EventCode 4720, 4728, 4732
- Scheduled Task or Service Creation (Persistence)
EventCode 4698, 7045
- Suspicious Login Times / Anomalous Logons
EventCode 4624
- Executable File Creation (Potential Malware Drop)
EventCode 4663 with Object_Name=".exe"*

These events are derived from the Splunk botsv3 dataset.


3. Relevant MITRE ATT&CK Techniques
Detection Type	                  MITRE ID	    Technique
New Local Admin / Priv Esc	      T1078, T1134	Valid Accounts, Access Token Manipulation
Scheduled Task / Service Creation	T1053, T1050	Scheduled Task, New Service
Suspicious Login Times	          T1078	        Valid Accounts
Executable Creation	              T1204, T1059	User Execution, Command Execution


4. Required Tools
Splunk Enterprise
Access to event logs from botsv3 dataset
OSINT sources for validation (VirusTotal, AbuseIPDB, WHOIS, etc.)


5. Triaging Workflow
This is the actual step‑by‑step procedure analysts should follow.

5.1 Step 1 — Validate Detection Trigger
A. Privilege Escalation Events
Run:
index=botsv3 (EventCode=4720 OR EventCode=4728 OR EventCode=4732)
| table _time, Account_Name, Target_Account, Group_Name, host
| sort -_time
Confirm:
Was a new account created?
Was an account added to Administrators?
Was the change expected (e.g., maintenance window)?

B. Scheduled Task or New Service Creation
Run:
index=botsv3 (EventCode=4698 OR EventCode=7045)
| table _time, Account_Name, TaskName, ServiceName, host
| sort -_time
Confirm:
Was the task/service created by an authorized user?
Does the service name look suspicious or random?
Is it associated with unsigned binaries?

C. Suspicious Login Time
Run:
index=botsv3 EventCode=4624
| eval hour=strftime(_time,"%H")
| stats count by Account_Name, hour
| where count > 3 AND (hour < 6 OR hour > 20)
| sort -count
Confirm:
Was this user's logon activity expected?
Has the user logged in outside normal work hours before?
Is their login source suspicious?

D. Executable File Creation
Run:
index=botsv3 EventCode=4663 Object_Type="File" Object_Name="*.exe"
| table _time, Account_Name, Object_Name, Object_Path, host
| sort -_time
Confirm:
Is the executable located in a suspicious folder (AppData, Temp)?
Is the filename unusual?
Was antivirus triggered shortly after?

5.2 Step 2 — Correlate Events
Determine whether events appear linked. Example correlations:
New admin created → same account logs in at unusual hours
Suspicious login → followed by scheduled task creation
Executable drop → followed by service creation
Correlation strengthens likelihood of malicious activity.

5.3 Step 3 — Profile the Account
Checklist:
Is the account domain or local?
Does the account belong to a real employee?
Does the employee’s job role require admin privileges?
Recent password reset?
Recent MFA enrollment change?

5.4 Step 4 — Investigate Source Host
Checklist:
Are there additional logs around the same timestamp?
AV or EDR alerts?
Unknown scheduled tasks?
Newly installed services?
Presence of suspicious executables in filesystem?

5.5 Step 5 — Containment Actions
Depending on severity:
Disable or reset the compromised account
Isolate the host (EDR isolation)
Terminate malicious processes
Remove unauthorized scheduled tasks or services
Block malicious binaries

5.6 Step 6 — Eradication and Recovery
Restore legitimate configurations
Reinstall affected services
Re-enable user accounts after resetting credentials
Perform forensic imaging if required

5.7 Step 7 — Reporting
Include:
Timeline of events
Root cause analysis
Indicators of compromise
Affected systems
Actions taken
Recommendations for prevention

____________________________________________________________________________________________________________________________
