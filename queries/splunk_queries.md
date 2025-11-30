# SPL Queries — splunk-bots-soc-project
Index: `botsv3`
Timepicker: start with **All time** or a broad recent range (Last 30 days). If you see "no results", expand time range to "All time" and confirm index.

---

A. New Local Admin / Privilege Escalation (EventCode 4720 / 4728 / 4732)
```spl
index=botsv3 (EventCode=4720 OR EventCode=4728 OR EventCode=4732)
| table _time, Account_Name, Target_Account, Group_Name, host
| sort -_time
Explanation: Detects when a new account is created or added to a privileged group. Indicates potential attacker escalation.
MITRE: T1078 (Valid Accounts) / T1134 (Access Token Manipulation / account management notes)
What to look for: who created the account, which account was added to which group, host name, and timestamps.

B. Persistence via Scheduled Task / Service Creation (EventCode 4698 / 7045)

 
index=botsv3 (EventCode=4698 OR EventCode=7045)
| table _time, Account_Name, TaskName, ServiceName, host
| sort -_time
Explanation: Detects creation of scheduled tasks or new services — common attacker persistence tactic.
MITRE: T1053 (Scheduled Task/Job) / T1050 (New Service)
What to look for: new task/service names, which account created them, and host.

C. Suspicious Login Times / Anomalous Logons (EventCode 4624)

 
index=botsv3 EventCode=4624
| eval hour=strftime(_time,"%H")
| stats count by Account_Name, hour
| where count > 3 AND (hour < 6 OR hour > 20)
| sort -count
Explanation: Finds accounts with logins during unusual hours (before 6am or after 8pm). May indicate compromised credentials or attacker presence.
MITRE: T1078 (Valid Accounts)
What to look for: account names logging in at odd hours and frequency.

D. Executable Creation / Potential Malware Dropped (EventCode 4663)

 
index=botsv3 EventCode=4663 Object_Type="File" Object_Name="*.exe"
| table _time, Account_Name, Object_Name, Object_Path, host
| sort -_time
Explanation: Shows file creation events for executables — often attacker droppers or malware.
MITRE: T1204 (User Execution), T1059 (Execution)
What to look for: new executables, suspicious paths (temp folders, user profiles), user who created it.

E. Suspicious Network Connections / External Beaconing (netflow/firewall logs)

 
index=botsv3 sourcetype=*netflow* OR sourcetype=*firewall*
| stats count by src_ip, dest_ip, dest_port
| where count > 5
| sort -count
Explanation: Identifies hosts making repeated connections to the same external destination — could be C2 beaconing or data exfiltration.
MITRE: T1071 (Application Layer Protocol)
What to look for: dest_ip with high counts, unusual dest_ports, matching hosts.

 

**Important run notes (read before running any search):**

- Set the Splunk **timepicker** at top-right to **All time** first. If no results then:
  - Confirm index exists: run `| eventcount summarize=false index=botsv3` to see counts.
  - Confirm sourcetypes: run `index=botsv3 | stats count by sourcetype | sort -count`.
  - If a query uses a sourcetype that doesn’t exist in your dataset, remove the `sourcetype=` filter or replace with the correct one shown by `stats count by sourcetype`.
- Use `head 50` or `limit` if results are huge.

---

# 2) Splunk step-by-step: run searches + what to capture

Follow this exact order and take the screenshots named exactly as shown (you’ll upload to `screenshots/`):

### Prep: confirm index & sample events
1. In Splunk Search bar run:
```spl
| eventcount summarize=false index=botsv3
