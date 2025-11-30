# SPL Queries — splunk-bots-soc-project
Index: botsv3
Timepicker: set to a window that includes data (All time initially)

---

## A. New Local Admin / Privilege Escalation
**SPL**
index=botsv3 (EventCode=4720 OR EventCode=4728 OR EventCode=4732)
| table _time, Account_Name, Target_Account, Group_Name, host
| sort -_time

**Explanation:** Detects when a new admin is created or an account is added to a privileged group. This often indicates attacker privilege escalation or persistence after compromise.

**MITRE:** T1078 (Valid Accounts) / T1134 (Access Token Manipulation — related escalation behavior)

---

## B. Executable Creation / Potential Malware Dropped
**SPL**
index=botsv3 EventCode=4663 Object_Type="File" Object_Name="*.exe"
| table _time, Account_Name, Object_Name, Object_Path, host
| sort -_time

**Explanation:** Detects creation/modification of .exe files. Attackers frequently drop executables (payloads) on hosts; spotting new or unexpected executables is a high-value signal.

**MITRE:** T1204 (User Execution), T1059 (Execution)

---

## C. Suspicious Login Times / Anomalous Logons
**SPL**
index=botsv3 EventCode=4624
| eval hour=strftime(_time,"%H")
| stats count by Account_Name, hour
| where count > 3 AND (hour < 6 OR hour > 20)
| sort -count

**Explanation:** Identifies accounts that log in multiple times outside normal business hours. Compromised accounts are often used at odd hours.

**MITRE:** T1078 (Valid Accounts)

---

## D. Persistence via Scheduled Task / Service Creation
**SPL**
index=botsv3 (EventCode=4698 OR EventCode=7045)
| table _time, Account_Name, TaskName, ServiceName, host
| sort -_time

**Explanation:** Detects scheduled task or service creation — common persistence mechanism used by attackers to survive reboots or maintain access.

**MITRE:** T1053 (Scheduled Task/Job), T1050 (New Service)

---

## E. Suspicious Network Connections / External Beaconing
**SPL**
index=botsv3 sourcetype=*netflow* OR sourcetype=*firewall*
| stats count by src_ip, dest_ip, dest_port
| where count > 5
| sort -count

**Explanation:** High frequency outbound connections to the same external IP/port can indicate Command & Control (C2) or data exfiltration. Threshold set low (5) for demo/dataset sensitivity; tune in production.

**MITRE:** T1071 (Application Layer Protocol)
