
# Alert: Suspicious Power / Executable / Admin Activities (Examples)

## Alert 1 — New Admin Added (High)
**SPL:** (A)
index=botsv3 (EventCode=4720 OR EventCode=4728 OR EventCode=4732)
| table _time, Account_Name, Target_Account, Group_Name, host
 
**Trigger:** Scheduled search every 5 minutes (or real-time if you have resources)  
**Condition:** number of results > 0  
**Severity:** High  
**Actions:** Send email to SOC (or log to index=alerts), create a ticket, include fields: _time, Account_Name, Target_Account, Group_Name, host  
**Notes:** Escalate immediately to L2 if Target_Account is a privileged account.

---

## Alert 2 — New Scheduled Task / Service (High)
**SPL:** (B)
index=botsv3 (EventCode=4698 OR EventCode=7045)
| table _time, Account_Name, TaskName, ServiceName, host
 
**Trigger:** real-time / scheduled every 5 minutes  
**Condition:** number of results > 0  
**Severity:** High  
**Actions:** Notify SOC, collect host timeline.

---

## Alert 3 — Executable Creation (Medium)
**SPL:** (D)
index=botsv3 EventCode=4663 Object_Type="File" Object_Name="*.exe"
| table _time, Account_Name, Object_Name, Object_Path, host
 
**Trigger:** scheduled 5 minutes  
**Condition:** number of results > 0  
**Severity:** Medium  
**Actions:** Log alert, screenshot evidence, check parent process.

---
