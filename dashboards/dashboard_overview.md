# Dashboard: SOC Monitoring — 4 panels (A→D)

## SOC-Monitoring-MITRE

## Panel 1 — New Admin Events (A)
- Query:
  index=botsv3 (EventCode=4720 OR EventCode=4728 OR EventCode=4732)
  | table _time, Account_Name, Target_Account, Group_Name, host
  | sort -_time
- Visualization:
<img width="1904" height="588" alt="admin_events" src="https://github.com/user-attachments/assets/95735028-53bd-43a0-a62a-59789af68462" />
- Dashboard:
<img width="1889" height="822" alt="admin_events_dashboard" src="https://github.com/user-attachments/assets/da69a8e3-3416-4135-a98e-4836faeaad05" />
- Purpose: show recent admin creation / group adds.

## Panel 2 — Scheduled Task / Service Creation (B)
- Query:
  index=botsv3 (EventCode=4698 OR EventCode=7045)
  | table _time, Account_Name, TaskName, ServiceName, host
  | sort -_time
- Visualization:
<img width="1898" height="446" alt="task_service_events" src="https://github.com/user-attachments/assets/bcf2fb73-1720-4324-af45-8419b2c02747" />
- Purpose: detect persistence.

## Panel 3 — Suspicious Login Times (C)
- Query:
  index=botsv3 EventCode=4624
  | eval hour=strftime(_time,"%H")
  | stats count by Account_Name, hour
  | where count > 3 AND (hour < 6 OR hour > 20)
  | sort -count
- Visualization:
<img width="1905" height="154" alt="image" src="https://github.com/user-attachments/assets/00dbc4a5-e457-4541-9b3d-62eebd492643" />
- Dashboard:
<img width="1873" height="372" alt="suspicious_logins_dashboard" src="https://github.com/user-attachments/assets/30650409-2e10-4087-95b8-bf5b7ef8613a" />
- Purpose: highlight logins at odd hours.

## Panel 4 — Executable Creation (D)
- Query D:
index=botsv3 EventCode=4663 Object_Type="File" Object_Name="*.exe"
| table _time, Account_Name, Object_Name, Object_Path, host
| sort -_time
- Visualization:
<img width="1895" height="937" alt="exe_creation_results" src="https://github.com/user-attachments/assets/74f35244-cd71-4400-a716-c4bcd87890c0" />
- Dashboard:
<img width="1872" height="535" alt="executable_creation_dashboard" src="https://github.com/user-attachments/assets/0282538e-754b-429c-9834-f2de0c1e39f5" />
- Purpose: identify droppers or malware.
