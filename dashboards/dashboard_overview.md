# Dashboard: SOC Monitoring — 4 panels (A→D)

## SOC-Monitoring-MITRE Dashboard

## Panel 1 — New Admin Events (A)
- Query:
  index=botsv3 (EventCode=4720 OR EventCode=4728 OR EventCode=4732)
  | table _time, Account_Name, Target_Account, Group_Name, host
  | sort -_time
- Visualization:
<img width="1904" height="588" alt="admin_events" src="https://github.com/user-attachments/assets/95735028-53bd-43a0-a62a-59789af68462" />
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
- Purpose: highlight logins at odd hours.

## Panel 4 — Executable Creation (D)
- Query D:
index=botsv3 EventCode=4663 Object_Type="File" Object_Name="*.exe"
| table _time, Account_Name, Object_Name, Object_Path, host
| sort -_time
- Visualization:
<img width="1895" height="937" alt="exe_creation_results" src="https://github.com/user-attachments/assets/74f35244-cd71-4400-a716-c4bcd87890c0" />
- Purpose: identify droppers or malware.

## Instructions to create dashboard in Splunk:
1. Apps → Search & Reporting → Dashboards → Create New Dashboard
2. Name: `SOC-Monitoring-MITRE`, permissions: shared/read
3. Add new panel → paste the panel query → choose visualization → Save Panel.
4. Repeat for all 4 panels.
5. Save full dashboard → take a full-screen screenshot named `screenshots/12_dashboard_full.png`
6. For each panel screenshot, crop the panel and save as:
   - `screenshots/13_panel_admins.png`
   - `screenshots/14_panel_tasks.png`
   - `screenshots/15_panel_logons.png`
   - `screenshots/16_panel_network.png`

