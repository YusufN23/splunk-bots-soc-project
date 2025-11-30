# Splunk BOTS v3 SOC Lab — Mini SOC Project
**Author:** Yusuf Nazeer
**Date:** 11-30-2025
**Purpose:** Demonstrate Tier-1 SOC detection & triage using Splunk Enterprise and the BOTS v3 dataset. Includes SPL queries, dashboards, alerts, an incident report, and a Tier-1 playbook, mapped to MITRE ATT&CK.

## What I built
1. Ingested BOTS v3 dataset into Splunk (index: `botsv3`).  
2. Developed prioritized SPL detections for:
   - A: New admin / privilege escalation (T1078 / T1134)
   - B: Scheduled task / service creation (T1053 / T1050)
   - C: Anomalous login times (T1078)
   - D: Executable creation (T1204 / T1059)
3. Built a 4-panel SOC dashboard for rapid triage.  
4. Created real-time/scheduled alerts and a playbook for Tier-1 response.  
5. Investigated triggered alerts and produced an incident report with IOCs and remediation steps.

## How to reproduce
1. Install Splunk Enterprise and log into Splunk Web (`http://localhost:8000`).  
2. Download BOTS v3 from GitHub and add data to Splunk (`Settings → Add Data`) into index `botsv3`.  
3. Run queries in `queries/splunk_queries.md`, create dashboard panels per `dashboards/dashboard overview.md`, and create alerts per `alerts/alert definition.md`.  

## Files
- `queries/splunk_queries.md` — SPL queries & MITRE mapping  
- `dashboards/dashboard overview.md` — dashboard panels + instructions  
- `alerts/alert definition.md` — alert SPL and settings  
- `incident report.md` — incident report template to fill with captured evidence  
- `playbooks/bruteforceplaybooks.md` — Tier-1 playbook  
- `screenshots/` — annotated screenshots gathered

## Contact
Yusuf Nazeer — LINKEDIN: linkedin.com/in/yusuf-nazeer-960bb1242
