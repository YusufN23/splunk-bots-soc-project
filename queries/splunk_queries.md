A. Failed login brute-force (EventCode=4625)

index=botsv3 EventCode=4625
| stats count by Account_Name, src_ip, host
| sort -count
| head 50

Explanation: finds accounts with many failed logins and top source IPs.



B. Successful login after multiple failures (detects credential stuffing or compromised account)

index=botsv3 (EventCode=4624 OR EventCode=4625)
| transaction Account_Name maxspan=10m
| search EventCode=4624
| where mvcount(EventCode=4625) > 5
| table _time, Account_Name, src_ip, host, EventCode

Explanation: transaction collects related events within timeframe; we flag accounts that had >5 failures then a success.



C. New local admin / privilege creation (EventCode=4728/4720/4732 depending)

index=botsv3 (EventCode=4720 OR EventCode=4728 OR EventCode=4732)
| table _time, Account_Name, Target_Account, Group_Name, host
| sort -_time

Explanation: reveals admin account creations or group adds — a common persistence/escalation sign.



D. Suspicious PowerShell / commandline usage (process spawn)

index=botsv3 sourcetype=WinEventLog:Security EventCode=4688
CommandLine="*powershell*" OR CommandLine="*Invoke-Expression*" OR CommandLine="*b64*"
| table _time, Account_Name, CommandLine, host, src_ip
| sort -_time

Explanation: Command line abuse often indicates attacker execution.



E. External C2 beaconing (network logs if present)

index=botsv3 sourcetype="*netflow*" OR sourcetype="*firewall*"
| stats count by dest_ip, dest_port, src_ip
| where count > 50
| sort -count

Explanation: high volume to an external IP/port could be beaconing.
