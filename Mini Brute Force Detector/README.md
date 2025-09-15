I built a lightweight Python tool that detects brute-force login attempts by analyzing system logs. The script checks for three or more failed logins within sixty seconds (MITRE ATT&CK T1110: Brute Force).

On Linux, it parses /var/log/auth.log for Failed password entries.

On Windows, it parses Security Event ID 4625 (failed logon), exported to CSV using PowerShell.

Alerts are printed to the console and also written to alerts.txt.

To test functionality, I:

Created a sample Linux log with three failed SSH logins, which triggered an alert.

Built a fake Windows 4625 CSV and confirmed the script detected repeated failed logons.