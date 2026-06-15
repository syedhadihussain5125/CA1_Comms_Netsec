"""
log_activity.py  —  BENIGN Persistence Payload
Larkspur Retail Group  |  Student: Syed Hadi Hussain  |  CA1

PURPOSE:
  This is the benign "malware" payload referenced in the Windows
  scheduled task simulation (sim-windows-task.ps1).

  It ONLY writes the current username and timestamp to a local file.
  No network access, no credential dumping, no exfiltration.

  In the real attacker scenario it simulates, the payload would be
  a keylogger or data collection script — but for this lab we use
  a completely harmless write-to-file operation to generate the
  scheduled task persistence signal without any real risk.

ATT&CK context:  T1053.005 (Scheduled Task — Persistence)
"""

import os
import datetime

LOG_PATH = r"C:\Temp\activity.log"

def log_activity():
    now  = datetime.datetime.now().isoformat()
    user = os.getenv("USERNAME", "unknown")
    entry = f"{now}  user={user}  host={os.environ.get('COMPUTERNAME', 'unknown')}\n"

    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(entry)

if __name__ == "__main__":
    log_activity()
