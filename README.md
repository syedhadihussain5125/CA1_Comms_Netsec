# Larkspur Retail Group — Endpoint Security Lab (CA1)
**Module:** B9CY110 Communication and Network Security  
**Programme:** MSc Cybersecurity — Dublin Business School  
**Student:** Batool Fatima  
**Assessment:** CA1 — Endpoint Security Incident Response and Automated Remediation

---

## Quick Start (Full Demo Runbook)

### Prerequisites

- VirtualBox (or any hypervisor)
- Three VMs on a host-only network (192.168.56.0/24):

| VM | OS | IP |
|---|---|---|
| wazuh-manager | Ubuntu 22.04 LTS | 192.168.56.10 |
| windows-endpoint | Windows 10 Enterprise | 192.168.56.20 |
| linux-endpoint | Ubuntu 22.04 LTS | 192.168.56.30 |

### Step 1: Set up the Wazuh Manager

```bash
# On wazuh-manager (192.168.56.10)
git clone <your-repo-url> CA1
cd CA1
sudo bash setup/wazuh-manager-setup.sh
```

After ~5 minutes:
- Wazuh dashboard: https://192.168.56.10 (admin / SecureWazuh@Lab1)
- AI dashboard: http://192.168.56.10:8501

### Step 2: Set up the Linux Endpoint

```bash
# On linux-endpoint (192.168.56.30)
git clone <your-repo-url> CA1
cd CA1
sudo bash setup/linux-endpoint-setup.sh
```

### Step 3: Set up the Windows Endpoint

```powershell
# On windows-endpoint (192.168.56.20) — Run as Administrator
git clone <your-repo-url> CA1
cd CA1
.\setup\windows-endpoint-setup.ps1
```

### Step 4: Verify Time Synchronisation

```bash
# On wazuh-manager
bash setup/timesync-verify.sh
```

### Step 5: Verify Agent Status

In Wazuh dashboard: **Agents** → Both agents should show **Active**.

Or via CLI:
```bash
/var/ossec/bin/wazuh-control list-agents
```

### Step 6: Start the Docker AI Stack

```bash
# On wazuh-manager
cd CA1
docker compose up -d
docker compose logs -f   # watch for model pull completion
```

Open: http://192.168.56.10:8501

---

## Running Attack Simulations

### Simulation 1 — SSH Brute Force (T1110)

**Expected:** Rule 105760 fires → firewall-drop blocks source IP 60 seconds

```bash
# From wazuh-manager or any host on the lab network
bash simulations/sim-brute-force.sh 192.168.56.30 labuser 5
```

**Verify:**
```bash
# On linux-endpoint
iptables -L INPUT -n --line-numbers   # should show DROP rule
# After 60s: rule removed automatically
```

**Wazuh filter:** `rule.id:105760`

---

### Simulation 2 — Linux Persistence (T1136.001 + T1548.003)

**Expected:** Rule 100010 fires (new user) → Rule 100011 fires (sudo) → account-lock

```bash
# On linux-endpoint (run as root)
sudo bash simulations/sim-linux-persistence.sh
```

**Verify:**
```bash
sudo passwd -S backdooruser   # should show 'L' (locked)
```

**Wazuh filter:** `rule.id:(100010 OR 100011)`

---

### Simulation 3 — Suspicious Windows Scheduled Task (T1053.005)

**Expected:** Rule 100600 fires → remove-task deletes the task

```powershell
# On windows-endpoint (Run as Administrator)
.\simulations\sim-windows-task.ps1
```

**Verify:**
```powershell
schtasks /query /tn keylog   # should return "system cannot find file"
```

**Wazuh filter:** `rule.id:100600`

---

### Simulation 4 — Suspicious PowerShell (T1059.001)

**Expected:** Rule 100700 fires (Sysmon EID 1 with -EncodedCommand)

```powershell
# On windows-endpoint
.\simulations\sim-powershell-suspicious.ps1
```

**Wazuh filter:** `rule.id:100700`

---

## Repository Structure

```
CA1/
├── README.md                    ← This file (runbook)
├── docker-compose.yml           ← AI stack (Ollama + Streamlit)
│
├── ai-stack/
│   ├── Dockerfile               ← Streamlit app container
│   ├── app.py                   ← Dashboard with AI summarisation
│   └── requirements.txt
│
├── wazuh/
│   ├── local_rules.xml          ← 6 custom detection rules
│   ├── ossec-manager.conf       ← Manager config with active response
│   ├── ossec-linux-agent.conf   ← Linux agent telemetry config
│   ├── ossec-windows-agent.conf ← Windows agent telemetry config
│   ├── auditd.rules             ← Linux auditd rules
│   ├── sysmon-config.xml        ← Windows Sysmon configuration
│   └── active-response/
│       ├── firewall-drop.sh     ← Block attacker IP (60s)
│       ├── account-lock.sh      ← Lock backdoor account
│       ├── remove-task.cmd      ← CMD wrapper for Windows AR
│       └── remove-task.ps1      ← Delete suspicious scheduled task
│
├── simulations/
│   ├── sim-brute-force.sh       ← SSH brute force (T1110)
│   ├── sim-linux-persistence.sh ← useradd + sudo escalation (T1136/T1548)
│   ├── sim-windows-task.ps1     ← Suspicious scheduled task (T1053)
│   ├── sim-powershell-suspicious.ps1 ← Encoded PowerShell (T1059)
│   └── log_activity.py          ← Benign task payload
│
├── setup/
│   ├── wazuh-manager-setup.sh   ← Full manager + Docker install
│   ├── linux-endpoint-setup.sh  ← Linux endpoint setup
│   ├── windows-endpoint-setup.ps1 ← Windows endpoint setup
│   └── timesync-verify.sh       ← NTP verification script
│
└── report/
    └── CA1-Report.md            ← Full academic report
```

---

## Detection Rules Summary

| Rule ID | Use Case | ATT&CK | Active Response |
|---|---|---|---|
| 105760 | SSH Brute Force | T1110 | firewall-drop (60s) |
| 100010 | New Linux User Created | T1136.001 | None (alert + chain) |
| 100011 | Sudo Privilege Escalation | T1548.003 | account-lock |
| 100600 | Suspicious Scheduled Task | T1053.005 | remove-task |
| 100700 | Suspicious PowerShell | T1059.001 | None (alert only) |
| 100900 | Sensitive Privilege Assignment | T1078.003 | None (alert only) |

---

## Automated Remediation Summary

| Action | Trigger Rule | Reversal |
|---|---|---|
| IP Block (iptables DROP) | 105760 | Auto-expires after 60 seconds |
| Account Lock (usermod -L) | 100011 | Manual: `sudo usermod -U <username>` |
| Task Deletion (Unregister-ScheduledTask) | 100600 | Manual: recreate task; XML in `C:\Temp\removed_tasks_audit.log` |

---

## Intentional Weaknesses (Documented)

| Weakness | VM | Why (for lab) |
|---|---|---|
| SSH password auth enabled | linux-endpoint | Required for brute-force simulation |
| labuser weak password | linux-endpoint | Enables credential attack demo |
| Windows Defender disabled | windows-endpoint | Prevents simulation interference |
| labadmin local admin account | windows-endpoint | Generates EID 4672 for detection |

**All weaknesses are confined to the isolated host-only network (192.168.56.0/24) and documented explicitly.**

---

## Ethical and Safety Notes

- No real malware is used at any point
- All simulation scripts use standard OS commands only
- The Python payload (`log_activity.py`) writes only username/timestamp to a local file
- No services are exposed to public networks
- All automated remediation actions are reversible
- The AI component is strictly read-only — it cannot execute commands
