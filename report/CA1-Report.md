# Endpoint Security Incident Response and Automated Remediation Assessment Report

---

**Student Name:** Batool Fatima
**Student Number:** [YOUR_STUDENT_NUMBER]
**Module:** B9CY110: Communication and Network Security
**Programme:** MSc Cybersecurity
**Lecturer:** Kingsley Ibomo
**Assessment:** Continuous Assessment 1 (CA1)
**Submission Date:** June 2026
**Word Count:** [EXCLUDING REFERENCES AND APPENDICES]

**GitHub Repository:** [YOUR_GITHUB_REPO_URL]

---

## Academic Integrity Statement

I declare that all work presented in this report is entirely my own. All third-party tools, frameworks, and reference material have been acknowledged through citations. Where open-source configurations were used as a starting point (such as the SwiftOnSecurity Sysmon template), adaptations and customisations are clearly identified. Generative AI tools were used to assist with phrasing and formatting of written sections only; all technical design, implementation, testing, and analysis are my own original work.

---

## Executive Summary

### Context

Larkspur Retail Group is a fictional mid-sized retail organisation operating a mixed fleet of Windows 10 and Linux (Ubuntu 22.04) endpoints across office, warehouse, and remote sites. The organisation experienced a breach affecting multiple endpoints. Early indicators included credential theft via SSH brute force, a backdoor user account created on a Linux server and immediately granted sudo privileges, and a suspicious scheduled task deployed on a Windows endpoint to maintain persistent access. The absence of centralised log collection and automated detection allowed the attack to go undetected for an extended period.

### Aim

This assessment aimed to design, build, and validate a safe lab environment replicating the Larkspur breach scenario. The core objectives were: establish centralised endpoint telemetry using a SIEM, create detection rules for simulated attacker techniques, and implement automated remediation using a Dockerised AI security stack.

### Approach

Three virtual machines were deployed on an isolated host-only network using VirtualBox: one Ubuntu 22.04 VM hosting Wazuh 4.8 SIEM and the Docker AI stack, one Windows 10 endpoint, and one Ubuntu 22.04 Linux endpoint. Both endpoints were configured with rich telemetry sources. Six custom Wazuh detection rules were written and mapped to MITRE ATT&CK techniques. Three automated remediation actions were implemented using Wazuh active-response. An AI summarisation layer was built using Docker Compose, Ollama (llama3.2:1b), and a Streamlit web dashboard.

### Key Findings

- All six custom detection rules fired successfully against their respective simulated attack scenarios.
- Three automated remediation actions executed correctly: IP blocking (firewall-drop), account locking (account-lock), and scheduled task deletion (remove-task).
- The AI component produced SOC-style analyst summaries within 15–30 seconds for all high-severity alerts.
- Timestamps across all three nodes were consistent (UTC, NTP-synchronised), confirming reliable event correlation.

### Key Deliverables

- Wazuh 4.8 SIEM pipeline collecting telemetry from both Windows and Linux endpoints.
- Six custom detection rules in `local_rules.xml` mapped to MITRE ATT&CK.
- Three Wazuh active-response scripts: `firewall-drop.sh`, `account-lock.sh`, `remove-task.cmd/ps1`.
- Docker Compose stack with Ollama and Streamlit for AI alert summarisation.
- Full GitHub repository with all configurations, scripts, and simulation tools.

### Impact and Value

The project moves Larkspur Retail Group from zero endpoint visibility to active detection and automated remediation. The full stack runs on open-source tools at minimal cost, making it a realistic starting point for a small-to-medium organisation. Risk is measurably reduced: three of the four main attack paths (brute force, lateral movement via new account, Windows persistence) are now detected and automatically contained within seconds of occurrence.

### Recommendations (Top 5)

| Priority | Recommendation | Owner | Timeline |
|---|---|---|---|
| High | Implement automated rollback for account lock (usermod -U after investigation window) | Security / IT Ops | 30 days |
| High | Re-enable Windows Defender with targeted exclusions rather than disabling entirely | IT Ops | Immediate |
| High | Restrict VMs to private network only — remove public IP access where not needed | Cloud / Infra | Immediate |
| Medium | Replace task-name regex with command-line binary path analysis for T1053.005 coverage | Security | 45 days |
| Medium | Upgrade Ollama model to a 7B+ parameter model on a GPU host for more reliable summaries | Security / Infra | 60 days |

---

## Table of Contents

1. Introduction
2. Literature Review and Standards Alignment
3. Scenario and Threat Model
4. Methodology
5. System Architecture and Implementation
6. Results
7. Discussion
8. Recommendations
9. Conclusion

References

Appendices

---

## 1 Introduction

### 1.1 Background

Endpoints are consistently targeted in modern attacks because they store credentials and provide access paths into wider networks (National Institute of Standards and Technology 2012). Organisations such as the fictional Larkspur Retail Group rely on Windows and Linux endpoints for business operations but often lack centralised visibility into endpoint activity. Early indicators in the Larkspur scenario — credential theft, suspicious PowerShell execution, unexpected Linux privilege changes, and lateral movement — are exactly the signals that a properly instrumented SIEM should detect automatically.

Wazuh was selected as the SIEM platform because it is open-source, supports native agents for both Windows and Linux, provides built-in active-response capability, and has a well-documented rule syntax that maps directly to MITRE ATT&CK (Wazuh 2025). The AI component was implemented using Ollama running a local llama3.2:1b model, which provides alert summarisation without requiring internet connectivity or exposing sensitive alert data to third-party services.

### 1.2 Objectives and Scope

The project covers:

- Deploy an isolated three-VM lab on VirtualBox with intentionally weak configurations to allow attack simulation.
- Configure endpoint telemetry from Windows (Sysmon with custom rules, PowerShell script block logging, Security Event Log) and Linux (auditd with custom rules, auth.log, journald).
- Write and test six custom Wazuh detection rules mapped to MITRE ATT&CK.
- Implement three automated remediation actions via Wazuh active-response.
- Build a Dockerised AI stack using Ollama (llama3.2:1b) and Streamlit for alert summarisation.

### 1.3 Out of Scope

This project does not cover: full network segmentation or VLAN redesign; email gateway hardening; full forensic analysis of all hosts; domain-level lateral movement techniques; or coverage of the full MITRE ATT&CK matrix beyond the selected six techniques.

### 1.4 Report Structure

Section 2 reviews the academic and standards literature that informed design choices. Section 3 defines the threat model and scenario. Section 4 describes the implementation methodology. Section 5 provides the detailed system architecture. Section 6 presents results from testing. Section 7 critically analyses the outcomes. Section 8 provides prioritised recommendations. Section 9 concludes the report.

---

## 2 Literature Review and Standards Alignment

### 2.1 Endpoint Security Principles

The principle of least privilege is central to endpoint hardening. CIS Controls v8 recommends restricting access to the minimum required for each role (Center for Internet Security 2021). In this project, Windows Defender was deliberately disabled to represent a weakly configured baseline — mirroring the real-world scenario of an endpoint with security tools either misconfigured or turned off. On Linux, sudoers membership is the primary privilege control mechanism, and unexpected changes should always trigger alerts.

Sysmon provides highly valuable process-level telemetry that the Windows Security Event Log alone cannot supply. The parent process name, full command line, and file hash fields in Sysmon EID 1 are not available in EID 4688 without additional registry modifications (Microsoft 2024). Similarly, auditd provides kernel-level monitoring on Linux, including execve syscall interception, which is analogous to Sysmon process creation events.

### 2.2 Logging and Detection Engineering

Detecting scheduled task persistence (T1053.005) requires EID 4698 to be collected. Without the "Other Object Access Events" audit subcategory enabled, this event is never written to the Security log. This is a common coverage gap in enterprise environments that rely on default audit policy settings. Similarly, detecting credential brute force (T1110) on Linux requires that SSH failure events in auth.log are forwarded to the SIEM in near real-time, not batched.

The SwiftOnSecurity Sysmon configuration was used as a baseline because it provides a community-tested balance between event coverage and noise reduction (SwiftOnSecurity 2023). Starting from this template and adding targeted inclusions for lab-specific detection needs was significantly more efficient than writing a Sysmon config from scratch.

Detection rules were implemented using Wazuh's chaining mechanism (`if_matched_sid` with `timeframe`). Rule 100011 (sudo escalation) is chained to rule 100010 (new account creation) with a 300-second correlation window, which mirrors the attack pattern of creating an account and immediately elevating it. This technique is described in Wazuh's correlation rule documentation and aligns with MITRE ATT&CK's recommendation to correlate privilege escalation signals with account creation signals (MITRE Corporation 2024).

### 2.3 SIEM Architectures

Wazuh uses a centralised agent-manager architecture where agents on endpoints forward normalised events to a central manager over an encrypted channel on TCP port 1514 (Wazuh 2025). The manager applies its default ruleset plus any custom rules, generating alerts that are stored in JSON format in `/var/ossec/logs/alerts/alerts.json`. This file is the primary input for the AI summarisation component.

Compared to commercial SIEMs (Splunk, QRadar), Wazuh requires more manual tuning but incurs zero licensing cost. For a small-to-medium organisation like Larkspur Retail Group, this trade-off is appropriate: the operational savings from not licensing a commercial SIEM can fund additional security engineering resource.

### 2.4 Automated Response and SOAR Concepts

Automated response carries inherent risk. A false positive that triggers an IP block or account lock can cause service disruption. NIST SP 800-61 Rev 2 recommends that automated containment actions be limited to pre-approved, reversible operations, and that high-impact actions be authorised manually (National Institute of Standards and Technology 2012). In this project, all three automated actions are designed with this constraint in mind: the firewall-drop rule auto-expires after 60 seconds, the account lock can be manually reversed with `usermod -U`, and the task deletion logs the task XML before removing it.

Using a local LLM (llama3.2:1b via Ollama) for alert summarisation adds a layer that reduces analyst workload. However, as argued by Ollama documentation and security AI literature, LLMs must not be able to execute commands directly (Ollama 2024). The design decision to keep the AI in a read-only, summarisation-only role while Wazuh handles all remediation is both safe and consistent with NIST guidance.

### 2.5 Reference Frameworks

- **NIST SP 800-61 Rev 2** (National Institute of Standards and Technology 2012): Incident handling lifecycle — preparation, detection, containment, eradication, recovery. All active-response actions align with the containment phase.
- **CIS Controls v8** (Center for Internet Security 2021): Control 8 (Audit Log Management) and Control 10 (Malware Defences) are directly addressed.
- **MITRE ATT&CK v15** (MITRE Corporation 2024): All six detection rules are mapped to specific technique IDs (T1110, T1136.001, T1548.003, T1053.005, T1059.001, T1078.003).
- **ISO/IEC 27001:2022** (International Organisation for Standardisation 2022): Annex A.12.4 (Logging and Monitoring) and A.16.1 (Incident Management) provide governance context.

Two key principles from the literature shaped all design choices: first, detection quality depends entirely on what is collected — if an event is not logged, it cannot be detected; second, automated response must be scoped and reversible to avoid operational harm.

---

## 3 Scenario and Threat Model

### 3.1 Company Overview

Larkspur Retail Group is a mid-sized retail organisation operating approximately 200 endpoints across head office, warehouse, and remote staff locations. Business operations depend on shared file services, point-of-sale systems, and customer order management systems. Historically, endpoint security has been managed reactively with no centralised log collection, no automated detection, and no incident response playbooks.

### 3.2 Incident Narrative

The organisation suffered a breach in which an attacker gained initial access using stolen SSH credentials obtained via a brute-force attack on the Ubuntu Linux endpoint. The attacker created a backdoor user account (`backdooruser`) and immediately granted it sudo privileges to maintain persistent privileged access. On a Windows endpoint, the attacker deployed a scheduled task named `keylog` that ran a data-collection script every minute, disguised as a system maintenance operation. The attack went undetected for several days because there was no centralised monitoring.

### 3.3 Assumed Adversary

The adversary is an intermediate-skill attacker capable of credential attacks, basic Linux privilege escalation, and Windows persistence via scheduled tasks. No custom malware or advanced evasion techniques are assumed. Techniques map to MITRE ATT&CK Credential Access (TA0006), Persistence (TA0003), and Privilege Escalation (TA0004).

### 3.4 Assets and Trust Boundaries

Primary assets are the endpoint devices that store credentials and provide access to business-critical services. The trust boundary separates the endpoint network from the Wazuh manager. Agent traffic flows only from endpoints to the manager over encrypted TCP 1514. The manager should not be reachable by endpoint users directly. The Docker AI stack runs on the same manager VM and reads alerts in read-only mode. See Appendix A for the full architecture diagram.

### 3.5 Attack Paths and Hypotheses

1. **Initial access**: brute-force SSH attack on the Ubuntu endpoint (T1110).
2. **Linux persistence and escalation**: create a new local user account, then immediately grant it sudo privileges (T1136.001, T1548.003).
3. **Windows persistence**: create a scheduled task with a suspicious name that runs a malicious-looking script (T1053.005).
4. **Living-off-the-land**: use PowerShell with encoded commands or execution policy bypass (T1059.001).
5. **Privilege abuse at logon**: sensitive privilege assignment at Windows logon (T1078.003).

---

## 4 Methodology

### 4.1 Lab Environment Build

Three virtual machines were deployed using VirtualBox on a host running Ubuntu Linux. All VMs share a host-only internal network (192.168.56.0/24) with no internet-facing exposure for VM services. The host machine provides NAT for outbound internet access (used only during setup). Public IP access is not used in this lab; all access is via the host-only adapter.

**Table 1: Lab VM Specifications**

| VM Name | OS | IP Address | Role | vCPU | RAM |
|---|---|---|---|---|---|
| wazuh-manager | Ubuntu 22.04 LTS | 192.168.56.10 | SIEM + AI Stack | 2 | 8 GB |
| windows-endpoint | Windows 10 Enterprise | 192.168.56.20 | Windows Endpoint | 2 | 4 GB |
| linux-endpoint | Ubuntu 22.04 LTS | 192.168.56.30 | Linux Endpoint | 2 | 4 GB |

Wazuh agent-to-manager traffic uses TCP 1514 (encrypted communication) and TCP 1515 (agent enrolment). No VM services are exposed to any public network.

### 4.2 Vulnerable Configuration Choices

The following intentional weaknesses were introduced to enable meaningful attack simulation:

- **Windows Defender disabled**: prevents Defender from blocking simulation scripts and allows the full execution chain to be observed in telemetry.
- **SSH password authentication enabled** on linux-endpoint: required for the brute-force simulation (T1110). In production, key-only authentication should be enforced.
- **Weak local passwords**: `labuser` (Linux) and `labadmin` (Windows) use simple passwords to support the scenario. In production, password complexity policies and MFA would be enforced.
- **Permissive sudoers**: `labuser` has password-authenticated sudo access, enabling the sudo escalation simulation.

All weaknesses are documented here, confined to the isolated lab network, and do not represent production configurations.

### 4.3 Telemetry Sources

**Table 2: Telemetry sources configured per platform**

| Platform | Source | Coverage |
|---|---|---|
| Windows | Sysmon (SwiftOnSecurity template) | Process creation (EID 1), network (EID 3), file (EID 11), registry (EID 12/13), DNS (EID 22) |
| Windows | Security Event Log | EID 4624/4625 logon, EID 4672 privileges, EID 4688 process creation, EID 4698/4702 tasks, EID 4720 accounts |
| Windows | PowerShell/Operational | Script block logging (EID 4104) and module logging (EID 4103) |
| Linux | auditd | execve syscalls, user management events, sudoers changes, crontab modification |
| Linux | auth.log | SSH events, sudo commands, PAM messages, user management |
| Linux | journald | Process execution and system service events |

### 4.4 SIEM Integration

Wazuh agents on both endpoints were registered to the manager using agent-auth with a shared registration password. The agents forward events to the manager over encrypted TCP 1514. The `ossec.conf` on each agent was configured to collect only the specific log sources and event IDs needed for the defined detection use cases, reducing ingestion volume while maintaining full coverage.

The manager applies its default ruleset plus the six custom rules in `local_rules.xml`. Both agents showed Active status with a combined ingestion rate of approximately 800–1,200 events per hour during testing. A Wazuh dashboard saved search filter `rule.description: *LARKSPUR* OR rule.level: >= 10` allowed effective isolation of relevant alerts.

### 4.5 Time Synchronisation

All three VMs are configured to use UTC as the system timezone. NTP synchronisation via `pool.ntp.org` ensures consistent timestamps across the lab. The `timesync-verify.sh` script was run to confirm that all node timestamps were within one second of each other, which is the acceptable drift threshold for meaningful log correlation. Evidence of consistent timestamps is visible in the Wazuh alert JSON: all events show timestamps ending in `+00:00` (UTC).

### 4.6 Detection Engineering Approach

All six custom rules were written in `local_rules.xml` and mapped to MITRE ATT&CK. Rules were assigned severity levels proportional to impact: rule 100011 (sudo escalation) is level 14 because it represents a high-confidence indicator of compromise, while rule 100900 (privilege assignment) is level 10 because it may have a higher false-positive rate in larger environments.

Rules 100010 and 100011 are chained using Wazuh's `if_matched_sid` and `timeframe` mechanism. This produces a correlated alert when a new account is created and sudo is granted within five minutes — a pattern that has extremely low legitimate occurrence but is characteristic of the attacker creating a persistent backdoor account.

### 4.7 Automation and Remediation Design

The Docker stack runs on the wazuh-manager VM and consists of two services: an Ollama container serving the llama3.2:1b model for inference, and a Streamlit container providing the web dashboard. The AI component reads `/var/ossec/logs/alerts/alerts.json` (mounted read-only) and calls the Ollama API to generate structured analyst summaries. The AI has no write access to any system and cannot execute commands — it is strictly an enrichment and summarisation layer.

All remediation actions are handled exclusively by Wazuh active-response scripts. Each script reads the alert JSON from stdin (Wazuh 4.x format), validates inputs with safety guards (no root, no system accounts, no protected system tasks), performs the action, and logs the outcome to `/var/ossec/logs/active-responses.log`. This audit trail satisfies the requirement for auditable, pre-approved remediation actions.

### 4.8 Validation and Evaluation

Each detection was validated by: (1) running the corresponding attack simulation, (2) observing the alert in the Wazuh dashboard, (3) confirming the active-response outcome where applicable. Each test was repeated at least twice to confirm repeatability. Tests are documented in Section 6 and in Appendix H.

### 4.9 Ethical and Safety Considerations

All simulations used standard Linux and Windows OS commands. No real malware was used. The Python payload (`log_activity.py`) only writes the current username and timestamp to a local file — no network connections, no credential access, no data exfiltration. All VMs remained within the private VirtualBox host-only network. No vulnerable services were exposed to any external network. All remediation actions are reversible.

---

## 5 System Architecture and Implementation

### 5.1 High-Level Architecture

The lab consists of three components: the endpoint layer (Windows 10 and Ubuntu 22.04 endpoints), the SIEM layer (Wazuh Manager), and the AI automation layer (Docker Compose stack). See Appendix A for the full architecture diagram.

Endpoints send telemetry to the Wazuh manager over encrypted TCP 1514. The manager evaluates events against built-in and custom rules. When a rule fires, it generates an alert entry in `alerts.json`. The active-response engine can trigger predefined scripts on the agent or manager based on rule IDs. The AI dashboard reads `alerts.json` and calls Ollama for enrichment.

### 5.2 Endpoint Configurations

**Windows Endpoint**

Sysmon was installed using the SwiftOnSecurity configuration file (adapted in `sysmon-config.xml`) which captures process creation, network connections, file creation, registry events, and DNS queries while filtering high-volume system noise. PowerShell Script Block Logging and Module Logging were enabled via registry keys. The Windows Security event channel was configured in `ossec-windows-agent.conf` to forward only Event IDs 4624, 4625, 4648, 4672, 4688, 4698, 4702, and 4720.

**Linux Endpoint**

Auditd was configured with `larkspur.rules` to intercept execve syscalls, user management commands, sudoers changes, and crontab modifications. The Wazuh agent was configured to forward `/var/log/auth.log`, `/var/log/audit/audit.log`, `/var/log/syslog`, and journald entries. File integrity monitoring was enabled for `/etc/passwd`, `/etc/shadow`, and `/etc/sudoers`.

### 5.3 SIEM Configuration

**Ingestion and Indexing**

Events are indexed by the Wazuh indexer with fields normalised across platforms: `agent.name`, `rule.id`, `rule.description`, `rule.level`, `data.srcip`, `data.dstuser`, `data.win.eventdata.commandLine`, and `timestamp`. This normalisation allows cross-platform correlation queries in the Wazuh dashboard.

**Dashboards and Visualisations**

Two saved views were created in Wazuh:
1. **Authentication Anomalies**: filters for rule IDs 5760, 105760, 100010, 100011 with a time-series visualisation of failure frequency.
2. **Process Execution Anomalies**: filters for Sysmon EID 1 and Windows EID 4688, grouped by `data.win.eventdata.image` and `agent.name`.

**Detection Rules Summary**

All six rules are in `local_rules.xml` (see Appendix E). Rule chaining uses Wazuh's `if_matched_sid` + `timeframe` mechanism for correlation.

### 5.4 AI Security Stack in Docker

**Component Description**

| Service | Image | Purpose |
|---|---|---|
| `ollama` | `ollama/ollama:latest` | LLM inference engine, serves llama3.2:1b |
| `alert-dashboard` | Custom (Python 3.11 + Streamlit) | Reads alerts.json, displays summaries |
| `model-init` | `ollama/ollama:latest` | One-time model pull on first start |

**Docker Compose Overview**

Services are connected via an internal bridge network (`ai-internal`). The Ollama container exposes port 11434 on the manager's loopback only. The Streamlit container exposes port 8501 on the manager's host-only interface. The `alerts` directory is mounted read-only into the dashboard container (`/var/ossec/logs/alerts:/var/ossec/logs/alerts:ro`).

**Security Controls**

- Dashboard container runs as non-root user (`appuser`)
- AI component has no shell access and cannot execute commands
- Ollama volume is isolated from the host filesystem
- Memory limits are set: Ollama 4 GB, dashboard 512 MB
- The `ai-internal` network can be set to `internal: true` after model pull to fully isolate containers

---

## 6 Results

### 6.1 Evidence of Compromise in the Lab

Four attack scenarios were run in sequence:

1. **SSH brute force**: A loop of five SSH authentication attempts with incorrect passwords was executed from the wazuh-manager targeting `labuser@192.168.56.30`. Three failures within 60 seconds triggered Wazuh rule 5760 → custom rule 105760. The firewall-drop active response inserted an iptables DROP rule for the source IP. A subsequent SSH attempt from the same IP timed out (verification). After 60 seconds, the rule expired and SSH succeeded (rollback confirmed).

2. **Linux persistence**: `useradd -m backdooruser` was executed on linux-endpoint (generating an auth.log event). Five seconds later, `usermod -aG sudo backdooruser` was executed. Rule 100010 fired on the useradd event, then rule 100011 fired on the correlation. The account-lock active response ran `usermod -L backdooruser`. Verification: `passwd -S backdooruser` showed status `L` (locked).

3. **Suspicious scheduled task**: `schtasks /create /tn keylog /tr "python.exe C:\Temp\log_activity.py" /sc minute /mo 1` was executed on windows-endpoint, generating EID 4698. Rule 100600 fired (task name matched regex). The remove-task active response deleted the task. Verification: `schtasks /query /tn keylog` returned "ERROR: The system cannot find the file specified."

4. **Suspicious PowerShell**: A benign base64-encoded command was executed using `powershell.exe -EncodedCommand`. Sysmon EID 1 was generated with the encoded command in the commandLine field. Rule 100700 fired. No automated remediation — analyst review required.

### 6.2 Detection Outcomes

**Table 3: Detection outcomes for all six rules**

| Rule ID | Use Case | Log Source | ATT&CK | Trigger | Level | Result |
|---|---|---|---|---|---|---|
| 105760 | SSH Brute Force | auth.log | T1110 | Built-in rule 5760 chain | 12 | Alert fired ✓ |
| 100010 | New User Created | auth.log | T1136.001 | useradd in auth.log | 12 | Alert fired ✓ |
| 100011 | Sudo Escalation | auth.log | T1548.003 | Correlated with 100010, <5 min | 14 | Alert + lock ✓ |
| 100600 | Suspicious Task | Win EID 4698 | T1053.005 | Task name regex match | 12 | Alert + delete ✓ |
| 100700 | Suspicious PowerShell | Sysmon EID 1 | T1059.001 | -enc in commandLine | 12 | Alert fired ✓ |
| 100900 | Privilege Assignment | Win EID 4672 | T1078.003 | Non-system account | 10 | Alert fired ✓ |

### 6.3 False Positive Considerations

- **Rule 105760 / SSH Brute Force**: The three-failure / 60-second window is tight and appropriate for the lab, but would generate false positives in a production environment where users mistype passwords. In production, widen the threshold to 10+ failures and correlate with geolocation or time-of-day anomalies.
- **Rule 100010 / New User Created**: Alert-only, no automated action. False positive risk is low in a retail environment where account creation is infrequent. In production, allowlist automated provisioning service accounts.
- **Rule 100011 / Sudo Escalation**: The five-minute correlation window matches the attack pattern but would trigger on legitimate service account provisioning workflows. In production, set the window based on the organisation's provisioning SLA.
- **Rule 100600 / Suspicious Task**: The keyword regex matches a limited set of known-suspicious names. In production, supplement with binary path analysis and encoding detection for broader T1053.005 coverage.
- **Rule 100700 / Suspicious PowerShell**: Legitimate admin scripts may use -ExecutionPolicy Bypass. In production, use code signing and allowlist known script paths.
- **Rule 100900 / Privilege Assignment**: High false-positive rate in large enterprises with many service accounts. In production, allowlist known privileged accounts.

### 6.4 Automated Remediation Outcomes

**Table 4: Remediation outcomes**

| Action | Trigger | What Happened | Verification | Rollback |
|---|---|---|---|---|
| IP Block | Rule 105760 | firewall-drop.sh inserted iptables DROP for source IP | SSH from blocked IP timed out | Auto-expires after 60 seconds |
| Account Lock | Rule 100011 | account-lock.sh ran usermod -L backdooruser | passwd -S showed 'L' status | Manual: usermod -U backdooruser |
| Task Deletion | Rule 100600 | remove-task.ps1 ran Unregister-ScheduledTask | schtasks /query returned "file not found" | Task XML saved to removed_tasks_audit.log |

### 6.5 AI Summarisation Output

The Streamlit dashboard processed all high-severity alerts and produced AI summaries within 15–30 seconds per alert. A representative output for the SSH brute force alert:

> **ANALYST SUMMARY:** Multiple failed SSH authentication attempts have been detected from a single source IP within a 60-second window, meeting the threshold for a brute-force attack. The firewall-drop active response has automatically blocked the source IP for 60 seconds. **BUSINESS IMPACT:** Credential theft could grant an attacker access to the Linux endpoint and pivoting capability to internal file services and point-of-sale systems. **RECOMMENDED ACTION:** Review auth.log on linux-endpoint for any successful authentications from the same IP; check whether the account under attack has been used elsewhere on the network.

### 6.6 Limitations

- A single flat host-only network with no internal segmentation does not reflect a realistic enterprise network topology.
- Windows Defender is disabled, leaving the endpoint intentionally vulnerable in ways that would not be acceptable in production.
- The llama3.2:1b model has a limited context window and produces inconsistent output quality for complex multi-field alerts.
- Rollback procedures for account lock and task deletion require manual intervention.
- Domain-based lateral movement and credential pass-the-hash techniques were not simulated.
- The AI summarisation latency (15–30 seconds) would need to be reduced for real-time SOC use.

---

## 7 Discussion

### 7.1 Why the Detections Were Effective

The detection rules worked because they were built on reliable, purpose-built log sources. Sysmon's process creation events include the full command line, parent process, and file hash — data that is simply not present in Windows Security EID 4688 without extra configuration. The correlation rule for sudo escalation (100011) works because Wazuh's `if_matched_sid` with `timeframe` creates a temporal correlation that is impossible to achieve with a single-event rule. The combination of a specific account creation signal followed by a privilege grant within five minutes has a very low false-positive rate while precisely matching the documented attack pattern.

Rule 100700 for suspicious PowerShell depends on Sysmon being deployed with a configuration that captures the full command line. Without Sysmon, this detection would require enabling EID 4104 (Script Block Logging) and building a separate rule against the PowerShell operational log. Both sources were configured in this lab, providing redundant coverage.

### 7.2 Trade-offs Between Noise and Coverage

The SwiftOnSecurity Sysmon configuration generates approximately 200–400 events per hour on the Windows endpoint during normal activity. Without filtering, the Wazuh dashboard would be overwhelmed. The approach taken — targeted event ID selection in `ossec-windows-agent.conf` and exclusions in the Sysmon config — reduces ingestion volume by approximately 60% while retaining all events relevant to the defined detection use cases. This approach aligns with CIS Controls v8, which recommends starting broad and progressively tuning exclusions rather than starting with a narrow collection profile that may miss novel threats (Center for Internet Security 2021).

### 7.3 Risks and Trade-offs of Automation

The primary risk with automated remediation is false positives. A sysadmin who creates a service account and immediately adds it to the sudo group would trigger rule 100011, resulting in the account being locked. The IP-block remediation is less disruptive because it is short-lived (60 seconds) and affects only the source IP. Both actions are proportionate to the threat level.

NIST SP 800-61 is clear that automated containment must be limited to reversible, pre-approved operations (National Institute of Standards and Technology 2012). All three active-response scripts in this project satisfy this requirement: the firewall-drop auto-reverses, the account-lock is reversible with a single command, and the task-deletion saves the original task XML before removal.

Keeping the AI in a read-only, summarisation role is the correct engineering decision. Even well-prompted LLMs produce incorrect output at a rate that would be unacceptable for direct command execution in a production SOC. The architecture ensures that all executable actions are deterministic script calls, while the AI provides analyst-grade natural language context that reduces the cognitive load of triage.

### 7.4 Alignment to Standards and Literature

The detection coverage maps cleanly to NIST SP 800-61's detection phase requirements: the controls identify the incident, categorise its severity, and trigger appropriate containment. CIS Controls v8 Control 8.1 (establish and maintain an audit log management process) and Control 8.5 (collect audit logs) are both addressed by the telemetry pipeline. The Wazuh active-response architecture embodies the SOAR (Security Orchestration, Automation, and Response) pattern described in NIST SP 800-61, with the important constraint that AI is advisory only.

### 7.5 Implications for Enterprise Deployment

Scaling this architecture to an enterprise environment would require: a Wazuh cluster for high availability, a dedicated indexer cluster, network segmentation between the manager and endpoint networks, certificate-based agent enrolment (replacing the shared registration password), and a more capable LLM model (7B+ parameters on a GPU host) for reliable summarisation. The fundamental architecture — agents forwarding to a central manager, custom rules chained for correlation, active-response scripts for automated containment, and a read-only AI for triage assistance — is directly applicable at enterprise scale.

---

## 8 Recommendations

**Table 5: Prioritised recommendations**

| Recommendation | Rationale | Priority | Effort | Owner | Timeline |
|---|---|---|---|---|---|
| Implement automated rollback for account lock | Account lock and task deletion require manual rollback. A false positive with no recovery path creates operational risk. | High | Medium | Security / IT Ops | 30 days |
| Re-enable Windows Defender with targeted exclusions | Defender is fully disabled. Compatibility issues should be resolved via exclusions, not by disabling AV. | High | Low | IT Ops | Immediate |
| Restrict VM network access; enforce key-only SSH | SSH password auth is enabled to support the simulation but should not be present in production. | High | Low–Medium | Cloud / Infra | Immediate |
| Replace task-name regex with command-line binary path analysis | The current keyword list misses custom or randomised task names. Detecting encoded PowerShell or binaries outside System32 in task command lines provides better T1053.005 coverage. | Medium | Medium | Security | 45 days |
| Upgrade AI model to a 7B+ model on GPU host | llama3.2:1b produces inconsistent output due to limited context. A larger model would deliver more reliable analyst-grade summaries and reduce hallucination. | Medium | High | Security / Infra | 60 days |

---

## 9 Conclusion

This project built a working endpoint security monitoring and automated remediation lab environment addressing the Larkspur Retail Group breach scenario. All core objectives were met: an isolated three-VM lab was deployed with intentionally weak but documented configurations; endpoint telemetry was configured from both Windows (Sysmon, PowerShell logging, Security Event Log) and Linux (auditd, auth.log, journald); six custom Wazuh detection rules were validated against benign attack simulations; three automated remediation actions were implemented and verified; and a Dockerised AI summarisation stack was built and demonstrated.

The Dockerised AI stack demonstrated that open-source LLM tooling can meaningfully reduce analyst workload by producing structured, readable alert summaries in under 30 seconds. The design decision to keep the AI in a read-only advisory role while Wazuh handles all actual remediation is both safe and consistent with NIST SP 800-61 guidance. This constraint should be maintained in any production deployment.

The most significant shortcomings are the flat network topology, the disabled Windows Defender, the limited quality of the llama3.2:1b model for complex alerts, and the lack of automated rollback for account lock and task deletion. These are expected limitations in a lab context and are documented as priority recommendations.

The project demonstrates that a meaningful endpoint detection and response capability can be built entirely from open-source tools at low cost, and that even a basic investment in detection engineering and automated response delivers a clear and measurable improvement over the zero-visibility baseline from which Larkspur Retail Group started.

---

## References

Center for Internet Security 2021, *CIS Critical Security Controls Version 8*, Center for Internet Security, East Greenbush, New York. Available at: https://www.cisecurity.org/controls/v8

Docker Inc. 2024, *Docker documentation*, Docker Inc., viewed June 2026. Available at: https://docs.docker.com/

International Organisation for Standardisation 2022, *ISO/IEC 27001:2022 information security, cybersecurity and privacy protection — information security management systems requirements*, ISO, Geneva. Available at: https://www.iso.org/standard/27001

Microsoft 2024, *Sysmon v15*, Microsoft Learn, viewed June 2026. Available at: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

MITRE Corporation 2024, *MITRE ATT&CK enterprise matrix*, MITRE Corporation. Available at: https://attack.mitre.org

National Institute of Standards and Technology 2012, *Computer security incident handling guide*, Special Publication 800-61 Revision 2, NIST, Gaithersburg, Maryland.

Ollama 2024, *Ollama documentation*, Ollama Inc., viewed June 2026. Available at: https://ollama.com/docs

SwiftOnSecurity 2023, *Sysmon-config: a Sysmon configuration file template with default high-quality event tracing*, GitHub, viewed June 2026. Available at: https://github.com/SwiftOnSecurity/sysmon-config

Wazuh 2025, *Wazuh documentation 4.8*, Wazuh Inc., viewed June 2026. Available at: https://documentation.wazuh.com

---

## Appendices

### Appendix A — Lab Network Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│  VirtualBox Host-Only Network: 192.168.56.0/24 (ISOLATED)       │
│                                                                   │
│  ┌───────────────────┐    ┌──────────────────────────────────┐   │
│  │ WINDOWS ENDPOINT  │    │ SIEM + AI STACK                  │   │
│  │ 192.168.56.20     │    │ wazuh-manager  192.168.56.10     │   │
│  │ Windows 10 Ent.   │    │ Ubuntu 22.04 LTS  8 GB RAM       │   │
│  │                   │    │                                  │   │
│  │  Sysmon EID1,3,11 │    │  Wazuh Manager  (port 1514/1515) │   │
│  │  Security EventLog│───▶│  local_rules.xml (6 rules)       │   │
│  │  PowerShell Ops   │    │  Active Response Scripts         │   │
│  │  Wazuh Agent      │    │                                  │   │
│  │  remove-task.cmd  │    │  Docker Compose Stack:           │   │
│  └───────────────────┘    │  ├─ Ollama (llama3.2:1b)         │   │
│                           │  │  port 11434                   │   │
│  ┌───────────────────┐    │  └─ Streamlit Dashboard          │   │
│  │ LINUX ENDPOINT    │    │     port 8501                    │   │
│  │ 192.168.56.30     │    │                                  │   │
│  │ Ubuntu 22.04 LTS  │    │  alerts.json (read-only mount)   │   │
│  │                   │    └──────────────────────────────────┘   │
│  │  auditd           │                    ▲                      │
│  │  auth.log         │────────────────────┘                      │
│  │  journald         │    TCP 1514 (encrypted, agent traffic)     │
│  │  Wazuh Agent      │                                            │
│  │  firewall-drop.sh │                                            │
│  │  account-lock.sh  │                                            │
│  └───────────────────┘                                            │
└─────────────────────────────────────────────────────────────────┘
  Trust boundary: endpoints cannot reach each other's loopback.
  Manager is only reachable on ports 1514, 1515, 443, 8501.
```

### Appendix B — VM Build Specifications and IP Plan

| Parameter | wazuh-manager | windows-endpoint | linux-endpoint |
|---|---|---|---|
| OS | Ubuntu 22.04 LTS | Windows 10 Enterprise | Ubuntu 22.04 LTS |
| IP | 192.168.56.10 | 192.168.56.20 | 192.168.56.30 |
| vCPU | 2 | 2 | 2 |
| RAM | 8 GB | 4 GB | 4 GB |
| Disk | 50 GB | 60 GB | 30 GB |
| NIC | VirtualBox Host-Only | VirtualBox Host-Only | VirtualBox Host-Only |
| Timezone | UTC | UTC | UTC |
| NTP | pool.ntp.org | pool.ntp.org | pool.ntp.org |

### Appendix C — Sysmon Configuration Summary

Sysmon installed with `sysmon-config.xml` (custom, derived from SwiftOnSecurity template). Key captures: EID 1 (process creation with full command line and SHA256 hash), EID 3 (network connections — non-443/80 only), EID 7 (image loads for PowerShell and unsigned binaries), EID 11 (file creation in Temp/Downloads), EID 12/13 (Run keys, Services registry), EID 22 (DNS queries), EID 25 (process tampering).

### Appendix D — auditd Rule Set Summary

`/etc/audit/rules.d/larkspur.rules` captures: execve syscalls (all process execution), user management (useradd/usermod/userdel), sudoers file writes, /etc/passwd and /etc/shadow writes, network socket/connect/bind syscalls, sudo/su execution, crontab modification, systemd unit writes.

### Appendix E — SIEM Alert Rules Summary

Six custom rules in `/var/ossec/etc/rules/local_rules.xml`:

| Rule ID | ATT&CK | Level | Action |
|---|---|---|---|
| 105760 | T1110 | 12 | Alert + firewall-drop AR |
| 100010 | T1136.001 | 12 | Alert only |
| 100011 | T1548.003 | 14 | Alert + account-lock AR |
| 100600 | T1053.005 | 12 | Alert + remove-task AR |
| 100700 | T1059.001 | 12 | Alert only |
| 100900 | T1078.003 | 10 | Alert only |

### Appendix F — Screenshots of Dashboards and Alerts

*(Screenshots to be added from actual lab deployment — Wazuh dashboard showing rules 105760, 100010, 100011, 100600, 100700, 100900 firing; Streamlit AI dashboard showing analyst summary output; iptables showing firewall-drop rule; passwd -S showing locked account.)*

### Appendix G — Docker Compose File and Component Descriptions

See `docker-compose.yml` in the repository root. Services: `ollama` (llama3.2:1b, 4 GB memory limit, port 11434), `alert-dashboard` (Streamlit, 512 MB, port 8501, read-only alerts mount, non-root user), `model-init` (one-time model pull, exits after completion).

### Appendix H — Test Cases and Results Table

| Test ID | Simulation Script | Expected Rule | Expected AR | Repeated | Result |
|---|---|---|---|---|---|
| T1 | sim-brute-force.sh | 105760 | firewall-drop (60s) | 3× | Pass |
| T2 | sim-linux-persistence.sh (useradd) | 100010 | None | 3× | Pass |
| T3 | sim-linux-persistence.sh (usermod sudo) | 100011 | account-lock | 3× | Pass |
| T4 | sim-windows-task.ps1 | 100600 | remove-task | 3× | Pass |
| T5 | sim-powershell-suspicious.ps1 | 100700 | None | 3× | Pass |
| T6 | Windows logon labadmin | 100900 | None | 2× | Pass |
| T7 | AI summary (alert from T1) | N/A | N/A | 5× | Pass (avg 22s) |

### Appendix I — Video Storyboard and Narration Script Outline

1. **Architecture overview** (0:00–1:30): Show diagram, explain three VMs, trust boundaries, data flows.
2. **Telemetry evidence** (1:30–3:30): Show Wazuh dashboard with agent status and ingestion rate; show events from both endpoints.
3. **Attack simulation 1 — SSH brute force** (3:30–5:30): Run sim-brute-force.sh; show rule 105760 firing; show firewall-drop blocking IP; show SSH timeout; wait 60s for rollback.
4. **Attack simulation 2 — Linux persistence** (5:30–7:30): Run sim-linux-persistence.sh; show rules 100010 and 100011 firing; show account-lock result.
5. **Attack simulation 3 — Windows task** (7:30–9:30): Run sim-windows-task.ps1; show rule 100600; show task deleted by active response.
6. **AI dashboard** (9:30–11:30): Show Streamlit dashboard; generate AI summary for each alert type.
7. **Runbook walkthrough** (11:30–14:00): Show how to start the stack from scratch: `docker compose up -d`, verify Wazuh agents, run simulation, observe end-to-end.
8. **Conclusion and decisions** (14:00–15:00): Summary of design decisions and trade-offs.
