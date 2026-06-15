# Assignment Compliance Review

**Project:** Larkspur Retail Group Endpoint Security Assessment  
**Module:** B9CY110 Communication and Network Security  
**Reviewer:** Codex static review of repository artefacts  
**Review date:** June 2026

## Executive Finding

The submission is technically strong and maps well to the assignment brief. The repository includes the required lab design, Windows and Linux endpoint telemetry configuration, Wazuh custom detections, benign simulation scripts, Dockerised AI summarisation, and allowlisted remediation actions.

Two gaps were found during review and corrected in the repository:

- The Linux active-response scripts were not copied onto the Linux endpoint during endpoint setup. `setup/linux-endpoint-setup.sh` now deploys `firewall-drop.sh` and `account-lock.sh`.
- The Wazuh manager setup previously installed only `wazuh-manager`, while the report and runbook require a dashboard/indexer SIEM experience. `setup/wazuh-manager-setup.sh` now uses the official Wazuh all-in-one installer.

One evidence gap remains because it cannot be completed from static files alone:

- Final dashboard screenshots and live command outputs must be captured from the running VMs after deployment. Appendix F now contains the exact screenshot/export checklist.

## Requirement Matrix

| Assignment Requirement | Repository Evidence | Status | Notes |
|---|---|---|---|
| Isolated lab network | `README.md`, `report/figures/lab-architecture.svg`, Section 4.1 | Complete | Host-only network `192.168.56.0/24` documented with no public inbound exposure. |
| Windows endpoint | `setup/windows-endpoint-setup.ps1`, `wazuh/ossec-windows-agent.conf` | Complete | Windows 10 endpoint with Security, Sysmon, and PowerShell logging. |
| Linux endpoint | `setup/linux-endpoint-setup.sh`, `wazuh/ossec-linux-agent.conf`, `wazuh/auditd.rules` | Complete | Ubuntu endpoint with auth.log, auditd, journald, FIM, and active response scripts. |
| SIEM choice | Wazuh configs and setup scripts | Complete | Wazuh Manager, Indexer, and Dashboard installed by updated manager setup script. |
| Automation layer | `docker-compose.yml`, `ai-stack/app.py`, `ai-stack/Dockerfile` | Complete | Dockerised Ollama + Streamlit AI dashboard. |
| Intentional weak baseline | README and report Section 4.2 | Complete | Weaknesses documented and scoped to private lab. |
| Topology, trust boundaries, IP plan | Report Sections 3.4 and 4.1; figures | Complete | New SVG diagrams make this clearer. |
| Time synchronisation | `setup/timesync-verify.sh`, report Section 4.5 | Complete | Includes UTC/NTP verification workflow. |
| Windows Security Event Log | `wazuh/ossec-windows-agent.conf` | Complete | Includes logon, process, scheduled task, account, and privilege events. |
| Windows process creation | Sysmon EID 1 and Security EID 4688 | Complete | Both sources configured. |
| Advanced Windows telemetry | Sysmon and PowerShell Operational log | Complete | Meets advanced source requirement. |
| Linux auth logs | `wazuh/ossec-linux-agent.conf` | Complete | `/var/log/auth.log` forwarded. |
| Linux process execution | `wazuh/auditd.rules` | Complete | `execve` syscall capture configured. |
| Advanced Linux telemetry | auditd | Complete | Meets advanced source requirement. |
| Normalised key fields | Report Sections 4.4 and 5.3 | Complete | Fields documented for host, user, command line, process, rule, and timestamp. |
| Evidence of delivery | Appendix F checklist | Needs live capture | Static repo cannot prove ingestion rate or agent status. Capture screenshots after running VMs. |
| At least 3 attacker techniques | `simulations/` scripts | Complete | SSH brute force, Linux persistence/sudo, Windows scheduled task, PowerShell. |
| At least 5 detections | `wazuh/local_rules.xml` | Complete | Six custom rules mapped to ATT&CK. |
| Triage workflow | Report Sections 5.3, 6.2, Appendix F | Mostly complete | Add live screenshots of Wazuh filters and pivots for final PDF. |
| Rationale and false positives | Report Section 6.3 | Complete | Each detection includes false-positive notes. |
| Dockerised AI component | `docker-compose.yml`, `ai-stack/app.py` | Complete | Read-only summarisation using local Ollama. |
| No unrestricted command execution | `docker-compose.yml`, `ai-stack/app.py` | Complete | No Docker socket, dropped capabilities, read-only dashboard filesystem, AI does not execute commands. |
| At least 2 remediation actions | Active-response scripts | Complete | Three actions: IP block, account lock, scheduled task removal. |
| Remediation verification | README and report Section 6.4 | Complete | Verification commands documented. Live screenshots still required. |
| Rollback/recovery | README and report Section 6.4 | Complete | IP auto-expiry, manual account unlock, task XML export. |
| Architecture overview | Report Section 5.1 and diagrams | Complete | Three new figures added. |
| Engineering decisions and trade-offs | Report Sections 7 and 8 | Complete | Discusses noise, automation risk, standards alignment, enterprise scaling. |
| End-to-end runbook | README and Appendix I | Complete | Video storyboard included. |
| Video deliverable | Appendix I | Needs recording | Repository includes storyboard, but the video must be recorded manually. |
| PDF report max 10 pages | `report/CA1-Report.md` | Needs formatting pass | Content is complete but likely too long if directly exported. Condense or use smaller margins/font before final PDF. |
| GitHub artefacts | Full repo contents | Ready locally | Remote push still needs GitHub token or browser-created repository. |

## Corrective Changes Made

### Active Response Wiring

- Updated `wazuh/ossec-manager.conf` so the `firewall-drop` command points to `firewall-drop.sh`.
- Added Wazuh authd configuration for agent enrolment on TCP 1515.
- Updated `setup/linux-endpoint-setup.sh` to install both Linux active-response scripts on the endpoint.

### SIEM Installation

- Updated `setup/wazuh-manager-setup.sh` to install Wazuh manager, indexer, and dashboard using the official all-in-one installer.
- Added registration password deployment to `/var/ossec/etc/authd.pass`.
- Restricted firewall rules to the host-only lab subnet.

### Docker AI Hardening

- Bound Ollama host access to `127.0.0.1` only.
- Added dropped Linux capabilities, `no-new-privileges`, memory limits, read-only dashboard filesystem, and tmpfs for runtime files.
- Removed the external Wazuh logo fetch from the Streamlit dashboard so it runs cleanly without internet access.

### Report and Diagrams

- Added three SVG diagrams under `report/figures/`.
- Added a live evidence checklist for Appendix F.
- Replaced report placeholders for student number, word count estimate, and GitHub URL.

## Final Evidence To Capture

Before submitting the final PDF/video, capture these from the running lab:

| Evidence | How to Capture |
|---|---|
| Agent status | Wazuh Dashboard > Agents showing both endpoints Active |
| Windows events | Wazuh Discover filter for `agent.name:windows-endpoint` and rules `100600`, `100700`, `100900` |
| Linux events | Wazuh Discover filter for `agent.name:linux-endpoint` and rules `105760`, `100010`, `100011` |
| Authentication dashboard | Saved view for SSH brute force and Linux account changes |
| Process dashboard | Saved view for Sysmon EID 1 and Windows EID 4688 |
| Active response audit | `tail -50 /var/ossec/logs/active-responses.log` |
| Firewall verification | `sudo iptables -L INPUT -n --line-numbers` |
| Account lock verification | `sudo passwd -S backdooruser` |
| Task deletion verification | `schtasks /query /tn keylog` |
| AI summary | Streamlit dashboard with one selected alert and generated summary |

## Submission Readiness Rating

**Static repository readiness:** 90-95%  
**Final submission readiness after live screenshots/video:** 100% if all evidence is captured successfully.

The remaining work is not code or documentation design; it is execution evidence from the actual lab. That evidence is required by the assignment and should not be replaced with simulated screenshots.
