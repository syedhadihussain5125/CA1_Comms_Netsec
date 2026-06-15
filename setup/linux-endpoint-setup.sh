#!/bin/bash
# =============================================================================
# linux-endpoint-setup.sh  —  Linux Endpoint Configuration
# Larkspur Retail Group  |  Student: Syed Hadi Hussain  |  CA1
# Target OS: Ubuntu 22.04 LTS  |  IP: 192.168.56.30  |  RAM: 4 GB
#
# Intentionally weak configurations (documented, controlled):
#   - Password authentication enabled on SSH (supports brute-force sim)
#   - Weak labuser password (for demo only)
#   - No AppArmor enforcement (baseline visibility test)
#   - Permissive sudoers (to demonstrate escalation detection)
#
# Telemetry configured:
#   - auditd with larkspur.rules
#   - Wazuh agent (connects to manager at 192.168.56.10)
#   - NTP time sync
# =============================================================================

set -euo pipefail
LOGFILE="/var/log/larkspur-endpoint-setup.log"
exec > >(tee -a "$LOGFILE") 2>&1

WAZUH_MANAGER="192.168.56.10"
WAZUH_REG_PASS="AgentRegPass@Lab1"

log() { echo "[$(date '+%Y-%m-%dT%H:%M:%S')] $*"; }

log "=== Larkspur Linux Endpoint Setup — CA1 ==="

# ---- 1. Hostname + NTP ------------------------------------------------------
log "--- Step 1: Hostname and NTP ---"
hostnamectl set-hostname linux-endpoint
timedatectl set-timezone UTC
apt-get update -qq
apt-get install -y -qq ntp ntpdate curl wget auditd audispd-plugins

systemctl enable ntp && systemctl start ntp
ntpdate -u pool.ntp.org || true
log "Time sync: $(date)"

# ---- 2. Intentionally weak configurations (DOCUMENTED) ---------------------
log "--- Step 2: Intentional weaknesses (controlled lab) ---"

# Enable SSH password authentication (needed for brute-force simulation)
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/'  /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/'                 /etc/ssh/sshd_config
systemctl restart sshd
log "WEAK: SSH password auth enabled (required for brute-force simulation)"

# Create a lab user with a simple password (intentionally weak for demo)
if ! id "labuser" &>/dev/null; then
    useradd -m -s /bin/bash labuser
fi
echo "labuser:Lab@Password1" | chpasswd
log "WEAK: labuser account created with simple demo password"

# Permissive sudoers for labuser (to generate sudo events)
echo "labuser ALL=(ALL) PASSWD: ALL" > /etc/sudoers.d/labuser
chmod 440 /etc/sudoers.d/labuser
log "WEAK: labuser added to sudoers (generates sudo events for detection)"

# ---- 3. Auditd configuration ------------------------------------------------
log "--- Step 3: auditd telemetry ---"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ -f "$REPO_DIR/wazuh/auditd.rules" ]; then
    cp "$REPO_DIR/wazuh/auditd.rules" /etc/audit/rules.d/larkspur.rules
    augenrules --load
    systemctl restart auditd
    log "auditd rules deployed and loaded."
else
    log "WARNING: auditd.rules not found at $REPO_DIR/wazuh/auditd.rules"
fi

# Verify auditd is collecting events
auditctl -l | head -20
log "auditd status: $(systemctl is-active auditd)"

# ---- 4. Install Wazuh Agent -------------------------------------------------
log "--- Step 4: Installing Wazuh Agent ---"
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
    gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list

apt-get update -qq
WAZUH_AGENT_VERSION=4.8.0 apt-get install -y wazuh-agent

# ---- 5. Configure Wazuh Agent -----------------------------------------------
log "--- Step 5: Configuring Wazuh Agent ---"
if [ -f "$REPO_DIR/wazuh/ossec-linux-agent.conf" ]; then
    cp "$REPO_DIR/wazuh/ossec-linux-agent.conf" /var/ossec/etc/ossec.conf
    log "Linux agent ossec.conf deployed."
fi

# Register agent with manager
WAZUH_MANAGER_IP="$WAZUH_MANAGER" \
WAZUH_AGENT_NAME="linux-endpoint" \
WAZUH_REGISTRATION_PASSWORD="$WAZUH_REG_PASS" \
    /var/ossec/bin/agent-auth -m "$WAZUH_MANAGER" \
    -A "linux-endpoint" \
    -P "$WAZUH_REG_PASS" || true

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl start wazuh-agent
sleep 5
systemctl status wazuh-agent --no-pager

log "Agent status: $(grep 'status' /var/ossec/var/run/ossec-agentd.state 2>/dev/null || echo 'check manually')"

# ---- 6. Deploy Linux active response scripts -------------------------------
log "--- Step 6: Deploying Linux active response scripts ---"
AR_BIN="/var/ossec/active-response/bin"

if [ -f "$REPO_DIR/wazuh/active-response/firewall-drop.sh" ]; then
    cp "$REPO_DIR/wazuh/active-response/firewall-drop.sh" "$AR_BIN/firewall-drop.sh"
fi

if [ -f "$REPO_DIR/wazuh/active-response/account-lock.sh" ]; then
    cp "$REPO_DIR/wazuh/active-response/account-lock.sh" "$AR_BIN/account-lock.sh"
fi

chown root:wazuh "$AR_BIN/firewall-drop.sh" "$AR_BIN/account-lock.sh"
chmod 750 "$AR_BIN/firewall-drop.sh" "$AR_BIN/account-lock.sh"
log "Linux active response scripts deployed."

# ---- 7. Firewall (UFW) -------------------------------------------------------
log "--- Step 7: UFW Firewall ---"
ufw allow 22/tcp comment "SSH"
ufw allow from 192.168.56.10 to any port 1514 proto tcp comment "Wazuh manager"
ufw --force enable

# ---- Summary ----------------------------------------------------------------
log ""
log "=== Linux Endpoint Setup Complete ==="
log "Agent should appear in Wazuh manager within ~60 seconds."
log "Verify: ssh root@$WAZUH_MANAGER '/var/ossec/bin/wazuh-control list-agents'"
log ""
log "VULNERABILITY SUMMARY (intentional weaknesses for lab):"
log "  - SSH password auth enabled  (needed for T1110 simulation)"
log "  - labuser weak password      (Lab@Password1)"
log "  - labuser in sudoers         (needed for T1548.003 simulation)"
log ""
log "TELEMETRY SOURCES:"
log "  - /var/log/auth.log          (SSH, sudo, PAM events)"
log "  - /var/log/audit/audit.log   (auditd: execve, user mgmt, sudoers)"
log "  - journald                   (process and system events)"
log "ACTIVE RESPONSE:"
log "  - firewall-drop.sh           (temporary IP block for rule 105760)"
log "  - account-lock.sh            (locks backdoor account for rule 100011)"
