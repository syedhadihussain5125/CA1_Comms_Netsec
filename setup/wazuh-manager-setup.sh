#!/bin/bash
# =============================================================================
# wazuh-manager-setup.sh  —  Wazuh Manager + Docker AI Stack Setup
# Larkspur Retail Group  |  Student: Syed Hadi Hussain  |  CA1
# Target OS: Ubuntu 22.04 LTS  |  IP: 192.168.56.10  |  RAM: 8 GB
#
# This script:
#   1. Sets hostname and NTP time sync
#   2. Installs Wazuh all-in-one components via official installer
#   3. Deploys local_rules.xml and ossec.conf
#   4. Deploys active response scripts
#   5. Installs Docker + Docker Compose
#   6. Starts the AI security stack
# =============================================================================

set -euo pipefail
LOGFILE="/var/log/larkspur-setup.log"
exec > >(tee -a "$LOGFILE") 2>&1

log() { echo "[$(date '+%Y-%m-%dT%H:%M:%S')] $*"; }

log "=== Larkspur Retail Group — Wazuh Manager Setup ==="
log "Student: Syed Hadi Hussain  |  CA1  |  B9CY110"

# ---- 1. Prerequisites -------------------------------------------------------
log "--- Step 1: System update and hostname ---"
hostnamectl set-hostname wazuh-manager
apt-get update -qq
apt-get install -y -qq curl wget gnupg apt-transport-https lsb-release \
    iptables ntp ntpdate python3 python3-pip docker.io docker-compose-plugin

# ---- 2. NTP Time Synchronisation -------------------------------------------
log "--- Step 2: NTP time synchronisation ---"
timedatectl set-timezone UTC
systemctl enable ntp
systemctl start ntp
sleep 3
timedatectl status
ntpq -p
log "Time sync configured. All VMs should use UTC to ensure consistent timestamps."

# ---- 3. Install Wazuh all-in-one SIEM --------------------------------------
log "--- Step 3: Installing Wazuh all-in-one SIEM ---"
WAZUH_INSTALLER="/tmp/wazuh-install.sh"

if systemctl list-unit-files | grep -q '^wazuh-dashboard.service'; then
    log "Wazuh dashboard already installed; skipping all-in-one installer."
else
    curl -sSL https://packages.wazuh.com/4.8/wazuh-install.sh -o "$WAZUH_INSTALLER"
    bash "$WAZUH_INSTALLER" -a
    log "Wazuh manager, indexer, and dashboard installed."
fi

# ---- 4. Deploy Wazuh configuration -----------------------------------------
log "--- Step 4: Deploying Wazuh configuration ---"
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ -f "$REPO_DIR/wazuh/ossec-manager.conf" ]; then
    cp "$REPO_DIR/wazuh/ossec-manager.conf" /var/ossec/etc/ossec.conf
    log "ossec.conf deployed."
fi

if [ -f "$REPO_DIR/wazuh/local_rules.xml" ]; then
    cp "$REPO_DIR/wazuh/local_rules.xml" /var/ossec/etc/rules/local_rules.xml
    chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
    chmod 640 /var/ossec/etc/rules/local_rules.xml
    log "local_rules.xml deployed."
fi

echo "AgentRegPass@Lab1" > /var/ossec/etc/authd.pass
chown root:wazuh /var/ossec/etc/authd.pass
chmod 640 /var/ossec/etc/authd.pass
log "Agent registration password deployed to /var/ossec/etc/authd.pass."

# ---- 5. Deploy active response scripts -------------------------------------
log "--- Step 5: Deploying active response scripts ---"
AR_BIN="/var/ossec/active-response/bin"

if [ -f "$REPO_DIR/wazuh/active-response/firewall-drop.sh" ]; then
    cp "$REPO_DIR/wazuh/active-response/firewall-drop.sh" "$AR_BIN/firewall-drop.sh"
fi

if [ -f "$REPO_DIR/wazuh/active-response/account-lock.sh" ]; then
    cp "$REPO_DIR/wazuh/active-response/account-lock.sh" "$AR_BIN/account-lock.sh"
fi

# Set correct ownership and permissions for all AR scripts
chown root:wazuh "$AR_BIN/firewall-drop.sh" "$AR_BIN/account-lock.sh"
chmod 750 "$AR_BIN/firewall-drop.sh" "$AR_BIN/account-lock.sh"
log "Active response scripts deployed."

# ---- 6. Validate Wazuh configuration and start service --------------------
log "--- Step 6: Validate config and start Wazuh ---"
/var/ossec/bin/wazuh-control configtest
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager
sleep 5
systemctl status wazuh-manager --no-pager
log "Wazuh Manager started."

# Increase JWT session to 8h (avoid dashboard re-logins during demo)
sed -i 's/"sessions_time": 900/"sessions_time": 28800/' \
    /etc/wazuh-indexer/opensearch.yml 2>/dev/null || true

# ---- 7. Install Docker and start AI stack ----------------------------------
log "--- Step 7: Docker AI Stack ---"
systemctl enable docker
systemctl start docker

# Add current user to docker group
usermod -aG docker "$SUDO_USER" 2>/dev/null || true

cd "$REPO_DIR"
docker compose pull
docker compose up -d
sleep 15
docker compose ps
log "Docker AI stack started. Dashboard at http://192.168.56.10:8501"

# Pull Ollama model
log "Pulling Ollama model (llama3.2:1b)..."
docker exec larkspur-ollama ollama pull llama3.2:1b || true

# ---- 8. Open firewall ports ------------------------------------------------
log "--- Step 8: Firewall (UFW) ---"
ufw allow from 192.168.56.0/24 to any port 1514 proto tcp comment "Wazuh agent communication"
ufw allow from 192.168.56.0/24 to any port 1515 proto tcp comment "Wazuh agent enrollment"
ufw allow from 192.168.56.0/24 to any port 443 proto tcp comment "Wazuh Dashboard"
ufw allow from 192.168.56.0/24 to any port 8501 proto tcp comment "Streamlit AI Dashboard"
ufw --force enable

# ---- Summary ----------------------------------------------------------------
log ""
log "=== Setup Complete ==="
log "Wazuh Dashboard: https://192.168.56.10"
log "Wazuh credentials are printed by the installer and stored in ./wazuh-install-files.tar."
log "AI Dashboard:   http://192.168.56.10:8501"
log "Log file:       $LOGFILE"
log ""
log "Next steps:"
log "  1. Register Windows endpoint:  ./setup/windows-endpoint-setup.ps1"
log "  2. Register Linux endpoint:    ./setup/linux-endpoint-setup.sh"
log "  3. Verify time sync:           ./setup/timesync-verify.sh"
log "  4. Run simulations:            ./simulations/*.sh"
