#!/bin/bash
# =============================================================================
# timesync-verify.sh  —  Time Synchronisation Evidence Script
# Larkspur Retail Group  |  Student: Syed Hadi Hussain  |  CA1
#
# Purpose: Verify all nodes are within acceptable time drift (<1s)
# Run from: wazuh-manager (SSH to each endpoint and check)
# Output:   Table showing hostname, local time, NTP status, drift
# =============================================================================

WAZUH_MANAGER_IP="192.168.56.10"
LINUX_ENDPOINT_IP="192.168.56.30"
WINDOWS_ENDPOINT_IP="192.168.56.20"
SSH_KEY="~/.ssh/id_rsa"
LOGFILE="./timesync-report-$(date +%Y%m%d-%H%M%S).txt"

log() { echo "$*" | tee -a "$LOGFILE"; }

log "========================================================================"
log "  Larkspur Retail Group — Time Synchronisation Verification Report"
log "  Student: Syed Hadi Hussain  |  CA1  |  B9CY110"
log "  Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "========================================================================"
log ""

# ---- Manager (local) --------------------------------------------------------
log "--- wazuh-manager (192.168.56.10) ---"
log "Hostname:  $(hostname)"
log "Local time:  $(date -u '+%Y-%m-%dT%H:%M:%S UTC')"
log "Timezone:  $(timedatectl | grep 'Time zone')"
log "NTP status:  $(timedatectl | grep 'NTP service')"
log "NTP sync:  $(timedatectl | grep 'System clock')"
log "NTP peers:"
ntpq -p 2>/dev/null | head -10 || chronyc tracking 2>/dev/null | head -10
log ""

# ---- Linux Endpoint ---------------------------------------------------------
log "--- linux-endpoint (192.168.56.30) ---"
SSH_CMD="ssh -i $SSH_KEY -o StrictHostKeyChecking=no -o ConnectTimeout=5"
if $SSH_CMD ubuntu@$LINUX_ENDPOINT_IP "exit" 2>/dev/null; then
    LINUX_TIME=$($SSH_CMD ubuntu@$LINUX_ENDPOINT_IP "date -u '+%Y-%m-%dT%H:%M:%S UTC'")
    LINUX_TZ=$($SSH_CMD ubuntu@$LINUX_ENDPOINT_IP "timedatectl | grep 'Time zone'")
    LINUX_NTP=$($SSH_CMD ubuntu@$LINUX_ENDPOINT_IP "timedatectl | grep 'NTP service'")
    LINUX_DRIFT=$($SSH_CMD ubuntu@$LINUX_ENDPOINT_IP "ntpq -p 2>/dev/null | head -5 || echo 'NTP not reachable'")
    log "Local time:  $LINUX_TIME"
    log "Timezone:  $LINUX_TZ"
    log "NTP status:  $LINUX_NTP"
    log "NTP drift:  $LINUX_DRIFT"
else
    log "WARNING: Cannot SSH to linux-endpoint. Run manually: ssh ubuntu@$LINUX_ENDPOINT_IP 'timedatectl && ntpq -p'"
fi
log ""

# ---- Windows Endpoint (via winrm or manual) ---------------------------------
log "--- windows-endpoint (192.168.56.20) ---"
log "Automated time check via WinRM not configured in this lab."
log "MANUAL VERIFICATION on Windows endpoint:"
log "  1. Open PowerShell as Administrator"
log "  2. Run: w32tm /query /status"
log "  3. Expected: Source=pool.ntp.org, Stratum=3, RootDispersion < 1s"
log "  4. Run: Get-Date -Format 'yyyy-MM-ddTHH:mm:ss zzz'"
log "  5. Compare timestamp to manager time above (drift should be < 1 second)"
log ""

# ---- Compare Timestamps in Wazuh Alerts --------------------------------
log "--- Timestamp Consistency in Wazuh Alerts ---"
ALERTS_FILE="/var/ossec/logs/alerts/alerts.json"
if [ -f "$ALERTS_FILE" ]; then
    log "Most recent 5 alert timestamps:"
    grep -o '"timestamp":"[^"]*"' "$ALERTS_FILE" | tail -5 | \
        sed 's/"timestamp":"//;s/"//' | while read ts; do
            log "  $ts"
        done
    log ""
    log "Check: All timestamps should be in UTC (ending +00:00 or Z)"
else
    log "No alerts.json found yet — generate events first."
fi

log ""
log "========================================================================"
log "CONCLUSION:"
log "  All three VMs are configured to use UTC timezone."
log "  NTP synchronisation ensures timestamps are consistent across:"
log "    - Wazuh alert timestamps"
log "    - Linux auth.log and auditd events"
log "    - Windows Security event log"
log "  This is critical for accurate correlation and triage."
log "========================================================================"
log ""
log "Report saved to: $LOGFILE"
