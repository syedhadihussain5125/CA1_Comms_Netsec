#!/bin/bash
# =============================================================================
# firewall-drop.sh  —  Active Response: Block source IP via iptables
# Larkspur Retail Group  |  Student: Syed Hadi Hussain  |  CA1
#
# Triggered by: Wazuh rule 105760 (SSH brute force)
# Location:     /var/ossec/active-response/bin/firewall-drop.sh  (linux-endpoint)
# Permissions:  chmod 750  |  chown root:wazuh
#
# Wazuh 4.x active-response passes a JSON document on STDIN.
# This script parses the source IP and applies/removes an iptables DROP rule.
# The Wazuh manager sets timeout=60 so the UNDO action is called after 60s.
#
# Remediation verification:
#   ssh <blocked_ip>@192.168.56.30  →  connection will time out while rule is active
#   iptables -L INPUT -n --line-numbers  →  shows the DROP rule
# Rollback:
#   Wazuh automatically calls  firewall-drop.sh delete  after <timeout> seconds.
#   Manual rollback:  iptables -D INPUT -s <ip> -j DROP
# =============================================================================

LOCAL=$(dirname "$0")
LOG_FILE="/var/ossec/logs/active-responses.log"
IPTABLES=$(which iptables 2>/dev/null)

log() {
    echo "$(date '+%Y-%m-%dT%H:%M:%S%z') firewall-drop.sh: $*" >> "$LOG_FILE"
}

# ---- Parse Wazuh 4.x JSON input from stdin ----------------------------------
INPUT_JSON=$(cat)
ACTION=$(echo "$INPUT_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('command','add'))" 2>/dev/null)
SRCIP=$(echo "$INPUT_JSON"  | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    alert = d.get('parameters', {}).get('alert', {})
    ip = (alert.get('data', {}).get('srcip') or
          alert.get('data', {}).get('src_ip') or
          alert.get('data', {}).get('srcIp') or '')
    print(ip.strip())
except Exception as e:
    print('')
" 2>/dev/null)

# ---- Validate inputs --------------------------------------------------------
if [ -z "$SRCIP" ]; then
    log "ERROR: Could not extract source IP from alert JSON. No action taken."
    exit 1
fi

# Sanity check: do not block localhost or the Wazuh manager
if echo "$SRCIP" | grep -qE '^(127\.|::1|192\.168\.56\.10)'; then
    log "SKIP: Refusing to block protected address $SRCIP"
    exit 0
fi

if [ -z "$IPTABLES" ]; then
    log "ERROR: iptables not found on this system."
    exit 1
fi

# ---- Apply or remove the firewall rule --------------------------------------
case "$ACTION" in
    add|"")
        log "BLOCK: Adding iptables DROP for $SRCIP (rule 105760 trigger)"
        $IPTABLES -I INPUT -s "$SRCIP" -j DROP
        $IPTABLES -I FORWARD -s "$SRCIP" -j DROP
        log "BLOCK: iptables rules inserted for $SRCIP. Auto-expires after 60s via Wazuh timeout."
        ;;
    delete)
        log "UNBLOCK: Removing iptables DROP for $SRCIP (timeout expired)"
        $IPTABLES -D INPUT -s "$SRCIP" -j DROP 2>/dev/null
        $IPTABLES -D FORWARD -s "$SRCIP" -j DROP 2>/dev/null
        log "UNBLOCK: iptables rules removed for $SRCIP."
        ;;
    *)
        log "ERROR: Unknown action '$ACTION'. Expected 'add' or 'delete'."
        exit 1
        ;;
esac

exit 0
