#!/bin/bash
# =============================================================================
# sim-brute-force.sh  —  BENIGN SSH Brute Force Simulation
# Larkspur Retail Group  |  Student: Syed Hadi Hussain  |  CA1
#
# PURPOSE: Generate SSH authentication failure events on linux-endpoint
#          to trigger Wazuh rule 5760 → custom rule 105760 (SSH brute force)
#          and test the firewall-drop active response.
#
# SAFETY:
#   - Uses deliberately wrong passwords — no system is compromised
#   - Run from windows-endpoint (192.168.56.20) or wazuh-manager
#   - Target is ONLY the lab linux-endpoint (192.168.56.30)
#   - No real malware or exploitation tools used
#
# EXPECTED OUTCOME:
#   1. 3+ SSH failures logged in /var/log/auth.log on linux-endpoint
#   2. Wazuh rule 5760 fires on manager (SSH brute force)
#   3. Custom rule 105760 fires (LARKSPUR-ALERT)
#   4. firewall-drop active response blocks the source IP for 60 seconds
#   5. Subsequent SSH from same IP times out (verification)
#
# ATT&CK: T1110 — Brute Force
# =============================================================================

TARGET_IP="${1:-192.168.56.30}"
TARGET_USER="${2:-labuser}"
ATTEMPTS="${3:-5}"
DELAY_SECS="${4:-2}"

echo "[*] SSH Brute Force Simulation — Larkspur CA1"
echo "[*] Target:   $TARGET_USER@$TARGET_IP"
echo "[*] Attempts: $ATTEMPTS  |  Delay: ${DELAY_SECS}s between attempts"
echo "[*] Using deliberately wrong passwords..."
echo ""

# Confirm this is a lab environment
if [[ "$TARGET_IP" != "192.168.56."* ]] && [[ "$TARGET_IP" != "10.0.0."* ]]; then
    echo "[!] WARNING: Target IP $TARGET_IP does not look like a lab network."
    echo "[!] This script is for authorised lab use ONLY. Exiting."
    exit 1
fi

WRONG_PASSWORDS=(
    "wrongpassword123"
    "Password1234"
    "test1234"
    "admin123"
    "letmein999"
)

SUCCESS=0
FAILED=0

for i in $(seq 1 "$ATTEMPTS"); do
    PASS="${WRONG_PASSWORDS[$((i % ${#WRONG_PASSWORDS[@]}))]}"
    echo -n "[*] Attempt $i/$ATTEMPTS — password '$PASS'... "

    # Use sshpass to attempt auth with wrong password (-o StrictHostKeyChecking=no for lab)
    # If sshpass is not installed:  apt-get install -y sshpass
    if command -v sshpass &>/dev/null; then
        sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no \
            -o ConnectTimeout=5 \
            -o BatchMode=no \
            -p 22 \
            "$TARGET_USER@$TARGET_IP" "exit" 2>/dev/null
        EXIT_CODE=$?
    else
        # Fallback: use ssh with empty stdin to force password prompt failure
        ssh -o StrictHostKeyChecking=no \
            -o ConnectTimeout=5 \
            -o PreferredAuthentications=password \
            -o PasswordAuthentication=yes \
            -p 22 \
            "$TARGET_USER@$TARGET_IP" "exit" </dev/null 2>/dev/null
        EXIT_CODE=$?
    fi

    if [ "$EXIT_CODE" -eq 0 ]; then
        echo "Connected (unexpected success — check target)"
        SUCCESS=$((SUCCESS + 1))
    else
        echo "Failed (expected — auth failure logged)"
        FAILED=$((FAILED + 1))
    fi

    sleep "$DELAY_SECS"
done

echo ""
echo "[*] Simulation complete: $FAILED failed / $SUCCESS succeeded"
echo ""
echo "[*] VERIFICATION STEPS:"
echo "    1. On wazuh-manager: grep '105760' /var/ossec/logs/alerts/alerts.log"
echo "    2. In Wazuh dashboard: search rule.id:105760"
echo "    3. On linux-endpoint: iptables -L INPUT -n --line-numbers"
echo "       (should show a DROP rule for this host's IP)"
echo "    4. Wait ~60s and retry SSH — connection should succeed again (rollback)"
