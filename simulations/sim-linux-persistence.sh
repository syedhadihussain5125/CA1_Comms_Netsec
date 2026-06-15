#!/bin/bash
# =============================================================================
# sim-linux-persistence.sh  —  BENIGN Linux Persistence Simulation
# Larkspur Retail Group  |  Student: Syed Hadi Hussain  |  CA1
#
# PURPOSE: Simulate an attacker creating a backdoor user and immediately
#          granting it sudo privileges — triggering:
#            - Rule 100010 (new user created)
#            - Rule 100011 (sudo escalation within 5 minutes)
#            - account-lock active response
#
# SAFETY:
#   - Creates a real but harmless local account (backdooruser)
#   - Account is locked by the active response immediately
#   - Cleanup script at the end removes the account entirely
#   - No actual privilege is ever exercised
#   - Run ONLY on linux-endpoint (192.168.56.30) as root or sudo user
#
# ATT&CK:
#   T1136.001 — Create Account: Local Account
#   T1548.003 — Abuse Elevation Control Mechanism: Sudo
# =============================================================================

TEST_USER="backdooruser"
LOG_MARKER="[CA1-SIM]"

echo "$LOG_MARKER Linux Persistence Simulation — Larkspur CA1"
echo "$LOG_MARKER Running on: $(hostname) at $(date)"
echo "$LOG_MARKER Simulated attacker creates backdoor account + grants sudo"
echo ""

# ---- Pre-flight checks ------------------------------------------------------
if [[ "$EUID" -ne 0 ]]; then
    echo "$LOG_MARKER ERROR: This script must run as root (sudo ./sim-linux-persistence.sh)"
    exit 1
fi

if id "$TEST_USER" &>/dev/null; then
    echo "$LOG_MARKER User '$TEST_USER' already exists — removing first for clean test."
    userdel -r "$TEST_USER" 2>/dev/null || true
fi

# ---- Step 1: Create the backdoor user (T1136.001) ---------------------------
echo "$LOG_MARKER STEP 1: Creating backdoor account '$TEST_USER'..."
useradd -m -s /bin/bash -c "Larkspur CA1 Test Account" "$TEST_USER"

if id "$TEST_USER" &>/dev/null; then
    echo "$LOG_MARKER SUCCESS: User '$TEST_USER' created."
    echo "$LOG_MARKER EXPECTED: Wazuh rule 100010 should fire now."
else
    echo "$LOG_MARKER ERROR: Failed to create user '$TEST_USER'."
    exit 1
fi

# ---- Brief pause (simulates attacker establishing foothold) ------------------
echo ""
echo "$LOG_MARKER Pausing 5 seconds (simulates attacker confirming access)..."
sleep 5

# ---- Step 2: Grant sudo privileges (T1548.003) --------------------------------
echo ""
echo "$LOG_MARKER STEP 2: Granting sudo to '$TEST_USER' (usermod -aG sudo)..."
usermod -aG sudo "$TEST_USER"
echo "$LOG_MARKER SUCCESS: '$TEST_USER' added to sudo group."
echo "$LOG_MARKER EXPECTED: Wazuh rule 100011 should fire (correlation: account creation + sudo grant within 5 min)."
echo "$LOG_MARKER EXPECTED: account-lock active response should lock '$TEST_USER'."

# ---- Wait for Wazuh to process events ---------------------------------------
echo ""
echo "$LOG_MARKER Waiting 10 seconds for Wazuh active response to execute..."
sleep 10

# ---- Verify active response -------------------------------------------------
echo ""
echo "$LOG_MARKER VERIFICATION:"
PASSWD_STATUS=$(passwd -S "$TEST_USER" 2>/dev/null || echo "unknown")
echo "$LOG_MARKER   passwd -S $TEST_USER:  $PASSWD_STATUS"

if echo "$PASSWD_STATUS" | grep -q " L "; then
    echo "$LOG_MARKER   CONFIRMED: Account is LOCKED (status 'L'). Active response succeeded."
else
    echo "$LOG_MARKER   Account does not show locked status — check Wazuh active-response logs."
    echo "$LOG_MARKER   Manual verify: cat /var/ossec/logs/active-responses.log"
fi

# ---- Cleanup ----------------------------------------------------------------
echo ""
echo "$LOG_MARKER CLEANUP: Removing test account '$TEST_USER'..."
userdel -r "$TEST_USER" 2>/dev/null
# Remove from sudoers if it got written there
sed -i "/^$TEST_USER/d" /etc/sudoers 2>/dev/null || true

if ! id "$TEST_USER" &>/dev/null; then
    echo "$LOG_MARKER CLEANUP: User '$TEST_USER' removed successfully."
else
    echo "$LOG_MARKER CLEANUP WARNING: Could not remove '$TEST_USER' — remove manually with: userdel -r $TEST_USER"
fi

echo ""
echo "$LOG_MARKER Simulation complete. Check Wazuh dashboard for rules 100010 and 100011."
echo "$LOG_MARKER Search filter: rule.id:(100010 OR 100011)"
