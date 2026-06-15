#!/bin/bash
# =============================================================================
# account-lock.sh  —  Active Response: Lock a Linux user account
# Larkspur Retail Group  |  Student: Syed Hadi Hussain  |  CA1
#
# Triggered by: Wazuh rule 100011 (sudo escalation after new account creation)
# Location:     /var/ossec/active-response/bin/account-lock.sh  (linux-endpoint)
# Permissions:  chmod 750  |  chown root:wazuh
#
# Action:  Runs  usermod -L <username>  to set a ! password lock.
#          The account still exists but cannot be used for password auth.
#          SSH key auth is NOT disabled by this (see notes below).
#
# Remediation verification:
#   sudo passwd -S <username>   →  should show tag 'L' (locked)
# Rollback (manual):
#   sudo usermod -U <username>
#
# IMPORTANT SAFETY GUARDS:
#   - Never locks root, wazuh, or any system account (uid < 1000)
#   - Logs every action to active-responses.log for audit trail
#   - timeout=0 means the lock is NOT auto-reversed (intentional —
#     operator must manually unlock after investigation)
# =============================================================================

LOG_FILE="/var/ossec/logs/active-responses.log"

log() {
    echo "$(date '+%Y-%m-%dT%H:%M:%S%z') account-lock.sh: $*" >> "$LOG_FILE"
}

# ---- Parse Wazuh 4.x JSON input from stdin ----------------------------------
INPUT_JSON=$(cat)
ACTION=$(echo "$INPUT_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin).get('command','add'))" 2>/dev/null)
USERNAME=$(echo "$INPUT_JSON" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    alert = d.get('parameters', {}).get('alert', {})
    user = (alert.get('data', {}).get('dstuser') or
            alert.get('data', {}).get('user') or
            alert.get('data', {}).get('syscheck', {}).get('uname') or '')
    print(user.strip())
except Exception as e:
    print('')
" 2>/dev/null)

# ---- Validate username ------------------------------------------------------
if [ -z "$USERNAME" ]; then
    log "ERROR: Could not extract username from alert JSON. No action taken."
    exit 1
fi

# Safety: refuse to lock protected system accounts
PROTECTED_ACCOUNTS="root wazuh ubuntu daemon bin sys games man lp mail news uucp proxy www-data backup list irc gnats nobody systemd-network systemd-resolve messagebus syslog _apt"
for PROTECTED in $PROTECTED_ACCOUNTS; do
    if [ "$USERNAME" = "$PROTECTED" ]; then
        log "SKIP: Refusing to lock protected account: $USERNAME"
        exit 0
    fi
done

# Safety: refuse to lock accounts with uid < 1000 (system accounts)
USER_UID=$(id -u "$USERNAME" 2>/dev/null)
if [ -n "$USER_UID" ] && [ "$USER_UID" -lt 1000 ]; then
    log "SKIP: Refusing to lock system account (uid $USER_UID): $USERNAME"
    exit 0
fi

# ---- Apply or remove the account lock ---------------------------------------
case "$ACTION" in
    add|"")
        if id "$USERNAME" &>/dev/null; then
            usermod -L "$USERNAME"
            if [ $? -eq 0 ]; then
                log "LOCKED: Account $USERNAME has been locked (usermod -L). Rule 100011 triggered."
                log "LOCKED: Verification: run 'sudo passwd -S $USERNAME' — should show 'L' status."
                log "LOCKED: Rollback: run 'sudo usermod -U $USERNAME' to unlock."
            else
                log "ERROR: usermod -L $USERNAME failed (exit $?)."
            fi
        else
            log "WARNING: User $USERNAME does not exist. Cannot lock."
        fi
        ;;
    delete)
        # Wazuh calls 'delete' on timeout; we keep the lock (timeout=0 means no auto-delete)
        # but log it in case this is triggered manually with a non-zero timeout.
        log "INFO: account-lock delete action called for $USERNAME — lock kept intentionally (manual unlock required)."
        ;;
    *)
        log "ERROR: Unknown action '$ACTION'."
        exit 1
        ;;
esac

exit 0
