# =============================================================================
# sim-windows-task.ps1  —  BENIGN Windows Scheduled Task Simulation
# Larkspur Retail Group  |  Student: Batool Fatima  |  CA1
#
# PURPOSE: Create a scheduled task with a suspicious name to trigger:
#            - Windows Security EID 4698 (task created)
#            - Wazuh rule 100600 (suspicious task — task name regex match)
#            - remove-task active response (Wazuh deletes the task)
#
# SAFETY:
#   - The task payload (log_activity.py) is a benign Python script
#     that only writes the current username and timestamp to a log file.
#   - No network connections, no privilege escalation, no file exfiltration.
#   - The task is expected to be deleted by Wazuh within seconds of creation.
#   - If Wazuh active response is not running, the cleanup section at the
#     bottom of this script removes the task manually.
#
# ATT&CK: T1053.005 — Scheduled Task/Job: Scheduled Task
# =============================================================================

$SimUser    = $env:USERNAME
$TaskName   = "keylog"           # name matches rule 100600 regex
$TaskPath   = "C:\Temp"
$PayloadFile = "$TaskPath\log_activity.py"
$LogFile    = "$TaskPath\sim_windows_task.log"

function Write-SimLog {
    param([string]$Message)
    $Ts = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
    "$Ts [CA1-SIM] $Message" | Tee-Object -Append -FilePath $LogFile
}

Write-SimLog "Windows Task Simulation — Larkspur CA1"
Write-SimLog "Running on: $env:COMPUTERNAME as $SimUser"
Write-SimLog "Task name to create: '$TaskName'"
Write-SimLog ""

# ---- Create temp directory --------------------------------------------------
if (-not (Test-Path $TaskPath)) {
    New-Item -ItemType Directory -Path $TaskPath | Out-Null
    Write-SimLog "Created $TaskPath"
}

# ---- Write the benign payload script ----------------------------------------
$PayloadContent = @'
# log_activity.py  —  BENIGN payload (Larkspur CA1)
# Only writes current username and timestamp to a local log file.
# No network access, no credential access, no exfiltration.
import os, datetime
log_path = r"C:\Temp\activity.log"
with open(log_path, "a") as f:
    f.write(f"{datetime.datetime.now().isoformat()} user={os.getenv('USERNAME','unknown')}\n")
'@

Set-Content -Path $PayloadFile -Value $PayloadContent -Encoding UTF8
Write-SimLog "Benign payload written to $PayloadFile"

# ---- Create the suspicious scheduled task (generates EID 4698) ---------------
Write-SimLog ""
Write-SimLog "STEP 1: Creating scheduled task '$TaskName' (generates EID 4698)..."

$Action    = New-ScheduledTaskAction  -Execute "python.exe" -Argument $PayloadFile
$Trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(60)
$Settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 1)
$Principal = New-ScheduledTaskPrincipal -UserId $SimUser -LogonType Interactive

try {
    Register-ScheduledTask -TaskName $TaskName `
        -Action $Action `
        -Trigger $Trigger `
        -Settings $Settings `
        -Principal $Principal `
        -Description "Larkspur CA1 Simulation Task" `
        -Force -ErrorAction Stop | Out-Null

    Write-SimLog "SUCCESS: Task '$TaskName' created."
    Write-SimLog "EXPECTED: EID 4698 generated in Windows Security log."
    Write-SimLog "EXPECTED: Wazuh rule 100600 fires."
    Write-SimLog "EXPECTED: remove-task active response deletes the task."
} catch {
    Write-SimLog "ERROR: Failed to create task — $_"
}

# ---- Pause and verify -------------------------------------------------------
Write-SimLog ""
Write-SimLog "Waiting 15 seconds for Wazuh active response to execute..."
Start-Sleep -Seconds 15

Write-SimLog ""
Write-SimLog "STEP 2: Checking if task was deleted by active response..."
$TaskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue

if ($null -eq $TaskExists) {
    Write-SimLog "CONFIRMED: Task '$TaskName' has been deleted. Active response succeeded."
} else {
    Write-SimLog "Task still exists — Wazuh active response may not have fired yet."
    Write-SimLog "Manual verification: schtasks /query /tn $TaskName"
    Write-SimLog "Manual cleanup: Unregister-ScheduledTask -TaskName $TaskName -Confirm:`$false"

    # Manual cleanup if active response did not fire
    Write-SimLog "Performing manual cleanup..."
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-SimLog "Manual cleanup complete."
}

Write-SimLog ""
Write-SimLog "Simulation complete. Check Wazuh dashboard for rule 100600."
Write-SimLog "Search filter in Wazuh: rule.id:100600"
