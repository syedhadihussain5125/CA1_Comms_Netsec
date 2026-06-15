# =============================================================================
# remove-task.ps1  —  Active Response: Delete a suspicious Windows scheduled task
# Larkspur Retail Group  |  Student: Syed Hadi Hussain  |  CA1
#
# Triggered by: Wazuh rule 100600 (suspicious scheduled task — EID 4698)
# Location:     C:\Program Files (x86)\ossec-agent\active-response\bin\remove-task.ps1
#
# Reads Wazuh 4.x JSON from STDIN, extracts the task name from
# win.eventdata.taskName, and calls Unregister-ScheduledTask.
#
# Remediation verification:
#   schtasks /query /tn <taskname>   →  "ERROR: The system cannot find the file specified."
# Rollback:
#   Task must be manually recreated if the alert was a false positive.
#   Original task XML is saved to C:\Temp\removed_tasks_audit.log before deletion.
# =============================================================================

$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

function Write-ARLog {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
    Add-Content -Path $LogFile -Value "$Timestamp remove-task.ps1: $Message" -ErrorAction SilentlyContinue
}

# ---- Parse Wazuh 4.x JSON input from stdin ----------------------------------
try {
    $InputLine = [Console]::In.ReadLine()
    if ([string]::IsNullOrWhiteSpace($InputLine)) {
        Write-ARLog "ERROR: Empty input. No action taken."
        exit 1
    }

    $AlertData = $InputLine | ConvertFrom-Json
    $Command   = $AlertData.command

    # Extract task name from nested alert data
    $TaskName  = $AlertData.parameters.alert.data.win.eventdata.taskName
    if ([string]::IsNullOrWhiteSpace($TaskName)) {
        # Fallback: try top-level data field
        $TaskName = $AlertData.parameters.alert.data.taskName
    }
} catch {
    Write-ARLog "ERROR: Failed to parse alert JSON — $_"
    exit 1
}

# ---- Validate task name -----------------------------------------------------
if ([string]::IsNullOrWhiteSpace($TaskName)) {
    Write-ARLog "ERROR: Could not extract task name from alert data. No action taken."
    exit 1
}

# Safety: never delete Windows built-in tasks
$ProtectedPrefixes = @(
    '\Microsoft\Windows\',
    '\Microsoft\Office\',
    '\Microsoft\VisualStudio\',
    '\Adobe\',
    '\Google\',
    '\MozillaMaintenanceService\',
    '\User_Feed_Synchronization'
)

foreach ($Prefix in $ProtectedPrefixes) {
    if ($TaskName -like "$Prefix*") {
        Write-ARLog "SKIP: Refusing to delete protected system task: $TaskName"
        exit 0
    }
}

# ---- Apply or skip based on action ------------------------------------------
if ($Command -ne "add") {
    Write-ARLog "INFO: Command is '$Command' — no action taken for task: $TaskName"
    exit 0
}

# ---- Export task XML before deletion (audit trail) --------------------------
try {
    $AuditLog = "C:\Temp\removed_tasks_audit.log"
    if (-not (Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" | Out-Null }
    $TaskXML = schtasks.exe /query /tn $TaskName /xml 2>&1
    $AuditEntry = "$(Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz')  TASK_DELETED: $TaskName`n$TaskXML`n---`n"
    Add-Content -Path $AuditLog -Value $AuditEntry -ErrorAction SilentlyContinue
} catch {
    Write-ARLog "WARNING: Could not export task XML before deletion — $_"
}

# ---- Delete the task --------------------------------------------------------
try {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction Stop
    Write-ARLog "DELETED: Scheduled task '$TaskName' removed. Rule 100600 triggered."
    Write-ARLog "DELETED: Verify with: schtasks /query /tn '$TaskName'"
    Write-ARLog "DELETED: Task XML saved to C:\Temp\removed_tasks_audit.log for rollback."
} catch {
    # Fallback: try schtasks.exe directly (handles tasks with path prefixes)
    $Result = schtasks.exe /delete /tn $TaskName /f 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-ARLog "DELETED: Scheduled task '$TaskName' removed via schtasks.exe."
    } else {
        Write-ARLog "ERROR: Failed to delete task '$TaskName' — schtasks exit $LASTEXITCODE — $Result"
    }
}

exit 0
