# =============================================================================
# sim-powershell-suspicious.ps1  —  BENIGN PowerShell Simulation
# Larkspur Retail Group  |  Student: Batool Fatima  |  CA1
#
# PURPOSE: Execute a safe PowerShell command using the -EncodedCommand flag
#          to trigger Sysmon EID 1 with -enc in the command line.
#          This triggers Wazuh rule 100700 (suspicious PowerShell execution).
#
# SAFETY:
#   - The encoded payload is ONLY: Get-Date; Write-Output "CA1 simulation"
#   - No network access, no file download, no credential access
#   - Deliberately uses -EncodedCommand for detection signal purposes only
#
# ATT&CK: T1059.001 — Command and Scripting Interpreter: PowerShell
# =============================================================================

$LogFile = "C:\Temp\sim_powershell.log"

function Write-SimLog {
    param([string]$Message)
    $Ts = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
    "$Ts [CA1-SIM] $Message" | Tee-Object -Append -FilePath $LogFile
}

if (-not (Test-Path "C:\Temp")) { New-Item -ItemType Directory -Path "C:\Temp" | Out-Null }

Write-SimLog "PowerShell Suspicious Execution Simulation — Larkspur CA1"
Write-SimLog "Machine: $env:COMPUTERNAME  User: $env:USERNAME"
Write-SimLog ""

# ---- Build the encoded command (benign payload) -----------------------------
# Payload: Get-Date; Write-Output "Larkspur CA1 Simulation"
$BenignPayload  = 'Get-Date; Write-Output "Larkspur CA1 Simulation - benign test"'
$EncodedBytes   = [System.Text.Encoding]::Unicode.GetBytes($BenignPayload)
$EncodedCommand = [Convert]::ToBase64String($EncodedBytes)

Write-SimLog "STEP 1: Payload (plaintext): $BenignPayload"
Write-SimLog "STEP 2: Base64 encoded:      $EncodedCommand"
Write-SimLog "STEP 3: Executing with -EncodedCommand flag (generates Sysmon EID 1)..."
Write-SimLog ""

# ---- Execute the encoded command --------------------------------------------
# Sysmon captures the full command line including the -enc flag and encoded blob
# This is exactly the signal that rule 100700 watches for
$Output = powershell.exe -NonInteractive -NoProfile `
              -ExecutionPolicy Bypass `
              -EncodedCommand $EncodedCommand 2>&1

Write-SimLog "Execution output: $Output"
Write-SimLog "EXPECTED: Sysmon EID 1 logged with powershell.exe -EncodedCommand in commandLine"
Write-SimLog "EXPECTED: Wazuh rule 100700 fires on wazuh-manager"
Write-SimLog ""

# ---- Second simulation: -w hidden (hidden window) ---------------------------
Write-SimLog "STEP 4: Executing with -WindowStyle hidden -NonInteractive (second signal variant)..."
Start-Process powershell.exe -ArgumentList "-NonInteractive", "-NoProfile",
    "-WindowStyle", "Hidden",
    "-Command", "Get-Date | Out-File C:\Temp\ps_sim_output.txt" -Wait

Write-SimLog "EXPECTED: Sysmon EID 1 with '-WindowStyle hidden' in commandLine"
Write-SimLog ""
Write-SimLog "Simulation complete. Verify in Wazuh dashboard: rule.id:100700"
Write-SimLog "Also check Sysmon log: Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' | Where EventID -eq 1 | Select -First 10 | Format-List"
