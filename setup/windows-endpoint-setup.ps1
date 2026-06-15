# =============================================================================
# windows-endpoint-setup.ps1  —  Windows Endpoint Configuration
# Larkspur Retail Group  |  Student: Batool Fatima  |  CA1
# Target OS: Windows 10 Enterprise  |  IP: 192.168.56.20
#
# Intentionally weak configurations (documented, controlled):
#   - Windows Defender real-time protection disabled (allows simulation to run)
#   - Audit policy configured for key Security event IDs
#   - PowerShell ScriptBlock and Module logging enabled
#   - Sysmon installed with larkspur config
#
# Wazuh Agent installed and registered to manager at 192.168.56.10
# =============================================================================

#Requires -RunAsAdministrator

$WazuhManager = "192.168.56.10"
$WazuhRegPass = "AgentRegPass@Lab1"
$RepoDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$LogFile = "C:\Temp\larkspur-endpoint-setup.log"

function Write-SetupLog {
    param([string]$Message)
    $Ts = Get-Date -Format "yyyy-MM-ddTHH:mm:sszzz"
    "$Ts [SETUP] $Message" | Tee-Object -Append -FilePath $LogFile
}

if (-not (Test-Path "C:\Temp")) { New-Item -ItemType Directory "C:\Temp" | Out-Null }

Write-SetupLog "=== Larkspur Windows Endpoint Setup — CA1 ==="
Write-SetupLog "Computer: $env:COMPUTERNAME  |  User: $env:USERNAME"

# ---- 1. Hostname and Time Sync -----------------------------------------------
Write-SetupLog "--- Step 1: Hostname and NTP ---"
Rename-Computer -NewName "windows-endpoint" -Force -ErrorAction SilentlyContinue
w32tm /config /manualpeerlist:"pool.ntp.org" /syncfromflags:manual /reliable:YES /update
Restart-Service w32tm
w32tm /resync /force
Write-SetupLog "Time: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz')"

# ---- 2. Intentionally Weak Configuration (DOCUMENTED) -----------------------
Write-SetupLog "--- Step 2: Intentional weaknesses (controlled lab) ---"

# Disable Windows Defender real-time protection (prevents simulation interference)
Set-MpPreference -DisableRealtimeMonitoring $true
Write-SetupLog "WEAK: Windows Defender real-time protection disabled."

# Create a local admin account with a simple password (for lateral movement demo)
$LabUserPass = ConvertTo-SecureString "Lab@Password1" -AsPlainText -Force
if (-not (Get-LocalUser -Name "labadmin" -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name "labadmin" -Password $LabUserPass -Description "Larkspur CA1 Lab Account"
    Add-LocalGroupMember -Group "Administrators" -Member "labadmin"
    Write-SetupLog "WEAK: labadmin created with weak password and admin rights."
}

# ---- 3. Audit Policy — enable Security Event IDs ---------------------------
Write-SetupLog "--- Step 3: Audit Policy ---"
# Logon/Logoff
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable

# Process Creation (EID 4688)
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

# Account Management (EID 4720, 4726, 4732, 4756)
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable

# Privilege Use (EID 4672)
auditpol /set /subcategory:"Special Logon" /success:enable

# Scheduled Task (EID 4698, 4702)
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

# Enable command line logging in process creation events (EID 4688 includes cmdline)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
    -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force

Write-SetupLog "Audit policies configured."
auditpol /get /category:* | Where-Object { $_ -match "Success|Failure" }

# ---- 4. PowerShell Logging via Registry ------------------------------------
Write-SetupLog "--- Step 4: PowerShell Script Block and Module Logging ---"
$PsLoggingPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

# Script Block Logging (captures full script content)
$SBLPath = "$PsLoggingPath\ScriptBlockLogging"
New-Item -Path $SBLPath -Force | Out-Null
Set-ItemProperty -Path $SBLPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# Module Logging (captures module calls)
$MLPath = "$PsLoggingPath\ModuleLogging"
New-Item -Path $MLPath -Force | Out-Null
Set-ItemProperty -Path $MLPath -Name "EnableModuleLogging" -Value 1 -Type DWord
New-ItemProperty -Path $MLPath -Name "ModuleNames" -Value @("*") -PropertyType MultiString -Force | Out-Null

# Transcription (optional — full transcript logs)
$TransPath = "$PsLoggingPath\Transcription"
New-Item -Path $TransPath -Force | Out-Null
Set-ItemProperty -Path $TransPath -Name "EnableTranscripting" -Value 1 -Type DWord
Set-ItemProperty -Path $TransPath -Name "OutputDirectory" -Value "C:\PSTranscripts" -Type String
New-Item -ItemType Directory "C:\PSTranscripts" -Force | Out-Null

Write-SetupLog "PowerShell logging configured."

# ---- 5. Install Sysmon ------------------------------------------------------
Write-SetupLog "--- Step 5: Sysmon ---"
$SysmonDir  = "C:\Sysmon"
$SysmonExe  = "$SysmonDir\Sysmon64.exe"
$SysmonConf = "$SysmonDir\sysmon-config.xml"

New-Item -ItemType Directory -Path $SysmonDir -Force | Out-Null

# Copy our sysmon config
$SysmonConfigSrc = "$RepoDir\wazuh\sysmon-config.xml"
if (Test-Path $SysmonConfigSrc) {
    Copy-Item $SysmonConfigSrc $SysmonConf -Force
    Write-SetupLog "Sysmon config copied."
}

# Download Sysmon if not already present
if (-not (Test-Path $SysmonExe)) {
    Write-SetupLog "Downloading Sysmon from Microsoft..."
    $SysmonZip = "$SysmonDir\Sysmon.zip"
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" `
        -OutFile $SysmonZip -UseBasicParsing
    Expand-Archive -Path $SysmonZip -DestinationPath $SysmonDir -Force
    Write-SetupLog "Sysmon downloaded."
}

if (Test-Path $SysmonExe) {
    # Check if already installed
    $SvcExists = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if ($SvcExists) {
        & $SysmonExe -c $SysmonConf
        Write-SetupLog "Sysmon config updated."
    } else {
        & $SysmonExe -accepteula -i $SysmonConf
        Write-SetupLog "Sysmon installed and started."
    }
} else {
    Write-SetupLog "WARNING: Sysmon64.exe not found. Download manually from Sysinternals."
}

# ---- 6. Install Wazuh Agent -------------------------------------------------
Write-SetupLog "--- Step 6: Installing Wazuh Agent ---"
$WazuhMsi = "C:\Temp\wazuh-agent.msi"

if (-not (Test-Path $WazuhMsi)) {
    Write-SetupLog "Downloading Wazuh agent MSI..."
    Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.8.0-1.msi" `
        -OutFile $WazuhMsi -UseBasicParsing
}

Write-SetupLog "Installing Wazuh agent..."
Start-Process msiexec.exe -ArgumentList "/i $WazuhMsi /q WAZUH_MANAGER=$WazuhManager WAZUH_AGENT_NAME=windows-endpoint WAZUH_REGISTRATION_PASSWORD=$WazuhRegPass" -Wait

# ---- 7. Deploy Wazuh Windows Agent Config -----------------------------------
Write-SetupLog "--- Step 7: Deploy agent ossec.conf ---"
$WazuhAgentConf = "$RepoDir\wazuh\ossec-windows-agent.conf"
$WazuhOssecPath = "C:\Program Files (x86)\ossec-agent\ossec.conf"

if (Test-Path $WazuhAgentConf) {
    Copy-Item $WazuhAgentConf $WazuhOssecPath -Force
    Write-SetupLog "Windows agent ossec.conf deployed."
}

# Deploy active response scripts
$ARBin = "C:\Program Files (x86)\ossec-agent\active-response\bin"
$RemoveTaskCmd = "$RepoDir\wazuh\active-response\remove-task.cmd"
$RemoveTaskPs1 = "$RepoDir\wazuh\active-response\remove-task.ps1"

if (Test-Path $RemoveTaskCmd) { Copy-Item $RemoveTaskCmd $ARBin -Force }
if (Test-Path $RemoveTaskPs1) { Copy-Item $RemoveTaskPs1 $ARBin -Force }
Write-SetupLog "Windows active response scripts deployed."

# Start Wazuh service
Start-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
Start-Sleep 5
Get-Service -Name "WazuhSvc" | Select-Object Name, Status | Format-Table
Write-SetupLog "Wazuh agent service started."

# ---- Summary ----------------------------------------------------------------
Write-SetupLog ""
Write-SetupLog "=== Windows Endpoint Setup Complete ==="
Write-SetupLog "Agent should appear in Wazuh dashboard within ~60 seconds."
Write-SetupLog ""
Write-SetupLog "VULNERABILITY SUMMARY (intentional for lab):"
Write-SetupLog "  - Windows Defender disabled  (simulation interference prevention)"
Write-SetupLog "  - labadmin account           (Lab@Password1, local admin)"
Write-SetupLog ""
Write-SetupLog "TELEMETRY SOURCES:"
Write-SetupLog "  - Security Event Log         (EID 4624/4625/4672/4688/4698/4720)"
Write-SetupLog "  - Sysmon/Operational          (EID 1/3/7/11/12/13/22)"
Write-SetupLog "  - PowerShell/Operational     (EID 4103/4104 script block)"
