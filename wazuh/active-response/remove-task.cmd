@echo off
::
:: remove-task.cmd  —  Active Response CMD wrapper for PowerShell task removal
:: Larkspur Retail Group  |  Student: Batool Fatima  |  CA1
::
:: Triggered by: Wazuh rule 100600 (suspicious scheduled task created)
:: Location:     C:\Program Files (x86)\ossec-agent\active-response\bin\remove-task.cmd
::
:: Wazuh active-response on Windows requires a CMD or EXE entry point.
:: This wrapper receives the alert JSON on STDIN, passes it to the
:: PowerShell script which parses the task name and deletes the task.
::
:: Rollback: Task must be manually recreated if it was legitimate.
:: Verification: schtasks /query /tn <taskname>  →  should return "ERROR: The system cannot find the file specified."
::

:: Locate the PowerShell script in the same directory
set "AR_PATH=%~dp0"
set "PS_SCRIPT=%AR_PATH%remove-task.ps1"

:: Pass all stdin through to PowerShell
powershell.exe -ExecutionPolicy Bypass -NonInteractive -NoProfile -File "%PS_SCRIPT%"

exit /b %ERRORLEVEL%
