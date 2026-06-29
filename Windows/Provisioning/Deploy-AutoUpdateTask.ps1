<#
.SYNOPSIS
    Deploys an idempotent, Base64-encoded Windows Auto-Update scheduled task.
.AUTHOR
    Zachary Schmalz
.NOTES
    Source: https://github.com/ZacharySchmalzEng/Tools
#>

# 1. Define the Update Payload
$UpdatePayload = {
    $EventSource = "OS-AutoUpdater"
    $EventLog = "Application"
    
    if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
        New-EventLog -LogName $EventLog -Source $EventSource
    }

    Write-EventLog -LogName $EventLog -Source $EventSource -EventId 1000 -EntryType Information -Message "Initiating Automated Update Sequence."

    try {
        # Phase 1: Third-Party Application Updates (Winget)
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-EventLog -LogName $EventLog -Source $EventSource -EventId 1001 -EntryType Information -Message "Executing Winget global upgrade."
            # Note: Winget under SYSTEM context is best-effort.
            winget upgrade --all --silent --accept-source-agreements --accept-package-agreements
        } else {
            Write-EventLog -LogName $EventLog -Source $EventSource -EventId 2001 -EntryType Warning -Message "Winget binary not found in SYSTEM path. Skipping application updates."
        }

        # Phase 2: OS Updates (PSWindowsUpdate)
        Write-EventLog -LogName $EventLog -Source $EventSource -EventId 1002 -EntryType Information -Message "Bootstrapping NuGet and executing PSWindowsUpdate."
        
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers -ErrorAction SilentlyContinue
        Install-Module PSWindowsUpdate -Force -AcceptLicense -AllowClobber -ErrorAction SilentlyContinue
        Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue
        
        # Executes update and handles native reboot signaling if required
        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot -ErrorAction Stop

        Write-EventLog -LogName $EventLog -Source $EventSource -EventId 1004 -EntryType Information -Message "Update Sequence completed successfully."
    }
    catch {
        Write-EventLog -LogName $EventLog -Source $EventSource -EventId 4000 -EntryType Error -Message "Fatal execution error in Update Sequence: $_"
    }
}

# 2. Encode the Payload to Base64
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($UpdatePayload.ToString())
$EncodedCommand = [Convert]::ToBase64String($Bytes)

# 3. Detect OS version strictly for interactive bounds
$OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
if (($null -ne $OSInfo) -and ($OSInfo.Caption -match "Windows 10")) {
    Write-Host "[!] Windows 10 Detected. Skipping auto-update task registration due to interactive UI bounds." -ForegroundColor Yellow
    exit
}

# 4. Define Scheduled Task Parameters
$TaskName = "Automated-OS-AutoUpdate"
$TaskSignature = "Deployed via automated provisioning. Maintained by Zachary Schmalz (Github: ZacharySchmalzEng)."
$TaskDescription = "Automated silent app updates via Winget and OS patching via PSWindowsUpdate. | $TaskSignature"
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $EncodedCommand"

# Staggered execution: Wednesday mornings (avoids collision with Sunday Maintenance)
$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Wednesday -At 3:00AM
$Trigger.RandomDelay = "PT2H" 

$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew

# 5. Idempotent State Teardown
$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $ExistingTask) {
    Write-Host "[-] Existing task detected. Executing teardown sequence..." -ForegroundColor Yellow
    if ($ExistingTask.State -eq 'Running') {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}

# 6. Register the Task
Register-ScheduledTask -TaskName $TaskName -Description $TaskDescription -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force -ErrorAction Stop | Out-Null
Write-Host "[+] Scheduled task '$TaskName' successfully registered and initialized." -ForegroundColor Green