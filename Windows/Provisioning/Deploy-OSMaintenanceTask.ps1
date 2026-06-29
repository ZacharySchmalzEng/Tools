<#
.SYNOPSIS
    Deploys an idempotent, Base64-encoded Windows OS maintenance scheduled task.
#>

# 1. Define the Maintenance Payload
$MaintenancePayload = {
    $EventSource = "OS-Maintenance"
    $EventLog = "Application"
    
    if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
        New-EventLog -LogName $EventLog -Source $EventSource
    }

    Write-EventLog -LogName $EventLog -Source $EventSource -EventId 1000 -EntryType Information -Message "Initiating Monthly OS Maintenance Sequence."

    try {
        # Phase 1: Storage & Network Hygiene
        Write-EventLog -LogName $EventLog -Source $EventSource -EventId 1001 -EntryType Information -Message "Executing NVMe/SSD TRIM and DNS Cache Flush."
        Optimize-Volume -DriveLetter C -ReTrim -ErrorAction SilentlyContinue
        Clear-DnsClientCache -ErrorAction SilentlyContinue

        # Phase 2: Proactive Component Cleanup
        Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /Quiet" -Wait -NoNewWindow

        # Phase 3: Online NTFS Scan
        $ChkdskProcess = Start-Process -FilePath "chkdsk.exe" -ArgumentList "C: /scan /perf" -Wait -NoNewWindow -PassThru
        if ($ChkdskProcess.ExitCode -ne 0) {
            Write-EventLog -LogName $EventLog -Source $EventSource -EventId 2500 -EntryType Warning -Message "CHKDSK detected potential disk corruption. Please review the Application Event Log for OS-Maintenance."
            $DiskAlertCmd = "powershell.exe -WindowStyle Hidden -Command `"Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Automated Maintenance detected potential disk corruption. Please review the Application Event Log for OS-Maintenance.', 'System Health Alert', 'OK', 'Error')`""
            Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "DiskCorruptionAlert" -Value $DiskAlertCmd
        }

        # Phase 4: Conditional Repair Logic
        $SfcProcess = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -Wait -NoNewWindow -PassThru

        if ($SfcProcess.ExitCode -ne 0) {
            Write-EventLog -LogName $EventLog -Source $EventSource -EventId 2000 -EntryType Warning -Message "SFC detected corruption. Initiating DISM RestoreHealth."
            Start-Process -FilePath "dism.exe" -ArgumentList "/Online /Cleanup-Image /RestoreHealth /Quiet" -Wait -NoNewWindow
            
            $SfcVerify = Start-Process -FilePath "sfc.exe" -ArgumentList "/scannow" -Wait -NoNewWindow -PassThru
            
            if ($SfcVerify.ExitCode -ne 0) {
                Write-EventLog -LogName $EventLog -Source $EventSource -EventId 3000 -EntryType Error -Message "CRITICAL: DISM/SFC failed to repair system corruption."
                $AlertCmd = "powershell.exe -WindowStyle Hidden -Command `"Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Automated Maintenance detected unrepaired OS corruption. Please review the Application Event Log for OS-Maintenance.', 'System Health Alert', 'OK', 'Error')`""
                Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" -Name "OSCorruptionAlert" -Value $AlertCmd
            } else {
                Write-EventLog -LogName $EventLog -Source $EventSource -EventId 1002 -EntryType Information -Message "System corruption successfully repaired via DISM."
            }
        } else {
            Write-EventLog -LogName $EventLog -Source $EventSource -EventId 1003 -EntryType Information -Message "SFC verification passed. No corruption detected."
        }

        # Phase 5: Stale Temporary Data Purge (> 14 Days Old)
        $TempPaths = @("$env:WINDIR\Temp\*", "$env:LOCALAPPDATA\Temp\*")
        $Threshold = (Get-Date).AddDays(-14)
        foreach ($Path in $TempPaths) {
            Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue | 
                Where-Object { $_.LastWriteTime -lt $Threshold } | 
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
        }

        Clear-RecycleBin -Force -ErrorAction SilentlyContinue

        Write-EventLog -LogName $EventLog -Source $EventSource -EventId 1004 -EntryType Information -Message "Monthly OS Maintenance Sequence completed successfully."
    }
    catch {
        Write-EventLog -LogName $EventLog -Source $EventSource -EventId 4000 -EntryType Error -Message "Fatal execution error in Maintenance Sequence: $_"
    }
}

# 2. Encode the Payload to Base64
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($MaintenancePayload.ToString())
$EncodedCommand = [Convert]::ToBase64String($Bytes)

# 3. Detect OS version correctly (Bypass NT 10.0 kernel overlap for Win 11)
$OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$OSCaption = if ($null -ne $OSInfo) { $OSInfo.Caption } else { "Unknown" }
$IsWindows10 = $OSCaption -match "Windows 10"

Write-Host "[*] Detected OS: $OSCaption. Skip interactive tasks: $IsWindows10" -ForegroundColor Cyan

# 4. Define Scheduled Task Parameters
$TaskName = "Automated-OS-Maintenance"
$TaskDescription = "Performs conditional OS maintenance, image servicing, and telemetry injection."
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $EncodedCommand"

$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -WeeksInterval 4 -At 2:00AM
$Trigger.RandomDelay = "PT2H" # FIXED: Strict ISO 8601 compliance required for XML parsing

$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew

# 5. Idempotent State Teardown
$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $ExistingTask) {
    Write-Host "[-] Existing task detected. Executing teardown sequence..." -ForegroundColor Yellow
    if ($ExistingTask.State -eq 'Running') {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Write-Host "[-] Halted active execution of '$TaskName'." -ForegroundColor Yellow
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}

# 6. Register the Maintenance Task
Register-ScheduledTask -TaskName $TaskName -Description $TaskDescription -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force -ErrorAction Stop | Out-Null
Write-Host "[+] Scheduled task '$TaskName' successfully registered and initialized." -ForegroundColor Green

# 7. Register Weekly Auto-Update Task
if ($IsWindows10) {
    Write-Host "[!] Skipping auto-update task registration due to interactive UI bounds on Windows 10." -ForegroundColor Yellow
}
else {
    $AutoUpdateCommands = @()

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $AutoUpdateCommands += 'winget upgrade --all --silent --accept-source-agreements --accept-package-agreements'
    } else {
        Write-Host "[-] 'winget' not found; skipping winget upgrades." -ForegroundColor Yellow
    }

    # FIXED: Bootstrap NuGet Provider to prevent Session 0 execution hang
    $AutoUpdateCommands += 'Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers -ErrorAction SilentlyContinue'
    $AutoUpdateCommands += 'Install-Module PSWindowsUpdate -Force -AcceptLicense -AllowClobber -ErrorAction SilentlyContinue'
    $AutoUpdateCommands += 'Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue'
    $AutoUpdateCommands += 'Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot -ErrorAction SilentlyContinue'

    if ($AutoUpdateCommands.Count -eq 0) {
        Write-Host "[-] No auto-update commands available; not registering auto-update task." -ForegroundColor Yellow
    }
    else {
        $AutoUpdateScript = $AutoUpdateCommands -join "`n"
        $AutoUpdateBytes = [System.Text.Encoding]::Unicode.GetBytes($AutoUpdateScript)
        $AutoUpdateEncoded = [Convert]::ToBase64String($AutoUpdateBytes)
        
        $AutoUpdateTaskName = "Automated-OS-AutoUpdate"
        $AutoUpdateDescription = "Automated silent app updates via Winget and Windows Update via PSWindowsUpdate module."
        $AutoUpdateAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $AutoUpdateEncoded"
        
        $AutoUpdateTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3:00AM
        $AutoUpdateTrigger.RandomDelay = "PT2H" # FIXED: Strict ISO 8601 compliance
        
        $AutoUpdatePrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        Register-ScheduledTask -TaskName $AutoUpdateTaskName -Description $AutoUpdateDescription -Action $AutoUpdateAction -Trigger $AutoUpdateTrigger -Principal $AutoUpdatePrincipal -Settings $Settings -Force -ErrorAction Stop | Out-Null
        Write-Host "[+] Scheduled task '$AutoUpdateTaskName' successfully registered and initialized." -ForegroundColor Green
    }
}