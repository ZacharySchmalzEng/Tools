<#
.SYNOPSIS
    Deploys an idempotent, Base64-encoded Windows OS maintenance scheduled task.

.DESCRIPTION
    Registers a monthly scheduled task executing in the SYSTEM context. The payload performs:
    1. Storage optimization (TRIM) and DNS cache flushing.
    2. Proactive WinSxS component store cleanup.
    3. Online NTFS health auditing.
    4. Conditional DISM/SFC system file repair.
    5. Aggressive purging of temporary data older than 14 days.
    6. Native Application Event Log telemetry injection (Source: OS-Maintenance).

.EXAMPLE
    PS C:\> .\Deploy-OSMaintenanceTask.ps1
    Executes the deployment, automatically tearing down any existing task registration before initializing the new payload.

.NOTES
    Name:           Deploy-OSMaintenanceTask.ps1
    Author:         Zachary Schmalz
    Version:        1.0.0
    Date:           2026-05-27
    Repository:     https://github.com/ZacharySchmalzEng/Tools
    Changes:        Initial deployment featuring idempotency, conditional repair logic, and Session 0 alert bypass.
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
        Start-Process -FilePath "chkdsk.exe" -ArgumentList "C: /scan /perf" -Wait -NoNewWindow

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

# 3. Define Scheduled Task Parameters
$TaskName = "Automated-OS-Maintenance"
$TaskDescription = "Performs conditional OS maintenance, image servicing, and telemetry injection."
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $EncodedCommand"

$Trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -WeeksInterval 4 -At 2:00AM
$Trigger.RandomDelay = [TimeSpan]::FromHours(2)

$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew

# 4. Idempotent State Teardown
$ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($null -ne $ExistingTask) {
    Write-Host "[-] Existing task detected. Executing teardown sequence..." -ForegroundColor Yellow
    if ($ExistingTask.State -eq 'Running') {
        Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        Write-Host "[-] Halted active execution of '$TaskName'." -ForegroundColor Yellow
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}

# 5. Register the Scheduled Task
Register-ScheduledTask -TaskName $TaskName -Description $TaskDescription -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null

Write-Host "[+] Scheduled task '$TaskName' successfully registered and initialized." -ForegroundColor Green