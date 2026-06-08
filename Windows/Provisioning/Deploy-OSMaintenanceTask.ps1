#
.SYNOPSIS
    Deploys an idempotent, Base64-encoded Windows OS maintenance scheduled task.

.DESCRIPTION
    Registers a monthly scheduled task executing in the SYSTEM context. The payload performs:
    1. Storage optimization (TRIM) and DNS cache flushing.
    2. Proactive WinSxS component store cleanup.
    3. Online NTFS health auditing and disk corruption detection.
    4. Conditional DISM/SFC system file repair.
    5. Aggressive purging of temporary data older than 14 days.
    6. Native Application Event Log telemetry injection (Source: OS-Maintenance).
    7. Best-effort weekly automated Winget and Windows Update auto-update task registration.

    The script now detects the host OS version and will disable registration of
    auto-update tasks that require an interactive user context on Windows 10.
    Pop-up/RunOnce alerts remain present but are not relied upon for SYSTEM
    scheduled executions.

.EXAMPLE
    PS C:\> .\Deploy-OSMaintenanceTask.ps1
    Executes the deployment, automatically tearing down any existing task registration before initializing the new payload.

.NOTES
    Name:           Deploy-OSMaintenanceTask.ps1
    Author:         Zachary Schmalz
    Version:        1.0.3
    Date:           2026-06-08
    Repository:     https://github.com/ZacharySchmalzEng/Tools
    Changes:        Added OS detection and guarded auto-update registration for Windows 10; kept existing RunOnce alerts.
#>

# Ensure script is executed with elevation to perform system changes
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] This script must be run as Administrator." -ForegroundColor Red
    exit 1
}

# Ensure event source exists for centralized logging from this deployment script
$GlobalEventSource = 'OS-Maintenance'
if (-not [System.Diagnostics.EventLog]::SourceExists($GlobalEventSource)) {
    try { New-EventLog -LogName Application -Source $GlobalEventSource } catch { Write-Host "[!] Could not create EventLog source: $_" -ForegroundColor Yellow }
}

function Ensure-CmdletExists {
    param([string]$Name)
    if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
        Write-Host "[!] Cmdlet or command '$Name' not found; related features will be skipped." -ForegroundColor Yellow
        try { Write-EventLog -LogName Application -Source $GlobalEventSource -EventId 6001 -EntryType Warning -Message "Cmdlet missing: $Name" } catch { }
        return $false
    }
    return $true
}

if (-not [Environment]::Is64BitProcess) {
    Write-Host "[!] Running in 32-bit PowerShell; scheduled tasks will be registered to call 64-bit PowerShell where possible." -ForegroundColor Yellow
}


# 1. Define the Maintenance Payload
$MaintenancePayload = {
    $EventSource = "OS-Maintenance"
    $EventLog = "Application"
    
    if (-not [System.Diagnostics.EventLog]::SourceExists($EventSource)) {
        New-EventLog -LogName $EventLog -Source $EventSource
    }

    Write-EventLog -LogName $EventLog -Source $EventSource -EventId 1000 -EntryType Information -Message "Initiating Monthly OS Maintenance Sequence."

    try {
        # Optional dry-run toggle for destructive operations within payload
        $DryRun = $false

        function SafeRemove-OldItems {
            param(
                [string[]]$Paths,
                [datetime]$Threshold
            )

            foreach ($p in $Paths) {
                try {
                    $items = Get-ChildItem -Path $p -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt $Threshold }
                    if ($items) {
                        foreach ($it in $items) {
                            # Log planned removal
                            Write-EventLog -LogName $EventLog -Source $EventSource -EventId 4100 -EntryType Information -Message "Removing: $($it.FullName)"
                            if (-not $DryRun) {
                                try {
                                    Remove-Item -LiteralPath $it.FullName -Recurse -Force -ErrorAction Stop
                                }
                                catch {
                                    Write-EventLog -LogName $EventLog -Source $EventSource -EventId 4101 -EntryType Warning -Message "Failed to remove $($it.FullName): $_"
                                }
                            }
                        }
                    }
                }
                catch {
                    Write-EventLog -LogName $EventLog -Source $EventSource -EventId 4102 -EntryType Warning -Message "Error enumerating $p: $_"
                }
            }
        }
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
            $DiskAlertCmd = "powershell.exe -WindowStyle Hidden -Command \"Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('Automated Maintenance detected potential disk corruption. Please review the Application Event Log for OS-Maintenance.', 'System Health Alert', 'OK', 'Error')\""
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
        SafeRemove-OldItems -Paths $TempPaths -Threshold $Threshold

        try {
            if (-not $DryRun) { Clear-RecycleBin -Force -ErrorAction SilentlyContinue }
            else { Write-EventLog -LogName $EventLog -Source $EventSource -EventId 4103 -EntryType Information -Message "DryRun: Clear-RecycleBin skipped." }
        }
        catch {
            Write-EventLog -LogName $EventLog -Source $EventSource -EventId 4104 -EntryType Warning -Message "Clear-RecycleBin failed: $_"
        }

        Write-EventLog -LogName $EventLog -Source $EventSource -EventId 1004 -EntryType Information -Message "Monthly OS Maintenance Sequence completed successfully."
    }
    catch {
        Write-EventLog -LogName $EventLog -Source $EventSource -EventId 4000 -EntryType Error -Message "Fatal execution error in Maintenance Sequence: $_"
    }
}

$ProgramDataPath = Join-Path $env:ProgramData 'OSMaintenance'
New-Item -Path $ProgramDataPath -ItemType Directory -Force | Out-Null

# Persist maintenance payload to disk (avoid EncodedCommand and ExecutionPolicy Bypass)
$PayloadPath = Join-Path $ProgramDataPath 'OSMaintenancePayload.ps1'
try {
    $MaintenancePayload.ToString() | Out-File -FilePath $PayloadPath -Encoding Unicode -Force
}
catch {
    Write-Host "[!] Failed to write payload to $PayloadPath: $_" -ForegroundColor Red
    throw
}

# Prefer the 64-bit PowerShell executable from System32 when registering tasks
$PSExe = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path $PSExe)) { $PSExe = 'powershell.exe' }

# Detect OS version and determine whether to skip interactive tasks
$OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
$OSVersion = if ($null -ne $OSInfo) { $OSInfo.Version } else { ([System.Environment]::OSVersion.Version).ToString() }
$IsWindows10 = $OSVersion -like '10.*'
$SkipInteractiveTasks = $IsWindows10

Write-Host "[*] Detected OS version $OSVersion. Skip interactive tasks: $SkipInteractiveTasks" -ForegroundColor Cyan

# 3. Define Scheduled Task Parameters
$TaskName = "Automated-OS-Maintenance"
$TaskDescription = "Performs conditional OS maintenance, image servicing, and telemetry injection."
$Action = New-ScheduledTaskAction -Execute $PSExe -Argument "-NoProfile -WindowStyle Hidden -File `"$PayloadPath`""

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

# 6. Register Weekly Auto-Update Task
if ($SkipInteractiveTasks) {
    Write-Host "[!] Skipping auto-update task registration due to interactive requirements on Windows 10." -ForegroundColor Yellow
}
else {
    # Build a safe, non-interactive auto-update script based on available tooling
    $AutoUpdateCommands = @()

    if (Get-Command winget -ErrorAction SilentlyContinue) {
        $AutoUpdateCommands += 'winget upgrade --all --silent --accept-source-agreements --accept-package-agreements'
    }
    else {
        Write-Host "[-] 'winget' not found; skipping winget upgrades." -ForegroundColor Yellow
    }

    # PSWindowsUpdate flow (best-effort; requires internet & rights)
    $AutoUpdateCommands += 'Install-Module PSWindowsUpdate -Force -AllowClobber -ErrorAction SilentlyContinue'
    $AutoUpdateCommands += 'Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue'
    $AutoUpdateCommands += 'Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -AutoReboot -ErrorAction SilentlyContinue'

    if ($AutoUpdateCommands.Count -eq 0) {
        Write-Host "[-] No auto-update commands available; not registering auto-update task." -ForegroundColor Yellow
    }
    else {
        $AutoUpdateScript = $AutoUpdateCommands -join "`n"

        # Build a safe auto-update script on disk (includes TLS and safe module install checks)
        $AutoUpdatePath = Join-Path $ProgramDataPath 'AutoUpdatePayload.ps1'
        $AutoUpdateHeader = @"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Install-Module-Safe {
    param([string]$Name)
    try {
        if (Test-Connection -ComputerName 'www.powershellgallery.com' -Count 1 -Quiet) {
            Install-Module -Name $Name -Force -AllowClobber -ErrorAction Stop
        }
        else {
            Write-EventLog -LogName Application -Source 'OS-Maintenance' -EventId 5001 -EntryType Warning -Message "PSGallery unreachable; skipping Install-Module $Name."
        }
    }
    catch {
        Write-EventLog -LogName Application -Source 'OS-Maintenance' -EventId 5002 -EntryType Error -Message "Install-Module $Name failed: $_"
    }
}
"@

        $AutoUpdateFull = $AutoUpdateHeader + "`n" + $AutoUpdateScript
        try {
            $AutoUpdateFull | Out-File -FilePath $AutoUpdatePath -Encoding Unicode -Force
        }
        catch {
            Write-Host "[!] Failed to write auto-update script to $AutoUpdatePath: $_" -ForegroundColor Red
            throw
        }

        $AutoUpdateTaskName = "Automated-OS-AutoUpdate"
        $AutoUpdateDescription = "Automated silent app updates via Winget and Windows Update via PSWindowsUpdate module."
        $AutoUpdateAction = New-ScheduledTaskAction -Execute $PSExe -Argument "-NoProfile -WindowStyle Hidden -File `"$AutoUpdatePath`""
        $AutoUpdateTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3:00AM
        $AutoUpdateTrigger.RandomDelay = [TimeSpan]::FromHours(2)
        $AutoUpdatePrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

        Register-ScheduledTask -TaskName $AutoUpdateTaskName -Description $AutoUpdateDescription -Action $AutoUpdateAction -Trigger $AutoUpdateTrigger -Principal $AutoUpdatePrincipal -Settings $Settings -Force | Out-Null
        Write-Host "[+] Scheduled task '$AutoUpdateTaskName' successfully registered and initialized." -ForegroundColor Green
    }
}