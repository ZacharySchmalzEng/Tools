<#
.SYNOPSIS
    Automated Windows 10/11 Pro, Home, and Server provisioning and environment setup script.
.AUTHOR
    Zachary Schmalz
.NOTES
    Name: Windows-Deployment-Tool.ps1
    Version: 6.10.1
    Date: 2026-04-06
    Changes: Added -Light profile, Base64 -Maintenance Scheduled Task, and global -Uninstall flag with native .exe/.msi support.
#>

param (
    [switch]$System,
    [switch]$Debloat,
    [switch]$Security,
    [switch]$Dev,
    [switch]$Apps,
    [switch]$DevApps,
    [switch]$Cyber,
    [switch]$Maker,
    [switch]$Gaming,
    [switch]$Nvidia,
    [switch]$Creators,
    [switch]$DualBoot,
    [switch]$AutoUpdate,
    [switch]$Standard,
    [switch]$Complete,
    [switch]$Light,
    [switch]$Maintenance,
    [switch]$Uninstall,
    [switch]$Help
)

# ==============================================================================
# WINDOWS EVENT LOGGING
# ==============================================================================

$script:EventLogName = 'Application'
$script:EventLogSource = 'Windows-Deployment-Tool.ps1'
$script:EventLogEnabled = $true
$script:EventLogInitialized = $false

function Initialize-DeploymentEventLog {
    if ($script:EventLogInitialized -or -not $script:EventLogEnabled) { return }

    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($script:EventLogSource)) {
            New-EventLog -LogName $script:EventLogName -Source $script:EventLogSource -ErrorAction Stop
        }
        $script:EventLogInitialized = $true
    } catch {
        $script:EventLogEnabled = $false
        Microsoft.PowerShell.Utility\Write-Warning "Could not initialize Windows event log source '$script:EventLogSource'. Event logging disabled. Error: $_"
    }
}

function Write-DeploymentEventLogEntry {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('Information', 'Warning', 'Error')]
        [string]$EntryType = 'Information',

        [int]$EventId = 1000
    )

    if (-not $script:EventLogEnabled) { return }

    Initialize-DeploymentEventLog | Out-Null
    if (-not $script:EventLogInitialized) { return }

    try {
        Write-EventLog -LogName $script:EventLogName -Source $script:EventLogSource -EntryType $EntryType -EventId $EventId -Message $Message
    } catch {
        $script:EventLogEnabled = $false
    }
}

function global:Write-Host {
    [CmdletBinding(DefaultParameterSetName = 'Object')]
    param(
        [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
        [object]$Object,
        [Nullable[System.ConsoleColor]]$BackgroundColor,
        [Nullable[System.ConsoleColor]]$ForegroundColor,
        [switch]$NoNewline,
        [string]$Separator
    )

    $writeHostParams = @{ Object = $Object }
    if ($PSBoundParameters.ContainsKey('BackgroundColor')) { $writeHostParams.BackgroundColor = $BackgroundColor }
    if ($PSBoundParameters.ContainsKey('ForegroundColor')) { $writeHostParams.ForegroundColor = $ForegroundColor }
    if ($PSBoundParameters.ContainsKey('NoNewline')) { $writeHostParams.NoNewline = $NoNewline.IsPresent }
    if ($PSBoundParameters.ContainsKey('Separator')) { $writeHostParams.Separator = $Separator }

    Microsoft.PowerShell.Utility\Write-Host @writeHostParams

    if ($null -ne $Object) {
        $messageText = [string]$Object
        if (-not [string]::IsNullOrWhiteSpace($messageText)) {
            Write-DeploymentEventLogEntry -Message $messageText -EntryType Information
        }
    }
}

function global:Write-Warning {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
        [object]$Message
    )

    Microsoft.PowerShell.Utility\Write-Warning -Message $Message
    if ($null -ne $Message) {
        Write-DeploymentEventLogEntry -Message ([string]$Message) -EntryType Warning -EventId 2000
    }
}

function global:Write-Error {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
        [object]$Message
    )

    Microsoft.PowerShell.Utility\Write-Error -Message $Message
    if ($null -ne $Message) {
        Write-DeploymentEventLogEntry -Message ([string]$Message) -EntryType Error -EventId 3000
    }
}

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

function Get-LinuxDiskPath {
    Write-Host "--- Scanning for Linux partitions... ---" -ForegroundColor Yellow
    $LinuxDisk = Get-Partition | Where-Object { $_.Type -eq 'Unknown' -or $_.GptType -eq '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' } | Sort-Object Size -Descending | Select-Object -First 1

    if ($null -ne $LinuxDisk) {
        $DiskNum = $LinuxDisk.DiskNumber
        $PartNum = $LinuxDisk.PartitionNumber
        return @{ Path = "\\.\PHYSICALDRIVE$DiskNum"; Partition = $PartNum; Found = $true }
    } else {
        return @{ Path = "\\.\PHYSICALDRIVE1"; Partition = "2"; Found = $false }
    }
}

function Test-IsServerOS {
    $OS = Get-CimInstance Win32_OperatingSystem
    return $OS.ProductType -ne 1
}

function Test-IsWin11 {
    return [Environment]::OSVersion.Version.Build -ge 22000
}

function Set-RegTweak {
    param([string]$Path, [string]$Name, $Value, [string]$Type="DWord")
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
    $current = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $current -or $current.$Name -ne $Value) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force
        Write-Host "Applied tweak: $Name -> $Value" -ForegroundColor Green
    } else {
        Write-Host "Already applied: $Name" -ForegroundColor DarkGray
    }
}

function Uninstall-NativeApp {
    param([string]$DisplayName)
    
    $uninstallPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    $apps = Get-ItemProperty $uninstallPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match $DisplayName }
    
    if ($apps) {
        foreach ($app in $apps) {
            $uninstallString = $app.QuietUninstallString
            if ([string]::IsNullOrWhiteSpace($uninstallString)) {
                $uninstallString = $app.UninstallString
            }
            
            if ($uninstallString) {
                Write-Host "--- Uninstalling $($app.DisplayName)... ---" -ForegroundColor Yellow
                
                if ($uninstallString -match "msiexec") {
                    $uninstallString = $uninstallString -ireplace "/I", "/X"
                    if ($uninstallString -notmatch "/qn" -and $uninstallString -notmatch "/quiet") {
                        $uninstallString += " /qn /norestart"
                    }
                }
                
                try {
                    Start-Process cmd.exe -ArgumentList "/c `"$uninstallString`"" -Wait -NoNewWindow
                    Write-Host "$($app.DisplayName) uninstalled successfully." -ForegroundColor Green
                } catch {
                    Write-Warning "Failed to execute uninstall string for $($app.DisplayName)."
                }
            } else {
                Write-Warning "Found $($app.DisplayName) in registry, but no uninstall string was present."
            }
        }
    } else {
        Write-Host "$DisplayName is not installed or not found in registry. Skipping..." -ForegroundColor DarkGray
    }
}

# ==============================================================================
# PARAMETER LOGIC & PROFILES
# ==============================================================================

if ($Complete) { 
    $System = $true; $Debloat = $true; $Security = $true; $Dev = $true;  
    $Apps = $true; $DevApps = $true; $Cyber = $true; $Maker = $true; 
    $Gaming = $true; $Nvidia = $true; $Creators = $true; $AutoUpdate = $true; $Maintenance = $true;
}
if ($Standard) { 
    $System = $true; $Debloat = $true; $Security = $true; $Apps = $true; $AutoUpdate = $true; $Maintenance = $true;
}
if ($Light) {
    $System = $true; $Debloat = $true; $Security = $true;
}

$RunSoftware = ($Apps -or $DevApps -or $Cyber -or $Maker -or $Gaming -or $Nvidia -or $Creators)
$RunAny = ($System -or $Debloat -or $Security -or $Dev -or $DualBoot -or $RunSoftware -or $AutoUpdate -or $Maintenance)

if (-not $RunAny) { $Help = $true }

if ($Help) {
    Write-Host "`n================================================================" -ForegroundColor Cyan
    Write-Host " WINDOWS DEPLOYMENT TOOL HELP MENU" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "Usage: .\Windows-Deployment-Tool.ps1 [OPTIONS]"
    Write-Host "NOTE: Must be executed with: powershell.exe -ExecutionPolicy Bypass -File .\Windows-Deployment-Tool.ps1`n" -ForegroundColor Yellow
    Write-Host "PROFILES:"
    Write-Host " -Standard      Baselines (System, Debloat, Security, Apps, AutoUpdate, Maintenance)"
    Write-Host " -Complete      Full Suite (All modules including Gaming, Dev, Cyber, etc.)"
    Write-Host " -Light         Core OS only (System, Debloat, Security) - No Apps"
    Write-Host "`nINDIVIDUAL MODULES:"
    Write-Host " -System        Registry tweaks, power plans, and UI adjustments."
    Write-Host " -Debloat       Removes Windows consumer bloatware and widgets."
    Write-Host " -Security      Hardens Defender, disables telemetry, and applies updates."
    Write-Host " -Dev           Enables WSL, Virtual Machine Platform, Sudo (Inline), and SSH."
    Write-Host " -DualBoot      Configures auto-mounting for Linux partitions via WSL."
    Write-Host " -Apps          Installs general productivity apps (Brave, Discord, WhatsApp, etc.)"
    Write-Host " -DevApps       Installs development tools (VS Code, Python, OpenSSL, etc.)"
    Write-Host " -Cyber         Installs security tools (Wireshark, Nmap, etc.)"
    Write-Host " -Maker         Installs 3D printing tools (OrcaSlicer, Fusion360, etc.)"
    Write-Host " -Creators      Installs creative tools (Blender, Darktable, Audacity, etc.)"
    Write-Host " -Gaming        Installs Steam, OBS, and Battle.net."
    Write-Host " -Nvidia        Installs the latest NVIDIA App."
    Write-Host " -AutoUpdate    Configures a weekly scheduled task for silent Winget and OS updates."
    Write-Host " -Maintenance   Configures a monthly scheduled task for SFC, DISM, and temp cleanup."
    Write-Host " -Uninstall     Global modifier: Reverts configurations and uninstalls matched apps."
    Write-Host " -Help          Displays this help menu."
    Write-Host ""
    return
}

# ==============================================================================
# PRE-FLIGHT CHECKS
# ==============================================================================

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Administrator permissions are required to run provisioning modules."
    Write-Host "Please re-run this script with 'Run as Administrator'."
    Start-Sleep -Seconds 5
    return
}

$ScriptDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$LogDir = Join-Path -Path $ScriptDir -ChildPath "InstallerLogs"
$InstallerDir = Join-Path -Path $ScriptDir -ChildPath "Installers"

if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $InstallerDir)) { New-Item -Path $InstallerDir -ItemType Directory -Force | Out-Null }

$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogFile = "installer_log_$Timestamp.log"
$LogPath = Join-Path -Path $LogDir -ChildPath $LogFile

Start-Transcript -Path $LogPath
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host "Running with Administrator privileges." -ForegroundColor Green
Set-Location -Path $ScriptDir

$IsWin11 = Test-IsWin11
if ($IsWin11) { Write-Host "Windows 11 Detected. Enabling Win11-specific configurations." -ForegroundColor Cyan }
else { Write-Host "Windows 10/Home Detected. Bypassing Win11-specific configurations." -ForegroundColor Cyan }

try {
    $logFiles = Get-ChildItem -Path $LogDir -Filter "*.log" | Sort-Object CreationTime -Descending
    if ($logFiles.Count -gt 10) {
        $filesToDelete = $logFiles | Select-Object -Skip 10
        foreach ($file in $filesToDelete) { Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue }
    }
} catch { Write-Warning "Could not perform log rotation. Error: $_" }

# ==============================================================================
# MODULE: DEBLOAT
# ==============================================================================
if ($Debloat) {
    if ($Uninstall) {
        Write-Host "`n[-] DEBLOAT REVERSION NOT SUPPORTED. Re-install apps manually from the Windows Store." -ForegroundColor DarkGray
    } else {
        Write-Host "`n[+] STARTING DEBLOAT MODULE..." -ForegroundColor Magenta

        if ($IsWin11) {
            Write-Host "--- Checking Windows 11 Widgets... ---" -ForegroundColor Yellow
            $WidgetsCheck = Get-AppxPackage -Name "MicrosoftWindows.Client.WebExperience"
            if ($null -ne $WidgetsCheck) {
                winget uninstall --id 9MSSGKG348SP --silent
                if ($LASTEXITCODE -eq 0) { Write-Host "--- Windows Widgets uninstalled successfully. ---" -ForegroundColor Green }
            } else {
                Write-Host "Windows Widgets already removed. Skipping..." -ForegroundColor DarkGray
            }
        }

        Write-Host "--- Checking Windows Consumer Features... ---" -ForegroundColor Yellow
        Set-RegTweak -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Value 1

        Write-Host "--- Checking select pre-installed Appx packages... ---" -ForegroundColor Yellow
        $bloatware = @(
            "*Microsoft.BingNews*", "*Microsoft.GetHelp*", "*Microsoft.Getstarted*",  
            "*Microsoft.MicrosoftOfficeHub*", "*Microsoft.MicrosoftSolitaireCollection*",  
            "*Microsoft.PowerAutomateDesktop*", "*Microsoft.Todos*"
        )
        foreach ($app in $bloatware) {
            if (Get-AppxPackage -Name $app) {
                Write-Host "Removing $app..."
                Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
                Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
            }
        }
        Write-Host "--- Appx debloat routine complete. ---" -ForegroundColor Green
    }
}

# ==============================================================================
# MODULE: SYSTEM
# ==============================================================================
if ($System) {
    if ($Uninstall) {
        Write-Host "`n[-] SYSTEM TWEAK REVERSION NOT IMPLEMENTED AUTOMATICALLY." -ForegroundColor DarkGray
    } else {
        Write-Host "`n[+] STARTING SYSTEM MODULE..." -ForegroundColor Magenta
        Write-Host "--- Checking core system & registry tweaks... ---" -ForegroundColor Yellow
        try {
            Set-RegTweak -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Value 1
            Set-RegTweak -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MSAOptional" -Value 1
            Set-RegTweak -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\OOBE" -Name "DisablePrivacyExperience" -Value 1
            Set-RegTweak -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name "LongPathsEnabled" -Value 1 
            $ExplorerKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            Set-RegTweak -Path $ExplorerKey -Name "Hidden" -Value 1
            Set-RegTweak -Path $ExplorerKey -Name "HideFileExt" -Value 0

            # ------------------------------------------------------------------
            # SCHEDULED TASK HISTORY ENABLEMENT
            # ------------------------------------------------------------------
            Write-Host "--- Checking Task Scheduler ETW Logging... ---" -ForegroundColor Yellow
            $TaskEtwStatus = wevtutil gl Microsoft-Windows-TaskScheduler/Operational | Select-String "enabled: true"
            if (-not $TaskEtwStatus) {
                wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
                Write-Host "Applied tweak: Scheduled Task History Enabled" -ForegroundColor Green
            } else { 
                Write-Host "Already applied: Scheduled Task History" -ForegroundColor DarkGray 
            }
            # ------------------------------------------------------------------

            if ($IsWin11) {
                Write-Host "--- Checking Windows 11-specific UI tweaks... ---" -ForegroundColor Yellow
                $ContextMenuKey = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
                if (-not (Test-Path $ContextMenuKey)) { 
                    New-Item -Path $ContextMenuKey -Force | Out-Null
                    Set-ItemProperty -Path $ContextMenuKey -Name "(Default)" -Value "" -Force
                    Write-Host "Applied tweak: Classic Context Menu" -ForegroundColor Green
                } else { Write-Host "Already applied: Classic Context Menu" -ForegroundColor DarkGray }

                Set-RegTweak -Path $ExplorerKey -Name "TaskbarAl" -Value 0
            }
        } catch { Write-Error "Failed to apply system registry tweaks. Error: $_" }

        Write-Host "--- Checking Power Plan... ---" -ForegroundColor Yellow
        try {
            $existingPlans = powercfg -list
            $ultimatePlan = $existingPlans | Select-String "Ultimate Performance" | Select-Object -First 1 
            $PlanGUID = $null
            if ($ultimatePlan) {
                $PlanGUID = [regex]::Match($ultimatePlan, '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})').Value
                Write-Host "Ultimate Performance plan is already available on this system." -ForegroundColor DarkGray
            } else {
                $Plan = powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
                $PlanGUID = [regex]::Match($Plan, '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})').Value
                Write-Host "Ultimate Performance plan unlocked." -ForegroundColor Green
            }

            $activePlan = powercfg -getactivescheme
            if ($activePlan -notmatch $PlanGUID) {
                $title = "Power Plan Configuration"
                $message = "Would you like to activate the Ultimate Performance power plan now? (Select No to maintain your current energy-efficient settings)."
                $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Activates Ultimate Performance."
                $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Leaves current plan active."
                $choices = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)  
                $decision = $Host.UI.PromptForChoice($title, $message, $choices, 1)  

                if ($decision -eq 0) {
                    powercfg -setactive $PlanGUID
                    Write-Host "Ultimate Performance enabled." -ForegroundColor Green
                } else { Write-Host "Leaving current power plan active." -ForegroundColor DarkGray }
            } else { Write-Host "Ultimate Performance Power Plan is already active. Skipping..." -ForegroundColor DarkGray }
        } catch { Write-Warning "Could not configure power plan. Error: $_" }
    }
}

# ==============================================================================
# MODULE: SECURITY (Part 1 - Policies)
# ==============================================================================
if ($Security) {
    if ($Uninstall) {
        Write-Host "`n[-] SECURITY TWEAK REVERSION NOT IMPLEMENTED AUTOMATICALLY." -ForegroundColor DarkGray
    } else {
        Write-Host "`n[+] STARTING SECURITY MODULE (Policies)..." -ForegroundColor Magenta
        Write-Host "--- Checking Windows Telemetry... ---" -ForegroundColor Yellow
        Set-RegTweak -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0

        Write-Host "--- Checking Defender PUA Protection... ---" -ForegroundColor Yellow
        try {
            $mpPref = Get-MpPreference
            if ($mpPref.PUAProtection -ne 1) {
                Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
                Write-Host "PUA Protection enabled." -ForegroundColor Green
            } else { Write-Host "PUA Protection is already enabled. Skipping..." -ForegroundColor DarkGray }
        } catch { Write-Warning "Failed to enable PUA Protection. Error: $_" }
    }
}

# ==============================================================================
# MODULE: DEV (OS Features)
# ==============================================================================
if ($Dev) {
    $features = @("Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform", "Containers-DisposableClientVM")
    
    if ($Uninstall) {
        Write-Host "`n[-] DISABLING DEV OS FEATURES..." -ForegroundColor DarkYellow
        foreach ($feature in $features) {
            Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -WarningAction SilentlyContinue | Out-Null
            Write-Host "Disabled Feature: $feature" -ForegroundColor Green
        }
        
        Write-Host "--- Disabling Windows 11 Sudo... ---" -ForegroundColor Yellow
        Set-RegTweak -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sudo" -Name "EnableSudo" -Value 0
        
    } else {
        Write-Host "`n[+] STARTING DEV MODULE (OS Features)..." -ForegroundColor Magenta 
        
        if ($IsWin11) {
            Write-Host "--- Checking Windows 11 Sudo Configuration... ---" -ForegroundColor Yellow
            try { Set-RegTweak -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Sudo" -Name "EnableSudo" -Value 3 } 
            catch { Write-Warning "Failed to configure Windows Sudo. Error: $_" }
        }

        Write-Host "--- Checking Windows Optional Features & Capabilities... ---" -ForegroundColor Yellow
        try {
            foreach ($feature in $features) {
                $checkFeature = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
                if ($checkFeature.State -ne 'Enabled') {
                    Enable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -All -WarningAction SilentlyContinue | Out-Null
                    Write-Host "Enabled Feature: $feature" -ForegroundColor Green
                } else { Write-Host "Feature $feature is already enabled. Skipping..." -ForegroundColor DarkGray }
            }

            $sshFeatures = @("OpenSSH.Client~~~~0.0.1.0", "OpenSSH.Server~~~~0.0.1.0")
            foreach ($ssh in $sshFeatures) {
                $checkCapability = Get-WindowsCapability -Online -Name $ssh -ErrorAction SilentlyContinue
                if ($checkCapability.State -ne 'Installed') {
                    Write-Host "Installing Capability: $ssh..."
                    Add-WindowsCapability -Online -Name $ssh -ErrorAction SilentlyContinue | Out-Null
                    Write-Host "Installed Capability: $ssh" -ForegroundColor Green
                } else { Write-Host "Capability $ssh is already installed. Skipping..." -ForegroundColor DarkGray }
            }

            try {
                $sshService = Get-Service -Name sshd -ErrorAction SilentlyContinue
                if ($sshService.StartType -ne 'Automatic' -or $sshService.Status -ne 'Running') {
                    Set-Service -Name sshd -StartupType 'Automatic' -ErrorAction SilentlyContinue
                    Start-Service sshd -ErrorAction SilentlyContinue
                    Write-Host "SSH Server (sshd) service configured and started." -ForegroundColor Green
                } else { Write-Host "SSH Server is already running and set to Automatic. Skipping..." -ForegroundColor DarkGray }
            } catch { Write-Warning "Could not configure sshd service. It may require a reboot first." }
        } catch { Write-Warning "Failed during Windows Features configuration. Error: $_" }
    }
}

# ==============================================================================
# MODULE: DUAL BOOT (Dynamic Linux Mounting)
# ==============================================================================
if ($DualBoot) {
    $TaskName = "Mount-Linux-WSL"
    
    if ($Uninstall) {
        Write-Host "`n[-] REMOVING DUAL BOOT WSL MOUNT TASK..." -ForegroundColor DarkYellow
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Host "Task '$TaskName' removed successfully." -ForegroundColor Green
    } else {
        Write-Host "`n[+] STARTING DUAL BOOT MODULE..." -ForegroundColor Magenta  
        $LinuxInfo = Get-LinuxDiskPath
        $TargetDrive = $LinuxInfo.Path
        $TargetPart = $LinuxInfo.Partition

        if ($LinuxInfo.Found) {
            Write-Host "Auto-Detected Linux partition on Disk $($TargetDrive.Replace('\\.\PHYSICALDRIVE','')), Partition $TargetPart" -ForegroundColor Green
        } else { Write-Warning "Could not auto-detect Linux partition. Defaulting to $TargetDrive." }

        Write-Host "--- Configuring Scheduled Task for Linux WSL Mount... ---" -ForegroundColor Yellow
        try {
            $CustomScriptsDir = "$env:SystemDrive\Scripts"
            if (-not (Test-Path $CustomScriptsDir)) { New-Item -Path $CustomScriptsDir -ItemType Directory -Force | Out-Null } 
            
            $MountScriptPath = Join-Path -Path $CustomScriptsDir -ChildPath "Mount-Linux.ps1"
            $MountScriptContent = @"
<#
.SYNOPSIS Automated silent background script to mount the Linux partition via WSL.
#>
`$DrivePath = "$TargetDrive"
`$PartitionNum = "$TargetPart"
`$FileSystem = "btrfs"

Start-Sleep -Seconds 15
wsl --mount `$DrivePath --partition `$PartitionNum --type `$FileSystem
"@
            Set-Content -Path $MountScriptPath -Value $MountScriptContent -Force
            Write-Host "Helper script generated/overwritten at: $MountScriptPath" -ForegroundColor Green

            $ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue 
            if ($null -ne $ExistingTask) {
                Write-Host "Task '$TaskName' already exists. Re-registering to ensure updated disk paths..." -ForegroundColor DarkGray
                Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            }

            $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$MountScriptPath`""
            $Trigger = New-ScheduledTaskTrigger -AtLogOn
            $Principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
            $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable 
            Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
            Write-Host "Scheduled Task '$TaskName' registered successfully." -ForegroundColor Green
        } catch { Write-Error "Failed to configure Dual Boot task. Error: $_" }
    }
}

# ==============================================================================
# MODULE: SOFTWARE DEPLOYMENT
# ==============================================================================
if ($RunSoftware) {
    Write-Host "`n[+] STARTING SOFTWARE DEPLOYMENT MODULE..." -ForegroundColor Magenta

    if (-not (Get-Command winget -ErrorAction SilentlyContinue) -and -not $Uninstall) {
        Write-Host "Winget not found. Bootstrapping App Installer..." -ForegroundColor Yellow
        try {
            $url = "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
            $installer = Join-Path $InstallerDir "winget.msixbundle"
            if (-not (Test-Path $installer)) { Invoke-WebRequest -Uri $url -OutFile $installer -ErrorAction Stop }
            Add-AppxPackage -Path $installer -ErrorAction Stop
            Write-Host "Winget bootstrapped successfully." -ForegroundColor Green
            Start-Sleep -Seconds 5
        } catch { Write-Warning "Failed to bootstrap Winget. Software installation may fail. Error: $_" }
    }

    if (-not $Uninstall) {
        Write-Host "--- Updating winget sources... ---" -ForegroundColor Yellow
        winget source update | Out-Null
        Write-Host "--- Taking memory snapshot of installed software... ---" -ForegroundColor Yellow
        $InstalledSoftware = winget list --accept-source-agreements | Out-String -Width 4096
    }

    $IsServer = Test-IsServerOS
    if ($IsServer -and -not $Uninstall) { Write-Host "--- Server OS detected: Substituting WinDirStat for TreeSize Free ---" -ForegroundColor Cyan }

    # Compile the array dynamically based on requested modules
    $packages = @() 
    if ($Apps) {
        $packages += "Brave.Brave", "Google.Chrome", "Mozilla.Firefox", "Opera.Opera", "7zip.7zip", 
                     "VideoLAN.VLC", "Discord.Discord", "Obsidian.Obsidian", "OpenWhisperSystems.Signal", 
                     "9NKSQGP7F2NH", "CrystalDewWorld.CrystalDiskInfo.ShizukuEdition", 
                     "Microsoft.PowerToys", "voidtools.Everything", "Microsoft.WindowsTerminal", "Rufus.Rufus" 
        if ($IsServer) { $packages += "WinDirStat.WinDirStat" } else { $packages += "JAMSoftware.TreeSize.Free" }
    } 
    if ($DevApps) {
        $packages += "Microsoft.VisualStudioCode", "GitHub.GitHubDesktop", "Python.Python.3.13", 
                     "Microsoft.PowerShell", "Notepad++.Notepad++", "PuTTY.PuTTY", "FireDaemon.OpenSSL"
    } 
    if ($Cyber) {
        $packages += "WiresharkFoundation.Wireshark", "Insecure.Nmap", "Famatech.AdvancedIPScanner"
    }
    if ($Maker) {
        $packages += "Prusa3D.PrusaSlicer", "SoftFever.OrcaSlicer", "Bambulab.Bambustudio"
    }
    if ($Creators) {
        $packages += "darktable.darktable", "BlenderFoundation.Blender", "HandBrake.HandBrake", "Audacity.Audacity", "Inkscape.Inkscape"
    }
    if ($Gaming) {
        $packages += "Valve.Steam", "OBSProject.OBSStudio"
    }

    # Execute Winget Operations
    if ($packages.Count -gt 0) {
        if ($Uninstall) {
            Write-Host "--- Uninstalling Application Stacks ---" -ForegroundColor DarkYellow
            foreach ($pkg in $packages) {
                Write-Host "Uninstalling $pkg..."
                winget uninstall --id $pkg --silent --accept-source-agreements
            }
        } else {
            foreach ($pkg in $packages) {
                $DisplayName = if ($pkg -eq "9NKSQGP7F2NH") { "WhatsApp" } else { $pkg }
                Write-Host "--- Checking status of $DisplayName ---" 
                
                if ($InstalledSoftware -match [regex]::Escape($pkg)) {
                    Write-Host "$DisplayName is already installed. Skipping..." -ForegroundColor DarkGray
                } else {
                    $null = winget list --id $pkg -e --accept-source-agreements
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "$DisplayName is already installed (Verified via Deep Check). Skipping..." -ForegroundColor DarkGray
                    } else {
                        Write-Host "Installing $DisplayName via winget..."
                        winget install --id $pkg -e --silent --accept-source-agreements --accept-package-agreements --force
                        if ($LASTEXITCODE -ne 0) { Write-Warning "Winget returned a non-zero exit code for $DisplayName." }
                    }
                }
            }
        }
    }

    # Custom Executable Handling (Nvidia App)
    if ($Nvidia) {
        Write-Host "--- Processing NVIDIA App ---" -ForegroundColor Magenta
        
        if ($Uninstall) {
            Write-Host "--- Uninstalling NVIDIA App... ---" -ForegroundColor DarkYellow
            Uninstall-NativeApp -DisplayName "NVIDIA app"
        } else {
            Write-Host "--- Checking NVIDIA App status... ---" -ForegroundColor Yellow
            try {
                $NvAppPaths = @(
                    "$env:ProgramFiles\NVIDIA Corporation\NVIDIA app\nvapp.exe",
                    "$env:ProgramFiles\NVIDIA Corporation\NVIDIA app\NVIDIA app.exe",
                    "$env:ProgramFiles\NVIDIA Corporation\NVIDIA app\CEF\NVIDIA app.exe"
                ) 
                
                $NvAppInstalled = $false
                foreach ($path in $NvAppPaths) { if (Test-Path $path) { $NvAppInstalled = $true; break } }

                if ($NvAppInstalled) {
                    Write-Host "NVIDIA App is already installed. Skipping download and installation." -ForegroundColor DarkGray
                } else {
                    Write-Host "NVIDIA App not found. Fetching the latest download link dynamically..."
                    $nvWebPage = Invoke-WebRequest -Uri "https://www.nvidia.com/en-us/software/nvidia-app/" -UseBasicParsing -ErrorAction SilentlyContinue
                    $regex = '(https://us\.download\.nvidia\.com/nvapp/client/[^"''\s><]+\.exe)'
                    $match = [regex]::Match($nvWebPage.Content, $regex) 

                    if ($match.Success) {
                        $url = $match.Value
                        Write-Host "Found latest NVIDIA installer: $url" -ForegroundColor Cyan
                    } else {
                        $url = "https://us.download.nvidia.com/nvapp/client/11.0.6.383/NVIDIA_app_v11.0.6.383.exe"
                        Write-Host "Dynamic fetch failed. Using default fallback URL: $url" -ForegroundColor DarkYellow
                    }

                    $fileName = Split-Path -Path $url -Leaf
                    $InstallerPath = Join-Path -Path $InstallerDir -ChildPath $fileName

                    if (-not (Test-Path $InstallerPath)) {
                        Write-Host "Downloading $fileName to $InstallerDir..."
                        Invoke-WebRequest -Uri $url -OutFile $InstallerPath -ErrorAction Stop
                        Write-Host "Download complete." -ForegroundColor Green
                    } else { Write-Host "Existing installer found. Skipping download." -ForegroundColor DarkGray }

                    Write-Host "Starting silent installation from $InstallerPath..."
                    $nvProcess = Start-Process -FilePath $InstallerPath -ArgumentList '-s -n -passive -noreboot' -Wait -PassThru -ErrorAction Stop 

                    if ($nvProcess.ExitCode -eq 3010) {
                        Write-Host "NVIDIA App installed (Reboot Required: Code 3010)." -ForegroundColor Yellow
                    } elseif ($nvProcess.ExitCode -ne 0 -and $nvProcess.ExitCode -ne $null) {
                        Write-Warning "NVIDIA installer exited with code $($nvProcess.ExitCode)."
                    } else { Write-Host "NVIDIA App installed successfully." -ForegroundColor Green }
                }
            } catch { Write-Warning "Could not install NVIDIA App. Error: $_" }
        }
    }
}

# ==============================================================================
# MODULE: MAINTENANCE JOB (ORCHESTRATOR WRAPPER)
# ==============================================================================
if ($Maintenance) {
    # TaskName defined in the decoupled script: Deploy-OSMaintenanceTask.ps1
    $TaskName = "Automated-OS-Maintenance" 
    
    if ($Uninstall) {
        Write-Host "`n[-] REMOVING MAINTENANCE JOB MODULE..." -ForegroundColor DarkYellow
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-EventLog -LogName "Application" -Source "OS-Maintenance" -ErrorAction SilentlyContinue
        Write-Host "Monthly maintenance task and Event Source removed." -ForegroundColor Green
    } else {
        Write-Host "`n[+] STARTING MAINTENANCE JOB MODULE (DECOUPLED WRAPPER)..." -ForegroundColor Magenta
        
        $RepoURI = "https://raw.githubusercontent.com/ZacharySchmalzEng/Tools/main/Windows/Provisioning/Deploy-OSMaintenanceTask.ps1"
        $LocalPath = Join-Path -Path $ScriptDir -ChildPath "Deploy-OSMaintenanceTask.ps1"
        
        try {
            if (Test-Path $LocalPath) {
                Write-Host "--- Local module detected. Sourcing execution to $LocalPath ---" -ForegroundColor Yellow
                & $LocalPath
                if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) { Write-Warning "Decoupled script returned a non-zero exit code." }
            } else {
                Write-Host "--- Local module not found. Fetching fileless payload from Upstream Repository... ---" -ForegroundColor Yellow
                
                # Fetch script content into memory and cast to a runtime ScriptBlock
                $RemotePayload = Invoke-RestMethod -Uri $RepoURI -UseBasicParsing -ErrorAction Stop
                $ScriptBlock = [ScriptBlock]::Create($RemotePayload)
                
                Write-Host "--- Executing Upstream Payload ---" -ForegroundColor Yellow
                & $ScriptBlock
            }
            Write-Host "Maintenance deployment wrapper execution completed." -ForegroundColor Green
        } catch {
            Write-Error "Failed to invoke decoupled OS Maintenance deployment script. Error: $_"
        }
    }
}

# ==============================================================================
# MODULE: AUTO-UPDATER (ORCHESTRATOR WRAPPER)
# ==============================================================================
if ($AutoUpdate) {
    $TaskName = "Automated-OS-AutoUpdate" 
    
    if ($Uninstall) {
        Write-Host "`n[-] REMOVING AUTO-UPDATE JOB MODULE..." -ForegroundColor DarkYellow
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-EventLog -LogName "Application" -Source "OS-AutoUpdater" -ErrorAction SilentlyContinue
        Write-Host "Auto-Update task and Event Source removed." -ForegroundColor Green
    } else {
        Write-Host "`n[+] STARTING AUTO-UPDATE JOB MODULE (DECOUPLED WRAPPER)..." -ForegroundColor Magenta
        
        $RepoURI = "https://raw.githubusercontent.com/ZacharySchmalzEng/Tools/main/Windows/Provisioning/Deploy-AutoUpdateTask.ps1"
        $LocalPath = Join-Path -Path $ScriptDir -ChildPath "Deploy-AutoUpdateTask.ps1"
        
        try {
            if (Test-Path $LocalPath) {
                Write-Host "--- Local module detected. Sourcing execution to $LocalPath ---" -ForegroundColor Yellow
                & $LocalPath
                if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) { Write-Warning "Decoupled script returned a non-zero exit code." }
            } else {
                Write-Host "--- Local module not found. Fetching fileless payload from Upstream Repository... ---" -ForegroundColor Yellow
                $RemotePayload = Invoke-RestMethod -Uri $RepoURI -UseBasicParsing -ErrorAction Stop
                $ScriptBlock = [ScriptBlock]::Create($RemotePayload)
                
                Write-Host "--- Executing Upstream Payload ---" -ForegroundColor Yellow
                & $ScriptBlock
            }
            Write-Host "Auto-Update deployment wrapper execution completed." -ForegroundColor Green
        } catch {
            Write-Error "Failed to invoke decoupled Auto-Update deployment script. Error: $_"
        }
    }
}

Stop-Transcript
Write-Host "`n[+] SCRIPT EXECUTION COMPLETE. Logs saved to: $LogPath" -ForegroundColor Green