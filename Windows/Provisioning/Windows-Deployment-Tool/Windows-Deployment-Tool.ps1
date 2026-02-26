<#
.SYNOPSIS
    Automated Windows 10/11 Pro and Server provisioning and environment setup script.
.AUTHOR
    Zachary Schmalz
.NOTES
    Name:           Windows-Deployment-Tool.ps1
    Version:        6.9
    Date:           2026-02-26
    Changes:        Architectural overhaul for idempotency, O(1) Winget memory snapshots, 
                    native 64-bit Battle.net detection. Replaced OpenSSL source and removed legacy BareTail.
#>

param (
    [switch]$System, [switch]$Debloat, [switch]$Security, [switch]$Dev,
    [switch]$Apps, [switch]$DevApps, [switch]$Cyber, [switch]$Maker,
    [switch]$Gaming, [switch]$Nvidia, [switch]$Creators, [switch]$DualBoot,
    [switch]$Standard, [switch]$Complete, [switch]$Help
)

# ==============================================================================
#  HELPER FUNCTIONS
# ==============================================================================

function Get-LinuxDiskPath {
    Write-Host "--- Scanning for Linux partitions... ---" -ForegroundColor Yellow
    $LinuxDisk = Get-Partition | Where-Object { $_.Type -eq 'Unknown' -or $_.GptType -eq '{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}' } | 
                 Sort-Object Size -Descending | Select-Object -First 1

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

# ==============================================================================
#  PARAMETER LOGIC & PROFILES
# ==============================================================================

if ($Complete) {
    $System = $true; $Debloat = $true; $Security = $true; $Dev = $true; 
    $Apps = $true; $DevApps = $true; $Cyber = $true; $Maker = $true; $Gaming = $true; $Nvidia = $true; $Creators = $true;
}
if ($Standard) {
    $System = $true; $Debloat = $true; $Security = $true; $Dev = $true; $Apps = $true; $DevApps = $true;
}

$RunSoftware = ($Apps -or $DevApps -or $Cyber -or $Maker -or $Gaming -or $Nvidia -or $Creators)
$RunAny = ($System -or $Debloat -or $Security -or $Dev -or $DualBoot -or $RunSoftware)

if ($Help -or -not $RunAny) {
    Write-Host "`nUsage: .\Windows-Deployment-Tool.ps1 [-Standard | -Complete | -System | -Debloat | ...]"
    Write-Host "NOTE: Must be executed with: powershell.exe -ExecutionPolicy Bypass -File .\Windows-Deployment-Tool.ps1`n" -ForegroundColor Cyan
    return
}

# ==============================================================================
#  PRE-FLIGHT CHECKS
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
# Suppress the ASCII progress bars from Invoke-WebRequest to prevent transcript bloat
$ProgressPreference = 'SilentlyContinue'

Write-Host "Running with Administrator privileges." -ForegroundColor Green
Set-Location -Path $ScriptDir

$IsWin11 = Test-IsWin11
if ($IsWin11) { Write-Host "Windows 11 Detected. Enabling Win11-specific configurations." -ForegroundColor Cyan }
else { Write-Host "Windows 10 Detected. Bypassing Win11-specific configurations." -ForegroundColor Cyan }

try {
    $logFiles = Get-ChildItem -Path $LogDir -Filter "*.log" | Sort-Object CreationTime -Descending
    if ($logFiles.Count -gt 10) {
        $filesToDelete = $logFiles | Select-Object -Skip 10
        foreach ($file in $filesToDelete) { Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue }
    }
} catch { Write-Warning "Could not perform log rotation. Error: $_" }


# ==============================================================================
#  MODULE: DEBLOAT
# ==============================================================================
if ($Debloat) {
    Write-Host "`n[+] STARTING DEBLOAT MODULE..." -ForegroundColor Magenta

    if ($IsWin11) {
        Write-Host "--- Checking Windows 11 Widgets... ---" -ForegroundColor Yellow
        $WidgetsCheck = Get-AppxPackage -Name "MicrosoftWindows.Client.WebExperience"
        if ($null -ne $WidgetsCheck) {
            winget uninstall --id 9MSSGKG348SP --silent
            if ($LASTEXITCODE -eq 0) { Write-Host "--- Windows Widgets uninstalled successfully. ---" -ForegroundColor Green }
        } else { Write-Host "Windows Widgets already removed. Skipping..." -ForegroundColor DarkGray }
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


# ==============================================================================
#  MODULE: SYSTEM
# ==============================================================================
if ($System) {
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
        $currentPlan = powercfg -getactivescheme
        if ($currentPlan -notmatch "e9a42b02-d5df-448d-aa00-03f14749eb61") {
            $Plan = powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
            $PlanGUID = [regex]::Match($Plan, '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})').Value
            powercfg -setactive $PlanGUID
            Write-Host "Ultimate Performance enabled." -ForegroundColor Green
        } else { Write-Host "Ultimate Performance Power Plan is already active. Skipping..." -ForegroundColor DarkGray }
    } catch { Write-Warning "Could not set power plan. Error: $_" }
}


# ==============================================================================
#  MODULE: SECURITY (Part 1 - Policies)
# ==============================================================================
if ($Security) {
    Write-Host "`n[+] STARTING SECURITY MODULE (Policies)..." -ForegroundColor Magenta

    Write-Host "--- Checking Windows Telemetry... ---" -ForegroundColor Yellow
    Set-RegTweak -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 0

    Write-Host "--- Checking Defender PUA Protection... ---" -ForegroundColor Yellow
    try {
        $mpPref = Get-MpPreference
        if ($mpPref.PUAProtection -ne 1) {
            Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
            Write-Host "PUA Protection enabled." -ForegroundColor Green
        } else {
            Write-Host "PUA Protection is already enabled. Skipping..." -ForegroundColor DarkGray
        }
    } catch { Write-Warning "Failed to enable PUA Protection. Error: $_" }
}


# ==============================================================================
#  MODULE: DEV (OS Features)
# ==============================================================================
if ($Dev) {
    Write-Host "`n[+] STARTING DEV MODULE (OS Features)..." -ForegroundColor Magenta
    Write-Host "--- Checking Windows Optional Features & Capabilities... ---" -ForegroundColor Yellow
    try {
        $features = @("Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform", "Containers-DisposableClientVM")
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


# ==============================================================================
#  MODULE: DUAL BOOT (Dynamic Linux Mounting)
# ==============================================================================
if ($DualBoot) {
    Write-Host "`n[+] STARTING DUAL BOOT MODULE..." -ForegroundColor Magenta
    
    $LinuxInfo = Get-LinuxDiskPath
    $TargetDrive = $LinuxInfo.Path
    $TargetPart = $LinuxInfo.Partition

    if ($LinuxInfo.Found) {
        Write-Host "Auto-Detected Linux partition on Disk $($TargetDrive.Replace('\\.\PHYSICALDRIVE','')), Partition $TargetPart" -ForegroundColor Green
    } else {
        Write-Warning "Could not auto-detect Linux partition. Defaulting to $TargetDrive."
    }

    Write-Host "--- Configuring Scheduled Task for Linux WSL Mount... ---" -ForegroundColor Yellow
    try {
        $CustomScriptsDir = "$env:SystemDrive\Scripts"
        if (-not (Test-Path $CustomScriptsDir)) { New-Item -Path $CustomScriptsDir -ItemType Directory -Force | Out-Null }
        
        $MountScriptPath = Join-Path -Path $CustomScriptsDir -ChildPath "Mount-Linux.ps1"
        $MountScriptContent = @"
<#
.SYNOPSIS
    Automated silent background script to mount the Linux partition via WSL.
#>
`$DrivePath = "$TargetDrive"
`$PartitionNum = "$TargetPart"
`$FileSystem = "btrfs"

Start-Sleep -Seconds 15
wsl --mount `$DrivePath --partition `$PartitionNum --type `$FileSystem
"@
        Set-Content -Path $MountScriptPath -Value $MountScriptContent -Force
        Write-Host "Helper script generated/overwritten at: $MountScriptPath" -ForegroundColor Green

        $TaskName = "Mount-Linux-WSL"
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

# ==============================================================================
#  MODULE: SOFTWARE DEPLOYMENT
# ==============================================================================
if ($RunSoftware) {
    Write-Host "`n[+] STARTING SOFTWARE DEPLOYMENT MODULE..." -ForegroundColor Magenta

    # --- Windows 10 Winget Bootstrapper ---
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "Winget not found. Bootstrapping App Installer for Windows 10..." -ForegroundColor Yellow
        try {
            $url = "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
            $installer = Join-Path $InstallerDir "winget.msixbundle"
            if (-not (Test-Path $installer)) { Invoke-WebRequest -Uri $url -OutFile $installer -ErrorAction Stop }
            Add-AppxPackage -Path $installer -ErrorAction Stop
            Write-Host "Winget bootstrapped successfully." -ForegroundColor Green
            Start-Sleep -Seconds 5
        } catch { Write-Warning "Failed to bootstrap Winget. Software installation may fail. Error: $_" }
    }

    Write-Host "--- Updating winget sources... ---" -ForegroundColor Yellow
    winget source update | Out-Null
    Write-Host "--- Winget sources updated. ---" -ForegroundColor Green

    Write-Host "--- Taking memory snapshot of installed software... ---" -ForegroundColor Yellow
    $InstalledSoftware = winget list --accept-source-agreements | Out-String -Width 4096

    $IsServer = Test-IsServerOS
    if ($IsServer) { Write-Host "--- Server OS detected: Substituting WinDirStat for TreeSize Free ---" -ForegroundColor Cyan }

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
    
    if ($Cyber) { $packages += "WiresharkFoundation.Wireshark", "Insecure.Nmap", "Famatech.AdvancedIPScanner" }
    if ($Maker) { $packages += "Prusa3D.PrusaSlicer", "SoftFever.OrcaSlicer", "Bambulab.Bambustudio", "Autodesk.Fusion360" }
    if ($Creators) { $packages += "darktable.darktable", "BlenderFoundation.Blender", "HandBrake.HandBrake", "Audacity.Audacity", "Inkscape.Inkscape" }
    if ($Gaming) { $packages += "Valve.Steam", "OBSProject.OBSStudio" }

    if ($packages.Count -gt 0) {
        foreach ($pkg in $packages) {
            $DisplayName = if ($pkg -eq "9NKSQGP7F2NH") { "WhatsApp" } else { $pkg }
            Write-Host "--- Checking status of $DisplayName ---"
            
            # Hybrid Verification: Fast memory check first
            if ($InstalledSoftware -match [regex]::Escape($pkg)) {
                Write-Host "$DisplayName is already installed. Skipping..." -ForegroundColor DarkGray
            } else {
                # Fallback: Deep check for truncated IDs
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

    if ($Nvidia) {
        Write-Host "--- Processing NVIDIA App ---" -ForegroundColor Magenta
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
                
                if ($nvProcess.ExitCode -eq 3010) { Write-Host "NVIDIA App installed (Reboot Required: Code 3010)." -ForegroundColor Yellow }
                elseif ($nvProcess.ExitCode -ne 0 -and $nvProcess.ExitCode -ne $null) { Write-Warning "NVIDIA installer exited with code $($nvProcess.ExitCode)." }
                else { Write-Host "--- NVIDIA App installation complete. ---" -ForegroundColor Green }
            }
        } catch { Write-Error "An error occurred during the NVIDIA App routine: $_" }
    }

    if ($Gaming) {
        Write-Host "--- Processing Gaming Custom Packages ---" -ForegroundColor Magenta
        Write-Host "--- Checking status of Blizzard.BattleNet ---"
        
        $BnetPaths = @(
            "${env:ProgramFiles(x86)}\Battle.net\Battle.net.exe",
            "${env:ProgramFiles(x86)}\Battle.net\Battle.net Launcher.exe",
            "$env:ProgramFiles\Battle.net\Battle.net.exe",
            "$env:ProgramFiles\Battle.net\Battle.net Launcher.exe"
        )
        
        $BnetInstalled = $false
        foreach ($path in $BnetPaths) { if (Test-Path $path) { $BnetInstalled = $true; break } }

        if ($BnetInstalled) {
            Write-Host "Blizzard.Battle.net is already installed. Skipping..." -ForegroundColor DarkGray
        } else {
            try {
                Write-Host "Attempting to install Blizzard.BattleNet..."
                winget install --id Blizzard.BattleNet -e --override "--silent" --accept-source-agreements --accept-package-agreements
                if ($LASTEXITCODE -ne 0) { throw "Winget failed to install Battle.net. Exit code: $LASTEXITCODE" }
                Write-Host "--- Successfully installed Blizzard.Battle.net. ---" -ForegroundColor Green
            } catch { Write-Error "Failed to install Blizzard.Battle.net. Error: $_" }
        }
    }
}


# ==============================================================================
#  MODULE: SECURITY (Part 2 - Updates)
# ==============================================================================
if ($Security) {
    Write-Host "`n[+] STARTING SECURITY MODULE (Updates)..." -ForegroundColor Magenta
    Write-Host "--- Checking for PSWindowsUpdate module... ---" -ForegroundColor Yellow
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        Install-Module -Name PSWindowsUpdate -Repository PSGallery -Force -Scope AllUsers -ErrorAction SilentlyContinue
        Write-Host "--- Module installed. ---" -ForegroundColor Green
    } else { Write-Host "PSWindowsUpdate module is already installed. Skipping download..." -ForegroundColor DarkGray }

    Write-Host "--- Checking for and installing Windows Updates... ---" -ForegroundColor Yellow
    try {
        Import-Module PSWindowsUpdate -ErrorAction Stop
        Install-WindowsUpdate -AcceptAll -IgnoreReboot
        Write-Host "--- Windows Update check complete. ---" -ForegroundColor Green
    } catch { Write-Error "Failed to run PSWindowsUpdate module. Error: $_" }
}


# ==============================================================================
#  WRAP UP & REBOOT
# ==============================================================================
Write-Host "`n****************************************************************"
Write-Host "Execution of selected modules is complete!"
Write-Host "Log file is saved at: $LogPath"
Write-Host "****************************************************************"

# Turn progress back on in case user continues using the shell
$ProgressPreference = 'Continue'
Stop-Transcript

Write-Host ""
$title = "Reboot Recommended"
$message = "Script execution finished. A reboot may be required to apply system tweaks, updates, or dev features. Would you like to reboot now?"
$yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Restarts the computer."
$no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Exits the script without rebooting."
$choices = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
$decision = $Host.UI.PromptForChoice($title, $message, $choices, 1) # Default No

if ($decision -eq 0) {
    Write-Host "Rebooting computer now..." -ForegroundColor Yellow
    Restart-Computer
} else {
    Write-Host "Reboot skipped. Please restart your computer manually later."
}