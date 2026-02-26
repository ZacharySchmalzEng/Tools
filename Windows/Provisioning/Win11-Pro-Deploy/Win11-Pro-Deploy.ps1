<#
.SYNOPSIS
    Automated Windows 11 Pro provisioning and environment setup script.

.DESCRIPTION
    This script performs a comprehensive post-installation setup for a fresh Windows 11 Pro environment.
    It supports modular execution via command-line flags. If no flags are provided, it displays a help menu.

.AUTHOR
    Zachary Schmalz

.NOTES
    Version:        6.1
    Date:           2026-02-26
    Requirements:   Windows 11 Pro, PowerShell 5.1+, Active Internet Connection.
    Execution:      Must be run with local Administrator privileges.
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
    [switch]$DualBoot,
    [switch]$Standard,
    [switch]$Complete,
    [switch]$Help
)

# 1. --- Help Menu & Parameter Logic ---
$RunSoftware = ($Apps -or $DevApps -or $Cyber -or $Maker -or $Gaming -or $Nvidia -or $Standard -or $Complete)
$RunAny = ($System -or $Debloat -or $Security -or $Dev -or $DualBoot -or $RunSoftware)

if ($Help -or -not $RunAny) {
    Write-Host ""
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host " Windows 11 Pro Environment Setup Script v6.1" -ForegroundColor White
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host "Usage: .\Win11-Pro-Deploy.ps1 [Options]"
    Write-Host ""
    Write-Host "CORE OS OPTIONS:"
    Write-Host "  -System    Applies system tweaks (Explorer, Power Plan, Context Menu, MSA/OneDrive)"
    Write-Host "  -Debloat   Removes Appx bloatware, widgets, and disables Consumer Features"
    Write-Host "  -Security  Enables Defender PUA protection, OS Telemetry disable, Windows Updates"
    Write-Host "  -Dev       Enables OS developer features (WSL, Windows Sandbox, OpenSSH Client & Server)"
    Write-Host "  -DualBoot  Configures an automated Scheduled Task to mount Linux via WSL at logon"
    Write-Host ""
    Write-Host "SOFTWARE OPTIONS:"
    Write-Host "  -Apps      Core utilities (Browsers, Signal, WhatsApp, 7-Zip, VLC, Discord, Obsidian, PowerToys, Terminal)"
    Write-Host "  -DevApps   Scripting/Dev tools (VS Code, Python, GitHub Desktop, Notepad++, PuTTY)"
    Write-Host "  -Cyber     Network & Analysis tools (Wireshark, Nmap, Advanced IP Scanner)"
    Write-Host "  -Maker     3D Printing & CAD tools (PrusaSlicer, OrcaSlicer, Bambu Studio, Fusion 360)"
    Write-Host "  -Gaming    Gaming & Media (Steam, Battle.net, OBS Studio)"
    Write-Host "  -Nvidia    Dynamically fetches and silently installs the latest NVIDIA App"
    Write-Host ""
    Write-Host "DEPLOYMENT PROFILES:"
    Write-Host "  -Standard  Universal baseline: System, Debloat, Security, Dev, Apps, DevApps"
    Write-Host "  -Complete  Heavy workstation: All Standard modules PLUS Cyber, Maker, Gaming, and Nvidia"
    Write-Host "  -Help      Displays this help menu"
    Write-Host "===============================================================" -ForegroundColor Cyan
    Write-Host ""
    return
}

# Deployment Profile Logic (Note: Both profiles intentionally exclude the hardware-specific -DualBoot)
if ($Complete) {
    $System = $true; $Debloat = $true; $Security = $true; $Dev = $true; 
    $Apps = $true; $DevApps = $true; $Cyber = $true; $Maker = $true; $Gaming = $true; $Nvidia = $true;
    $RunSoftware = $true
}

if ($Standard) {
    $System = $true; $Debloat = $true; $Security = $true; $Dev = $true; 
    $Apps = $true; $DevApps = $true;
    $RunSoftware = $true
}

# 2. --- Execution Policy Bypass ---
function Invoke-ExecutionPolicyBypass {
    $currentPolicy = Get-ExecutionPolicy -Scope Process
    if ($currentPolicy -ne 'Bypass') {
        Write-Host "Setting process-level Execution Policy to Bypass..." -ForegroundColor Yellow
        try {
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
            Write-Host "Execution Policy successfully bypassed for this session." -ForegroundColor Green
        } catch { Write-Warning "Failed to bypass Execution Policy. Error: $_" }
    }
}
Invoke-ExecutionPolicyBypass

# 3. --- Administrator Check ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Administrator permissions are required to run provisioning modules."
    Write-Host "Please re-run this script with 'Run as Administrator'."
    Start-Sleep -Seconds 5
    return
}

# 4. --- Setup Logging & Paths ---
$ScriptDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$LogDir = Join-Path -Path $ScriptDir -ChildPath "InstallerLogs"
$InstallerDir = Join-Path -Path $ScriptDir -ChildPath "Installers"

if (-not (Test-Path $LogDir)) { New-Item -Path $LogDir -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $InstallerDir)) { New-Item -Path $InstallerDir -ItemType Directory -Force | Out-Null }

$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogFile = "installer_log_$Timestamp.log"
$LogPath = Join-Path -Path $LogDir -ChildPath $LogFile

Start-Transcript -Path $LogPath

Write-Host "Running with Administrator privileges." -ForegroundColor Green
Set-Location -Path $ScriptDir

# --- Log Rotation (Keep only the last 10 logs) ---
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

    Write-Host "--- Attempting to uninstall Windows Widgets... ---" -ForegroundColor Yellow
    $WidgetsCheck = Get-AppxPackage -Name "MicrosoftWindows.Client.WebExperience"
    if ($null -ne $WidgetsCheck) {
        winget uninstall --id 9MSSGKG348SP --silent
        if ($LASTEXITCODE -eq 0) { Write-Host "--- Windows Widgets uninstalled successfully. ---" -ForegroundColor Green }
    } else { Write-Host "Windows Widgets already removed. Skipping..." -ForegroundColor Green }

    Write-Host "--- Disabling Windows Consumer Features... ---" -ForegroundColor Yellow
    $CloudContentKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    if (-not (Test-Path $CloudContentKey)) { New-Item -Path $CloudContentKey -Force | Out-Null }
    Set-ItemProperty -Path $CloudContentKey -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force

    Write-Host "--- Removing select pre-installed Appx packages... ---" -ForegroundColor Yellow
    $bloatware = @(
        "*Microsoft.BingNews*", "*Microsoft.GetHelp*", "*Microsoft.Getstarted*", 
        "*Microsoft.MicrosoftOfficeHub*", "*Microsoft.MicrosoftSolitaireCollection*", 
        "*Microsoft.PowerAutomateDesktop*", "*Microsoft.Todos*"
    )
    foreach ($app in $bloatware) {
        if (Get-AppxPackage -Name $app) {
            Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
            Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
        }
    }
    Write-Host "--- Base bloatware removal complete. ---" -ForegroundColor Green
}


# ==============================================================================
#  MODULE: SYSTEM
# ==============================================================================
if ($System) {
    Write-Host "`n[+] STARTING SYSTEM MODULE..." -ForegroundColor Magenta

    Write-Host "--- Applying core system & registry tweaks... ---" -ForegroundColor Yellow
    try {
        $OneDriveKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
        if (-not (Test-Path $OneDriveKey)) { New-Item -Path $OneDriveKey -Force | Out-Null }
        Set-ItemProperty -Path $OneDriveKey -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force

        $MSAKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        if (-not (Test-Path $MSAKey)) { New-Item -Path $MSAKey -Force | Out-Null }
        Set-ItemProperty -Path $MSAKey -Name "MSAOptional" -Value 1 -Type DWord -Force

        $OOBEKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\OOBE"
        if (-not (Test-Path $OOBEKey)) { New-Item -Path $OOBEKey -Force | Out-Null }
        Set-ItemProperty -Path $OOBEKey -Name "DisablePrivacyExperience" -Value 1 -Type DWord -Force

        $ContextMenuKey = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
        if (-not (Test-Path $ContextMenuKey)) { New-Item -Path $ContextMenuKey -Force | Out-Null }
        Set-ItemProperty -Path $ContextMenuKey -Name "(Default)" -Value "" -Force

        $FileSystemKey = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
        if (-not (Test-Path $FileSystemKey)) { New-Item -Path $FileSystemKey -Force | Out-Null }
        Set-ItemProperty -Path $FileSystemKey -Name "LongPathsEnabled" -Value 1 -Type DWord -Force

        $ExplorerKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        if (-not (Test-Path $ExplorerKey)) { New-Item -Path $ExplorerKey -Force | Out-Null }
        Set-ItemProperty -Path $ExplorerKey -Name "TaskbarAl" -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $ExplorerKey -Name "Hidden" -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $ExplorerKey -Name "HideFileExt" -Value 0 -Type DWord -Force

        Write-Host "--- System registry tweaks applied successfully. ---" -ForegroundColor Green
    } catch { Write-Error "Failed to apply system registry tweaks. Error: $_" }

    Write-Host "--- Enabling Ultimate Performance Power Plan... ---" -ForegroundColor Yellow
    try {
        $currentPlan = powercfg -getactivescheme
        if ($currentPlan -notmatch "e9a42b02-d5df-448d-aa00-03f14749eb61") {
            $Plan = powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
            $PlanGUID = [regex]::Match($Plan, '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})').Value
            powercfg -setactive $PlanGUID
            Write-Host "Ultimate Performance enabled." -ForegroundColor Green
        } else { Write-Host "Ultimate Performance Power Plan is already active. Skipping..." -ForegroundColor Green }
    } catch { Write-Warning "Could not set power plan. Error: $_" }
}


# ==============================================================================
#  MODULE: SECURITY (Part 1 - Policies)
# ==============================================================================
if ($Security) {
    Write-Host "`n[+] STARTING SECURITY MODULE (Policies)..." -ForegroundColor Magenta

    Write-Host "--- Disabling Windows Telemetry... ---" -ForegroundColor Yellow
    $TelemetryKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    if (-not (Test-Path $TelemetryKey)) { New-Item -Path $TelemetryKey -Force | Out-Null }
    Set-ItemProperty -Path $TelemetryKey -Name "AllowTelemetry" -Value 0 -Type DWord -Force

    Write-Host "--- Enabling Defender PUA Protection... ---" -ForegroundColor Yellow
    try {
        Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
        Write-Host "--- PUA Protection enabled. ---" -ForegroundColor Green
    } catch { Write-Warning "Failed to enable PUA Protection. Error: $_" }
}


# ==============================================================================
#  MODULE: DEV (OS Features)
# ==============================================================================
if ($Dev) {
    Write-Host "`n[+] STARTING DEV MODULE (OS Features)..." -ForegroundColor Magenta
    Write-Host "--- Enabling Windows Optional Features & Capabilities... ---" -ForegroundColor Yellow
    try {
        $features = @("Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform", "Containers-DisposableClientVM")
        foreach ($feature in $features) {
            $checkFeature = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
            if ($checkFeature.State -ne 'Enabled') {
                Enable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -All -WarningAction SilentlyContinue | Out-Null
                Write-Host "Enabled Feature: $feature" -ForegroundColor Green
            } else { Write-Host "Feature $feature is already enabled. Skipping..." -ForegroundColor Green }
        }

        # OpenSSH Client and Server
        $sshFeatures = @("OpenSSH.Client~~~~0.0.1.0", "OpenSSH.Server~~~~0.0.1.0")
        foreach ($ssh in $sshFeatures) {
            $checkCapability = Get-WindowsCapability -Online -Name $ssh -ErrorAction SilentlyContinue
            if ($checkCapability.State -ne 'Installed') {
                Write-Host "Installing Capability: $ssh..."
                Add-WindowsCapability -Online -Name $ssh -ErrorAction SilentlyContinue | Out-Null
                Write-Host "Installed Capability: $ssh" -ForegroundColor Green
            } else { Write-Host "Capability $ssh is already installed. Skipping..." -ForegroundColor Green }
        }

        # Configure SSH Server to start automatically
        try {
            Set-Service -Name sshd -StartupType 'Automatic' -ErrorAction SilentlyContinue
            Start-Service sshd -ErrorAction SilentlyContinue
            Write-Host "SSH Server (sshd) service configured and started." -ForegroundColor Green
        } catch { Write-Warning "Could not configure sshd service. It may require a reboot first." }

    } catch { Write-Warning "Failed during Windows Features configuration. Error: $_" }
}


# ==============================================================================
#  MODULE: DUAL BOOT (Linux Mounting Task)
# ==============================================================================
if ($DualBoot) {
    Write-Host "`n[+] STARTING DUAL BOOT MODULE..." -ForegroundColor Magenta
    Write-Host "--- Configuring Scheduled Task for Linux WSL Mount... ---" -ForegroundColor Yellow
    try {
        $CustomScriptsDir = "C:\Scripts"
        if (-not (Test-Path $CustomScriptsDir)) { 
            New-Item -Path $CustomScriptsDir -ItemType Directory -Force | Out-Null 
            Write-Host "Created directory: $CustomScriptsDir" -ForegroundColor Cyan
        }
        
        $MountScriptPath = Join-Path -Path $CustomScriptsDir -ChildPath "Mount-Linux.ps1"
        
        $MountScriptContent = @"
<#
.SYNOPSIS
    Automated silent background script to mount the Linux partition via WSL.
#>
# ==============================================================================
# CONFIGURATION 
# If your drive fails to mount, verify these settings by running 'wsl --mount --list' 
# in a standard Administrator PowerShell window.
# ==============================================================================
`$DrivePath = "\\.\PHYSICALDRIVE1"
`$PartitionNum = "2"
`$FileSystem = "btrfs"

# Sleep for 15 seconds to allow the user profile and WSL subsystem to fully initialize
Start-Sleep -Seconds 15

# Attempt to silently mount the drive
wsl --mount `$DrivePath --partition `$PartitionNum --type `$FileSystem
"@
        Set-Content -Path $MountScriptPath -Value $MountScriptContent -Force
        Write-Host "Helper script generated at: $MountScriptPath" -ForegroundColor Green

        # Register the Scheduled Task
        $TaskName = "Mount-Linux-WSL"
        $ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
        
        if ($null -ne $ExistingTask) {
            Write-Host "Task '$TaskName' already exists. Re-registering..." -ForegroundColor Yellow
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }

        $Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$MountScriptPath`""
        $Trigger = New-ScheduledTaskTrigger -AtLogOn
        # Run as the highest available privileges (Administrator) required for wsl --mount
        $Principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
        $Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        
        $Task = New-ScheduledTask -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings
        Register-ScheduledTask -TaskName $TaskName -InputObject $Task -Force | Out-Null

        Write-Host "--- Scheduled Task '$TaskName' created successfully. ---" -ForegroundColor Green
    } catch { Write-Error "Failed to configure Dual Boot task. Error: $_" }
}


# ==============================================================================
#  MODULE: SOFTWARE DEPLOYMENT
# ==============================================================================
if ($RunSoftware) {
    Write-Host "`n[+] STARTING SOFTWARE DEPLOYMENT MODULE..." -ForegroundColor Magenta

    Write-Host "--- Updating winget sources... ---" -ForegroundColor Yellow
    winget source update | Out-Null
    Write-Host "--- Winget sources updated. ---" -ForegroundColor Green

    $packages = @()
    
    if ($Apps) {
        $packages += "Brave.Brave", "Google.Chrome", "Mozilla.Firefox", "Opera.Opera", "7zip.7zip", 
                     "VideoLAN.VLC", "Discord.Discord", "Obsidian.Obsidian", "OpenWhisperSystems.Signal", 
                     "9NKSQGP7F2NH", "JAMSoftware.TreeSize.Free", "CrystalDewWorld.CrystalDiskInfo.ShizukuEdition", 
                     "Microsoft.PowerToys", "voidtools.Everything", "Microsoft.WindowsTerminal", "Rufus.Rufus"
    }
    
    if ($DevApps) {
        $packages += "Microsoft.VisualStudioCode", "GitHub.GitHubDesktop", "Python.Python.3.13", 
                     "Microsoft.PowerShell", "Notepad++.Notepad++", "PuTTY.PuTTY"
    }
    
    if ($Cyber) {
        $packages += "WiresharkFoundation.Wireshark", "Insecure.Nmap", "Famatech.AdvancedIPScanner"
    }

    if ($Maker) {
        $packages += "Prusa3D.PrusaSlicer", "SoftFever.OrcaSlicer", "Bambulab.Bambustudio", "Autodesk.Fusion360"
    }
    
    if ($Gaming) {
        $packages += "Valve.Steam", "OBSProject.OBSStudio"
    }

    if ($packages.Count -gt 0) {
        foreach ($pkg in $packages) {
            Write-Host "--- Checking status of $pkg ---"
            $null = winget list --id $pkg -e --accept-source-agreements
            if ($LASTEXITCODE -eq 0) {
                Write-Host "$pkg is already installed. Skipping..." -ForegroundColor Green
            } else {
                Write-Host "Installing $pkg via winget..."
                winget install --id $pkg -e --silent --accept-source-agreements --accept-package-agreements --force
                if ($LASTEXITCODE -ne 0) { Write-Warning "Winget returned a non-zero exit code for $pkg." }
            }
        }
    }

    if ($Nvidia) {
        Write-Host "--- Processing NVIDIA App ---" -ForegroundColor Magenta
        Write-Host "--- Checking NVIDIA App status... ---" -ForegroundColor Yellow
        try {
            $NvAppExe = "C:\Program Files\NVIDIA Corporation\NVIDIA app\nvapp.exe"
            if (Test-Path $NvAppExe) {
                Write-Host "NVIDIA App is already installed. Skipping download and installation." -ForegroundColor Green
            } else {
                Write-Host "NVIDIA App not found. Fetching the latest download link dynamically..."
                $nvWebPage = Invoke-WebRequest -Uri "https://www.nvidia.com/en-us/software/nvidia-app/" -UseBasicParsing -ErrorAction SilentlyContinue
                $regex = '(https://us\.download\.nvidia\.com/nvapp/client/[^"''\s><]+\.exe)'
                $match = [regex]::Match($nvWebPage.Content, $regex)
                
                if ($match.Success) {
                    $url = $match.Value
                    Write-Host "Found latest NVIDIA installer: $url" -ForegroundColor Cyan
                } else {
                    $url = "https://us.download.nvidia.com/nvapp/client/11.0.5.266/NVIDIA_app_v11.0.5.266.exe"
                    Write-Host "Dynamic fetch failed. Using default fallback URL: $url" -ForegroundColor DarkYellow
                }

                $fileName = Split-Path -Path $url -Leaf
                $InstallerPath = Join-Path -Path $InstallerDir -ChildPath $fileName

                if (-not (Test-Path $InstallerPath)) {
                    Write-Host "Downloading $fileName to $InstallerDir..."
                    Invoke-WebRequest -Uri $url -OutFile $InstallerPath -ErrorAction Stop
                    Write-Host "Download complete." -ForegroundColor Green
                } else { Write-Host "Existing installer found. Skipping download." -ForegroundColor Green }

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
        $null = winget list --id Blizzard.BattleNet -e --accept-source-agreements
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Blizzard.Battle.net is already installed. Skipping..." -ForegroundColor Green
        } else {
            try {
                Write-Host "Attempting to install Blizzard.BattleNet..."
                winget install --id Blizzard.BattleNet -e --location "C:\Program Files (x86)\Battle.net" --override "--silent" --accept-source-agreements --accept-package-agreements
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
    } else { Write-Host "PSWindowsUpdate module is already installed. Skipping download..." -ForegroundColor Green }

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