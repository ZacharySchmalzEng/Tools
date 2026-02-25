<#
.SYNOPSIS
    Automated Windows 11 Pro provisioning and environment setup script.

.DESCRIPTION
    This script performs a comprehensive post-installation setup for a fresh Windows 11 Pro environment.
    It bypasses the execution policy for the current session, ensures Administrator privileges, and executes the following:
    - System debloat (removing default Consumer Features and Appx packages).
    - Privacy and Explorer registry tweaks (Telemetry disable, Left-aligned taskbar, Hidden files visibility).
    - Enables Win32 Long Paths and Defender PUA Protection.
    - Checks for existing software and installer files to prevent redundant downloads/installs.
    - Installation of standard applications via Winget.
    - Dynamically scrapes NVIDIA's website to fetch and install the absolute latest NVIDIA App.
    - Special handling for Blizzard Battle.net silent installation.
    - Enables WSL, Windows Sandbox, and OpenSSH Client.
    - Applies the Ultimate Performance power plan.
    - Installs the latest Windows Updates.

.AUTHOR
    Zachary Schmalz

.NOTES
    Version:        4.3
    Date:           2026-02-25
    Requirements:   Windows 11 Pro, PowerShell 5.1+, Active Internet Connection.
    Execution:      Must be run with local Administrator privileges.
#>

# 0. --- Execution Policy Bypass ---
function Invoke-ExecutionPolicyBypass {
    $currentPolicy = Get-ExecutionPolicy -Scope Process
    if ($currentPolicy -ne 'Bypass') {
        Write-Host "Setting process-level Execution Policy to Bypass..." -ForegroundColor Yellow
        try {
            Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
            Write-Host "Execution Policy successfully bypassed for this session." -ForegroundColor Green
        } catch {
            Write-Warning "Failed to bypass Execution Policy. Error: $_"
        }
    } else {
        Write-Host "Execution Policy is already set to Bypass for this session." -ForegroundColor Green
    }
}

Invoke-ExecutionPolicyBypass

# 1. --- Administrator Check ---
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning "Administrator permissions are required."
    Write-Host "Please re-run this script with 'Run as Administrator'."
    Start-Sleep -Seconds 5
    return
}

# 2. --- Setup Logging & Paths ---
$ScriptDir = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
$LogDir = Join-Path -Path $ScriptDir -ChildPath "InstallerLogs"
$InstallerDir = Join-Path -Path $ScriptDir -ChildPath "Installers"

if (-not (Test-Path $LogDir)) {
    Write-Host "Creating log directory: $LogDir" -ForegroundColor Cyan
    New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
}
if (-not (Test-Path $InstallerDir)) {
    Write-Host "Creating installer directory: $InstallerDir" -ForegroundColor Cyan
    New-Item -Path $InstallerDir -ItemType Directory -Force | Out-Null
}

$Timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$LogFile = "installer_log_$Timestamp.log"
$LogPath = Join-Path -Path $LogDir -ChildPath $LogFile

Start-Transcript -Path $LogPath

Write-Host "Running with Administrator privileges." -ForegroundColor Green
Write-Host "All output is being logged to: $LogPath" -ForegroundColor Cyan
Set-Location -Path $ScriptDir
Write-Host "Working directory set to: $ScriptDir" -ForegroundColor Cyan
Start-Sleep -Seconds 3

# 3. --- Log Rotation (Keep only the last 10 logs) ---
Write-Host "--- Performing log rotation in $LogDir... ---" -ForegroundColor Yellow
try {
    $logFiles = Get-ChildItem -Path $LogDir -Filter "*.log" | Sort-Object CreationTime -Descending

    if ($logFiles.Count -gt 10) {
        $filesToDelete = $logFiles | Select-Object -Skip 10
        Write-Host "Found $($logFiles.Count) log files. Deleting $($filesToDelete.Count) older logs..."
        foreach ($file in $filesToDelete) {
            Write-Host "Removing old log: $($file.Name)"
            Remove-Item -Path $file.FullName -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host "Found $($logFiles.Count) log files. No rotation needed."
    }
} catch {
    Write-Warning "Could not perform log rotation. Error: $_"
}

# 4. --- Update Winget Sources ---
Write-Host "--- Updating winget sources... ---" -ForegroundColor Yellow
winget source update
Write-Host "--- Winget sources updated. ---" -ForegroundColor Green

# 5. --- Disable Windows 11 Widgets ---
Write-Host "--- Attempting to uninstall Windows Widgets... ---" -ForegroundColor Yellow
$WidgetsCheck = Get-AppxPackage -Name "MicrosoftWindows.Client.WebExperience"
if ($null -ne $WidgetsCheck) {
    winget uninstall --id 9MSSGKG348SP --silent
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to uninstall Windows Widgets."
    } else {
        Write-Host "--- Windows Widgets uninstalled successfully. ---" -ForegroundColor Green
    }
} else {
    Write-Host "Windows Widgets already removed. Skipping..." -ForegroundColor Green
}

# 6. --- Apply System Tweaks via Registry ---
Write-Host "--- Applying system tweaks... ---" -ForegroundColor Yellow
try {
    # Disable OneDrive via Group Policy registry key
    $OneDriveKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
    if (-not (Test-Path $OneDriveKey)) { New-Item -Path $OneDriveKey -Force | Out-Null }
    Set-ItemProperty -Path $OneDriveKey -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force

    # Make MS Account optional during OOBE/setup
    $MSAKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if (-not (Test-Path $MSAKey)) { New-Item -Path $MSAKey -Force | Out-Null }
    Set-ItemProperty -Path $MSAKey -Name "MSAOptional" -Value 1 -Type DWord -Force

    # Disable "Finish setting up your device" (Windows Welcome Experience) prompts
    $OOBEKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\OOBE"
    if (-not (Test-Path $OOBEKey)) { New-Item -Path $OOBEKey -Force | Out-Null }
    Set-ItemProperty -Path $OOBEKey -Name "DisablePrivacyExperience" -Value 1 -Type DWord -Force

    # Disable Windows Telemetry
    $TelemetryKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    if (-not (Test-Path $TelemetryKey)) { New-Item -Path $TelemetryKey -Force | Out-Null }
    Set-ItemProperty -Path $TelemetryKey -Name "AllowTelemetry" -Value 0 -Type DWord -Force

    # Disable Windows Consumer Features (Stops auto-install of TikTok/Candy Crush on clean Pro ISOs)
    $CloudContentKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    if (-not (Test-Path $CloudContentKey)) { New-Item -Path $CloudContentKey -Force | Out-Null }
    Set-ItemProperty -Path $CloudContentKey -Name "DisableWindowsConsumerFeatures" -Value 1 -Type DWord -Force

    # Restore Classic Context Menu
    $ContextMenuKey = "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32"
    if (-not (Test-Path $ContextMenuKey)) { New-Item -Path $ContextMenuKey -Force | Out-Null }
    Set-ItemProperty -Path $ContextMenuKey -Name "(Default)" -Value "" -Force

    # Enable Long Paths (Bypass 260 character limit)
    $FileSystemKey = "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem"
    if (-not (Test-Path $FileSystemKey)) { New-Item -Path $FileSystemKey -Force | Out-Null }
    Set-ItemProperty -Path $FileSystemKey -Name "LongPathsEnabled" -Value 1 -Type DWord -Force

    # --- Explorer & Taskbar Tweaks ---
    $ExplorerKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    if (-not (Test-Path $ExplorerKey)) { New-Item -Path $ExplorerKey -Force | Out-Null }
    
    # Move Windows 11 Taskbar to the Left (0 = Left, 1 = Center)
    Set-ItemProperty -Path $ExplorerKey -Name "TaskbarAl" -Value 0 -Type DWord -Force
    # Show hidden files and folders (1 = Show, 2 = Hide)
    Set-ItemProperty -Path $ExplorerKey -Name "Hidden" -Value 1 -Type DWord -Force
    # Show known file extensions (0 = Show, 1 = Hide)
    Set-ItemProperty -Path $ExplorerKey -Name "HideFileExt" -Value 0 -Type DWord -Force

    Write-Host "--- System tweaks applied successfully. ---" -ForegroundColor Green
} catch {
    Write-Error "Failed to apply system tweaks. Error: $_"
}

# 7. --- Apply System Defenses ---
Write-Host "--- Enabling Defender PUA Protection... ---" -ForegroundColor Yellow
try {
    Set-MpPreference -PUAProtection Enabled -ErrorAction Stop
    Write-Host "--- PUA Protection enabled. ---" -ForegroundColor Green
} catch {
    Write-Warning "Failed to enable PUA Protection. Error: $_"
}

# 8. --- Set Ultimate Performance Power Plan ---
Write-Host "--- Enabling Ultimate Performance Power Plan... ---" -ForegroundColor Yellow
try {
    $currentPlan = powercfg -getactivescheme
    if ($currentPlan -notmatch "e9a42b02-d5df-448d-aa00-03f14749eb61") {
        $Plan = powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61
        $PlanGUID = [regex]::Match($Plan, '([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})').Value
        powercfg -setactive $PlanGUID
        Write-Host "Ultimate Performance enabled." -ForegroundColor Green
    } else {
        Write-Host "Ultimate Performance Power Plan is already active. Skipping..." -ForegroundColor Green
    }
} catch {
    Write-Warning "Could not set power plan. Error: $_"
}

# 9. --- Clean Microsoft Base Bloatware ---
Write-Host "--- Removing select pre-installed Appx packages... ---" -ForegroundColor Yellow
$bloatware = @(
    "*Microsoft.BingNews*", 
    "*Microsoft.GetHelp*", 
    "*Microsoft.Getstarted*", 
    "*Microsoft.MicrosoftOfficeHub*", 
    "*Microsoft.MicrosoftSolitaireCollection*", 
    "*Microsoft.PowerAutomateDesktop*", 
    "*Microsoft.Todos*"
)
foreach ($app in $bloatware) {
    if (Get-AppxPackage -Name $app) {
        Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $app | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
    }
}
Write-Host "--- Base bloatware removal complete. ---" -ForegroundColor Green

# 10. --- Enable Windows Features & Capabilities ---
Write-Host "--- Enabling Windows Optional Features & Capabilities... ---" -ForegroundColor Yellow
try {
    # WSL & Sandbox
    $features = @("Microsoft-Windows-Subsystem-Linux", "VirtualMachinePlatform", "Containers-DisposableClientVM")
    foreach ($feature in $features) {
        $checkFeature = Get-WindowsOptionalFeature -Online -FeatureName $feature -ErrorAction SilentlyContinue
        if ($checkFeature.State -ne 'Enabled') {
            Enable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -All -WarningAction SilentlyContinue | Out-Null
            Write-Host "Enabled Feature: $feature" -ForegroundColor Green
        } else {
            Write-Host "Feature $feature is already enabled. Skipping..." -ForegroundColor Green
        }
    }

    # OpenSSH Client
    $sshFeatures = @("OpenSSH.Client~~~~0.0.1.0")
    foreach ($ssh in $sshFeatures) {
        $checkCapability = Get-WindowsCapability -Online -Name $ssh -ErrorAction SilentlyContinue
        if ($checkCapability.State -ne 'Installed') {
            Write-Host "Installing Capability: $ssh..."
            Add-WindowsCapability -Online -Name $ssh -ErrorAction SilentlyContinue | Out-Null
            Write-Host "Installed Capability: $ssh" -ForegroundColor Green
        } else {
            Write-Host "Capability $ssh is already installed. Skipping..." -ForegroundColor Green
        }
    }

} catch {
    Write-Warning "Failed during Windows Features configuration. Error: $_"
}

# 11. --- Install NVIDIA App (Dynamic Fetch & Check) ---
Write-Host "--- Checking NVIDIA App status... ---" -ForegroundColor Yellow
try {
    $NvAppExe = "C:\Program Files\NVIDIA Corporation\NVIDIA app\nvapp.exe"
    
    if (Test-Path $NvAppExe) {
        Write-Host "NVIDIA App is already installed on this system. Skipping download and installation." -ForegroundColor Green
    } else {
        Write-Host "NVIDIA App not found. Fetching the latest download link dynamically..."
        
        # Scrape the official page for the latest URL
        $nvWebPage = Invoke-WebRequest -Uri "https://www.nvidia.com/en-us/software/nvidia-app/" -UseBasicParsing -ErrorAction SilentlyContinue
        $regex = '(https://us\.download\.nvidia\.com/nvapp/client/[^"''\s><]+\.exe)'
        $match = [regex]::Match($nvWebPage.Content, $regex)
        
        if ($match.Success) {
            $url = $match.Value
            Write-Host "Found latest NVIDIA installer: $url" -ForegroundColor Cyan
        } else {
            # Fallback to the last known working version if scraping fails
            $url = "https://us.download.nvidia.com/nvapp/client/11.0.5.266/NVIDIA_app_v11.0.5.266.exe"
            Write-Host "Dynamic fetch failed. Using default fallback URL: $url" -ForegroundColor DarkYellow
        }

        $fileName = Split-Path -Path $url -Leaf
        $InstallerPath = Join-Path -Path $InstallerDir -ChildPath $fileName

        if (Test-Path $InstallerPath) {
            Write-Host "Existing installer found at $InstallerPath. Skipping download." -ForegroundColor Green
        } else {
            Write-Host "Downloading $fileName to $InstallerDir..."
            Invoke-WebRequest -Uri $url -OutFile $InstallerPath -ErrorAction Stop
            Write-Host "Download complete." -ForegroundColor Green
        }

        Write-Host "Starting silent installation from $InstallerPath..."
        $nvProcess = Start-Process -FilePath $InstallerPath -ArgumentList '-s -n -passive -noreboot' -Wait -PassThru -ErrorAction Stop
        
        if ($nvProcess.ExitCode -eq 3010) {
            Write-Host "NVIDIA App installed successfully, but a reboot is required to finalize (Exit Code 3010)." -ForegroundColor Yellow
        } elseif ($nvProcess.ExitCode -ne 0 -and $nvProcess.ExitCode -ne $null) {
            Write-Warning "NVIDIA installer exited with code $($nvProcess.ExitCode). Check NVIDIA logs if the app fails to launch."
        } else {
            Write-Host "Installation process finished with exit code 0." -ForegroundColor Green
        }

        Write-Host "--- NVIDIA App installation complete. ---" -ForegroundColor Green
    }
} catch {
    Write-Error "An error occurred during the NVIDIA App routine: $_"
}

# 12. --- Define Package Lists ---
$packages = @(
    "7zip.7zip",
    "Brave.Brave",
    "Google.Chrome",
    "CrystalDewWorld.CrystalDiskInfo.ShizukuEdition",
    "Discord.Discord",
    "GitHub.GitHubDesktop",
    "Microsoft.VisualStudioCode",
    "Microsoft.PowerShell",
    "Mozilla.Firefox",
    "Notepad++.Notepad++",
    "Obsidian.Obsidian",
    "Opera.Opera",
    "Python.Python.3.13",
    "OpenWhisperSystems.Signal",
    "Valve.Steam",
    "JAMSoftware.TreeSize.Free",
    "VideoLAN.VLC"
)

# 13. --- Install standard winget packages ---
foreach ($pkg in $packages) {
    Write-Host "--- Checking status of $pkg ---"
    # Suppress output; exit code 0 means installed
    $null = winget list --id $pkg -e --accept-source-agreements
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "$pkg is already installed. Skipping..." -ForegroundColor Green
    } else {
        Write-Host "Installing $pkg via winget..."
        winget install --id $pkg -e --silent --accept-source-agreements --accept-package-agreements --force
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Winget returned a non-zero exit code for $pkg. It may be pending a reboot or encountered an issue."
        }
    }
}

# 14. --- Install Battle.net (Special Case - REQUIRES LOCATION & OVERRIDE FLAGS) ---
Write-Host "--- Checking status of Blizzard.BattleNet ---"
$null = winget list --id Blizzard.BattleNet -e --accept-source-agreements
if ($LASTEXITCODE -eq 0) {
    Write-Host "Blizzard.Battle.net is already installed. Skipping..." -ForegroundColor Green
} else {
    try {
        Write-Host "Attempting to install Blizzard.BattleNet (silently with specified location)..."
        winget install --id Blizzard.BattleNet -e --location "C:\Program Files (x86)\Battle.net" --override "--silent" --accept-source-agreements --accept-package-agreements
        if ($LASTEXITCODE -ne 0) { throw "Winget failed to install Battle.net. Exit code: $LASTEXITCODE" }
        Write-Host "--- Successfully installed Blizzard.Battle.net. ---" -ForegroundColor Green
    } catch {
        Write-Error "Failed to install Blizzard.Battle.net. Error: $_"
    }
}

# 15. --- Install Windows Updates ---
Write-Host "--- Checking for PSWindowsUpdate module... ---" -ForegroundColor Yellow
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
    Install-Module -Name PSWindowsUpdate -Repository PSGallery -Force -Scope AllUsers -ErrorAction SilentlyContinue
    Write-Host "--- Module installed. ---" -ForegroundColor Green
} else {
    Write-Host "PSWindowsUpdate module is already installed. Skipping download..." -ForegroundColor Green
}

Write-Host "--- Checking for and installing Windows Updates... ---" -ForegroundColor Yellow
try {
    Import-Module PSWindowsUpdate -ErrorAction Stop
    Install-WindowsUpdate -AcceptAll -IgnoreReboot
    Write-Host "--- Windows Update check complete. ---" -ForegroundColor Green
} catch {
    Write-Error "Failed to run PSWindowsUpdate module. Error: $_"
}

# 16. --- Final Message ---
Write-Host ""
Write-Host "****************************************************************"
Write-Host "All installation and configuration steps are complete!"
Write-Host "Dynamic NVIDIA fetch processed."
Write-Host "A reboot may be required to finish installing Windows Updates or new features."
Write-Host "Log file is saved at: $LogPath"
Write-Host "****************************************************************"

# 17. --- Stop Logging ---
Stop-Transcript

# 18. --- Prompt for Reboot ---
Write-Host ""
$title = "Reboot Recommended"
$message = "Installation complete. A reboot is recommended to finish applying new features and system tweaks. Would you like to reboot now?"
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