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
winget uninstall --id 9MSSGKG348SP
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Failed to uninstall Windows Widgets. It may already be removed."
} else {
    Write-Host "--- Windows Widgets uninstalled successfully. ---" -ForegroundColor Green
}

# 6. --- Apply System Tweaks via Registry ---
Write-Host "--- Applying system tweaks... ---" -ForegroundColor Yellow
try {
    # Disable OneDrive via Group Policy registry key
    $OneDriveKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
    if (-not (Test-Path $OneDriveKey)) { New-Item -Path $OneDriveKey -Force }
    Set-ItemProperty -Path $OneDriveKey -Name "DisableFileSyncNGSC" -Value 1 -Type DWord -Force

    # Make MS Account optional during OOBE/setup
    $MSAKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    if (-not (Test-Path $MSAKey)) { New-Item -Path $MSAKey -Force }
    Set-ItemProperty -Path $MSAKey -Name "MSAOptional" -Value 1 -Type DWord -Force

    # Disable "Finish setting up your device" (Windows Welcome Experience) prompts
    $OOBEKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\OOBE"
    if (-not (Test-Path $OOBEKey)) { New-Item -Path $OOBEKey -Force }
    Set-ItemProperty -Path $OOBEKey -Name "DisablePrivacyExperience" -Value 1 -Type DWord -Force

    Write-Host "--- System tweaks applied successfully. ---" -ForegroundColor Green
} catch {
    Write-Error "Failed to apply system tweaks. Error: $_"
}

# 7. --- Install NVIDIA App (Download to Installers Directory) ---
Write-Host "--- Starting NVIDIA App installation... ---" -ForegroundColor Yellow
try {
    $url = "https://us.download.nvidia.com/nvapp/client/11.0.5.266/NVIDIA_app_v11.0.5.266.exe"
    $fileName = Split-Path -Path $url -Leaf
    $InstallerPath = Join-Path -Path $InstallerDir -ChildPath $fileName

    # Always download
    Write-Host "Using URL: $url"
    Write-Host "Downloading $fileName to $InstallerDir..."
    Invoke-WebRequest -Uri $url -OutFile $InstallerPath -ErrorAction Stop
    Write-Host "Download complete." -ForegroundColor Green

    Write-Host "Starting silent installation from $InstallerPath..."
    # Silent install flags: -s (silent), -c (clean install), -n (no system tray), -passive, -noreboot
    Start-Process -FilePath $InstallerPath -ArgumentList '-s -c -n -passive -noreboot' -Wait -ErrorAction Stop
    Write-Host "Installation process finished."

    Write-Host "Cleaning up $InstallerPath..."
    Remove-Item -Path $InstallerPath -Force -ErrorAction SilentlyContinue

    Write-Host "--- NVIDIA App installation complete. ---" -ForegroundColor Green

} catch {
    Write-Error "An error occurred during the NVIDIA App installation: $_"
}


# 8. --- Define Package Lists ---
$packages = @(
    "7zip.7zip",
    "Blizzard.BattleNet",
    "Brave.Brave",
    "Piriform.CCleaner",
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

# 9. --- Install standard winget packages ---
foreach ($pkg in $packages) {
    Write-Host "--- Attempting to install $pkg via winget ---"
    winget install --id $pkg -e --accept-source-agreements --accept-package-agreements
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Failed to install $pkg. Check the log for details."
    }
}

# 10. --- Install Battle.net (Special Case - REQUIRES LOCATION & UPGRADE FLAG) ---
Write-Host "--- Attempting to install/upgrade Blizzard.BattleNet (with custom location)... ---"
try {
    winget install --id Blizzard.BattleNet -e --location "C:\Program Files" --accept-source-agreements --accept-package-agreements --include-unknown
    if ($LASTEXITCODE -ne 0) { throw "Winget failed to install/upgrade Battle.net. Exit code: $LASTEXITCODE" }
    Write-Host "--- Successfully installed/upgraded Blizzard.Battle.net. ---" -ForegroundColor Green
} catch {
    Write-Error "Failed to install/upgrade Blizzard.Battle.net. Error: $_"
}

# 11. --- Install Windows Updates ---
Write-Host "--- Installing PSWindowsUpdate module (if needed)... ---" -ForegroundColor Yellow
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
Install-Module -Name PSWindowsUpdate -Repository PSGallery -Force -Scope AllUsers -ErrorAction SilentlyContinue
Write-Host "--- Module install attempt finished. ---"
Write-Host "--- Checking for and installing Windows Updates... ---" -ForegroundColor Yellow
try {
    Import-Module PSWindowsUpdate -ErrorAction Stop
    Install-WindowsUpdate -AcceptAll -IgnoreReboot # Does not force a reboot
    Write-Host "--- Windows Update check complete. ---" -ForegroundColor Green
} catch {
    Write-Error "Failed to run PSWindowsUpdate module. Error: $_"
}

# 12. --- Final Message ---
Write-Host ""
Write-Host "****************************************************************"
Write-Host "All installation attempts are complete!"
Write-Host "NVIDIA App version 11.0.5.266 should now be installed."
Write-Host "A reboot may be required to finish installing Windows Updates."
Write-Host "Log file is saved at: $LogPath"
Write-Host "****************************************************************"

# 13. --- Stop Logging ---
Stop-Transcript

# 14. --- Prompt for Reboot ---
Write-Host ""
$title = "Reboot Recommended"
$message = "Installation complete. A reboot is recommended to finish installing Windows Updates, the NVIDIA driver, and apply system tweaks. Would you like to reboot now?"
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