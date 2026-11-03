<#
.SYNOPSIS
    Zero-touch, automated Restic backup deployment for Windows with Google Drive backend.
.DESCRIPTION
    Automates the installation, configuration, and scheduling of an encrypted, deduplicated 
    backup pipeline. Integrates VSS (--use-fs-snapshot), intelligent retention, disaster 
    recovery, and Task Scheduler randomization to prevent API collisions.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

# --- Configuration ---
$RcloneRemote = "gdrive"
$BackupDirName = "WindowsBackup" # Differentiates from FedoraBackup if desired, though Restic isolates by hostname anyway.
$BasePath = "$env:USERPROFILE\.config"
$PasswdFile = "$BasePath\restic-passwd.txt"
$WorkerScriptPath = "C:\Scripts\Restic-Worker.ps1"

# Define targets (Comma-separated array of strings for PowerShell)
$Targets = "`"$env:USERPROFILE\Documents`"", "`"$env:USERPROFILE\Pictures`"", "`"$env:USERPROFILE\Videos`"", "`"$env:USERPROFILE\Desktop`""

Write-Output "[*] Starting Windows automated backup infrastructure setup..."

# 1. Dependency Check & Auto-Install
$missingPkgs = @()
if (-not (Get-Command "rclone" -ErrorAction SilentlyContinue)) { $missingPkgs += "Rclone.Rclone" }
if (-not (Get-Command "restic" -ErrorAction SilentlyContinue)) { $missingPkgs += "restic.restic" }

if ($missingPkgs.Count -gt 0) {
    Write-Output "[*] Missing dependencies detected. Installing via winget..."
    foreach ($pkg in $missingPkgs) {
        winget install --id $pkg --exact --accept-package-agreements --accept-source-agreements --silent
    }
    # Refresh environment variables for the current session to expose new binaries
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
}

# 2. Rclone Google Drive Integration (With Custom API Keys)
$rcloneList = rclone listremotes 2>$null
if ($rcloneList -notmatch "^${RcloneRemote}:") {
    Write-Output "`n[*] API RATE LIMIT PREVENTION"
    Write-Output "[*] Please provide your personal Google Cloud API keys."
    Write-Output "[*] (Press Enter to leave blank and use shared public keys, but expect 403 throttling).`n"
    
    $ClientID = Read-Host "    Enter Google Client ID"
    $ClientSecret = Read-Host "    Enter Google Client Secret" -AsSecureString
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)
    $PlainSecret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    
    Write-Output "`n[*] Initiating automated Rclone setup. A browser will open to authenticate..."
    Start-Sleep -Seconds 2
    
    if (-not [string]::IsNullOrWhiteSpace($ClientID) -and -not [string]::IsNullOrWhiteSpace($PlainSecret)) {
        rclone config create $RcloneRemote drive scope drive client_id $ClientID client_secret $PlainSecret
    } else {
        Write-Output "[!] Warning: Proceeding with shared public API keys..."
        rclone config create $RcloneRemote drive scope drive
    }
} else {
    Write-Output "[+] Google Drive connection ('$RcloneRemote') already configured."
}

# 3 & 4. Smart Password Handling & Repository Initialization
if (-not (Test-Path $BasePath)) { New-Item -ItemType Directory -Path $BasePath -Force | Out-Null }

$RepoExists = $false
$repoCheck = rclone ls "${RcloneRemote}:${BackupDirName}/config" 2>&1
if ($LASTEXITCODE -eq 0) { $RepoExists = $true }

if (-not (Test-Path $PasswdFile)) {
    if ($RepoExists) {
        Write-Output "`n[!] DISASTER RECOVERY MODE TRIGGERED"
        Write-Output "[!] An existing backup was found on Google Drive, but no local password file exists."
        $UserPass = Read-Host "    Enter your EXISTING Restic encryption password" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($UserPass)
        $PlainPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        
        Set-Content -Path $PasswdFile -Value $PlainPass
        
        Write-Output "[*] Verifying password against Google Drive repository..."
        $verify = restic -r "rclone:${RcloneRemote}:${BackupDirName}" --password-file $PasswdFile snapshots 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Output "[!] Error: Incorrect password. Decryption failed."
            Remove-Item $PasswdFile -Force
            exit 1
        }
        Write-Output "[+] Password verified and saved securely."
    } else {
        Write-Output "[*] Generating a secure, random encryption password for a NEW repository..."
        $RandomBytes = New-Object byte[] 32
        (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($RandomBytes)
        $GeneratedPass = [System.Convert]::ToBase64String($RandomBytes)
        
        Set-Content -Path $PasswdFile -Value $GeneratedPass
        Write-Output "[+] Password file created securely at: $PasswdFile"
        Write-Output "    CRITICAL: Back up this file safely! If lost, your backups cannot be recovered."
        
        Write-Output "[*] Initializing new Restic repository on Google Drive..."
        restic -r "rclone:${RcloneRemote}:${BackupDirName}" --password-file $PasswdFile init
    }
} else {
    Write-Output "[+] Existing local password file found. Using it."
    if (-not $RepoExists) {
        Write-Output "[!] Local password exists but Google Drive repo is missing. Initializing repo..."
        restic -r "rclone:${RcloneRemote}:${BackupDirName}" --password-file $PasswdFile init
    }
}

# Lock down password file ACLs to current user and SYSTEM
$Acl = Get-Acl $PasswdFile
$Acl.SetAccessRuleProtection($true, $false)
$RuleSys = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\SYSTEM", "FullControl", "Allow")
$RuleUsr = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "FullControl", "Allow")
$Acl.AddAccessRule($RuleSys)
$Acl.AddAccessRule($RuleUsr)
Set-Acl -Path $PasswdFile -AclObject $Acl

# 5. Create the Execution Backup Script
if (-not (Test-Path "C:\Scripts")) { New-Item -ItemType Directory -Path "C:\Scripts" -Force | Out-Null }

Write-Output "[*] Creating backup worker script at $WorkerScriptPath..."
$WorkerScriptContent = @"
`$ErrorActionPreference = "Stop"
`$Repo = "rclone:${RcloneRemote}:${BackupDirName}"
`$PassFile = "$PasswdFile"
`$Targets = $Targets

Write-Output "[*] Starting Windows Restic Backup: `$(Get-Date)"

# Execute backup utilizing VSS (--use-fs-snapshot)
restic -r `$Repo --password-file `$PassFile --use-fs-snapshot backup `$Targets

# Enforce identical 30-day retention policy
restic -r `$Repo --password-file `$PassFile forget --keep-daily 30 --keep-weekly 4 --keep-monthly 12 --prune

Write-Output "[+] Backup run completed successfully: `$(Get-Date)"
"@
Set-Content -Path $WorkerScriptPath -Value $WorkerScriptContent

# 6. Deploy Windows Scheduled Task (With Multi-Machine Randomizer)
Write-Output "[*] Deploying Task Scheduler Job..."
$TaskName = "Restic Background Backup"

# Remove existing task if updating
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Run at 3:00 AM with a 2-Hour random delay to prevent API collisions
$Trigger = New-ScheduledTaskTrigger -Daily -At "3:00 AM"
$Trigger.RandomDelay = New-TimeSpan -Hours 2

# Execute silently bypassing execution policies
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$WorkerScriptPath`""

# MUST run as SYSTEM/Highest to hook into VSS for file locks
$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings | Out-Null

Write-Output "=============================================================================="
Write-Output "[+] WINDOWS SETUP COMPLETE!"
Write-Output "=============================================================================="
Write-Output " -> Backup Worker:  $WorkerScriptPath"
Write-Output " -> Task Scheduler: $TaskName"
Write-Output " -> Manual Trigger: Start-ScheduledTask -TaskName `"$TaskName`""
Write-Output "=============================================================================="