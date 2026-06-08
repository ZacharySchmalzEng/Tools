#!/bin/bash
# ==============================================================================
# Automated Restic + Google Drive Backup Installer for Fedora
# ==============================================================================
set -euo pipefail

# --- Configuration ---
RCLONE_REMOTE="gdrive"
BACKUP_DIR_NAME="FedoraBackup"
RESTIC_BIN_DIR="$HOME/.local/bin"
RESTIC_SCRIPT="$RESTIC_BIN_DIR/gdrive-backup.sh"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
PASSWD_FILE="$HOME/.config/restic-passwd"

# Define what directories to back up (Space-separated)
TARGETS_TO_BACKUP="\"\$HOME/Documents\""

echo "[*] Starting automated backup infrastructure setup..."

# 1. Dependency Check & Auto-Install
MISSING_PKGS=""
for cmd in rclone restic; do
    if ! command -v "$cmd" &> /dev/null; then
        MISSING_PKGS="$MISSING_PKGS $cmd"
    fi
done

if [ -n "$MISSING_PKGS" ]; then
    echo "[!] Missing required dependencies:$MISSING_PKGS"
    read -p "[?] Would you like to install them now? (Will prompt for sudo password) [Y/n]: " choice
    case "$choice" in 
        y|Y|"" )
            echo "[*] Elevating privileges to install missing packages..."
            set +e
            sudo dnf install -y $MISSING_PKGS
            if [ $? -ne 0 ]; then
                echo "[!] Installation failed or was canceled. Exiting."
                exit 1
            fi
            set -e
            ;;
        * )
            echo "[!] Cannot proceed without required dependencies. Exiting."
            exit 1
            ;;
    esac
fi

# 2. Rclone Google Drive Integration
if ! rclone listremotes | grep -q "^${RCLONE_REMOTE}:"; then
    echo "[*] Google Drive connection not found."
    echo "[*] Initiating automated Rclone setup..."
    echo "[*] A browser window will open. Please authenticate with Google, allow access, and return here."
    sleep 2
    rclone config create "$RCLONE_REMOTE" drive scope drive
    if ! rclone listremotes | grep -q "^${RCLONE_REMOTE}:"; then
        echo "[!] Failed to configure Google Drive. Exiting."
        exit 1
    fi
    echo "[+] Google Drive connection established successfully!"
else
    echo "[+] Google Drive connection ('${RCLONE_REMOTE}') already configured."
fi

# 3 & 4. Smart Password Handling & Repository Initialization
mkdir -p "$(dirname "$PASSWD_FILE")"

# Check if a Restic repository already exists on the remote (looking for the 'config' file)
REPO_EXISTS=false
if rclone ls "${RCLONE_REMOTE}:${BACKUP_DIR_NAME}/config" &> /dev/null; then
    REPO_EXISTS=true
fi

if [ ! -f "$PASSWD_FILE" ]; then
    if [ "$REPO_EXISTS" = true ]; then
        echo "------------------------------------------------------------------------------"
        echo "[!] DISASTER RECOVERY MODE TRIGGERED"
        echo "[!] An existing backup was found on Google Drive, but no local password file exists."
        echo "------------------------------------------------------------------------------"
        # Prompt for existing password silently (-s)
        read -s -p "    Enter your EXISTING Restic encryption password: " USER_PASS
        echo ""
        
        # Temporarily save it to verify
        echo "$USER_PASS" > "$PASSWD_FILE"
        chmod 600 "$PASSWD_FILE"
        
        echo "[*] Verifying password against Google Drive repository..."
        if ! restic -r "rclone:${RCLONE_REMOTE}:${BACKUP_DIR_NAME}" --password-file "$PASSWD_FILE" snapshots &> /dev/null; then
            echo "[!] Error: Incorrect password. Decryption failed."
            rm -f "$PASSWD_FILE" # Clean up the wrong password
            exit 1
        fi
        echo "[+] Password verified and saved securely."
    else
        echo "[*] Generating a secure, random encryption password for a NEW repository..."
        openssl rand -base64 32 > "$PASSWD_FILE"
        chmod 600 "$PASSWD_FILE"
        echo "[+] Password file created securely at: $PASSWD_FILE"
        echo "    CRITICAL: Back up this file safely! If lost, your backups cannot be recovered."
        
        echo "[*] Initializing new Restic repository on Google Drive..."
        restic -r "rclone:${RCLONE_REMOTE}:${BACKUP_DIR_NAME}" --password-file "$PASSWD_FILE" init
        echo "[+] Repository initialized successfully."
    fi
else
    echo "[+] Existing local password file found at $PASSWD_FILE. Using it."
    if [ "$REPO_EXISTS" = true ]; then
        echo "[+] Valid Restic repository verified on Google Drive."
    else
        echo "[!] Local password exists but Google Drive repo is missing. Initializing repo..."
        restic -r "rclone:${RCLONE_REMOTE}:${BACKUP_DIR_NAME}" --password-file "$PASSWD_FILE" init
        echo "[+] Repository initialized successfully."
    fi
fi

# 5. Create the Execution Backup Script
mkdir -p "$RESTIC_BIN_DIR"
echo "[*] Creating backup worker script at $RESTIC_SCRIPT..."

cat << EOF > "$RESTIC_SCRIPT"
#!/bin/bash
set -euo pipefail

REPO="rclone:${RCLONE_REMOTE}:${BACKUP_DIR_NAME}"
PASS_FILE="$PASSWD_FILE"

echo "[*] Starting backup run: \$(date)"

# Run backup snapshot
restic -r "\$REPO" --password-file "\$PASS_FILE" backup $TARGETS_TO_BACKUP

# Enforce retention policy
restic -r "\$REPO" --password-file "\$PASS_FILE" forget \\
    --keep-daily 7 \\
    --keep-weekly 4 \\
    --keep-monthly 12 \\
    --prune

echo "[+] Backup run completed successfully: \$(date)"
EOF

chmod +x "$RESTIC_SCRIPT"

# 6. Create Systemd User Service Unit
mkdir -p "$SYSTEMD_USER_DIR"
echo "[*] Deploying Systemd User Service..."

cat << EOF > "$SYSTEMD_USER_DIR/restic-gdrive-backup.service"
[Unit]
Description=Automated Restic Backup to Google Drive
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$RESTIC_SCRIPT
IOSchedulingClass=idle
CPUSchedulingPolicy=idle
EOF

# 7. Create Systemd User Timer Unit
echo "[*] Deploying Systemd User Timer..."

cat << EOF > "$SYSTEMD_USER_DIR/restic-gdrive-backup.timer"
[Unit]
Description=Run Restic Google Drive Backup Daily

[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=7200
Persistent=true

[Install]
WantedBy=timers.target

# 8. Reload and Enable Systemd Timer
echo "[*] Activating Systemd automated timer..."
systemctl --user daemon-reload
systemctl --user enable --now restic-gdrive-backup.timer

echo "=============================================================================="
echo "[+] SETUP COMPLETE!"
echo "=============================================================================="
echo " -> Backup Worker:  $RESTIC_SCRIPT"
echo " -> Systemd Timer:  systemctl --user list-timers"
echo " -> Manual Trigger: systemctl --user start restic-gdrive-backup.service"
echo " -> View Logs:      journalctl --user -u restic-gdrive-backup.service"
echo "=============================================================================="