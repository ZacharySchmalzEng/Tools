#!/bin/bash
# ==============================================================================
# Script Name:    deploy-restic-gdrive.sh
# Description:    Zero-touch, automated Restic backup deployment with Google 
#                 Drive backend. Includes disaster recovery, multi-machine 
#                 randomization, and isolated API limits. Supports both Standard
#                 and Atomic (Silverblue/Kinoite) Fedora variants.
# Repository:     Linux Automation & Provisioning Tools
# Author:         Zachary Schmalz

# ==============================================================================
set -euo pipefail

# --- Configuration ---
RCLONE_REMOTE="gdrive"
BACKUP_DIR_NAME="FedoraBackup"
RESTIC_BIN_DIR="$HOME/.local/bin"
RESTIC_SCRIPT="$RESTIC_BIN_DIR/gdrive-backup.sh"
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
PASSWD_FILE="$HOME/.config/restic-passwd"
export XDG_RUNTIME_DIR="/run/user/$(id -u)"

# Define targets (Space-separated, safely quoted)
TARGETS_TO_BACKUP="\"$HOME/Documents\" \"$HOME/Pictures\" \"$HOME/Videos\" \"$HOME/Music\" \"$HOME/Desktop\""

echo "[*] Starting automated backup infrastructure setup..."

# 1. Dependency Check & Universal Package Management
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
            if command -v rpm-ostree &> /dev/null; then
                echo "[*] Fedora Atomic Host detected. Layering packages via rpm-ostree..."
                sudo rpm-ostree install $MISSING_PKGS
                echo "------------------------------------------------------------------------------"
                echo "[!] ATOMIC HOST REBOOT REQUIRED"
                echo "[!] Packages have been staged. Reboot, then run this deployment script again."
                echo "------------------------------------------------------------------------------"
                exit 0
            elif command -v dnf &> /dev/null; then
                sudo dnf install -y $MISSING_PKGS
            else
                echo "[!] Neither dnf nor rpm-ostree detected. Cannot install."
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

# 2. Rclone Google Drive Integration (Functional API Validation)
if ! rclone lsd "${RCLONE_REMOTE}:" &> /dev/null; then
    echo "[*] Google Drive connection invalid or missing. Initiating setup..."
    echo "[*] A browser window will open. Please authenticate with Google, allow access, and return here."
    sleep 2
    rclone config create "$RCLONE_REMOTE" drive scope drive
    
    # Post-setup functional validation
    if ! rclone lsd "${RCLONE_REMOTE}:" &> /dev/null; then
        echo "[!] OAuth token validation failed. Purging broken config..."
        rclone config delete "$RCLONE_REMOTE"
        exit 1
    fi
    echo "[+] Google Drive connection established successfully!"
else
    echo "[+] Google Drive connection ('${RCLONE_REMOTE}') already configured."
fi

# 3 & 4. Smart Password Handling & Repository Initialization
mkdir -p "$(dirname "$PASSWD_FILE")"

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
        read -s -p "    Enter your EXISTING Restic encryption password: " USER_PASS
        echo ""
        echo "$USER_PASS" > "$PASSWD_FILE"
        chmod 600 "$PASSWD_FILE"
        
        if ! restic -r "rclone:${RCLONE_REMOTE}:${BACKUP_DIR_NAME}" --password-file "$PASSWD_FILE" snapshots &> /dev/null; then
            echo "[!] Error: Incorrect password. Decryption failed."
            rm -f "$PASSWD_FILE"
            exit 1
        fi
        echo "[+] Password verified and saved securely."
    else
        echo "[*] Generating a secure, random encryption password for a NEW repository..."
        openssl rand -base64 32 > "$PASSWD_FILE"
        chmod 600 "$PASSWD_FILE"
        restic -r "rclone:${RCLONE_REMOTE}:${BACKUP_DIR_NAME}" --password-file "$PASSWD_FILE" init
        echo "[+] Repository initialized successfully."
    fi
else
    echo "[+] Existing local password file found. Using it."
    if [ "$REPO_EXISTS" = false ]; then
        restic -r "rclone:${RCLONE_REMOTE}:${BACKUP_DIR_NAME}" --password-file "$PASSWD_FILE" init
    fi
fi

# 5. Create the Execution Backup Script
mkdir -p "$RESTIC_BIN_DIR"
cat << EOF > "$RESTIC_SCRIPT"
#!/bin/bash
set -euo pipefail
REPO="rclone:${RCLONE_REMOTE}:${BACKUP_DIR_NAME}"
PASS_FILE="$PASSWD_FILE"
restic -r "\$REPO" --password-file "\$PASS_FILE" backup $TARGETS_TO_BACKUP
restic -r "\$REPO" --password-file "\$PASS_FILE" forget --keep-daily 30 --keep-weekly 4 --keep-monthly 12 --prune
EOF
chmod +x "$RESTIC_SCRIPT"

# 6. Create Systemd User Service Unit
mkdir -p "$SYSTEMD_USER_DIR"
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
cat << EOF > "$SYSTEMD_USER_DIR/restic-gdrive-backup.timer"
[Unit]
Description=Run Restic Google Drive Backup Daily

[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=7200
Persistent=true

[Install]
WantedBy=timers.target
EOF

# 8. Reload and Enable Systemd Timer
echo "[*] Activating Systemd automated timer..."
systemctl --user daemon-reload
systemctl --user enable --now restic-gdrive-backup.timer

echo "=============================================================================="
echo "[+] SETUP COMPLETE!"
echo "=============================================================================="