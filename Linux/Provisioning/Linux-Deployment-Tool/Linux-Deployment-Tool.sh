#!/bin/bash
# ==============================================================================
# SYNOPSIS
#     Automated Linux provisioning and environment setup script.
#
# DESCRIPTION
#     This script provides a modular, flag-based deployment tool for modern Linux
#     distributions. It combines system updates, dual-boot/Secure Boot MOK setup,
#     NTFS automounting, SSH/2FA provisioning, Nobara/Bazzite-grade gaming setup,
#     application deployment, and tiered system hardening.
#
# AUTHOR
#     Zachary Schmalz
#
# NOTES
#     Version:        1.3
#     Requirements:   Bash, root/sudo privileges, active internet connection.
#     Supported OS:   Fedora/RHEL-style systems and Debian/Ubuntu-style systems.
# ------------------------------------------------------------------------------
# 1. STRICT MODE & ERROR HANDLING
# ------------------------------------------------------------------------------
set -euo pipefail
IFS=$'\n\t'

# ------------------------------------------------------------------------------
# 2. CONSTANTS, GLOBAL PATHS & HELPER FUNCTIONS
# ------------------------------------------------------------------------------
readonly COLOR_INFO='\e[36m'
readonly COLOR_SUCCESS='\e[32m'
readonly COLOR_WARN='\e[33m'
readonly COLOR_ERROR='\e[31m'
readonly COLOR_RESET='\e[0m'

# Global configuration file paths (prevents readonly collisions across modules)
readonly SSHD_CONF="/etc/ssh/sshd_config"
readonly SSHD_DROPIN_DIR="/etc/ssh/sshd_config.d"
readonly SSHD_HARDEN_CONF="${SSHD_DROPIN_DIR}/00-provisioner-hardening.conf"
readonly SSHD_MFA_CONF="${SSHD_DROPIN_DIR}/01-mfa.conf"
readonly PAM_CONF="/etc/pam.d/sshd"
readonly DNF_AUTO_CONF="/etc/dnf/automatic.conf"
readonly SYSCTL_CONF="/etc/sysctl.d/99-security.conf"
readonly GAMING_SYSCTL_CONF="/etc/sysctl.d/99-gaming.conf"
readonly AUDIT_RULES="/etc/audit/rules.d/custom-security.rules"

# State tracking flags
DISTRO_FAMILY="unknown"
DISTRO_NAME="unknown"
SSH_SERVICE="sshd"
CACHE_REFRESHED=false
MOK_CONFIGURED=false
MOK_NEEDS_ENROLLMENT=false

log_info()    { echo -e "${COLOR_INFO}[INFO] $1${COLOR_RESET}"; }
log_success() { echo -e "${COLOR_SUCCESS}[+] $1${COLOR_RESET}"; }
log_warn()    { echo -e "${COLOR_WARN}[!] $1${COLOR_RESET}"; }
log_error()   { echo -e "${COLOR_ERROR}[ERROR] $1${COLOR_RESET}" >&2; }

trap 'handle_error $? $LINENO' ERR

handle_error() {
    local exit_code="${1:-0}"
    local line_number="${2:-unknown}"
    if [[ "$exit_code" -ne 0 ]]; then
        log_error "Command failed at line ${line_number} with exit code ${exit_code}."
    fi
}

run_cmd() {
    local description="$1"
    shift
    log_info "$description"
    "$@"
}

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO_NAME="${NAME:-unknown}"
        case "${ID,,}" in
            fedora|rhel|centos|rocky|almalinux)
                DISTRO_FAMILY="rpm"
                SSH_SERVICE="sshd"
                ;;
            debian|ubuntu|linuxmint|pop)
                DISTRO_FAMILY="deb"
                SSH_SERVICE="ssh"
                ;;
            *)
                DISTRO_FAMILY="unknown"
                SSH_SERVICE="sshd"
                ;;
        esac
    fi
}

refresh_package_cache() {
    local force="${1:-false}"
    if [[ "$CACHE_REFRESHED" == true ]] && [[ "$force" != "force" ]]; then
        return 0
    fi

    case "$DISTRO_FAMILY" in
        rpm)
            if run_cmd "Refreshing DNF package metadata" dnf makecache --refresh; then
                CACHE_REFRESHED=true
            else
                log_warn "DNF metadata refresh failed. Continuing..."
            fi
            ;;
        deb)
            export DEBIAN_FRONTEND=noninteractive
            if run_cmd "Refreshing APT package metadata" apt-get update; then
                CACHE_REFRESHED=true
            else
                log_warn "APT metadata refresh failed. Continuing..."
            fi
            ;;
    esac
}

resolve_package_name() {
    local package="$1"
    case "$DISTRO_FAMILY" in
        deb)
            case "$package" in
                btop) echo "btop" ;;
                bat) echo "bat" ;;
                eza) echo "eza" ;;
                plocate) echo "plocate" ;;
                mediawriter) echo "gnome-multi-writer" ;;
                p7zip-plugins) echo "p7zip-full" ;;
                vlc) echo "vlc" ;;
                timeshift) echo "timeshift" ;;
                remmina) echo "remmina" ;;
                wireshark-qt) echo "wireshark" ;;
                nmap-ncat) echo "netcat-openbsd" ;;
                prusa-slicer) echo "prusa-slicer" ;;
                darktable) echo "darktable" ;;
                blender) echo "blender" ;;
                audacity) echo "audacity" ;;
                inkscape) echo "inkscape" ;;
                obs-studio) echo "obs-studio" ;;
                steam) echo "steam" ;;
                lutris) echo "lutris" ;;
                winetricks) echo "winetricks" ;;
                openssh-server) echo "openssh-server" ;;
                google-authenticator) echo "libpam-google-authenticator" ;;
                dnf-automatic) echo "unattended-upgrades" ;;
                audit) echo "auditd" ;;
                *) echo "$package" ;;
            esac
            ;;
        *)
            echo "$package"
            ;;
    esac
}

pkg_install() {
    local packages=("$@")
    if [[ ${#packages[@]} -eq 0 ]]; then
        return 0
    fi

    local resolved_packages=()
    local package
    for package in "${packages[@]}"; do
        resolved_packages+=("$(resolve_package_name "$package")")
    done

    local install_cmd=()
    case "$DISTRO_FAMILY" in
        rpm)
            install_cmd=(dnf)
            if [[ "$AUTO_YES" == "-y" ]]; then
                install_cmd+=(-y)
            fi
            install_cmd+=(install)
            ;;
        deb)
            export DEBIAN_FRONTEND=noninteractive
            install_cmd=(apt-get)
            if [[ "$AUTO_YES" == "-y" ]]; then
                install_cmd+=(--yes)
            fi
            install_cmd+=(install)
            ;;
        *)
            log_warn "Unsupported package manager for distro: $DISTRO_NAME"
            return 1
            ;;
    esac

    refresh_package_cache
    install_cmd+=("${resolved_packages[@]}")

    if ! run_cmd "Installing packages: ${resolved_packages[*]}" "${install_cmd[@]}"; then
        log_warn "Package installation failed for: ${resolved_packages[*]}"
        return 1
    fi
}

update_system() {
    local update_cmd=()
    case "$DISTRO_FAMILY" in
        rpm)
            update_cmd=(dnf)
            if [[ "$AUTO_YES" == "-y" ]]; then
                update_cmd+=(-y)
            fi
            update_cmd+=(upgrade)
            if [[ -n "$DOWNLOAD_ONLY" ]]; then
                update_cmd+=("$DOWNLOAD_ONLY")
            fi
            ;;
        deb)
            export DEBIAN_FRONTEND=noninteractive
            update_cmd=(apt-get)
            if [[ "$AUTO_YES" == "-y" ]]; then
                update_cmd+=(--yes)
            fi
            update_cmd+=(upgrade)
            if [[ -n "$DOWNLOAD_ONLY" ]]; then
                update_cmd+=("$DOWNLOAD_ONLY")
            fi
            ;;
        *)
            log_warn "Unsupported package manager for distro: $DISTRO_NAME"
            return 1
            ;;
    esac

    refresh_package_cache "force"
    if ! run_cmd "Updating system packages" "${update_cmd[@]}"; then
        log_warn "System package update failed."
        return 1
    fi
}

ensure_flatpak() {
    if ! command -v flatpak &>/dev/null; then
        log_info "Installing Flatpak support..."
        pkg_install flatpak || log_warn "Flatpak installation failed."
    fi

    flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo || true
}

install_flatpak_apps() {
    local apps=("$@")
    if [[ ${#apps[@]} -eq 0 ]]; then
        return 0
    fi

    ensure_flatpak

    local flatpak_cmd=(flatpak install)
    if [[ "$AUTO_YES" == "-y" ]]; then
        flatpak_cmd+=(--assumeyes --noninteractive)
    fi
    flatpak_cmd+=(flathub "${apps[@]}")

    if ! run_cmd "Installing Flatpaks: ${apps[*]}" "${flatpak_cmd[@]}"; then
        log_warn "Batch Flatpak transaction reported an issue. Retrying individually..."
        local app
        for app in "${apps[@]}"; do
            if [[ "$AUTO_YES" == "-y" ]]; then
                flatpak install --assumeyes --noninteractive flathub "$app" || log_warn "Failed to install Flatpak app: $app"
            else
                flatpak install flathub "$app" || log_warn "Failed to install Flatpak app: $app"
            fi
        done
    fi
}

service_enable() {
    local service_name="$1"
    if ! run_cmd "Enabling service: $service_name" systemctl enable --now "$service_name"; then
        systemctl enable "$service_name" 2>/dev/null || true
    fi
}

service_restart() {
    local service_name="$1"
    systemctl restart "$service_name" 2>/dev/null || true
}

setup_secureboot_mok() {
    # Ensure idempotency if called by both --dualboot and --gaming
    if [[ "$MOK_CONFIGURED" == true ]]; then
        return 0
    fi

    if [[ "$DISTRO_FAMILY" != "rpm" ]]; then
        log_warn "Automated akmods MOK generation is tailored for Fedora/RPM systems. Skipping."
        MOK_CONFIGURED=true
        return 0
    fi

    pkg_install kmodtool akmods mokutil openssl || true

    if ! mokutil --sb-state 2>/dev/null | grep -qi "SecureBoot enabled"; then
        log_info "UEFI Secure Boot is currently disabled in BIOS. Skipping MOK enrollment."
        MOK_CONFIGURED=true
        return 0
    fi

    log_info "Secure Boot is ENABLED. Checking local Machine Owner Key (MOK) status..."

    # Generate the local keypair if it doesn't exist yet
    if [[ ! -f /etc/pki/akmods/certs/public_key.der ]]; then
        run_cmd "Generating local MOK keypair (/etc/pki/akmods/)" kmodgenca -a
    else
        log_info "Existing akmods MOK certificate found at /etc/pki/akmods/certs/public_key.der."
    fi

    # Check if the key is already enrolled in the motherboard's NVRAM
    if mokutil --test-key /etc/pki/akmods/certs/public_key.der 2>/dev/null | grep -qi "is already enrolled"; then
        log_success "MOK certificate is already enrolled in UEFI firmware. Nothing to do."
        MOK_CONFIGURED=true
        return 0
    fi

    MOK_NEEDS_ENROLLMENT=true

    echo -e "\n\e[33m****************************************************************"
    echo -e "SECURE BOOT MOK ENROLLMENT REQUIRED:"
    echo -e "You will now be prompted to create a one-time password."
    echo -e "Upon reboot, a blue UEFI screen (MokManager) will appear:"
    echo -e "Select: Enroll MOK -> Continue -> Yes -> Enter Password -> Reboot"
    echo -e "****************************************************************\e[0m\n"

    if [[ "$UNATTENDED" == true ]]; then
        log_warn "Unattended mode active! Skipping interactive 'mokutil --import'."
        log_warn "See the Post-Run Action Banner at the end of execution for manual enrollment command."
    else
        if mokutil --import /etc/pki/akmods/certs/public_key.der; then
            log_success "MOK certificate queued for UEFI enrollment on next reboot."
        else
            log_warn "MOK import was skipped or failed."
        fi
    fi

    MOK_CONFIGURED=true
}

print_usage() {
    echo -e "\n==============================================================="
    echo -e " Fedora Provisioning Environment Setup Script (v1.3)"
    echo -e "==============================================================="
    echo "Usage: sudo ./fedora-deployment-tool.sh [Options]"
    echo ""
    echo "MODULE OPTIONS:"
    echo "  --update           Sequentially upgrades DNF, Flatpak, and Snap"
    echo "  --dualboot         Configures Secure Boot MOK, RTC clock, and NTFS automounts"
    echo "  --apps             Installs core utilities (Browsers, Media, Search)"
    echo "  --devapps          Installs Dev tools (VS Code, Python, GitHub Desktop)"
    echo "  --cyber            Installs Security tools (Wireshark, Nmap, TCPDump)"
    echo "  --maker            Installs 3D Printing Slicers (Prusa, Orca, Bambu)"
    echo "  --creators         Installs Creative suite (Blender, Darktable, OBS)"
    echo "  --gaming           Configures RPM Fusion, Codecs, Lutris, Steam, Nvidia+CUDA"
    echo "  --ssh              Installs, enables, and verifies OpenSSH Server"
    echo "  --discord          Transitions Discord from Flatpak to native RPM"
    echo ""
    echo "SECURITY & HARDENING:"
    echo "  --harden           Safe baseline: SELinux, Auto-Patching, No Root SSH"
    echo "  --harden-advanced  Strict: auditd, Sysctl network drops, No Password SSH"
    echo "  --2fa              Modifies the --ssh module to enforce Google Auth MFA"
    echo ""
    echo "GLOBAL OPTIONS:"
    echo "  --all              Executes ALL standard modules (Excludes harden-advanced)"
    echo "  -y                 Auto-install (answers yes to prompts)"
    echo "  -d                 Download only (applies to DNF updates)"
    echo "  --debug            Enables command tracing (set -x) for troubleshooting"
    echo "  --unattended       Bypasses prompts, defaults to KDE, and auto-answers yes"
    echo "  --help             Displays this help menu"
    echo -e "===============================================================\n"
}

# ------------------------------------------------------------------------------
# 3. PARAMETER PARSING
# ------------------------------------------------------------------------------
RUN_ALL=false
RUN_UPDATE=false
RUN_DUALBOOT=false
RUN_APPS=false
RUN_DEVAPPS=false
RUN_CYBER=false
RUN_MAKER=false
RUN_CREATORS=false
RUN_GAMING=false
RUN_SSH=false
RUN_2FA=false
RUN_DISCORD=false
RUN_HARDEN=false
RUN_HARDEN_ADV=false
RUN_DEBUG=false
UNATTENDED=false
AUTO_YES=""
DOWNLOAD_ONLY=""

detect_distro

if [[ "$#" -eq 0 ]]; then
    print_usage
    exit 0
fi

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --all) RUN_ALL=true ;;
        --update) RUN_UPDATE=true ;;
        --dualboot|--secureboot) RUN_DUALBOOT=true ;;
        --apps) RUN_APPS=true ;;
        --devapps) RUN_DEVAPPS=true ;;
        --cyber) RUN_CYBER=true ;;
        --maker) RUN_MAKER=true ;;
        --creators) RUN_CREATORS=true ;;
        --gaming) RUN_GAMING=true ;;
        --ssh) RUN_SSH=true ;;
        --2fa|--mfa) RUN_2FA=true ;;
        --discord) RUN_DISCORD=true ;;
        --harden) RUN_HARDEN=true ;;
        --harden-advanced) RUN_HARDEN_ADV=true ;;
        --debug) RUN_DEBUG=true ;;
        --unattended) UNATTENDED=true ;;
        -y) AUTO_YES="-y" ;;
        -d) if [[ "$DISTRO_FAMILY" == "deb" ]]; then DOWNLOAD_ONLY="--download-only"; else DOWNLOAD_ONLY="--downloadonly"; fi ;;
        --help|-h) print_usage; exit 0 ;;
        *) log_error "Unknown parameter passed: $1"; print_usage; exit 1 ;;
    esac
    shift
done

if [[ "$RUN_ALL" == true ]]; then
    RUN_UPDATE=true; RUN_DUALBOOT=true; RUN_APPS=true; RUN_DEVAPPS=true;
    RUN_CYBER=true; RUN_MAKER=true; RUN_CREATORS=true; RUN_GAMING=true;
    RUN_SSH=true; RUN_DISCORD=true; RUN_HARDEN=true;
fi

if [[ "$UNATTENDED" == true ]]; then
    AUTO_YES="-y"
fi

# ------------------------------------------------------------------------------
# 4. PRE-FLIGHT CHECKS & LOGGING SETUP
# ------------------------------------------------------------------------------
if [[ "$EUID" -ne 0 ]]; then
    log_error "Administrator permissions are required. Please run with sudo."
    exit 1
fi

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
readonly LOG_DIR="${SCRIPT_DIR}/InstallerLogs"
mkdir -p "$LOG_DIR"

readonly TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
readonly LOG_FILE="${LOG_DIR}/installer_log_${TIMESTAMP}.log"
touch "$LOG_FILE"

# Ensure the invoking user owns the logs directory so git operations don't require sudo
if [[ -n "${SUDO_USER:-}" ]]; then
    chown -R "${SUDO_USER}:${SUDO_USER}" "$LOG_DIR" 2>/dev/null || true
fi

exec > >(tee -i "$LOG_FILE") 2>&1

if [[ "$RUN_DEBUG" == true ]]; then
    log_warn "Debug mode enabled. Command tracing (set -x) is active."
    set -x
fi

log_success "Running with root privileges."
log_info "Logging execution to: $LOG_FILE"

# ------------------------------------------------------------------------------
# 5. INTERACTIVE PROMPTS
# ------------------------------------------------------------------------------
if [[ "$UNATTENDED" == true ]]; then
    log_info "Unattended mode enabled. Automatically targeting KDE."
    DESKTOP_ENV="KDE"
else
    echo -e "\n\e[36m=== Desktop Environment Configuration ===\e[0m"
    while true; do
        read -r -p "Which Desktop Environment do you primarily use? (Gnome/KDE) [g/k]: " de_choice
        case "${de_choice,,}" in
            g|gnome) DESKTOP_ENV="GNOME"; break ;;
            k|kde) DESKTOP_ENV="KDE"; break ;;
            *) log_warn "Please enter 'g' for GNOME or 'k' for KDE." ;;
        esac
    done

    if [[ "$RUN_HARDEN_ADV" == true ]]; then
        echo -e "\n\e[31m[!] WARNING: Advanced hardening will disable SSH password authentication."
        echo -e "    Ensure you have an SSH Key provisioned before disconnecting.\e[0m"
        read -r -p "    Press Enter to acknowledge and continue..."
    fi
fi

# ==============================================================================
# MODULE: UPDATE & MAINTENANCE
# ==============================================================================
if [[ "$RUN_UPDATE" == true ]]; then
    echo -e "\n\e[35m[========== STARTING UPDATE MODULE ==========]\e[0m"
    log_info "Running system package updates..."
    if ! update_system; then
        log_warn "Package updates reported issues. Continuing..."
    fi

    if command -v flatpak &> /dev/null; then
        log_info "Running Flatpak updates..."
        flatpak upgrade ${AUTO_YES:+--assumeyes --noninteractive} || true
    fi

    if command -v snap &> /dev/null; then
        log_info "Running Snap refresh..."
        snap refresh || log_warn "Snap refresh returned a non-zero exit code. Continuing..."
    fi
    log_success "Update module complete."
fi

# ==============================================================================
# MODULE: DUAL-BOOT, SECURE BOOT MOK & NTFS AUTOMOUNT (--dualboot)
# ==============================================================================
if [[ "$RUN_DUALBOOT" == true ]]; then
    echo -e "\n\e[35m[========== STARTING DUAL-BOOT & SECURE BOOT MODULE ==========]\e[0m"

    # 1. Configure Secure Boot MOK Signing
    setup_secureboot_mok

    # 2. Fix Windows/Linux Dual-Boot System Clock Drift (RTC to Local Time)
    if command -v timedatectl &>/dev/null; then
        run_cmd "Setting hardware RTC to local time for Windows 11 compatibility" \
            timedatectl set-local-rtc 1 --adjust-system-clock || true
    fi

    # 3. Install NTFS-3G & Recovery Utilities (ntfsfix)
    log_info "Installing NTFS filesystem utilities (ntfs-3g / ntfsprogs)..."
    if [[ "$DISTRO_FAMILY" == "rpm" ]]; then
        pkg_install ntfs-3g ntfsprogs os-prober || true
    else
        pkg_install ntfs-3g os-prober || true
    fi

    # 4. Detect, Repair, and Automount Non-OS NTFS Data Partitions
    log_info "Scanning for shared NTFS data partitions..."
    TARGET_UID=$(id -u "${SUDO_USER:-root}")
    TARGET_GID=$(id -g "${SUDO_USER:-root}")

    while IFS=' ' read -r dev_name fs_type uuid raw_label; do
        [[ "$fs_type" != "ntfs" ]] && continue
        [[ -z "$uuid" ]] && continue

        dev_path="/dev/${dev_name}"
        # Decode hex-escaped spaces (\x20) from lsblk --raw
        label="${raw_label//\\x20/ }"

        # Skip obvious Windows system/recovery partitions by label
        if [[ "${label,,}" =~ (recovery|system|windows|boot|esp) ]]; then
            log_info "Skipping Windows system/recovery partition by label: $dev_path ($label)"
            continue
        fi

        # Unmount first if udisks2/Dolphin auto-mounted it, otherwise read-only probe will fail
        umount "$dev_path" 2>/dev/null || true

        # Probe partition contents to guarantee it is NOT the Windows OS C: root drive
        temp_probe=$(mktemp -d)
        is_windows_os=false
        if mount -t ntfs3 -o ro "$dev_path" "$temp_probe" 2>/dev/null || \
           mount -t ntfs-3g -o ro "$dev_path" "$temp_probe" 2>/dev/null; then
            if [[ -d "${temp_probe}/Windows/System32" ]] || [[ -f "${temp_probe}/Windows/explorer.exe" ]]; then
                is_windows_os=true
            fi
            umount "$temp_probe" 2>/dev/null || true
        fi
        rmdir "$temp_probe" 2>/dev/null || true

        if [[ "$is_windows_os" == true ]]; then
            log_info "Detected Windows OS installation on $dev_path. Skipping automount."
            continue
        fi

        # Determine clean mount point name (Default to Label, fallback to UUID)
        clean_name="${label//[^a-zA-Z0-9_-]/}"
        [[ -z "$clean_name" ]] && clean_name="NTFS_${uuid}"
        mount_point="/mnt/${clean_name}"

        log_info "Configuring shared NTFS Data Partition: $dev_path -> $mount_point"

        # Clear any dirty bit / hybrid sleep locks left by Windows
        run_cmd "Clearing NTFS dirty bit on $dev_path" ntfsfix -d "$dev_path" || true

        mkdir -p "$mount_point"

        # Add to /etc/fstab if UUID is not already present
        if ! grep -q "UUID=${uuid}" /etc/fstab; then
            log_info "Adding persistent automount entry to /etc/fstab for $mount_point..."
            [[ ! -f "/etc/fstab.bak.${TIMESTAMP}" ]] && cp /etc/fstab "/etc/fstab.bak.${TIMESTAMP}"
            echo "UUID=${uuid}  ${mount_point}  ntfs-3g  defaults,nofail,uid=${TARGET_UID},gid=${TARGET_GID},umask=0022,windows_names,exec  0  0" >> /etc/fstab
            log_success "Added $mount_point (UUID=${uuid}) to /etc/fstab."
        else
            log_info "UUID=${uuid} already exists in /etc/fstab. Skipping fstab append."
        fi

    done < <(lsblk -rno NAME,FSTYPE,UUID,LABEL)

    systemctl daemon-reload
    run_cmd "Mounting all configured fstab filesystems" mount -a || log_warn "Some fstab mounts reported warnings."

    # 5. Ensure GRUB detects Windows Boot Manager
    if [[ "$DISTRO_FAMILY" == "rpm" ]] && command -v grub2-mkconfig &>/dev/null; then
        run_cmd "Regenerating GRUB configuration to verify Windows Boot Manager entry" \
            grub2-mkconfig -o /boot/grub2/grub.cfg || true
    elif [[ "$DISTRO_FAMILY" == "deb" ]] && command -v update-grub &>/dev/null; then
        run_cmd "Regenerating GRUB configuration" update-grub || true
    fi

    log_success "Dual-Boot module complete."
fi

# ==============================================================================
# MODULE: APPS & SYSTEM QoL
# ==============================================================================
if [[ "$RUN_APPS" == true ]]; then
    echo -e "\n\e[35m[========== STARTING APPS & QoL MODULE ==========]\e[0m"
    QOL_APPS=(timeshift btop bat eza plocate mediawriter p7zip p7zip-plugins vlc)
    if ! pkg_install "${QOL_APPS[@]}"; then
        log_warn "Some QoL packages could not be installed. Continuing..."
    fi

    if [[ "$DESKTOP_ENV" == "GNOME" ]]; then
        if ! pkg_install baobab gnome-tweaks; then
            log_warn "Some GNOME QoL packages could not be installed. Continuing..."
        fi
    elif [[ "$DESKTOP_ENV" == "KDE" ]]; then
        if ! pkg_install filelight; then
            log_warn "Some KDE QoL packages could not be installed. Continuing..."
        fi
    fi

    FLATPAK_APPS=(com.brave.Browser com.google.Chrome md.obsidian.Obsidian org.signal.Signal)
    install_flatpak_apps "${FLATPAK_APPS[@]}"

    updatedb || true
    log_success "Apps module complete."
fi

# ==============================================================================
# MODULE: DEV APPS
# ==============================================================================
if [[ "$RUN_DEVAPPS" == true ]]; then
    echo -e "\n\e[35m[========== STARTING DEV APPS MODULE ==========]\e[0m"
    if ! pkg_install python3 python3-pip openssl remmina; then
        log_warn "Some development packages could not be installed. Continuing..."
    fi

    DEV_FLATPAKS=(com.visualstudio.code io.github.shiftey.Desktop)
    install_flatpak_apps "${DEV_FLATPAKS[@]}"

    # Install native PowerShell (Flathub com.microsoft.PowerShell is deprecated/EOL)
    if ! command -v pwsh &>/dev/null; then
        log_info "Installing native Microsoft PowerShell..."
        if [[ "$DISTRO_FAMILY" == "rpm" ]]; then
            rpm --import https://packages.microsoft.com/keys/microsoft.asc || true
            dnf install ${AUTO_YES:+$AUTO_YES} https://github.com/PowerShell/PowerShell/releases/latest/download/powershell-lts.rh.x86_64.rpm || \
                log_warn "Native PowerShell RPM installation failed. Skipping."
        fi
    fi

    log_success "Dev Apps module complete."
fi

# ==============================================================================
# MODULE: CYBERSECURITY
# ==============================================================================
if [[ "$RUN_CYBER" == true ]]; then
    echo -e "\n\e[35m[========== STARTING CYBER MODULE ==========]\e[0m"
    CYBER_PKGS=(wireshark-qt nmap tcpdump nmap-ncat)
    if ! pkg_install "${CYBER_PKGS[@]}"; then
        log_warn "Some cybersecurity packages could not be installed. Continuing..."
    fi
    if [[ -n "${SUDO_USER:-}" ]]; then
        usermod -aG wireshark "$SUDO_USER" || true
    fi
    log_success "Cyber module complete."
fi

# ==============================================================================
# MODULE: MAKER & CREATORS
# ==============================================================================
if [[ "$RUN_MAKER" == true ]]; then
    echo -e "\n\e[35m[========== STARTING MAKER MODULE ==========]\e[0m"
    if ! pkg_install prusa-slicer; then
        log_warn "The PrusaSlicer package could not be installed. Continuing..."
    fi

    MAKER_FLATPAKS=(com.softfever.OrcaSlicer com.bambulab.BambuStudio)
    install_flatpak_apps "${MAKER_FLATPAKS[@]}"
    log_success "Maker module complete."
fi

if [[ "$RUN_CREATORS" == true ]]; then
    echo -e "\n\e[35m[========== STARTING CREATORS MODULE ==========]\e[0m"
    CREATOR_PKGS=(darktable blender audacity inkscape obs-studio)
    if ! pkg_install "${CREATOR_PKGS[@]}"; then
        log_warn "Some creator packages could not be installed. Continuing..."
    fi
    log_success "Creators module complete."
fi

# ==============================================================================
# MODULE: STANDARD HARDENING (--harden)
# ==============================================================================
if [[ "$RUN_HARDEN" == true ]]; then
    echo -e "\n\e[35m[========== STARTING STANDARD HARDENING ==========]\e[0m"
    
    if [[ "$DISTRO_FAMILY" == "rpm" ]]; then
        log_info "Verifying SELinux Enforcement..."
        if command -v setenforce &> /dev/null && [[ -f /etc/selinux/config ]]; then
            setenforce 1 || true
            sed -i -E 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
            log_success "SELinux verified/set to Enforcing."
        fi
    fi

    log_info "Configuring Automatic Security Updates..."
    if [[ "$DISTRO_FAMILY" == "rpm" ]]; then
        pkg_install dnf-automatic || true
        if [[ ! -f "$DNF_AUTO_CONF" ]]; then
            mkdir -p /etc/dnf
            cat <<'EOF' > "$DNF_AUTO_CONF"
[commands]
upgrade_type = security
download_updates = yes
apply_updates = yes
EOF
        else
            sed -i -E 's/^upgrade_type =.*/upgrade_type = security/' "$DNF_AUTO_CONF"
            sed -i -E 's/^download_updates =.*/download_updates = yes/' "$DNF_AUTO_CONF"
            sed -i -E 's/^apply_updates =.*/apply_updates = yes/' "$DNF_AUTO_CONF"
        fi
        service_enable dnf-automatic.timer
    else
        pkg_install unattended-upgrades apt-listchanges
        cat <<'EOF' > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
        service_enable unattended-upgrades
    fi
    log_success "Automated background security patching enabled."

    if dpkg -s openssh-server &> /dev/null 2>&1 || rpm -q openssh-server &> /dev/null 2>&1; then
        log_info "Applying Standard SSH Hardening via drop-in config..."
        mkdir -p "$SSHD_DROPIN_DIR"
        echo "PermitRootLogin no" > "$SSHD_HARDEN_CONF"
        service_restart "$SSH_SERVICE"
        log_success "Direct root login over SSH disabled."
    fi
    log_success "Standard hardening complete."
fi

# ==============================================================================
# MODULE: ADVANCED HARDENING (--harden-advanced)
# ==============================================================================
if [[ "$RUN_HARDEN_ADV" == true ]]; then
    echo -e "\n\e[35m[========== STARTING ADVANCED HARDENING ==========]\e[0m"
    
    log_info "Applying Strict Sysctl Network Drops..."
    cat <<EOF > "$SYSCTL_CONF"
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_all = 1
EOF
    sysctl -p "$SYSCTL_CONF" || log_warn "Failed to apply sysctl parameters."
    log_success "Kernel network hardening applied (Ping disabled, strict routing)."

    log_info "Deploying and Configuring Auditd..."
    pkg_install audit
    service_enable auditd
    mkdir -p /etc/audit/rules.d
    cat <<EOF > "$AUDIT_RULES"
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
EOF
    augenrules --load || log_warn "Failed to load audit rules."
    log_success "Audit daemon configured for high-fidelity credential/privilege event generation."

    if dpkg -s openssh-server &> /dev/null 2>&1 || rpm -q openssh-server &> /dev/null 2>&1; then
        log_info "Applying Strict SSH Hardening via drop-in config..."
        mkdir -p "$SSHD_DROPIN_DIR"
        cat <<EOF > "$SSHD_HARDEN_CONF"
PermitRootLogin no
PasswordAuthentication no
X11Forwarding no
EOF
        service_restart "$SSH_SERVICE"
        log_success "SSH Password Authentication and X11 Forwarding disabled."
    fi
    log_success "Advanced hardening complete."
fi

# ==============================================================================
# MODULE: NETWORKING (SSH) & 2FA
# ==============================================================================
if [[ "$RUN_SSH" == true ]]; then
    echo -e "\n\e[35m[========== STARTING SSH PROVISIONING MODULE ==========]\e[0m"
    if ! dpkg -s openssh-server &> /dev/null 2>&1 && ! rpm -q openssh-server &> /dev/null 2>&1; then
        log_info "Installing OpenSSH Server..."
        pkg_install openssh-server
    fi

    if [[ "$RUN_2FA" == true ]]; then
        log_info "Configuring Google Authenticator MFA for SSH..."
        if [[ "$DISTRO_FAMILY" == "deb" ]]; then
            pkg_install libpam-google-authenticator
        else
            pkg_install google-authenticator
        fi

        mkdir -p "$SSHD_DROPIN_DIR"
        cat <<EOF > "$SSHD_MFA_CONF"
UsePAM yes
KbdInteractiveAuthentication yes
ChallengeResponseAuthentication yes
EOF

        if ! grep -q "pam_google_authenticator.so" "$PAM_CONF"; then
            echo "auth required pam_google_authenticator.so nullok" >> "$PAM_CONF"
        fi
    fi

    service_enable "$SSH_SERVICE"
    service_restart "$SSH_SERVICE"

    if systemctl is-active --quiet "$SSH_SERVICE"; then
        if ss -lt | grep -q ssh; then
            log_success "SSH Status is online and actively listening."
        else
            log_warn "Service is running, but no SSH listener detected."
        fi
    fi
    log_success "SSH provisioning module complete."
fi

# ==============================================================================
# MODULE: DISCORD & GAMING
# ==============================================================================
if [[ "$RUN_DISCORD" == true ]]; then
    echo -e "\n\e[35m[========== STARTING DISCORD TRANSITION MODULE ==========]\e[0m"
    if command -v flatpak &>/dev/null && flatpak list | grep -qi "discord"; then
        flatpak uninstall ${AUTO_YES:+--assumeyes --noninteractive} com.discordapp.Discord || true
    fi
    if [[ "$DISTRO_FAMILY" == "rpm" ]]; then
        pkg_install \
            "https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm" \
            "https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm" || true
        refresh_package_cache "force"
        pkg_install discord
    else
        log_warn "Discord transition is currently implemented for RPM-based systems. Skipping on this distro."
    fi
    log_success "Discord transition complete."
fi

if [[ "$RUN_GAMING" == true ]]; then
    echo -e "\n\e[35m[========== STARTING GAMING & DRIVER MODULE ==========]\e[0m"
    if [[ "$DISTRO_FAMILY" == "rpm" ]]; then
        PRE_PKGS=(flatpak snapd dnf-plugins-core)
        pkg_install "${PRE_PKGS[@]}"

        log_info "Enabling RPM Fusion Free and Non-Free repositories..."
        pkg_install \
            "https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm" \
            "https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm" || true
        refresh_package_cache "force"

        # Enable Cisco OpenH264 repository (DNF5 and DNF4 syntax fallback)
        dnf config-manager setopt fedora-cisco-openh264.enabled=1 2>/dev/null || \
            dnf config-manager --set-enabled fedora-cisco-openh264 2>/dev/null || true

        log_info "Swapping crippled Fedora ffmpeg-free for full RPM Fusion ffmpeg..."
        run_cmd "Swapping ffmpeg" dnf swap ${AUTO_YES:+$AUTO_YES} ffmpeg-free ffmpeg --allowerasing || true
        run_cmd "Updating multimedia groups" dnf group upgrade ${AUTO_YES:+$AUTO_YES} multimedia --exclude=PackageKit-gstreamer-plugin || \
            dnf group update ${AUTO_YES:+$AUTO_YES} sound-and-video || true
    else
        pkg_install flatpak snapd
    fi

    # Core gaming stack + Nobara/Bazzite performance parity packages
    GAMING_PKGS=(
        winetricks steam lutris gamemode mangohud gamescope
        steam-devices vulkan-tools goverlay
    )
    pkg_install "${GAMING_PKGS[@]}" || true

    # Flatpaks: ProtonUp-Qt, Bottles, and Flatseal
    GAMING_FLATPAKS=(net.davidotek.pupgui2 com.usebottles.bottles com.github.tchx84.Flatseal)
    install_flatpak_apps "${GAMING_FLATPAKS[@]}"

    # Apply SteamOS / Bazzite memory map tweak for heavy Wine/Proton games
    log_info "Applying SteamOS vm.max_map_count gaming tweak..."
    cat <<EOF > "$GAMING_SYSCTL_CONF"
vm.max_map_count = 2147483642
EOF
    sysctl --system &>/dev/null || true

    fwupdmgr refresh --force || true
    fwupdmgr get-devices || true
    fwupdmgr update ${AUTO_YES:+$AUTO_YES} || true

    # Full multi-line PCI check (avoids missing dGPU on hybrid iGPU+dGPU systems)
    GPU_INFO=$(lspci -nn 2>/dev/null | grep -E 'VGA|3D controller' || true)

    if [[ "$GPU_INFO" == *"NVIDIA"* ]]; then
        log_info "NVIDIA GPU detected. Preparing proprietary driver and CUDA stack..."
        if [[ "$DISTRO_FAMILY" == "deb" ]]; then
            if command -v ubuntu-drivers &>/dev/null; then
                ubuntu-drivers autoinstall || true
            else
                pkg_install nvidia-driver firmware-misc-nonfree nvidia-settings vulkan-tools || true
            fi
        else
            # 1. Ensure Secure Boot MOK is generated/queued BEFORE compiling akmod-nvidia
            setup_secureboot_mok

            # 2. Install NVIDIA Proprietary + CUDA + Wayland VAAPI Stack
            pkg_install akmod-nvidia xorg-x11-drv-nvidia xorg-x11-drv-nvidia-cuda \
                nvidia-settings libva-nvidia-driver vulkan-tools || true

            log_info "Forcing akmods to build and sign the NVIDIA kernel module (takes 1-2 mins)..."
            akmods --force || true
            dracut --force || true
        fi
    elif [[ "$GPU_INFO" == *"AMD"* ]] || [[ "$GPU_INFO" == *"Advanced Micro Devices"* ]]; then
        log_info "AMD GPU detected. Installing Mesa/Vulkan driver stack..."
        if [[ "$DISTRO_FAMILY" == "deb" ]]; then
            pkg_install mesa-vulkan-drivers vulkan-tools libvulkan1 || true
        else
            pkg_install mesa-vulkan-drivers vulkan-tools vulkan-loader mesa-va-drivers-freeworld || true
        fi
    else
        log_warn "Unable to detect a supported NVIDIA or AMD GPU. Skipping driver installation."
    fi

    log_success "Gaming module complete."
fi

# ==============================================================================
# WRAP UP, POST-RUN CALLOUTS & REBOOT
# ==============================================================================
if [[ "$RUN_DEBUG" == true ]]; then
    set +x
fi

echo -e "\n==============================================================="
log_success "Execution of selected modules is complete!"
log_info "Log file is saved at: $LOG_FILE"
echo -e "===============================================================\n"

# High-visibility Post-Run Action Callouts
if [[ "$RUN_DUALBOOT" == true ]] || [[ "$MOK_NEEDS_ENROLLMENT" == true ]] || [[ "$RUN_2FA" == true ]]; then
    echo -e "\e[1;33m=======================================================================\e[0m"
    echo -e "\e[1;41;97m                   [!] CRITICAL POST-RUN ACTION ITEMS                  \e[0m"
    echo -e "\e[1;33m=======================================================================\e[0m"

    if [[ "$RUN_DUALBOOT" == true ]]; then
        echo -e "\n\e[1;36m[1] WINDOWS 11 NTFS LOCKOUT PREVENTION (FAST STARTUP):\e[0m"
        echo -e "    Linux cannot permanently clear NTFS dirty bits if Windows Fast Startup"
        echo -e "    is active. Boot into Windows 11, open PowerShell as Administrator,"
        echo -e "    and run this command once to disable hibernation file locking:"
        echo -e "    \e[1;32mpowercfg /h off\e[0m"
    fi

    if [[ "$MOK_NEEDS_ENROLLMENT" == true ]]; then
        echo -e "\n\e[1;36m[2] UEFI SECURE BOOT MOK ENROLLMENT:\e[0m"
        if [[ "$UNATTENDED" == true ]]; then
            echo -e "    Unattended mode skipped the interactive MOK password prompt."
            echo -e "    Before rebooting, you MUST run:"
            echo -e "    \e[1;32msudo mokutil --import /etc/pki/akmods/certs/public_key.der\e[0m"
        fi
        echo -e "    Upon reboot, your motherboard will display a blue \e[1;37mMokManager\e[0m screen:"
        echo -e "    Select: \e[1;33mEnroll MOK -> Continue -> Yes -> [Enter Password] -> Reboot\e[0m"
    fi

    if [[ "$RUN_2FA" == true ]]; then
        echo -e "\n\e[1;36m[3] SSH 2FA TOKEN GENERATION:\e[0m"
        echo -e "    SSH MFA is now enforced. Before logging out, switch to your standard"
        echo -e "    user account and generate your TOTP QR code:"
        echo -e "    \e[1;32mgoogle-authenticator\e[0m"
    fi

    echo -e "\n\e[1;33m=======================================================================\e[0m\n"
fi

if [[ "$UNATTENDED" == true ]]; then
    log_warn "Unattended mode: Skipping interactive reboot prompt. Please restart manually."
elif [ -t 1 ]; then
    read -r -p "A reboot is recommended to apply kernel updates and drivers. Reboot now? (y/n): " -n 1
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_warn "Rebooting system..."
        reboot
    else
        log_info "Reboot skipped. Please restart your computer manually later."
    fi
fi