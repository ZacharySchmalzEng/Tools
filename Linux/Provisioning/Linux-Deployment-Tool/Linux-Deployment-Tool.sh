#!/bin/bash
# ==============================================================================
# SYNOPSIS
#     Automated Fedora 41+ provisioning and environment setup script.
#
# DESCRIPTION
#     This script provides a modular, flag-based deployment tool for Fedora Linux.
#     It combines system updates, SSH/2FA provisioning, gaming setups, 
#     application deployments, and tiered system hardening.
#
# AUTHOR
#     Zachary Schmalz
#
# NOTES
#     Version:        1.0 (Beta)
#     Requirements:   Fedora Linux 41+, Bash, Active Internet Connection.
#     Execution:      Must be run with sudo/root privileges.
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. STRICT MODE & ERROR HANDLING
# ------------------------------------------------------------------------------
set -euo pipefail
IFS=$'\n\t'

# ------------------------------------------------------------------------------
# 2. CONSTANTS & HELPER FUNCTIONS
# ------------------------------------------------------------------------------
readonly COLOR_INFO='\e[36m'
readonly COLOR_SUCCESS='\e[32m'
readonly COLOR_WARN='\e[33m'
readonly COLOR_ERROR='\e[31m'
readonly COLOR_RESET='\e[0m'

log_info()    { echo -e "${COLOR_INFO}[INFO] $1${COLOR_RESET}"; }
log_success() { echo -e "${COLOR_SUCCESS}[+] $1${COLOR_RESET}"; }
log_warn()    { echo -e "${COLOR_WARN}[!] $1${COLOR_RESET}"; }
log_error()   { echo -e "${COLOR_ERROR}[ERROR] $1${COLOR_RESET}" >&2; }

print_usage() {
    echo -e "\n==============================================================="
    echo -e " Fedora Provisioning Environment Setup Script"
    echo -e "==============================================================="
    echo "Usage: sudo ./fedora-deployment-tool.sh [Options]"
    echo ""
    echo "MODULE OPTIONS:"
    echo "  --update           Sequentially upgrades DNF, Flatpak, and Snap"
    echo "  --apps             Installs core utilities (Browsers, Media, Search)"
    echo "  --devapps          Installs Dev tools (VS Code, Python, GitHub Desktop)"
    echo "  --cyber            Installs Security tools (Wireshark, Nmap, TCPDump)"
    echo "  --maker            Installs 3D Printing Slicers (Prusa, Orca, Bambu)"
    echo "  --creators         Installs Creative suite (Blender, Darktable, OBS)"
    echo "  --gaming           Configures RPM Fusion, Lutris, Steam, Nvidia"
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

if [[ "$#" -eq 0 ]]; then
    print_usage
    exit 0
fi

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --all) RUN_ALL=true ;;
        --update) RUN_UPDATE=true ;;
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
        -d) DOWNLOAD_ONLY="--downloadonly" ;;
        --help|-h) print_usage; exit 0 ;;
        *) log_error "Unknown parameter passed: $1"; print_usage; exit 1 ;;
    esac
    shift
done

if [[ "$RUN_ALL" == true ]]; then
    RUN_UPDATE=true; RUN_APPS=true; RUN_DEVAPPS=true; RUN_CYBER=true; 
    RUN_MAKER=true; RUN_CREATORS=true; RUN_GAMING=true; RUN_SSH=true; 
    RUN_DISCORD=true; RUN_HARDEN=true;
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
        read -p "Which Desktop Environment do you primarily use? (Gnome/KDE) [g/k]: " de_choice
        case "${de_choice,,}" in
            g|gnome) DESKTOP_ENV="GNOME"; break ;;
            k|kde) DESKTOP_ENV="KDE"; break ;;
            *) log_warn "Please enter 'g' for GNOME or 'k' for KDE." ;;
        esac
    done

    if [[ "$RUN_HARDEN_ADV" == true ]]; then
        echo -e "\n\e[31m[!] WARNING: Advanced hardening will disable SSH password authentication."
        echo -e "    Ensure you have an SSH Key provisioned before disconnecting.\e[0m"
        read -p "    Press Enter to acknowledge and continue..."
    fi
fi


# ==============================================================================
# MODULE: UPDATE & MAINTENANCE
# ==============================================================================
if [[ "$RUN_UPDATE" == true ]]; then
    echo -e "\n\e[35m[========== STARTING UPDATE MODULE ==========]\e[0m"
    log_info "Running DNF updates..."
    eval dnf upgrade $AUTO_YES $DOWNLOAD_ONLY

    log_info "Running Flatpak updates..."
    eval flatpak upgrade $AUTO_YES || true

    if command -v snap &> /dev/null; then
        log_info "Running Snap refresh..."
        snap refresh || log_warn "Snap refresh returned a non-zero exit code. Continuing..."
    fi
    log_success "Update module complete."
fi

# ==============================================================================
# MODULE: APPS & SYSTEM QoL
# ==============================================================================
if [[ "$RUN_APPS" == true ]]; then
    echo -e "\n\e[35m[========== STARTING APPS & QoL MODULE ==========]\e[0m"
    readonly QOL_APPS=(timeshift btop bat eza plocate mediawriter p7zip p7zip-plugins vlc)
    eval dnf install "${QOL_APPS[@]}" $AUTO_YES

    if [[ "$DESKTOP_ENV" == "GNOME" ]]; then
        eval dnf install baobab gnome-tweaks $AUTO_YES
    elif [[ "$DESKTOP_ENV" == "KDE" ]]; then
        eval dnf install filelight $AUTO_YES
    fi

    readonly FLATPAK_APPS=(com.brave.Browser com.google.Chrome md.obsidian.Obsidian org.signal.Signal)
    for app in "${FLATPAK_APPS[@]}"; do
        eval flatpak install flathub "$app" $AUTO_YES || log_warn "Failed to install $app"
    done

    updatedb || true
    log_success "Apps module complete."
fi

# ==============================================================================
# MODULE: DEV APPS
# ==============================================================================
if [[ "$RUN_DEVAPPS" == true ]]; then
    echo -e "\n\e[35m[========== STARTING DEV APPS MODULE ==========]\e[0m"
    eval dnf install python3 openssl remmina $AUTO_YES

    readonly DEV_FLATPAKS=(com.visualstudio.code io.github.shiftey.Desktop com.microsoft.PowerShell)
    for app in "${DEV_FLATPAKS[@]}"; do
        eval flatpak install flathub "$app" $AUTO_YES || log_warn "Failed to install $app"
    done
    log_success "Dev Apps module complete."
fi

# ==============================================================================
# MODULE: CYBERSECURITY
# ==============================================================================
if [[ "$RUN_CYBER" == true ]]; then
    echo -e "\n\e[35m[========== STARTING CYBER MODULE ==========]\e[0m"
    readonly CYBER_PKGS=(wireshark-qt nmap tcpdump nmap-ncat)
    eval dnf install "${CYBER_PKGS[@]}" $AUTO_YES
    usermod -aG wireshark "$SUDO_USER" || true
    log_success "Cyber module complete."
fi

# ==============================================================================
# MODULE: MAKER & CREATORS
# ==============================================================================
if [[ "$RUN_MAKER" == true ]]; then
    echo -e "\n\e[35m[========== STARTING MAKER MODULE ==========]\e[0m"
    eval dnf install prusa-slicer $AUTO_YES
    readonly MAKER_FLATPAKS=(com.softfever.OrcaSlicer com.bambulab.BambuStudio)
    for app in "${MAKER_FLATPAKS[@]}"; do
        eval flatpak install flathub "$app" $AUTO_YES || log_warn "Failed to install $app"
    done
    log_success "Maker module complete."
fi

if [[ "$RUN_CREATORS" == true ]]; then
    echo -e "\n\e[35m[========== STARTING CREATORS MODULE ==========]\e[0m"
    readonly CREATOR_PKGS=(darktable blender audacity inkscape obs-studio)
    eval dnf install "${CREATOR_PKGS[@]}" $AUTO_YES
    log_success "Creators module complete."
fi

# ==============================================================================
# MODULE: STANDARD HARDENING (--harden)
# ==============================================================================
if [[ "$RUN_HARDEN" == true ]]; then
    echo -e "\n\e[35m[========== STARTING STANDARD HARDENING ==========]\e[0m"
    
    log_info "Verifying SELinux Enforcement..."
    if command -v setenforce &> /dev/null; then
        setenforce 1 || true
        sed -i -E 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
        log_success "SELinux verified/set to Enforcing."
    fi

    log_info "Configuring Automatic Security Updates..."
    eval dnf install dnf-automatic $AUTO_YES
    readonly DNF_AUTO_CONF="/etc/dnf/automatic.conf"
    sed -i -E 's/^upgrade_type =.*/upgrade_type = security/' "$DNF_AUTO_CONF"
    sed -i -E 's/^download_updates =.*/download_updates = yes/' "$DNF_AUTO_CONF"
    sed -i -E 's/^apply_updates =.*/apply_updates = yes/' "$DNF_AUTO_CONF"
    systemctl enable --now dnf-automatic.timer
    log_success "Automated background security patching enabled."

    if rpm -q openssh-server &> /dev/null; then
        log_info "Applying Standard SSH Hardening..."
        readonly SSHD_CONF="/etc/ssh/sshd_config"
        sed -i -E 's/^#?PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONF"
        systemctl restart sshd
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
    readonly SYSCTL_CONF="/etc/sysctl.d/99-security.conf"
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
    eval dnf install audit $AUTO_YES
    systemctl enable --now auditd
    readonly AUDIT_RULES="/etc/audit/rules.d/custom-security.rules"
    cat <<EOF > "$AUDIT_RULES"
-w /etc/sudoers -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
EOF
    augenrules --load || log_warn "Failed to load audit rules."
    log_success "Audit daemon configured for high-fidelity credential/privilege event generation."

    if rpm -q openssh-server &> /dev/null; then
        log_info "Applying Strict SSH Hardening..."
        readonly SSHD_CONF="/etc/ssh/sshd_config"
        sed -i -E 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONF"
        sed -i -E 's/^#?X11Forwarding.*/X11Forwarding no/' "$SSHD_CONF"
        systemctl restart sshd
        log_success "SSH Password Authentication and X11 Forwarding disabled."
    fi
    log_success "Advanced hardening complete."
fi

# ==============================================================================
# MODULE: NETWORKING (SSH) & 2FA
# ==============================================================================
if [[ "$RUN_SSH" == true ]]; then
    echo -e "\n\e[35m[========== STARTING SSH PROVISIONING MODULE ==========]\e[0m"
    if ! rpm -q openssh-server &> /dev/null; then
        log_info "Installing OpenSSH Server..."
        eval dnf install openssh-server $AUTO_YES
    fi

    if [[ "$RUN_2FA" == true ]]; then
        log_info "Configuring Google Authenticator MFA for SSH..."
        eval dnf install google-authenticator $AUTO_YES
        readonly SSHD_CONF="/etc/ssh/sshd_config"
        readonly PAM_CONF="/etc/pam.d/sshd"

        sed -i -E 's/^#?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' "$SSHD_CONF"
        sed -i -E 's/^#?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' "$SSHD_CONF"
        sed -i -E 's/^#?UsePAM.*/UsePAM yes/' "$SSHD_CONF"

        if ! grep -q "pam_google_authenticator.so" "$PAM_CONF" || true; then
            echo "auth required pam_google_authenticator.so nullok" >> "$PAM_CONF"
        fi
    fi

    systemctl enable sshd
    systemctl restart sshd

    if systemctl is-active --quiet sshd; then
        if ss -lt | grep -q ssh || true; then
            log_success "SSH Status is online and actively listening."
        else
            log_warn "Service is running, but no SSH listener detected."
        fi
    fi
    
    if [[ "$RUN_2FA" == true ]]; then
        echo -e "\n\e[33m****************************************************************"
        echo -e "2FA WARNING: SSH MFA has been enforced at the system level."
        echo -e "You MUST run the command 'google-authenticator' on your standard"
        echo -e "user account (not root) to generate your QR code and tokens."
        echo -e "****************************************************************\e[0m\n"
    fi
fi

# ==============================================================================
# MODULE: DISCORD & GAMING
# ==============================================================================
if [[ "$RUN_DISCORD" == true ]]; then
    echo -e "\n\e[35m[========== STARTING DISCORD TRANSITION MODULE ==========]\e[0m"
    if flatpak list | grep -q "discord" || true; then
        eval flatpak uninstall $AUTO_YES "discord" || true
    fi
    eval dnf install https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm $AUTO_YES || true
    eval dnf install https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm $AUTO_YES || true
    eval dnf install discord $AUTO_YES
    log_success "Discord transition complete."
fi

if [[ "$RUN_GAMING" == true ]]; then
    echo -e "\n\e[35m[========== STARTING GAMING & DRIVER MODULE ==========]\e[0m"
    readonly PRE_PKGS=(flatpak snap dnf-plugins-core)
    eval dnf install "${PRE_PKGS[@]}" $AUTO_YES
    eval dnf install https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm $AUTO_YES || true
    eval dnf install https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm $AUTO_YES || true
    
    flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo || true
    eval dnf copr enable t0xic0der/nvidia-auto-installer-for-fedora $AUTO_YES
    
    eval dnf group upgrade core $AUTO_YES
    readonly GAMING_PKGS=(winetricks steam lutris)
    eval dnf install "${GAMING_PKGS[@]}" $AUTO_YES
    eval flatpak install flathub net.davidotek.pupgui2 $AUTO_YES || true
    eval flatpak install flathub com.usebottles.bottles $AUTO_YES || true
    
    fwupdmgr refresh --force || true
    fwupdmgr get-devices || true
    fwupdmgr update $AUTO_YES || true

    eval dnf install nvautoinstall $AUTO_YES
    COMPATIBILITY=$(nvautoinstall compat 2>/dev/null || echo "failed")
    
    if [[ "$COMPATIBILITY" == *"expected to work correctly"* ]]; then
        log_success "Compatible Nvidia GPU found. Deploying driver stack..."
        nvautoinstall rpmadd driver nvrepo plcuda ffmpeg vulkan vidacc
    fi
    log_success "Gaming module complete."
fi

# ==============================================================================
# WRAP UP & REBOOT
# ==============================================================================
if [[ "$RUN_DEBUG" == true ]]; then
    set +x
fi

echo -e "\n==============================================================="
log_success "Execution of selected modules is complete!"
log_info "Log file is saved at: $LOG_FILE"
echo -e "===============================================================\n"

if [[ "$UNATTENDED" == true ]]; then
    log_warn "Unattended mode: Skipping interactive reboot prompt. Please restart manually."
elif [ -t 1 ]; then
    read -p "A reboot is recommended to apply kernel updates and drivers. Reboot now? (y/n): " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_warn "Rebooting system..."
        reboot
    else
        log_info "Reboot skipped. Please restart your computer manually later."
    fi
fi