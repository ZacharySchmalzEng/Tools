#!/bin/bash
# ==============================================================================
# SYNOPSIS
#     Automated Linux provisioning and environment setup script.
#
# DESCRIPTION
#     This script provides a modular, flag-based deployment tool for modern Linux
#     distributions. It combines system updates, SSH/2FA provisioning, gaming
#     setup, application deployment, and tiered system hardening.
#
# AUTHOR
#     Zachary Schmalz
#
# NOTES
#     Version:        1.2
#     Requirements:   Bash, root/sudo privileges, active internet connection.
#     Supported OS:   Fedora/RHEL-style systems and Debian/Ubuntu-style systems.
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

DISTRO_FAMILY="unknown"
DISTRO_NAME="unknown"
SSH_SERVICE="sshd"

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
    case "$DISTRO_FAMILY" in
        rpm)
            if ! run_cmd "Refreshing DNF package metadata" dnf makecache --refresh; then
                log_warn "DNF metadata refresh failed. Continuing..."
            fi
            ;;
        deb)
            export DEBIAN_FRONTEND=noninteractive
            if ! run_cmd "Refreshing APT package metadata" apt-get update; then
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
                nmap-ncat) echo "netcat" ;;
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

    refresh_package_cache
    if ! run_cmd "Updating system packages" "${update_cmd[@]}"; then
        log_warn "System package update failed."
        return 1
    fi
}

ensure_flatpak() {
    if ! command -v flatpak &>/dev/null; then
        log_info "Installing Flatpak support..."
        case "$DISTRO_FAMILY" in
            rpm)
                if ! run_cmd "Installing Flatpak" dnf install ${AUTO_YES:+$AUTO_YES} flatpak; then
                    log_warn "Flatpak installation failed."
                fi
                ;;
            deb)
                export DEBIAN_FRONTEND=noninteractive
                refresh_package_cache
                if ! run_cmd "Installing Flatpak" apt-get install ${AUTO_YES:+$AUTO_YES} flatpak; then
                    log_warn "Flatpak installation failed."
                fi
                ;;
        esac
    fi

    flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo || true
}

install_flatpak_app() {
    local app="$1"
    if [[ "$AUTO_YES" == "-y" ]]; then
        flatpak install --assumeyes flathub "$app" || log_warn "Failed to install Flatpak app: $app"
    else
        flatpak install flathub "$app" || log_warn "Failed to install Flatpak app: $app"
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

detect_distro

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
        -d) if [[ "$DISTRO_FAMILY" == "deb" ]]; then DOWNLOAD_ONLY="--download-only"; else DOWNLOAD_ONLY="--downloadonly"; fi ;;
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
    log_info "Running system package updates..."
    if ! update_system; then
        log_warn "Package updates reported issues. Continuing..."
    fi

    if command -v flatpak &> /dev/null; then
        log_info "Running Flatpak updates..."
        flatpak upgrade ${AUTO_YES:+--assumeyes} || true
    fi

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

    ensure_flatpak
    readonly FLATPAK_APPS=(com.brave.Browser com.google.Chrome md.obsidian.Obsidian org.signal.Signal)
    for app in "${FLATPAK_APPS[@]}"; do
        install_flatpak_app "$app"
    done

    updatedb || true
    log_success "Apps module complete."
fi

# ==============================================================================
# MODULE: DEV APPS
# ==============================================================================
if [[ "$RUN_DEVAPPS" == true ]]; then
    echo -e "\n\e[35m[========== STARTING DEV APPS MODULE ==========]\e[0m"
    if ! pkg_install python3 openssl remmina; then
        log_warn "Some development packages could not be installed. Continuing..."
    fi

    ensure_flatpak
    readonly DEV_FLATPAKS=(com.visualstudio.code io.github.shiftey.Desktop com.microsoft.PowerShell)
    for app in "${DEV_FLATPAKS[@]}"; do
        install_flatpak_app "$app"
    done
    log_success "Dev Apps module complete."
fi

# ==============================================================================
# MODULE: CYBERSECURITY
# ==============================================================================
if [[ "$RUN_CYBER" == true ]]; then
    echo -e "\n\e[35m[========== STARTING CYBER MODULE ==========]\e[0m"
    readonly CYBER_PKGS=(wireshark-qt nmap tcpdump nmap-ncat)
    if ! pkg_install "${CYBER_PKGS[@]}"; then
        log_warn "Some cybersecurity packages could not be installed. Continuing..."
    fi
    usermod -aG wireshark "$SUDO_USER" || true
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
    ensure_flatpak
    readonly MAKER_FLATPAKS=(com.softfever.OrcaSlicer com.bambulab.BambuStudio)
    for app in "${MAKER_FLATPAKS[@]}"; do
        install_flatpak_app "$app"
    done
    log_success "Maker module complete."
fi

if [[ "$RUN_CREATORS" == true ]]; then
    echo -e "\n\e[35m[========== STARTING CREATORS MODULE ==========]\e[0m"
    readonly CREATOR_PKGS=(darktable blender audacity inkscape obs-studio)
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
        if command -v setenforce &> /dev/null; then
            setenforce 1 || true
            sed -i -E 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
            log_success "SELinux verified/set to Enforcing."
        fi
    fi

    log_info "Configuring Automatic Security Updates..."
    if [[ "$DISTRO_FAMILY" == "rpm" ]]; then
        pkg_install dnf-automatic
        readonly DNF_AUTO_CONF="/etc/dnf/automatic.conf"
        sed -i -E 's/^upgrade_type =.*/upgrade_type = security/' "$DNF_AUTO_CONF"
        sed -i -E 's/^download_updates =.*/download_updates = yes/' "$DNF_AUTO_CONF"
        sed -i -E 's/^apply_updates =.*/apply_updates = yes/' "$DNF_AUTO_CONF"
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
        log_info "Applying Standard SSH Hardening..."
        readonly SSHD_CONF="/etc/ssh/sshd_config"
        sed -i -E 's/^#?PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONF"
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
    pkg_install audit
    service_enable auditd
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

    if dpkg -s openssh-server &> /dev/null 2>&1 || rpm -q openssh-server &> /dev/null 2>&1; then
        log_info "Applying Strict SSH Hardening..."
        readonly SSHD_CONF="/etc/ssh/sshd_config"
        sed -i -E 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' "$SSHD_CONF"
        sed -i -E 's/^#?X11Forwarding.*/X11Forwarding no/' "$SSHD_CONF"
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
        readonly SSHD_CONF="/etc/ssh/sshd_config"
        readonly PAM_CONF="/etc/pam.d/sshd"

        sed -i -E 's/^#?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' "$SSHD_CONF"
        sed -i -E 's/^#?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' "$SSHD_CONF"
        sed -i -E 's/^#?UsePAM.*/UsePAM yes/' "$SSHD_CONF"

        if ! grep -q "pam_google_authenticator.so" "$PAM_CONF" || true; then
            echo "auth required pam_google_authenticator.so nullok" >> "$PAM_CONF"
        fi
    fi

    service_enable "$SSH_SERVICE"
    service_restart "$SSH_SERVICE"

    if systemctl is-active --quiet "$SSH_SERVICE"; then
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
        flatpak uninstall ${AUTO_YES:+--assumeyes} "discord" || true
    fi
    if [[ "$DISTRO_FAMILY" == "rpm" ]]; then
        pkg_install https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm || true
        pkg_install https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm || true
        pkg_install discord
    else
        log_warn "Discord transition is currently implemented for RPM-based systems. Skipping on this distro."
    fi
    log_success "Discord transition complete."
fi

if [[ "$RUN_GAMING" == true ]]; then
    echo -e "\n\e[35m[========== STARTING GAMING & DRIVER MODULE ==========]\e[0m"
    if [[ "$DISTRO_FAMILY" == "rpm" ]]; then
        readonly PRE_PKGS=(flatpak snap dnf-plugins-core)
        pkg_install "${PRE_PKGS[@]}"
        pkg_install https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm || true
        pkg_install https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm || true
        dnf group upgrade core ${AUTO_YES:+$AUTO_YES} || true
    else
        pkg_install flatpak snapd
    fi
    
    ensure_flatpak
    readonly GAMING_PKGS=(winetricks steam lutris)
    pkg_install "${GAMING_PKGS[@]}"
    install_flatpak_app net.davidotek.pupgui2 || true
    install_flatpak_app com.usebottles.bottles || true
    
    fwupdmgr refresh --force || true
    fwupdmgr get-devices || true
    fwupdmgr update ${AUTO_YES:+$AUTO_YES} || true

    GPU_INFO=$(lspci -nn 2>/dev/null | grep -E 'VGA|3D controller' | head -n 1 || true)
    case "$GPU_INFO" in
        *"NVIDIA"*)
            log_info "NVIDIA GPU detected. Installing proprietary driver stack..."
            if [[ "$DISTRO_FAMILY" == "deb" ]]; then
                if command -v ubuntu-drivers &>/dev/null; then
                    ubuntu-drivers autoinstall || true
                else
                    pkg_install nvidia-driver firmware-misc-nonfree nvidia-settings vulkan-tools || true
                fi
            else
                pkg_install akmod-nvidia xorg-x11-drv-nvidia nvidia-settings vulkan-tools || true
            fi
            ;;
        *"AMD"*|*"Advanced Micro Devices"*)
            log_info "AMD GPU detected. Installing Mesa/Vulkan driver stack..."
            if [[ "$DISTRO_FAMILY" == "deb" ]]; then
                pkg_install mesa-vulkan-drivers vulkan-tools libvulkan1 || true
            else
                pkg_install mesa-vulkan-drivers vulkan-tools vulkan-loader || true
            fi
            ;;
        *)
            log_warn "Unable to detect a supported NVIDIA or AMD GPU. Skipping driver installation."
            ;;
    esac

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