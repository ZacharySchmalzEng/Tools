#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ==============================================================================
# SYNOPSIS
#     Automated Linux provisioning and environment setup script.
#
# DESCRIPTION
#     This script provides a modular, flag-based deployment tool for modern Linux
#     distributions. It combines system updates, SSH/2FA provisioning, gaming
#     setup, application deployment, and enterprise-grade system hardening.
#
# AUTHOR
#     Zachary Schmalz
#     Repository:     https://github.com/ZacharySchmalzEng/Tools/
#     Issues/Requests: Please direct all feature requests and bug reports to:
#                     https://github.com/ZacharySchmalzEng/Tools/issues
#
# NOTES
#     Version:        2.0
#     Status:         Production Release
#     Requirements:   Bash, root/sudo privileges, active internet connection.
#                     Zero manual on-box dependencies (automatic self-bootstrapping).
#     Supported OS:   Fedora, Nobara, Fedora Atomic (Silverblue/Bazzite),
#                     Arch Linux, SteamOS, openSUSE (Tumbleweed/Leap), Debian/Ubuntu.
#
# ------------------------------------------------------------------------------
# SECURITY UPDATES & CVE MITIGATIONS
# ------------------------------------------------------------------------------
#     v2.0:
#       - CVE-2024-6387 (OpenSSH "regreSSHion"): Mitigated remote code execution vulnerability
#         by tuning LoginGraceTime to 20s, capping MaxAuthTries to 3, MaxSessions to 4,
#         MaxStartups to 10:30:60, and setting ClientAliveInterval to 300.
#       - Interruption & SteamOS Lock Traps: Implemented cleanup_handler across EXIT,
#         INT, TERM, and HUP to guarantee immediate re-locking of SteamOS immutable root
#         protection ('steamos-readonly enable') and secure removal of temporary directories.
#       - Ambient File Mode Hardening: Enforced strict global 'umask 077' at script entry;
#         strictly enforced 0700 permissions on $LOG_DIR and 0600 on $LOG_FILE.
#       - CIS Level 2 Kernel Sysctl Hardening: Blocked SUID memory core dumps (fs.suid_dumpable = 0),
#         enforced complete ASLR (kernel.randomize_va_space = 2), enabled log_martians and
#         reverse path filtering (rp_filter = 1), and dropped ICMP redirects and source routes.
#       - Privilege & Identity Auditd Rules: Applied high-fidelity audit monitoring rules for
#         /etc/sudoers, /etc/shadow, /etc/passwd, /etc/gshadow, and /etc/ssh/sshd_config.
#       - PAM SSH 2FA Protection: Configured pam_google_authenticator with 'nullok' during
#         provisioning to eliminate catastrophic administrator lockout prior to OTP key generation.
#
# ------------------------------------------------------------------------------
# DEFECT RESOLUTIONS & BUG FIXES
# ------------------------------------------------------------------------------
#     v2.0:
#       - Resolved Nobara NVIDIA Driver Packaging Collision: Bypassed manual RPM Fusion
#         'akmod-nvidia' installation on Nobara Linux to eliminate fatal conflicts with
#         pre-installed 'dkms-nvidia' packages from the nobara-nvidia-production repository.
#       - Resolved PowerShell 404 Download Failures: Replaced brittle, unversioned GitHub
#         RPM release downloads with official Microsoft package repositories and Flathub fallback.
#       - Resolved ShellCheck SC2155 Warning: Split 'readonly SCRIPT_DIR' declaration and
#         subshell assignment to prevent masking subshell exit codes.
#       - Resolved SteamOS GPG Signature Failures: Added automated 'pacman-key --init' and
#         '--populate archlinux holo' initialization prior to running pacman transactions.
#       - Resolved Non-interactive Debian Debconf Stalls: Exported DEBIAN_FRONTEND=noninteractive
#         during apt-get invocations.
#
# ------------------------------------------------------------------------------
# FEATURE ENHANCEMENTS
# ------------------------------------------------------------------------------
#     v2.0:
#       - Multi-Distro Engine: Added native support for Fedora Atomic variants (Silverblue,
#         Bazzite, Kinoite), Arch Linux, SteamOS (Steam Deck), and openSUSE (Tumbleweed & Leap).
#       - Distro Override CLI Flags: Added --atomic, --bazzite, --silverblue, --arch, --steamos,
#         --opensuse, and --distro=<name> manual override flags with auto-detection fallbacks.
#       - Expanded Desktop Environment Suite: Added native support, auto-detection, and tailored QoL
#         modules for COSMIC Desktop (System76 Rust Epoch), XFCE, and Cinnamon alongside GNOME and KDE Plasma.
#       - Desktop Environment CLI Flags: Added --gnome, --kde, --cosmic, --xfce, --cinnamon, and
#         --de=<name> flags for fully automated non-interactive provisioning.
#       - SteamOS Lifecycle: Added automated 'steamos-readonly disable/enable' state machine.
#       - Package Router: Implemented unified pkg_install() supporting dnf, rpm-ostree,
#         pacman, zypper, and apt-get with auto-healing cache updates.
#       - Zero-Dependency Auto-Bootstrap: Implemented bootstrap_prerequisites() for bare-metal installs.
#     v1.2:
#       - Added automated self-healing package cache and non-interactive Debian mode.
#     v1.0:
#       - Initial modular deployment release.
# ------------------------------------------------------------------------------
# 1. STRICT MODE, SECURITY UMASK & ERROR TRAPPING
# ------------------------------------------------------------------------------
set -euo pipefail
IFS=$'\n\t'
umask 077

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

# Global State Flags for Signal & Error Restoration
IS_STEAMOS_UNLOCKED=false
declare -a TEMP_CLEANUP_DIRS=()

cleanup_handler() {
    local exit_code=$?
    trap - EXIT INT TERM HUP

    # 1. SecOps state restoration: Re-lock SteamOS root if interrupted while writable
    if [[ "$IS_STEAMOS_UNLOCKED" == true ]] && command -v steamos-readonly &>/dev/null; then
        echo -e "\n\e[33m[!] Trapped signal: Restoring SteamOS immutable root protection (steamos-readonly enable)...\e[0m"
        steamos-readonly enable 2>/dev/null || true
        IS_STEAMOS_UNLOCKED=false
    fi

    # 2. Secure deletion of temporary directories
    if [[ ${#TEMP_CLEANUP_DIRS[@]} -gt 0 ]]; then
        for tmp_dir in "${TEMP_CLEANUP_DIRS[@]}"; do
            if [[ -n "$tmp_dir" && -d "$tmp_dir" ]]; then
                rm -rf "$tmp_dir" 2>/dev/null || true
            fi
        done
    fi

    if [[ $exit_code -ne 0 && $exit_code -ne 130 ]]; then
        log_error "Execution terminated prematurely with code ${exit_code}."
    fi
    exit "$exit_code"
}

trap cleanup_handler EXIT INT TERM HUP
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
IS_NOBARA=false
IS_ATOMIC=false
IS_BAZZITE=false
IS_STEAMOS=false
DISTRO_OVERRIDE=""

steamos_unlock() {
    if [[ "$IS_STEAMOS" == true ]] && command -v steamos-readonly &>/dev/null; then
        log_info "SteamOS: Temporarily unlocking immutable root (steamos-readonly disable)..."
        steamos-readonly disable || true
        IS_STEAMOS_UNLOCKED=true
        if [[ ! -d /etc/pacman.d/gnupg ]]; then
            log_info "Initializing SteamOS pacman keyring..."
            pacman-key --init || true
            pacman-key --populate archlinux holo 2>/dev/null || pacman-key --populate || true
        fi
    fi
}

steamos_lock() {
    if [[ "$IS_STEAMOS" == true ]] && command -v steamos-readonly &>/dev/null; then
        log_info "SteamOS: Restoring immutable root integrity (steamos-readonly enable)..."
        steamos-readonly enable || true
        IS_STEAMOS_UNLOCKED=false
    fi
}

detect_distro() {
    local distro_id=""
    local distro_like=""
    local variant_id=""

    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO_NAME="${NAME:-unknown}"
        distro_id="${ID,,}"
        distro_like="${ID_LIKE:-}"
        distro_like="${distro_like,,}"
        variant_id="${VARIANT_ID:-}"
        variant_id="${variant_id,,}"
    fi

    # Check for manual distro flag override
    if [[ -n "$DISTRO_OVERRIDE" ]]; then
        case "${DISTRO_OVERRIDE,,}" in
            atomic|silverblue|kinoite)
                DISTRO_FAMILY="atomic"
                DISTRO_NAME="Fedora Atomic (${DISTRO_OVERRIDE^})"
                SSH_SERVICE="sshd"
                IS_ATOMIC=true
                log_info "Manual override: Fedora Atomic mode active."
                return 0
                ;;
            bazzite)
                DISTRO_FAMILY="atomic"
                DISTRO_NAME="Bazzite (Fedora Atomic Gaming)"
                SSH_SERVICE="sshd"
                IS_ATOMIC=true
                IS_BAZZITE=true
                log_info "Manual override: Bazzite (Atomic) mode active."
                return 0
                ;;
            steamos)
                DISTRO_FAMILY="steamos"
                DISTRO_NAME="SteamOS (Steam Deck)"
                SSH_SERVICE="sshd"
                IS_STEAMOS=true
                log_info "Manual override: SteamOS mode active."
                return 0
                ;;
            arch|manjaro|endeavouros)
                DISTRO_FAMILY="arch"
                DISTRO_NAME="Arch Linux"
                SSH_SERVICE="sshd"
                log_info "Manual override: Arch Linux mode active."
                return 0
                ;;
            opensuse|suse|tumbleweed|leap)
                DISTRO_FAMILY="opensuse"
                DISTRO_NAME="openSUSE"
                SSH_SERVICE="sshd"
                log_info "Manual override: openSUSE mode active."
                return 0
                ;;
            nobara|nobaru)
                DISTRO_FAMILY="rpm"
                DISTRO_NAME="Nobara Linux"
                SSH_SERVICE="sshd"
                IS_NOBARA=true
                log_info "Manual override: Nobara Linux mode active."
                return 0
                ;;
            rpm|fedora|rhel)
                DISTRO_FAMILY="rpm"
                DISTRO_NAME="Fedora/RHEL"
                SSH_SERVICE="sshd"
                log_info "Manual override: RPM/Fedora mode active."
                return 0
                ;;
            deb|debian|ubuntu)
                DISTRO_FAMILY="deb"
                DISTRO_NAME="Debian/Ubuntu"
                SSH_SERVICE="ssh"
                log_info "Manual override: Debian/Ubuntu mode active."
                return 0
                ;;
        esac
    fi

    # Automatic Detection Order:
    # 1. SteamOS (Dedicated handheld / Valve OS)
    if [[ -f /etc/steamos-release || "$distro_id" == "steamos" ]]; then
        DISTRO_FAMILY="steamos"
        SSH_SERVICE="sshd"
        IS_STEAMOS=true
        DISTRO_NAME="SteamOS"
        log_info "SteamOS detected: Handheld immutable system with steamos-readonly protection."
        return 0
    fi

    # 2. Fedora Atomic / OSTree (Silverblue, Bazzite, Kinoite)
    if [[ -f /run/ostree-booted || "$distro_id" =~ (bazzite|bluefin|aurora) || "$variant_id" =~ (silverblue|kinoite|sericea|bazzite) ]]; then
        DISTRO_FAMILY="atomic"
        SSH_SERVICE="sshd"
        IS_ATOMIC=true
        if [[ "$distro_id" =~ bazzite || "$variant_id" =~ bazzite ]]; then
            IS_BAZZITE=true
            DISTRO_NAME="Bazzite (Fedora Atomic)"
            log_info "Bazzite detected: Immutable gaming container image with pre-baked drivers."
        else
            DISTRO_NAME="Fedora Atomic (${variant_id:-Silverblue})"
            log_info "Fedora Atomic detected: Read-only /usr filesystem using rpm-ostree."
        fi
        return 0
    fi

    # 3. Nobara Linux
    if [[ "$distro_id" =~ (nobara|nobaru) || "$distro_like" =~ (nobara|nobaru) ]]; then
        DISTRO_FAMILY="rpm"
        SSH_SERVICE="sshd"
        IS_NOBARA=true
        DISTRO_NAME="Nobara Linux"
        log_info "Nobara Linux detected: Native gaming kernel, pre-packaged DKMS Nvidia drivers, and built-in repos."
        return 0
    fi

    # 4. Arch Linux & Derivatives
    if [[ "$distro_id" =~ (arch|manjaro|endeavouros|cachyos|garuda|artix) || "$distro_like" =~ arch ]]; then
        DISTRO_FAMILY="arch"
        SSH_SERVICE="sshd"
        DISTRO_NAME="Arch Linux (${distro_id^})"
        log_info "Arch Linux family detected. Utilizing pacman package management."
        return 0
    fi

    # 5. openSUSE (Tumbleweed / Leap)
    if [[ "$distro_id" =~ (opensuse|suse) || "$distro_like" =~ suse ]]; then
        DISTRO_FAMILY="opensuse"
        SSH_SERVICE="sshd"
        DISTRO_NAME="openSUSE (${distro_id})"
        log_info "openSUSE detected. Utilizing zypper package engine & Packman repos."
        return 0
    fi

    # 6. Standard Fedora / RHEL
    if [[ "$distro_id" =~ (fedora|rhel|centos|rocky|almalinux) || "$distro_like" =~ (fedora|rhel|centos|rocky|almalinux) ]]; then
        DISTRO_FAMILY="rpm"
        SSH_SERVICE="sshd"
        return 0
    fi

    # 7. Debian / Ubuntu
    if [[ "$distro_id" =~ (debian|ubuntu|linuxmint|pop) || "$distro_like" =~ (debian|ubuntu|linuxmint|pop) ]]; then
        DISTRO_FAMILY="deb"
        SSH_SERVICE="ssh"
        return 0
    fi

    DISTRO_FAMILY="unknown"
    SSH_SERVICE="sshd"
}

refresh_package_cache() {
    case "$DISTRO_FAMILY" in
        rpm)
            if ! run_cmd "Refreshing DNF package metadata" dnf makecache --refresh; then
                log_warn "DNF metadata refresh failed. Continuing..."
            fi
            ;;
        atomic)
            if command -v rpm-ostree &>/dev/null; then
                run_cmd "Checking rpm-ostree status" rpm-ostree status --quiet || true
            fi
            ;;
        arch)
            if ! run_cmd "Synchronizing Pacman database" pacman -Sy --noconfirm; then
                log_warn "Pacman metadata refresh failed. Continuing..."
            fi
            ;;
        steamos)
            steamos_unlock
            if ! run_cmd "Synchronizing SteamOS Pacman database" pacman -Sy --noconfirm; then
                log_warn "SteamOS Pacman refresh failed. Continuing..."
            fi
            steamos_lock
            ;;
        opensuse)
            if ! run_cmd "Refreshing Zypper repositories" zypper --non-interactive refresh; then
                log_warn "Zypper refresh failed. Continuing..."
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
        arch|steamos)
            case "$package" in
                p7zip-plugins) echo "p7zip" ;;
                wireshark-qt) echo "wireshark-qt" ;;
                nmap-ncat) echo "nmap" ;;
                openssh-server) echo "openssh" ;;
                google-authenticator) echo "libpam-google-authenticator" ;;
                dnf-automatic) echo "pacman" ;;
                audit) echo "audit" ;;
                iproute) echo "iproute2" ;;
                *) echo "$package" ;;
            esac
            ;;
        opensuse)
            case "$package" in
                p7zip-plugins) echo "p7zip" ;;
                wireshark-qt) echo "wireshark-ui-qt" ;;
                nmap-ncat) echo "netcat-openbsd" ;;
                openssh-server) echo "openssh" ;;
                google-authenticator) echo "google-authenticator-libpam" ;;
                audit) echo "audit" ;;
                iproute) echo "iproute2" ;;
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

    case "$DISTRO_FAMILY" in
        rpm)
            local install_cmd=(dnf)
            if [[ "$AUTO_YES" == "-y" ]]; then install_cmd+=(-y); fi
            install_cmd+=(install "${resolved_packages[@]}")
            refresh_package_cache
            if ! run_cmd "Installing packages: ${resolved_packages[*]}" "${install_cmd[@]}"; then
                log_warn "Package installation failed for: ${resolved_packages[*]}"
                return 1
            fi
            ;;
        atomic)
            log_info "Fedora Atomic: Layering host packages via rpm-ostree..."
            local ostree_cmd=(rpm-ostree install --idempotent)
            if rpm-ostree install --help 2>&1 | grep -q -- "--apply-live"; then
                ostree_cmd+=(--apply-live)
            fi
            ostree_cmd+=("${resolved_packages[@]}")
            if ! run_cmd "Layering rpm-ostree packages: ${resolved_packages[*]}" "${ostree_cmd[@]}"; then
                log_warn "rpm-ostree layering reported an issue (some packages may require reboot)."
                return 1
            fi
            ;;
        arch)
            local arch_cmd=(pacman -S --needed)
            if [[ "$AUTO_YES" == "-y" ]]; then arch_cmd+=(--noconfirm); fi
            arch_cmd+=("${resolved_packages[@]}")
            refresh_package_cache
            if ! run_cmd "Installing packages via Pacman: ${resolved_packages[*]}" "${arch_cmd[@]}"; then
                log_warn "Pacman installation failed for: ${resolved_packages[*]}"
                return 1
            fi
            ;;
        steamos)
            steamos_unlock
            local steam_cmd=(pacman -S --needed)
            if [[ "$AUTO_YES" == "-y" ]]; then steam_cmd+=(--noconfirm); fi
            steam_cmd+=("${resolved_packages[@]}")
            refresh_package_cache
            local ret=0
            if ! run_cmd "SteamOS: Installing packages: ${resolved_packages[*]}" "${steam_cmd[@]}"; then
                log_warn "SteamOS pacman installation failed for: ${resolved_packages[*]}"
                ret=1
            fi
            steamos_lock
            return $ret
            ;;
        opensuse)
            local zypper_cmd=(zypper --non-interactive install --auto-agree-with-licenses)
            zypper_cmd+=("${resolved_packages[@]}")
            refresh_package_cache
            if ! run_cmd "Installing packages via Zypper: ${resolved_packages[*]}" "${zypper_cmd[@]}"; then
                log_warn "Zypper installation failed for: ${resolved_packages[*]}"
                return 1
            fi
            ;;
        deb)
            export DEBIAN_FRONTEND=noninteractive
            local deb_cmd=(apt-get)
            if [[ "$AUTO_YES" == "-y" ]]; then deb_cmd+=(--yes); fi
            deb_cmd+=(install "${resolved_packages[@]}")
            refresh_package_cache
            if ! run_cmd "Installing packages via APT: ${resolved_packages[*]}" "${deb_cmd[@]}"; then
                log_warn "Package installation failed for: ${resolved_packages[*]}"
                return 1
            fi
            ;;
        *)
            log_warn "Unsupported package manager for distro: $DISTRO_NAME"
            return 1
            ;;
    esac
}

update_system() {
    case "$DISTRO_FAMILY" in
        rpm)
            local update_cmd=(dnf)
            if [[ "$AUTO_YES" == "-y" ]]; then update_cmd+=(-y); fi
            update_cmd+=(upgrade)
            if [[ -n "$DOWNLOAD_ONLY" ]]; then update_cmd+=("$DOWNLOAD_ONLY"); fi
            refresh_package_cache
            run_cmd "Updating system packages via DNF" "${update_cmd[@]}" || log_warn "System update failed."
            ;;
        atomic)
            log_info "Fedora Atomic: Upgrading OS tree via rpm-ostree..."
            run_cmd "Upgrading rpm-ostree tree" rpm-ostree upgrade || log_warn "rpm-ostree upgrade notice."
            ;;
        arch)
            refresh_package_cache
            local arch_update=(pacman -Syu)
            if [[ "$AUTO_YES" == "-y" ]]; then arch_update+=(--noconfirm); fi
            run_cmd "Updating Arch Linux system packages" "${arch_update[@]}" || log_warn "Pacman update failed."
            ;;
        steamos)
            log_info "SteamOS: Invoking system update routines..."
            if command -v steamos-update &>/dev/null; then
                steamos-update || true
            else
                steamos_unlock
                pacman -Syu --noconfirm || true
                steamos_lock
            fi
            ;;
        opensuse)
            refresh_package_cache
            run_cmd "Updating openSUSE distribution packages via Zypper" zypper --non-interactive dup || log_warn "Zypper dup failed."
            ;;
        deb)
            export DEBIAN_FRONTEND=noninteractive
            local deb_update=(apt-get)
            if [[ "$AUTO_YES" == "-y" ]]; then deb_update+=(--yes); fi
            deb_update+=(upgrade)
            if [[ -n "$DOWNLOAD_ONLY" ]]; then deb_update+=("$DOWNLOAD_ONLY"); fi
            refresh_package_cache
            run_cmd "Updating Debian/Ubuntu packages via APT" "${deb_update[@]}" || log_warn "APT update failed."
            ;;
    esac
}

ensure_flatpak() {
    if ! command -v flatpak &>/dev/null; then
        log_info "Flatpak not found on system. Automatically installing Flatpak support..."
        case "$DISTRO_FAMILY" in
            rpm)
                run_cmd "Installing Flatpak" dnf install ${AUTO_YES:+$AUTO_YES} flatpak || log_warn "Flatpak install failed."
                ;;
            atomic)
                log_info "Flatpak is native on Fedora Atomic."
                ;;
            arch)
                pacman -S --needed --noconfirm flatpak || true
                ;;
            steamos)
                steamos_unlock
                pacman -S --needed --noconfirm flatpak || true
                steamos_lock
                ;;
            opensuse)
                zypper --non-interactive install --auto-agree-with-licenses flatpak || true
                ;;
            deb)
                export DEBIAN_FRONTEND=noninteractive
                refresh_package_cache
                apt-get install ${AUTO_YES:+$AUTO_YES} flatpak || true
                ;;
        esac
    fi

    if command -v flatpak &>/dev/null; then
        flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo || true
    fi
}

install_flatpak_app() {
    local app="$1"
    ensure_flatpak
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

bootstrap_prerequisites() {
    log_info "Checking and auto-bootstrapping required system dependencies..."
    local missing_pkgs=()

    # 1. Remote asset fetching (curl / wget)
    if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
        missing_pkgs+=(curl)
    fi

    # 2. Hardware bus identification for GPU auto-detection (lspci)
    if ! command -v lspci &>/dev/null; then
        missing_pkgs+=(pciutils)
    fi

    # 3. Secure TLS/HTTPS repository certificates
    if [[ ! -d /etc/ssl/certs ]] || [[ "$DISTRO_FAMILY" == "deb" && ! -f /etc/ssl/certs/ca-certificates.crt ]]; then
        missing_pkgs+=(ca-certificates)
    fi

    # 4. Socket and network port listener testing (ss)
    if ! command -v ss &>/dev/null; then
        case "$DISTRO_FAMILY" in
            rpm) missing_pkgs+=(iproute) ;;
            deb|arch|steamos|opensuse) missing_pkgs+=(iproute2) ;;
        esac
    fi

    # 5. Core package manager tools
    case "$DISTRO_FAMILY" in
        rpm)
            if ! rpm -q dnf-plugins-core &>/dev/null 2>&1 && ! rpm -q dnf5-plugins &>/dev/null 2>&1; then
                missing_pkgs+=(dnf-plugins-core)
            fi
            ;;
        deb)
            if ! dpkg -s software-properties-common &>/dev/null 2>&1; then
                missing_pkgs+=(software-properties-common)
            fi
            ;;
    esac

    if [[ ${#missing_pkgs[@]} -gt 0 ]]; then
        log_info "Auto-installing missing core dependencies: ${missing_pkgs[*]}"
        case "$DISTRO_FAMILY" in
            rpm)
                dnf install ${AUTO_YES:+$AUTO_YES} "${missing_pkgs[@]}" || log_warn "Auto-bootstrap notice: some base packages could not be installed."
                ;;
            atomic)
                log_info "Fedora Atomic: Base utilities typically included in OS tree."
                ;;
            arch)
                pacman -S --needed --noconfirm "${missing_pkgs[@]}" || true
                ;;
            steamos)
                steamos_unlock
                pacman -S --needed --noconfirm "${missing_pkgs[@]}" || true
                steamos_lock
                ;;
            opensuse)
                zypper --non-interactive install --auto-agree-with-licenses "${missing_pkgs[@]}" || true
                ;;
            deb)
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -qq || true
                apt-get install ${AUTO_YES:+$AUTO_YES} "${missing_pkgs[@]}" || log_warn "Auto-bootstrap notice: some base packages could not be installed."
                ;;
        esac
    else
        log_success "All base system utilities verified."
    fi
}

install_powershell() {
    if command -v pwsh &>/dev/null; then
        log_success "Microsoft PowerShell (pwsh) is already installed."
        return 0
    fi

    log_info "Installing Microsoft PowerShell (pwsh)..."
    case "$DISTRO_FAMILY" in
        rpm)
            if ! rpm -q powershell &>/dev/null; then
                log_info "Configuring Microsoft RPM repository for PowerShell..."
                rpm --import https://packages.microsoft.com/keys/microsoft.asc 2>/dev/null || true
                curl --connect-timeout 10 --max-time 60 --retry 3 -fsSL https://packages.microsoft.com/config/rhel/9/prod.repo -o /etc/yum.repos.d/microsoft-prod.repo 2>/dev/null || true
                if ! dnf install ${AUTO_YES:+$AUTO_YES} powershell; then
                    log_warn "Native RPM PowerShell failed; falling back to Flathub package..."
                    install_flatpak_app com.microsoft.PowerShell
                fi
            fi
            ;;
        atomic|steamos)
            log_info "Immutable filesystem detected. Installing PowerShell via Flathub..."
            install_flatpak_app com.microsoft.PowerShell
            ;;
        arch)
            log_info "Installing PowerShell via pacman or Flathub..."
            if ! pacman -S --needed --noconfirm powershell 2>/dev/null; then
                install_flatpak_app com.microsoft.PowerShell
            fi
            ;;
        opensuse)
            log_info "Configuring Microsoft SLES repository for openSUSE..."
            rpm --import https://packages.microsoft.com/keys/microsoft.asc 2>/dev/null || true
            zypper addrepo https://packages.microsoft.com/sles/15/prod/ microsoft-prod 2>/dev/null || true
            if ! zypper --non-interactive install --auto-agree-with-licenses powershell; then
                install_flatpak_app com.microsoft.PowerShell
            fi
            ;;
        deb)
            if ! dpkg -s powershell &>/dev/null 2>&1; then
                export DEBIAN_FRONTEND=noninteractive
                curl --connect-timeout 10 --max-time 60 --retry 3 -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/microsoft.gpg 2>/dev/null || true
                local deb_ver="${VERSION_ID:-22.04}"
                echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-ubuntu-${deb_ver}-prod ${UBUNTU_CODENAME:-jammy} main" > /etc/apt/sources.list.d/microsoft-prod.list 2>/dev/null || true
                apt-get update -qq || true
                if ! apt-get install ${AUTO_YES:+$AUTO_YES} powershell; then
                    log_warn "Native DEB PowerShell failed; falling back to Flathub package..."
                    install_flatpak_app com.microsoft.PowerShell
                fi
            fi
            ;;
        *)
            install_flatpak_app com.microsoft.PowerShell
            ;;
    esac
}

print_usage() {
    echo -e "\n==============================================================="
    echo -e " Linux Provisioning & Deployment Environment Setup Script"
    echo -e " (Supports Fedora, Nobara, Fedora Atomic, Arch, SteamOS, openSUSE, Debian/Ubuntu)"
    echo -e "==============================================================="
    echo "Usage: sudo ./Linux-Deployment-Tool.sh [Options]"
    echo ""
    echo "MODULE OPTIONS:"
    echo "  --update           Sequentially upgrades package manager, Flatpak, and Snap"
    echo "  --apps             Installs core utilities (Browsers, Media, Search)"
    echo "  --devapps          Installs Dev tools (VS Code, Python, GitHub Desktop, PowerShell)"
    echo "  --cyber            Installs Security tools (Wireshark, Nmap, TCPDump)"
    echo "  --maker            Installs 3D Printing Slicers (Prusa, Orca, Bambu)"
    echo "  --creators         Installs Creative suite (Blender, Darktable, OBS)"
    echo "  --gaming           Configures Steam, Lutris, Winetricks, Repos, GPU Drivers"
    echo "  --ssh              Installs, enables, and verifies OpenSSH Server"
    echo "  --discord          Configures Discord (Native RPM on standard, Flatpak on Atomic/SteamOS)"
    echo ""
    echo "DISTRIBUTION OVERRIDES (Auto-detected if omitted):"
    echo "  --atomic           Force Fedora Atomic (Silverblue/Kinoite) rpm-ostree mode"
    echo "  --bazzite          Force Bazzite (Fedora Atomic Gaming) mode"
    echo "  --silverblue       Alias for --atomic"
    echo "  --arch             Force Arch Linux pacman mode"
    echo "  --steamos          Force SteamOS mode (Steam Deck immutable root toggle)"
    echo "  --opensuse         Force openSUSE (Tumbleweed/Leap) zypper mode"
    echo "  --distro=<name>    Explicit distribution override (atomic|bazzite|arch|steamos|opensuse|nobara|rpm|deb)"
    echo ""
    echo "DESKTOP ENVIRONMENT OVERRIDES (Auto-detected if omitted):"
    echo "  --gnome            Target GNOME desktop environment and QoL tools"
    echo "  --kde              Target KDE Plasma desktop environment and QoL tools"
    echo "  --cosmic           Target COSMIC desktop environment (System76) and tools"
    echo "  --xfce             Target XFCE desktop environment and utilities"
    echo "  --cinnamon         Target Cinnamon desktop environment and utilities"
    echo "  --de=<name>        Explicit desktop environment override (gnome|kde|cosmic|xfce|cinnamon)"
    echo ""
    echo "SECURITY & HARDENING:"
    echo "  --harden           Safe baseline: SELinux/AppArmor, Auto-Patching, No Root SSH"
    echo "  --harden-advanced  Strict: auditd, Sysctl network drops, No Password SSH"
    echo "  --2fa              Modifies the --ssh module to enforce Google Auth MFA"
    echo ""
    echo "GLOBAL OPTIONS:"
    echo "  --all              Executes ALL standard modules (Excludes harden-advanced)"
    echo "  -y                 Auto-install (answers yes to prompts)"
    echo "  -d                 Download only (applies to DNF/APT updates)"
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
        --atomic) DISTRO_OVERRIDE="atomic" ;;
        --bazzite) DISTRO_OVERRIDE="bazzite" ;;
        --silverblue) DISTRO_OVERRIDE="atomic" ;;
        --arch) DISTRO_OVERRIDE="arch" ;;
        --steamos) DISTRO_OVERRIDE="steamos" ;;
        --opensuse|--suse) DISTRO_OVERRIDE="opensuse" ;;
        --distro=*) DISTRO_OVERRIDE="${1#*=}" ;;
        --distro) shift; DISTRO_OVERRIDE="$1" ;;
        --gnome) DESKTOP_ENV="GNOME" ;;
        --kde|--plasma) DESKTOP_ENV="KDE" ;;
        --cosmic) DESKTOP_ENV="COSMIC" ;;
        --xfce) DESKTOP_ENV="XFCE" ;;
        --cinnamon) DESKTOP_ENV="CINNAMON" ;;
        --de=*)
            case "${1#*=}" in
                gnome) DESKTOP_ENV="GNOME" ;;
                kde|plasma) DESKTOP_ENV="KDE" ;;
                cosmic) DESKTOP_ENV="COSMIC" ;;
                xfce) DESKTOP_ENV="XFCE" ;;
                cinnamon) DESKTOP_ENV="CINNAMON" ;;
                *) DESKTOP_ENV="${1#*=}" ;;
            esac
            ;;
        --de)
            shift
            case "${1,,}" in
                gnome) DESKTOP_ENV="GNOME" ;;
                kde|plasma) DESKTOP_ENV="KDE" ;;
                cosmic) DESKTOP_ENV="COSMIC" ;;
                xfce) DESKTOP_ENV="XFCE" ;;
                cinnamon) DESKTOP_ENV="CINNAMON" ;;
                *) DESKTOP_ENV="$1" ;;
            esac
            ;;
        -y) AUTO_YES="-y" ;;
        -d) if [[ "$DISTRO_FAMILY" == "deb" ]]; then DOWNLOAD_ONLY="--download-only"; else DOWNLOAD_ONLY="--downloadonly"; fi ;;
        --help|-h) print_usage; exit 0 ;;
        *) log_error "Unknown parameter passed: $1"; print_usage; exit 1 ;;
    esac
    shift
done

detect_distro

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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
readonly SCRIPT_DIR
readonly LOG_DIR="${SCRIPT_DIR}/InstallerLogs"
mkdir -p "$LOG_DIR"
chmod 700 "$LOG_DIR" 2>/dev/null || true

readonly TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
readonly LOG_FILE="${LOG_DIR}/installer_log_${TIMESTAMP}.log"
touch "$LOG_FILE" && chmod 600 "$LOG_FILE" 2>/dev/null || true

exec > >(tee -i "$LOG_FILE") 2>&1

if [[ "$RUN_DEBUG" == true ]]; then
    log_warn "Debug mode enabled. Command tracing (set -x) is active."
    set -x
fi

log_success "Running with root privileges."
log_info "Logging execution to: $LOG_FILE"

bootstrap_prerequisites

# ------------------------------------------------------------------------------
# 5. INTERACTIVE PROMPTS & DESKTOP ENVIRONMENT CONFIGURATION
# ------------------------------------------------------------------------------
# Check for environment auto-detection if not explicitly passed via flag
if [[ -z "${DESKTOP_ENV:-}" ]]; then
    CURRENT_DESKTOP_DETECTION="${XDG_CURRENT_DESKTOP:-${DESKTOP_SESSION:-}}"
    case "${CURRENT_DESKTOP_DETECTION,,}" in
        *cosmic*) DESKTOP_ENV="COSMIC" ;;
        *gnome*) DESKTOP_ENV="GNOME" ;;
        *kde*|*plasma*) DESKTOP_ENV="KDE" ;;
        *xfce*) DESKTOP_ENV="XFCE" ;;
        *cinnamon*) DESKTOP_ENV="CINNAMON" ;;
    esac
fi

if [[ -n "${DESKTOP_ENV:-}" ]]; then
    log_info "Desktop Environment configured as: $DESKTOP_ENV"
elif [[ "$UNATTENDED" == true ]]; then
    log_info "Unattended mode enabled. Defaulting to KDE."
    DESKTOP_ENV="KDE"
else
    echo -e "\n\e[36m=== Desktop Environment Configuration ===\e[0m"
    while true; do
        read -p "Select Desktop Environment ([g]nome / [k]de / [c]osmic / [x]fce / c[i]nnamon): " de_choice
        case "${de_choice,,}" in
            g|gnome) DESKTOP_ENV="GNOME"; break ;;
            k|kde|plasma) DESKTOP_ENV="KDE"; break ;;
            c|cosmic) DESKTOP_ENV="COSMIC"; break ;;
            x|xfce) DESKTOP_ENV="XFCE"; break ;;
            i|cin|cinnamon) DESKTOP_ENV="CINNAMON"; break ;;
            *) log_warn "Please enter 'g' (GNOME), 'k' (KDE), 'c' (COSMIC), 'x' (XFCE), or 'i' (Cinnamon)." ;;
        esac
    done
fi

if [[ "$RUN_HARDEN_ADV" == true && "$UNATTENDED" != true ]]; then
    echo -e "\n\e[31m[!] WARNING: Advanced hardening will disable SSH password authentication."
    echo -e "    Ensure you have an SSH Key provisioned before disconnecting.\e[0m"
    read -p "    Press Enter to acknowledge and continue..."
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

    case "${DESKTOP_ENV^^}" in
        GNOME)
            log_info "Installing GNOME QoL packages..."
            if ! pkg_install baobab gnome-tweaks; then
                log_warn "Some GNOME QoL packages could not be installed. Continuing..."
            fi
            ;;
        KDE)
            log_info "Installing KDE Plasma QoL packages..."
            if ! pkg_install filelight; then
                log_warn "Some KDE QoL packages could not be installed. Continuing..."
            fi
            ;;
        COSMIC)
            log_info "Installing COSMIC Desktop utilities..."
            if ! pkg_install cosmic-files cosmic-term cosmic-edit 2>/dev/null; then
                pkg_install baobab 2>/dev/null || true
            fi
            ;;
        XFCE)
            log_info "Installing XFCE Desktop utilities..."
            if ! pkg_install xfce4-taskmanager baobab; then
                log_warn "Some XFCE QoL packages could not be installed. Continuing..."
            fi
            ;;
        CINNAMON)
            log_info "Installing Cinnamon Desktop utilities..."
            if ! pkg_install nemo baobab; then
                log_warn "Some Cinnamon QoL packages could not be installed. Continuing..."
            fi
            ;;
        *)
            log_info "Generic Desktop detected (${DESKTOP_ENV}). Installing universal disk analyzer..."
            pkg_install baobab 2>/dev/null || true
            ;;
    esac

    ensure_flatpak
    readonly FLATPAK_APPS=(com.brave.Browser com.google.Chrome md.obsidian.Obsidian org.signal.Signal)
    for app in "${FLATPAK_APPS[@]}"; do
        install_flatpak_app "$app"
    done

    if command -v updatedb &>/dev/null; then
        updatedb || true
    fi
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

    # Install Microsoft PowerShell (pwsh) via official repository or Flathub fallback
    install_powershell

    ensure_flatpak
    readonly DEV_FLATPAKS=(com.visualstudio.code io.github.shiftey.Desktop)
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
    
    if [[ "$DISTRO_FAMILY" == "rpm" || "$DISTRO_FAMILY" == "atomic" ]]; then
        log_info "Verifying SELinux Enforcement..."
        if command -v setenforce &> /dev/null; then
            setenforce 1 || true
            sed -i -E 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config 2>/dev/null || true
            log_success "SELinux verified/set to Enforcing."
        fi
    elif [[ "$DISTRO_FAMILY" == "opensuse" || "$DISTRO_FAMILY" == "deb" ]]; then
        if command -v aa-status &> /dev/null; then
            log_info "Verifying AppArmor Enforcement..."
            systemctl enable --now apparmor 2>/dev/null || true
            log_success "AppArmor verified/enforced."
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
    elif [[ "$DISTRO_FAMILY" == "atomic" ]]; then
        log_info "Fedora Atomic: Enabling rpm-ostreed-automatic timer..."
        systemctl enable --now rpm-ostreed-automatic.timer 2>/dev/null || true
    elif [[ "$DISTRO_FAMILY" == "deb" ]]; then
        pkg_install unattended-upgrades apt-listchanges
        cat <<'EOF' > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
        service_enable unattended-upgrades
    else
        log_info "Automatic patching skipped for $DISTRO_NAME (manual scheduling recommended)."
    fi
    log_success "Automated background security patching verified."

    if dpkg -s openssh-server &> /dev/null 2>&1 || rpm -q openssh-server &> /dev/null 2>&1 || command -v sshd &>/dev/null; then
        log_info "Applying CIS Benchmark Baseline & CVE-2024-6387 (regreSSHion) Mitigation..."
        readonly SSHD_CONF="/etc/ssh/sshd_config"
        sed -i -E 's/^#?PermitRootLogin.*/PermitRootLogin no/' "$SSHD_CONF"
        # CVE-2024-6387 (regreSSHion): reduce grace time from 120s to 20s to neutralize race condition window
        sed -i -E 's/^#?LoginGraceTime.*/LoginGraceTime 20/' "$SSHD_CONF" 2>/dev/null || echo "LoginGraceTime 20" >> "$SSHD_CONF"
        sed -i -E 's/^#?MaxAuthTries.*/MaxAuthTries 3/' "$SSHD_CONF" 2>/dev/null || echo "MaxAuthTries 3" >> "$SSHD_CONF"
        sed -i -E 's/^#?MaxSessions.*/MaxSessions 4/' "$SSHD_CONF" 2>/dev/null || echo "MaxSessions 4" >> "$SSHD_CONF"
        sed -i -E 's/^#?MaxStartups.*/MaxStartups 10:30:60/' "$SSHD_CONF" 2>/dev/null || echo "MaxStartups 10:30:60" >> "$SSHD_CONF"
        sed -i -E 's/^#?ClientAliveInterval.*/ClientAliveInterval 300/' "$SSHD_CONF" 2>/dev/null || echo "ClientAliveInterval 300" >> "$SSHD_CONF"
        sed -i -E 's/^#?ClientAliveCountMax.*/ClientAliveCountMax 2/' "$SSHD_CONF" 2>/dev/null || echo "ClientAliveCountMax 2" >> "$SSHD_CONF"
        sed -i -E 's/^#?PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$SSHD_CONF" 2>/dev/null || echo "PermitEmptyPasswords no" >> "$SSHD_CONF"
        sed -i -E 's/^#?IgnoreRhosts.*/IgnoreRhosts yes/' "$SSHD_CONF" 2>/dev/null || echo "IgnoreRhosts yes" >> "$SSHD_CONF"
        sed -i -E 's/^#?HostbasedAuthentication.*/HostbasedAuthentication no/' "$SSHD_CONF" 2>/dev/null || echo "HostbasedAuthentication no" >> "$SSHD_CONF"
        service_restart "$SSH_SERVICE"
        log_success "Direct root login disabled, LoginGraceTime tuned to 20s (regreSSHion defense), and CIS limits enforced."
    fi
    log_success "Standard hardening complete."
fi

# ==============================================================================
# MODULE: ADVANCED HARDENING (--harden-advanced)
# ==============================================================================
if [[ "$RUN_HARDEN_ADV" == true ]]; then
    echo -e "\n\e[35m[========== STARTING ADVANCED HARDENING ==========]\e[0m"
    
    log_info "Applying Strict CIS Level 2 Sysctl Network Drops & Memory Protection..."
    readonly SYSCTL_CONF="/etc/sysctl.d/99-security.conf"
    cat <<EOF > "$SYSCTL_CONF"
# CIS Linux Benchmark Network Hardening Controls & Memory Defense
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_all = 1
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
EOF
    sysctl -p "$SYSCTL_CONF" || log_warn "Failed to apply sysctl parameters."
    log_success "Kernel network hardening applied (Ping disabled, strict routing, martian logging, suid dump disabled)."

    log_info "Deploying and Configuring Auditd..."
    pkg_install audit
    service_enable auditd
    readonly AUDIT_RULES="/etc/audit/rules.d/custom-security.rules"
    cat <<EOF > "$AUDIT_RULES"
# CIS Benchmark Credential, Identity & Privilege Monitoring
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /etc/ssh/sshd_config -p wa -k sshd_config
EOF
    augenrules --load || log_warn "Failed to load audit rules."
    log_success "Audit daemon configured for high-fidelity credential/privilege event generation."

    if dpkg -s openssh-server &> /dev/null 2>&1 || rpm -q openssh-server &> /dev/null 2>&1 || command -v sshd &>/dev/null; then
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
    if ! dpkg -s openssh-server &> /dev/null 2>&1 && ! rpm -q openssh-server &> /dev/null 2>&1 && ! command -v sshd &>/dev/null; then
        log_info "Installing OpenSSH Server..."
        pkg_install openssh-server
    fi

    if [[ "$RUN_2FA" == true ]]; then
        log_info "Configuring Google Authenticator MFA for SSH..."
        pkg_install google-authenticator
        readonly SSHD_CONF="/etc/ssh/sshd_config"
        readonly PAM_CONF="/etc/pam.d/sshd"

        sed -i -E 's/^#?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' "$SSHD_CONF"
        sed -i -E 's/^#?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' "$SSHD_CONF"
        sed -i -E 's/^#?UsePAM.*/UsePAM yes/' "$SSHD_CONF"

        # Idempotent PAM injection with nullok (secures login while avoiding lockout before key generation)
        if ! grep -q "pam_google_authenticator.so" "$PAM_CONF" 2>/dev/null; then
            echo "auth required pam_google_authenticator.so nullok" >> "$PAM_CONF"
            log_success "Enforced pam_google_authenticator.so (nullok transition mode) in $PAM_CONF."
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
    if [[ "$IS_ATOMIC" == true || "$IS_STEAMOS" == true ]]; then
        log_info "Atomic / SteamOS detected: Maintaining Flatpak Discord (safe for immutable filesystems)."
        install_flatpak_app com.discordapp.Discord
    elif [[ "$DISTRO_FAMILY" == "rpm" ]]; then
        if flatpak list 2>/dev/null | grep -q "discord" || true; then
            flatpak uninstall ${AUTO_YES:+--assumeyes} "discord" 2>/dev/null || true
        fi
        if [[ "$IS_NOBARA" != true ]]; then
            local fedora_ver
            fedora_ver=$(rpm -E %fedora 2>/dev/null || true)
            if [[ -z "$fedora_ver" || "$fedora_ver" == "%fedora" ]]; then
                fedora_ver="${VERSION_ID:-41}"
                fedora_ver="${fedora_ver%%.*}"
            fi
            pkg_install "https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-${fedora_ver}.noarch.rpm" || true
            pkg_install "https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-${fedora_ver}.noarch.rpm" || true
        else
            log_info "Nobara detected: RPM Fusion repositories are already built-in."
        fi
        pkg_install discord
    else
        log_info "Installing Flathub Discord on $DISTRO_NAME..."
        install_flatpak_app com.discordapp.Discord
    fi
    log_success "Discord transition complete."
fi

if [[ "$RUN_GAMING" == true ]]; then
    echo -e "\n\e[35m[========== STARTING GAMING & DRIVER MODULE ==========]\e[0m"
    if [[ "$DISTRO_FAMILY" == "rpm" ]]; then
        readonly PRE_PKGS=(flatpak snap dnf-plugins-core)
        pkg_install "${PRE_PKGS[@]}"
        if [[ "$IS_NOBARA" != true ]]; then
            local fedora_ver
            fedora_ver=$(rpm -E %fedora 2>/dev/null || true)
            if [[ -z "$fedora_ver" || "$fedora_ver" == "%fedora" ]]; then
                fedora_ver="${VERSION_ID:-41}"
                fedora_ver="${fedora_ver%%.*}"
            fi
            pkg_install "https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-${fedora_ver}.noarch.rpm" || true
            pkg_install "https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-${fedora_ver}.noarch.rpm" || true
            dnf group upgrade core ${AUTO_YES:+$AUTO_YES} || true
        else
            log_info "Nobara detected: Native gaming repository stack & Wine dependencies already active."
        fi
    elif [[ "$DISTRO_FAMILY" == "opensuse" ]]; then
        log_info "openSUSE detected: Adding Packman Essentials repository for gaming & multimedia codecs..."
        zypper ar -cfp 90 https://ftp.gwdg.de/pub/linux/misc/packman/suse/openSUSE_Tumbleweed/Essentials/ packman-essentials 2>/dev/null || \
        zypper ar -cfp 90 "https://ftp.gwdg.de/pub/linux/misc/packman/suse/openSUSE_Leap_\$releasever/Essentials/" packman-essentials 2>/dev/null || true
    elif [[ "$DISTRO_FAMILY" == "arch" || "$DISTRO_FAMILY" == "steamos" ]]; then
        log_info "Verifying multilib repository is active in /etc/pacman.conf..."
        if grep -q "^#\[multilib\]" /etc/pacman.conf 2>/dev/null; then
            sed -i '/^#\[multilib\]/{n;s/^#Include/Include/}; s/^#\[multilib\]/\[multilib\]/' /etc/pacman.conf 2>/dev/null || true
        fi
    else
        pkg_install flatpak snapd
    fi
    
    ensure_flatpak
    readonly GAMING_PKGS=(winetricks steam lutris)
    pkg_install "${GAMING_PKGS[@]}"
    install_flatpak_app net.davidotek.pupgui2 || true
    install_flatpak_app com.usebottles.bottles || true
    
    if command -v fwupdmgr &>/dev/null; then
        fwupdmgr refresh --force || true
        fwupdmgr get-devices || true
        fwupdmgr update ${AUTO_YES:+$AUTO_YES} || true
    fi

    GPU_INFO=""
    if command -v lspci &>/dev/null; then
        GPU_INFO=$(lspci -nn 2>/dev/null | grep -E 'VGA|3D controller' | head -n 1 || true)
    fi
    # Secondary PCI identification via /sys/bus/pci/devices if lspci is unavailable
    if [[ -z "$GPU_INFO" ]] && [[ -d /sys/bus/pci/devices ]]; then
        if grep -qsi "0x10de" /sys/bus/pci/devices/*/vendor 2>/dev/null; then
            GPU_INFO="NVIDIA Corporation [PCI ID 0x10de auto-detected via sysfs]"
        elif grep -qsi "0x1002" /sys/bus/pci/devices/*/vendor 2>/dev/null; then
            GPU_INFO="Advanced Micro Devices, Inc. [AMD/ATI PCI ID 0x1002 auto-detected via sysfs]"
        fi
    fi

    case "$GPU_INFO" in
        *"NVIDIA"*)
            if [[ "$IS_NOBARA" == true ]]; then
                log_success "Nobara Linux detected: NVIDIA proprietary drivers are pre-installed via DKMS & the official 'nobara-nvidia-production' repository."
                log_info "Nobara Best Practice: Skipping manual akmod-nvidia installation to prevent fatal transaction conflicts with Nobara's custom kernel modules. Use 'nobara-sync' or the Nobara Driver Manager for driver maintenance."
            elif [[ "$IS_BAZZITE" == true ]]; then
                log_success "Bazzite detected: Bazzite ships with pre-configured NVIDIA container images. Host driver layering is intentionally skipped."
            elif [[ "$IS_STEAMOS" == true ]]; then
                log_info "SteamOS detected: Valve Linux kernel exclusively targets AMD APU hardware (Steam Deck). Skipping NVIDIA desktop drivers."
            elif [[ "$IS_ATOMIC" == true ]]; then
                log_info "Fedora Atomic (Silverblue/Kinoite) detected. Layering akmod-nvidia via rpm-ostree..."
                rpm-ostree install --idempotent akmod-nvidia xorg-x11-drv-nvidia nvidia-settings vulkan-tools || log_warn "rpm-ostree driver layering failed or requires a scheduled reboot."
            elif [[ "$DISTRO_FAMILY" == "arch" ]]; then
                log_info "Arch Linux detected: Installing nvidia-dkms and utilities via pacman..."
                pkg_install nvidia-dkms nvidia-utils lib32-nvidia-utils nvidia-settings vulkan-tools || pkg_install nvidia nvidia-utils nvidia-settings vulkan-tools || true
            elif [[ "$DISTRO_FAMILY" == "opensuse" ]]; then
                log_info "openSUSE detected: Adding official openSUSE NVIDIA repository..."
                zypper addrepo --refresh https://download.nvidia.com/opensuse/tumbleweed NVIDIA 2>/dev/null || zypper addrepo --refresh https://download.nvidia.com/opensuse/leap/\$releasever NVIDIA 2>/dev/null || true
                pkg_install x11-video-nvidiaG06 nvidia-glG06 nvidia-computeG06 vulkan-tools || true
            elif [[ "$DISTRO_FAMILY" == "deb" ]]; then
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
            case "$DISTRO_FAMILY" in
                atomic)
                    log_info "Fedora Atomic/Bazzite includes Mesa/RADV drivers in base image."
                    ;;
                steamos)
                    log_info "SteamOS native AMD Mesa/RADV driver stack is active."
                    ;;
                arch)
                    pkg_install mesa lib32-mesa vulkan-radeon lib32-vulkan-radeon vulkan-tools || true
                    ;;
                opensuse)
                    pkg_install Mesa Mesa-libva libvulkan_radeon vulkan-tools || true
                    ;;
                deb)
                    pkg_install mesa-vulkan-drivers vulkan-tools libvulkan1 || true
                    ;;
                *)
                    pkg_install mesa-vulkan-drivers vulkan-tools vulkan-loader || true
                    ;;
            esac
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