#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ==============================================================================
# SYNOPSIS
#     Shared core library for Linux-Deployment-Tool (v3.0.1 Beta Modular Suite).
#
# DESCRIPTION
#     Provides unified logging, strict error/signal trapping, multi-distribution
#     detection, package manager routing, Flatpak helpers, configuration file
#     mutators, and standalone child script bootstrapping.
#
# AUTHOR
#     Zachary Schmalz
#     Repository:      https://github.com/ZacharySchmalzEng/Tools/
#     Changelog:       See ./CHANGELOG.md for full release history.
#
# NOTES
#     Version:         3.0.1-beta
# ==============================================================================

if [[ "${COMMON_LIB_LOADED:-false}" == true ]]; then
    return 0 2>/dev/null || exit 0
fi
COMMON_LIB_LOADED=true

# ------------------------------------------------------------------------------
# 1. STRICT MODE, SECURITY UMASK & ERROR TRAPPING
# ------------------------------------------------------------------------------
set -euo pipefail
umask 0022

# ------------------------------------------------------------------------------
# 2. CONSTANTS & HELPER FUNCTIONS
# ------------------------------------------------------------------------------
readonly COLOR_INFO='\e[36m'
readonly COLOR_SUCCESS='\e[32m'
readonly COLOR_WARN='\e[33m'
readonly COLOR_ERROR='\e[31m'
readonly COLOR_RESET='\e[0m'
readonly DNF_RETRY_OPTIONS=(--setopt=retries=10 --setopt=timeout=60)
readonly SSHD_CONF="/etc/ssh/sshd_config"
readonly PAM_CONF="/etc/pam.d/sshd"
readonly GITHUB_RAW_BASE="${LDT_REPO_BASE_URL:-https://raw.githubusercontent.com/ZacharySchmalzEng/Tools/main/Linux/Provisioning/Linux-Deployment-Tool/Beta}"

# Print informational progress in cyan.
log_info()    { echo -e "${COLOR_INFO}[INFO] $1${COLOR_RESET}"; }
# Print successful completion messages in green.
log_success() { echo -e "${COLOR_SUCCESS}[+] $1${COLOR_RESET}"; }
# Print non-fatal issues in yellow.
log_warn()    { echo -e "${COLOR_WARN}[!] $1${COLOR_RESET}"; }
# Print errors to stderr in red.
log_error()   { echo -e "${COLOR_ERROR}[ERROR] $1${COLOR_RESET}" >&2; }

# Global State Flags for Signal & Error Restoration
IS_STEAMOS_UNLOCKED="${IS_STEAMOS_UNLOCKED:-false}"
CACHE_REFRESHED="${CACHE_REFRESHED:-false}"
TEMP_CLEANUP_DIRS=()

# Restore SteamOS read-only protection and remove temporary directories on exit or signal.
cleanup_handler() {
    local exit_code=$?
    trap - EXIT INT TERM HUP

    # 1. SecOps state restoration: Re-lock SteamOS root if interrupted while writable
    if [[ "${IS_STEAMOS_UNLOCKED:-false}" == true ]] && command -v steamos-readonly &>/dev/null; then
        echo -e "\n\e[33m[!] Trapped signal: Restoring SteamOS immutable root protection (steamos-readonly enable)...\e[0m"
        steamos-readonly enable 2>/dev/null || true
        IS_STEAMOS_UNLOCKED=false
    fi

    # 2. Secure deletion of temporary directories
    if [[ -n "${TEMP_CLEANUP_DIRS[*]:-}" ]]; then
        for tmp_dir in "${TEMP_CLEANUP_DIRS[@]}"; do
            if [[ -n "$tmp_dir" && ( -d "$tmp_dir" || -f "$tmp_dir" ) ]]; then
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

# Report the failing command's source line without replacing normal error handling.
handle_error() {
    local exit_code="${1:-0}"
    local line_number="${2:-unknown}"
    if [[ "$exit_code" -ne 0 ]]; then
        log_error "Command failed at line ${line_number} with exit code ${exit_code}."
    fi
}

# Log a description, then execute the supplied command and arguments.
run_cmd() {
    local description="$1"
    shift
    log_info "$description"
    "$@"
}

DISTRO_FAMILY="${DISTRO_FAMILY:-unknown}"
DISTRO_NAME="${DISTRO_NAME:-unknown}"
SSH_SERVICE="${SSH_SERVICE:-sshd}"
IS_NOBARA="${IS_NOBARA:-false}"
IS_ATOMIC="${IS_ATOMIC:-false}"
IS_BAZZITE="${IS_BAZZITE:-false}"
IS_STEAMOS="${IS_STEAMOS:-false}"
DISTRO_OVERRIDE="${DISTRO_OVERRIDE:-}"
DESKTOP_ENV="${DESKTOP_ENV:-}"
RUN_REINSTALL="${RUN_REINSTALL:-false}"
RUN_REBUILD="${RUN_REBUILD:-false}"
RUN_DEBUG="${RUN_DEBUG:-false}"
UNATTENDED="${UNATTENDED:-false}"
AUTO_YES="${AUTO_YES:-}"
DOWNLOAD_ONLY="${DOWNLOAD_ONLY:-}"
DOWNLOAD_ONLY_REQUESTED="${DOWNLOAD_ONLY_REQUESTED:-false}"
RUN_2FA="${RUN_2FA:-false}"
RUN_SYSADMIN="${RUN_SYSADMIN:-false}"

# Temporarily unlock SteamOS and initialize its pacman keyring when needed.
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

# Re-enable SteamOS read-only protection after a package operation.
steamos_lock() {
    if [[ "$IS_STEAMOS" == true ]] && command -v steamos-readonly &>/dev/null; then
        log_info "SteamOS: Restoring immutable root integrity (steamos-readonly enable)..."
        steamos-readonly enable || true
        IS_STEAMOS_UNLOCKED=false
    fi
}

# Select the package-manager family from an override or operating-system metadata.
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

    if [[ -f /etc/steamos-release || "$distro_id" == "steamos" ]]; then
        DISTRO_FAMILY="steamos"
        SSH_SERVICE="sshd"
        IS_STEAMOS=true
        DISTRO_NAME="SteamOS"
        log_info "SteamOS detected: Handheld immutable system with steamos-readonly protection."
        return 0
    fi

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

    if [[ "$distro_id" =~ (nobara|nobaru) || "$distro_like" =~ (nobara|nobaru) ]]; then
        DISTRO_FAMILY="rpm"
        SSH_SERVICE="sshd"
        IS_NOBARA=true
        DISTRO_NAME="Nobara Linux"
        log_info "Nobara Linux detected: Native gaming kernel, pre-packaged DKMS Nvidia drivers, and built-in repos."
        return 0
    fi

    if [[ "$distro_id" =~ (arch|manjaro|endeavouros|cachyos|garuda|artix) || "$distro_like" =~ arch ]]; then
        DISTRO_FAMILY="arch"
        SSH_SERVICE="sshd"
        DISTRO_NAME="Arch Linux (${distro_id^})"
        log_info "Arch Linux family detected. Utilizing pacman package management."
        return 0
    fi

    if [[ "$distro_id" =~ (opensuse|suse) || "$distro_like" =~ suse ]]; then
        DISTRO_FAMILY="opensuse"
        SSH_SERVICE="sshd"
        DISTRO_NAME="openSUSE (${distro_id})"
        log_info "openSUSE detected. Utilizing zypper package engine & Packman repos."
        return 0
    fi

    if [[ "$distro_id" =~ (fedora|rhel|centos|rocky|almalinux) || "$distro_like" =~ (fedora|rhel|centos|rocky|almalinux) ]]; then
        DISTRO_FAMILY="rpm"
        SSH_SERVICE="sshd"
        return 0
    fi

    if [[ "$distro_id" =~ (debian|ubuntu|linuxmint|pop) || "$distro_like" =~ (debian|ubuntu|linuxmint|pop) ]]; then
        DISTRO_FAMILY="deb"
        SSH_SERVICE="ssh"
        return 0
    fi

    DISTRO_FAMILY="unknown"
    SSH_SERVICE="sshd"
}

# Refresh repository metadata once per run, with SteamOS locking around pacman access.
refresh_package_cache() {
    local force="${1:-false}"
    if [[ "$CACHE_REFRESHED" == true && "$force" != "force" ]]; then
        return 0
    fi

    case "$DISTRO_FAMILY" in
        rpm)
            if ! run_cmd "Refreshing DNF package metadata" dnf "${DNF_RETRY_OPTIONS[@]}" makecache --refresh; then
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
    CACHE_REFRESHED=true
}

# Translate shared package names to distro-specific package identifiers.
resolve_package_name() {
    local package="$1"
    case "$DISTRO_FAMILY" in
        rpm|atomic)
            case "$package" in
                wireshark-qt) echo "wireshark" ;;
                *) echo "$package" ;;
            esac
            ;;
        deb)
            case "$package" in
                btop) echo "btop" ;;
                bat) echo "bat" ;;
                eza) echo "eza" ;;
                plocate) echo "plocate" ;;
                mediawriter) echo "gnome-multi-writer" ;;
                p7zip-plugins) echo "p7zip-full" ;;
                bind-utils) echo "dnsutils" ;;
                mtr) echo "mtr-tiny" ;;
                vlc) echo "vlc" ;;
                timeshift) echo "timeshift" ;;
                remmina) echo "remmina" ;;
                wireshark-qt) echo "wireshark" ;;
                nmap-ncat) echo "netcat" ;;
                prusa-slicer) echo "prusa-slicer" ;;
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
                bind-utils) echo "bind" ;;
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

# Route package installation or reinstall requests through the active distro manager.
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
            refresh_package_cache
            if [[ "$RUN_REINSTALL" == true ]]; then
                local reinstall_packages=() install_packages=()
                for package in "${resolved_packages[@]}"; do
                    if [[ "$package" =~ ^https?:// || "$package" == *.rpm ]]; then
                        install_packages+=("$package")
                    elif rpm -q "$package" &>/dev/null; then
                        reinstall_packages+=("$package")
                    else
                        install_packages+=("$package")
                    fi
                done
                if [[ ${#reinstall_packages[@]} -gt 0 ]]; then
                    local reinstall_cmd=(dnf "${DNF_RETRY_OPTIONS[@]}")
                    if [[ "$AUTO_YES" == "-y" ]]; then reinstall_cmd+=(-y); fi
                    reinstall_cmd+=(reinstall "${reinstall_packages[@]}")
                    if ! run_cmd "Reinstalling packages: ${reinstall_packages[*]}" "${reinstall_cmd[@]}"; then
                        log_warn "Package reinstallation failed for: ${reinstall_packages[*]}"
                        return 1
                    fi
                fi
                if [[ ${#install_packages[@]} -gt 0 ]]; then
                    local install_cmd=(dnf "${DNF_RETRY_OPTIONS[@]}")
                    if [[ "$AUTO_YES" == "-y" ]]; then install_cmd+=(-y); fi
                    install_cmd+=(install --skip-unavailable "${install_packages[@]}")
                    if ! run_cmd "Installing missing packages: ${install_packages[*]}" "${install_cmd[@]}"; then
                        log_warn "Package installation failed for: ${install_packages[*]}"
                        return 1
                    fi
                fi
            else
                local install_cmd=(dnf "${DNF_RETRY_OPTIONS[@]}")
                if [[ "$AUTO_YES" == "-y" ]]; then install_cmd+=(-y); fi
                install_cmd+=(install --skip-unavailable "${resolved_packages[@]}")
                if ! run_cmd "Installing packages: ${resolved_packages[*]}" "${install_cmd[@]}"; then
                    log_warn "Package installation failed for: ${resolved_packages[*]}"
                    return 1
                fi
            fi
            ;;
        atomic)
            log_info "Fedora Atomic: Layering host packages via rpm-ostree..."
            if [[ "$RUN_REINSTALL" == true ]]; then
                log_warn "rpm-ostree does not support package-level reinstall; applying its normal idempotent layering behavior."
            fi
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
            local arch_cmd=(pacman -S)
            if [[ "$RUN_REINSTALL" != true ]]; then
                arch_cmd+=(--needed)
            fi
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
            local steam_cmd=(pacman -S)
            if [[ "$RUN_REINSTALL" != true ]]; then
                steam_cmd+=(--needed)
            fi
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
            if [[ "$RUN_REINSTALL" == true ]]; then zypper_cmd+=(--force); fi
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
            deb_cmd+=(install)
            if [[ "$RUN_REINSTALL" == true ]]; then deb_cmd+=(--reinstall); fi
            deb_cmd+=("${resolved_packages[@]}")
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

# Apply system upgrades using the detected package manager and recovery options.
update_system() {
    case "$DISTRO_FAMILY" in
        rpm)
            local update_cmd=(dnf "${DNF_RETRY_OPTIONS[@]}")
            if [[ "$AUTO_YES" == "-y" ]]; then update_cmd+=(-y); fi
            update_cmd+=(upgrade)
            if [[ -n "$DOWNLOAD_ONLY" ]]; then update_cmd+=("$DOWNLOAD_ONLY"); fi
            refresh_package_cache
            run_cmd "Updating system packages via DNF" "${update_cmd[@]}" || log_warn "System update failed."
            if [[ "$RUN_REBUILD" == true && -z "$DOWNLOAD_ONLY" ]]; then
                log_info "Rebuild active with --update: Running DNF distro-sync to repair package drift..."
                dnf "${DNF_RETRY_OPTIONS[@]}" distro-sync ${AUTO_YES:+$AUTO_YES} --skip-unavailable || log_warn "DNF distro-sync reported warnings."
            fi
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
            deb_update+=(full-upgrade)
            if [[ -n "$DOWNLOAD_ONLY" ]]; then deb_update+=("$DOWNLOAD_ONLY"); fi
            refresh_package_cache
            run_cmd "Updating Debian/Ubuntu packages via APT" "${deb_update[@]}" || log_warn "APT update failed."
            if [[ "$RUN_REBUILD" == true && -z "$DOWNLOAD_ONLY" ]]; then
                log_info "Rebuild active with --update: Running apt-get install -f to repair broken dependencies..."
                apt-get install -f ${AUTO_YES:+--yes} || true
            fi
            ;;
    esac
}

# Install Flatpak when needed and register Flathub for application installs.
ensure_flatpak() {
    if ! command -v flatpak &>/dev/null; then
        log_info "Flatpak not found on system. Automatically installing Flatpak support..."
        case "$DISTRO_FAMILY" in
            rpm)
                run_cmd "Installing Flatpak" dnf "${DNF_RETRY_OPTIONS[@]}" install ${AUTO_YES:+$AUTO_YES} flatpak || log_warn "Flatpak install failed."
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

# Install a Flathub app, optionally trying a legacy app ID if the primary ID is unavailable.
install_flatpak_app() {
    local app="$1"
    local fallback="${2:-}"
    ensure_flatpak
    local fp_flags=()
    if [[ "$AUTO_YES" == "-y" ]]; then fp_flags+=(--assumeyes); fi
    if [[ "$RUN_REINSTALL" == true ]]; then fp_flags+=(--reinstall); fi

    if flatpak install "${fp_flags[@]}" flathub "$app" 2>/dev/null; then
        log_success "Flatpak app installed: $app"
        return 0
    elif [[ -n "$fallback" ]] && flatpak install "${fp_flags[@]}" flathub "$fallback" 2>/dev/null; then
        log_success "Flatpak app installed using legacy fallback: $fallback"
        return 0
    else
        log_warn "Skipped or failed to install Flatpak app: $app${fallback:+ (or legacy $fallback)}"
        return 0
    fi
}

# Enable a systemd service immediately, falling back to enable-only if startup fails.
service_enable() {
    local service_name="$1"
    if ! run_cmd "Enabling service: $service_name" systemctl enable --now "$service_name"; then
        systemctl enable "$service_name" 2>/dev/null || true
    fi
}

# Restart a systemd service without aborting provisioning if it is unavailable.
service_restart() {
    local service_name="$1"
    systemctl restart "$service_name" 2>/dev/null || true
}

# Replace an existing INI-style setting or append it when the file has no matching key.
set_ini_option() {
    local config_file="$1"
    local key="$2"
    local value="$3"
    local separator=" = "

    if [[ ! -f "$config_file" ]]; then
        return 0
    fi

    if [[ "$config_file" == "/etc/selinux/config" ]]; then
        separator="="
    fi

    if grep -Eq "^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*=" "$config_file"; then
        sed -i -E "s|^[[:space:]]*#?[[:space:]]*${key}[[:space:]]*=.*|${key}${separator}${value}|" "$config_file"
    else
        printf '%s%s%s\n' "$key" "$separator" "$value" >> "$config_file"
    fi
}

# Set a global sshd option once and insert missing options before any Match block.
set_sshd_option() {
    local config_file="$1"
    local option="$2"
    local value="$3"
    local tmp_file

    if [[ ! -f "$config_file" ]]; then
        return 0
    fi

    tmp_file=$(mktemp "${config_file}.XXXXXX")
    TEMP_CLEANUP_DIRS+=("$tmp_file")

    awk -v opt="$option" -v val="$value" '
        BEGIN {
            done = 0
            in_match = 0
            opt_lower = tolower(opt)
        }
        /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh]([[:space:]]|$)/ {
            if (!done) {
                print opt " " val
                done = 1
            }
            in_match = 1
        }
        {
            if (!in_match) {
                line = $0
                sub(/^[[:space:]]*#?[[:space:]]*/, "", line)
                split(line, parts, /[[:space:]]+/)
                if (tolower(parts[1]) == opt_lower) {
                    if (!done) {
                        print opt " " val
                        done = 1
                    }
                    next
                }
            }
            print $0
        }
        END {
            if (!done) {
                print opt " " val
            }
        }
    ' "$config_file" > "$tmp_file"

    chmod --reference="$config_file" "$tmp_file" 2>/dev/null || chmod 0600 "$tmp_file"
    mv -f "$tmp_file" "$config_file"
}

# Enable the multilib section and its Include directive without touching adjacent commented sections.
enable_multilib_repository() {
    local config_file="${1:-/etc/pacman.conf}"
    local tmp_file

    if [[ ! -f "$config_file" ]]; then
        return 0
    fi

    if ! grep -Eq '^[[:space:]]*#?[[:space:]]*\[multilib\][[:space:]]*$' "$config_file"; then
        printf '\n[multilib]\nInclude = /etc/pacman.d/mirrorlist\n' >> "$config_file"
        chmod 0644 "$config_file" 2>/dev/null || true
        return 0
    fi

    tmp_file=$(mktemp "${config_file}.XXXXXX")
    TEMP_CLEANUP_DIRS+=("$tmp_file")

    awk '
        BEGIN {
            in_multilib = 0
            inc_done = 0
        }
        /^[[:space:]]*#?[[:space:]]*\[multilib\][[:space:]]*$/ {
            print "[multilib]"
            in_multilib = 1
            next
        }
        /^[[:space:]]*#?[[:space:]]*\[[^]]+\][[:space:]]*$/ {
            if (in_multilib && !inc_done) {
                print "Include = /etc/pacman.d/mirrorlist"
                inc_done = 1
            }
            in_multilib = 0
        }
        {
            if (in_multilib && $0 ~ /^[[:space:]]*#?[[:space:]]*Include[[:space:]]*=/) {
                sub(/^[[:space:]]*#[[:space:]]*/, "")
                print $0
                inc_done = 1
                next
            }
            print $0
        }
        END {
            if (in_multilib && !inc_done) {
                print "Include = /etc/pacman.d/mirrorlist"
            }
        }
    ' "$config_file" > "$tmp_file"

    chmod --reference="$config_file" "$tmp_file" 2>/dev/null || chmod 0644 "$tmp_file"
    mv -f "$tmp_file" "$config_file"
}

# Display prompts on the controlling terminal instead of the asynchronous transcript pipe.
prompt_tty() {
    local prompt="$1"
    local response_variable="$2"
    local single_character="${3:-false}"

    if [[ ! -r /dev/tty || ! -w /dev/tty ]]; then
        log_error "An interactive prompt requires a controlling terminal."
        return 1
    fi

    printf '%s' "$prompt" > /dev/tty
    if [[ "$single_character" == true ]]; then
        IFS= read -r -n 1 "$response_variable" < /dev/tty
        printf '\n' > /dev/tty
    else
        IFS= read -r "$response_variable" < /dev/tty
    fi
}

# Detect and install utilities required by later provisioning routines.
bootstrap_prerequisites() {
    log_info "Checking and auto-bootstrapping required system dependencies..."
    local missing_pkgs=()

    if ! command -v curl &>/dev/null && ! command -v wget &>/dev/null; then
        missing_pkgs+=(curl)
    fi

    if ! command -v lspci &>/dev/null; then
        missing_pkgs+=(pciutils)
    fi

    if [[ ! -d /etc/ssl/certs ]] || [[ "$DISTRO_FAMILY" == "deb" && ! -f /etc/ssl/certs/ca-certificates.crt ]]; then
        missing_pkgs+=(ca-certificates)
    fi

    if ! command -v ss &>/dev/null; then
        case "$DISTRO_FAMILY" in
            rpm) missing_pkgs+=(iproute) ;;
            deb|arch|steamos|opensuse) missing_pkgs+=(iproute2) ;;
        esac
    fi

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
                dnf "${DNF_RETRY_OPTIONS[@]}" install ${AUTO_YES:+$AUTO_YES} "${missing_pkgs[@]}" || log_warn "Auto-bootstrap notice: some base packages could not be installed."
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

# Install Microsoft PowerShell from vendor repositories, with a Flathub fallback.
install_powershell() {
    if command -v pwsh &>/dev/null && [[ "$RUN_REINSTALL" != true ]]; then
        log_success "Microsoft PowerShell (pwsh) is already installed."
        return 0
    fi

    log_info "Installing Microsoft PowerShell (pwsh)..."
    case "$DISTRO_FAMILY" in
        rpm)
            if ! rpm -q powershell &>/dev/null || [[ "$RUN_REINSTALL" == true ]]; then
                log_info "Configuring Microsoft RPM repository for PowerShell..."
                rpm --import https://packages.microsoft.com/keys/microsoft.asc 2>/dev/null || true
                if curl --connect-timeout 10 --max-time 60 --retry 3 -fsSL https://packages.microsoft.com/config/rhel/9/prod.repo -o /etc/yum.repos.d/microsoft-prod.repo 2>/dev/null; then
                    chmod 0644 /etc/yum.repos.d/microsoft-prod.repo || log_warn "Could not make the Microsoft repository configuration readable to DNF."
                fi
                if ! pkg_install powershell; then
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
            if ! pkg_install powershell 2>/dev/null; then
                install_flatpak_app com.microsoft.PowerShell
            fi
            ;;
        opensuse)
            log_info "Configuring Microsoft SLES repository for openSUSE..."
            rpm --import https://packages.microsoft.com/keys/microsoft.asc 2>/dev/null || true
            zypper addrepo https://packages.microsoft.com/sles/15/prod/ microsoft-prod 2>/dev/null || true
            if ! pkg_install powershell; then
                install_flatpak_app com.microsoft.PowerShell
            fi
            ;;
        deb)
            if ! dpkg -s powershell &>/dev/null 2>&1 || [[ "$RUN_REINSTALL" == true ]]; then
                export DEBIAN_FRONTEND=noninteractive
                curl --connect-timeout 10 --max-time 60 --retry 3 -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/microsoft.gpg 2>/dev/null || true
                chmod 0644 /etc/apt/trusted.gpg.d/microsoft.gpg 2>/dev/null || true
                local deb_ver="${VERSION_ID:-22.04}"
                echo "deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-ubuntu-${deb_ver}-prod ${UBUNTU_CODENAME:-jammy} main" > /etc/apt/sources.list.d/microsoft-prod.list 2>/dev/null || true
                chmod 0644 /etc/apt/sources.list.d/microsoft-prod.list 2>/dev/null || true
                CACHE_REFRESHED=false
                if ! pkg_install powershell; then
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

# Resolve Desktop Environment interactively or via flags/environment when needed.
resolve_desktop_environment() {
    if [[ -z "${DESKTOP_ENV:-}" ]]; then
        local current_de="${XDG_CURRENT_DESKTOP:-${DESKTOP_SESSION:-}}"
        case "${current_de,,}" in
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
        local de_choice=""
        while true; do
            prompt_tty "Select Desktop Environment ([g]nome / [k]de / [c]osmic / [x]fce / c[i]nnamon): " de_choice
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
}

# Ensure a script file exists locally; if missing, download on-demand from GitHub.
ensure_remote_script() {
    local rel_path="$1"
    local target_path="$2"
    local remote_url="${GITHUB_RAW_BASE}/${rel_path}"

    if [[ -f "$target_path" ]]; then
        chmod 0755 "$target_path" 2>/dev/null || true
        return 0
    fi

    log_info "Local script '${rel_path}' not found. Downloading on-demand from GitHub..."
    mkdir -p "$(dirname "$target_path")"
    chmod 0755 "$(dirname "$target_path")" 2>/dev/null || true

    local tmp_dl="${target_path}.tmp.$$"
    TEMP_CLEANUP_DIRS+=("$tmp_dl")

    if command -v curl &>/dev/null; then
        if ! curl --connect-timeout 10 --max-time 60 --retry 3 -fsSL "$remote_url" -o "$tmp_dl"; then
            log_error "Failed to download ${rel_path} from ${remote_url}"
            return 1
        fi
    elif command -v wget &>/dev/null; then
        if ! wget -q --timeout=60 --tries=3 -O "$tmp_dl" "$remote_url"; then
            log_error "Failed to download ${rel_path} from ${remote_url}"
            return 1
        fi
    else
        log_error "Neither curl nor wget is available to fetch ${rel_path}."
        return 1
    fi

    if ! head -n 1 "$tmp_dl" | grep -q "^#!"; then
        log_error "Downloaded file for ${rel_path} did not contain a valid script header."
        rm -f "$tmp_dl" 2>/dev/null || true
        return 1
    fi

    chmod 0755 "$tmp_dl"
    mv -f "$tmp_dl" "$target_path"
    log_success "Downloaded and cached ${rel_path} -> ${target_path}"
}

# Check if a remote version of a script on GitHub differs from the local copy.
# Returns 0 if identical/up-to-date, 1 if an update exists (sets out_tmp_path), or 2 on network/error.
check_remote_script_update() {
    local rel_path="$1"
    local target_path="$2"
    local -n out_tmp_path="$3"
    local remote_url="${GITHUB_RAW_BASE}/${rel_path}"

    if [[ ! -f "$target_path" ]]; then
        return 0
    fi

    local tmp_check="${target_path}.chk.$$"
    TEMP_CLEANUP_DIRS+=("$tmp_check")

    if command -v curl &>/dev/null; then
        if ! curl --connect-timeout 4 --max-time 15 --retry 1 -fsSL "$remote_url" -o "$tmp_check" 2>/dev/null; then
            rm -f "$tmp_check" 2>/dev/null || true
            return 2
        fi
    elif command -v wget &>/dev/null; then
        if ! wget -q --timeout=15 --tries=1 -O "$tmp_check" "$remote_url" 2>/dev/null; then
            rm -f "$tmp_check" 2>/dev/null || true
            return 2
        fi
    else
        return 2
    fi

    if ! head -n 1 "$tmp_check" 2>/dev/null | grep -q "^#!"; then
        rm -f "$tmp_check" 2>/dev/null || true
        return 2
    fi

    local local_sha remote_sha
    local_sha=$(sha256sum "$target_path" 2>/dev/null | awk '{print $1}')
    remote_sha=$(sha256sum "$tmp_check" 2>/dev/null | awk '{print $1}')

    if [[ -n "$local_sha" && -n "$remote_sha" && "$local_sha" != "$remote_sha" ]]; then
        out_tmp_path="$tmp_check"
        return 1
    fi

    rm -f "$tmp_check" 2>/dev/null || true
    return 0
}

# Apply a downloaded update to target_path with 0755 permissions.
apply_script_update() {
    local rel_path="$1"
    local target_path="$2"
    local tmp_path="$3"

    if [[ -f "$tmp_path" ]]; then
        chmod 0755 "$tmp_path"
        mv -f "$tmp_path" "$target_path"
        log_success "Updated ${rel_path} to latest version from GitHub."
        return 0
    fi
    return 1
}

# ------------------------------------------------------------------------------
# MODULE DEPRECATION & REDIRECT HANDLER FRAMEWORK
# Format: "deprecated_flag|old_module_file|replacement_flag|replacement_module_file|old_var_name|new_var_name|reason"
# To deprecate a module (for example, wrapping mod-discord.sh into mod-gaming.sh),
# uncomment or add its entry in DEPRECATED_MODULES_REGISTRY below.
# ------------------------------------------------------------------------------
DEPRECATED_MODULES_REGISTRY=(
    # "--discord|mod-discord.sh|--gaming|mod-gaming.sh|RUN_DISCORD|RUN_GAMING|Discord provisioning has been wrapped into the Gaming module"
)

if [[ -n "${LDT_DEPRECATED_MODULES:-}" ]]; then
    IFS=';' read -r -a _extra_deprecations <<< "$LDT_DEPRECATED_MODULES"
    for _entry in "${_extra_deprecations[@]}"; do
        if [[ -n "$_entry" ]]; then
            DEPRECATED_MODULES_REGISTRY+=("$_entry")
        fi
    done
    unset _extra_deprecations _entry
fi

# Track modules that the user explicitly chose to keep and run as-is during this session.
KEEP_DEPRECATED_AS_IS=()

is_kept_as_is() {
    local target_mod="$1"
    local item
    if [[ -n "${KEEP_DEPRECATED_AS_IS[*]:-}" ]]; then
        for item in "${KEEP_DEPRECATED_AS_IS[@]}"; do
            if [[ "$item" == "$target_mod" ]]; then
                return 0
            fi
        done
    fi
    return 1
}

# Write a lightweight 0755 redirect stub to replace a deprecated local module script.
write_deprecated_module_stub() {
    local target_path="$1"
    local old_mod="$2"
    local new_mod="$3"
    local old_flag="$4"
    local new_flag="$5"
    local reason="$6"

    cat <<EOF > "$target_path"
#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# DEPRECATED_MODULE_STUB=true
# Deprecated stub for ${old_mod} (${old_flag}) -> Redirects to ${new_mod} (${new_flag})
set -euo pipefail
umask 0022

SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
SUITE_ROOT="\$(cd "\${SCRIPT_DIR}/.." &>/dev/null && pwd)"
COMMON_LIB_PATH="\${SUITE_ROOT}/lib/common.sh"

if [[ -f "\$COMMON_LIB_PATH" ]]; then
    # shellcheck disable=SC1090
    source "\$COMMON_LIB_PATH"
else
    echo -e "\e[31m[ERROR] Shared library (lib/common.sh) not found at \$COMMON_LIB_PATH\e[0m" >&2
    exit 1
fi

handle_deprecated_module_stub "${old_mod}" "${new_mod}" "${old_flag}" "${new_flag}" "${reason}" "\$@"
EOF
    chmod 0755 "$target_path" 2>/dev/null || true
}

# Handle execution when a deprecated module stub is invoked directly or sourced.
handle_deprecated_module_stub() {
    local old_mod="$1"
    local new_mod="$2"
    local old_flag="$3"
    local new_flag="$4"
    local reason="$5"
    shift 5

    echo -e "\n\e[33m==============================================================="
    echo -e "[!] DEPRECATION NOTICE: '${old_mod}' (${old_flag}) is deprecated."
    echo -e "    Reason:      ${reason}"
    echo -e "    Replacement: '${new_mod}' (${new_flag})"
    echo -e "===============================================================\e[0m"

    local run_replacement=false
    if [[ "${UNATTENDED:-false}" == true || "${AUTO_YES:-}" == "-y" ]]; then
        log_info "Unattended / -y mode: Automatically redirecting '${old_mod}' to '${new_mod}'."
        run_replacement=true
    elif [[ -r /dev/tty && -w /dev/tty ]]; then
        local reply=""
        prompt_tty "Run replacement module '${new_mod}' (${new_flag}) instead? ([y]es redirect / [n]o abort): " reply true
        if [[ "$reply" =~ ^[Yy]$ ]]; then
            run_replacement=true
        else
            log_info "Execution of deprecated module '${old_mod}' aborted by user."
            return 0
        fi
    else
        log_warn "Non-interactive terminal: Skipping deprecated module '${old_mod}'."
        return 0
    fi

    if [[ "$run_replacement" == true ]]; then
        local suite_root="${SUITE_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)}"
        local new_mod_path="${suite_root}/modules/${new_mod}"
        ensure_remote_script "modules/${new_mod}" "$new_mod_path"
        # shellcheck disable=SC1090
        source "$new_mod_path" "$@"
    fi
}

# Check active CLI flags against DEPRECATED_MODULES_REGISTRY.
# Prompts the user to redirect to the replacement module, abort redirect & run local as-is, or skip.
resolve_deprecated_flags() {
    local suite_root="$1"
    if [[ ${#DEPRECATED_MODULES_REGISTRY[@]} -eq 0 ]]; then
        return 0
    fi

    local entry old_flag old_mod new_flag new_mod old_var new_var reason
    for entry in "${DEPRECATED_MODULES_REGISTRY[@]}"; do
        IFS='|' read -r old_flag old_mod new_flag new_mod old_var new_var reason <<< "$entry"
        if [[ -z "$old_var" || "${!old_var:-false}" != true ]]; then
            continue
        fi

        # If triggered implicitly via --all and the replacement is already enabled, check if old_flag was explicitly requested
        local explicitly_passed=false
        local arg
        if [[ -n "${ORIGINAL_ARGS[*]:-}" ]]; then
            for arg in "${ORIGINAL_ARGS[@]}"; do
                if [[ "$arg" == "$old_flag" ]]; then
                    explicitly_passed=true
                    break
                fi
            done
        fi

        if [[ "${RUN_ALL:-false}" == true && "$explicitly_passed" == false && "${!new_var:-false}" == true ]]; then
            log_info "Note: '${old_mod}' (${old_flag}) is deprecated (${reason}); skipping redundant call in --all since '${new_mod}' is active."
            printf -v "$old_var" '%s' "false"
            continue
        fi

        echo -e "\n\e[33m==============================================================="
        echo -e "[!] DEPRECATION NOTICE: Flag '${old_flag}' (${old_mod}) is deprecated."
        echo -e "    Reason:      ${reason}"
        echo -e "    Replacement: '${new_flag}' (${new_mod})"
        echo -e "===============================================================\e[0m"

        local local_old_path="${suite_root}/modules/${old_mod}"
        local has_full_local_script=false
        if [[ -f "$local_old_path" ]] && ! grep -q "DEPRECATED_MODULE_STUB=true" "$local_old_path" 2>/dev/null; then
            has_full_local_script=true
        fi

        if [[ "${UNATTENDED:-false}" == true || "${AUTO_YES:-}" == "-y" ]]; then
            log_warn "Unattended / -y mode: Automatically redirecting deprecated '${old_flag}' to '${new_flag}' (${new_mod})."
            printf -v "$old_var" '%s' "false"
            printf -v "$new_var" '%s' "true"
        elif [[ -r /dev/tty && -w /dev/tty ]]; then
            local choice=""
            if [[ "$has_full_local_script" == true ]]; then
                prompt_tty "Select action: [y] Redirect to ${new_flag} / [a] Abort redirect & run local ${old_mod} as-is / [s] Skip module: " choice true
                case "$choice" in
                    [Yy])
                        log_info "Redirecting '${old_flag}' -> '${new_flag}' (${new_mod})."
                        printf -v "$old_var" '%s' "false"
                        printf -v "$new_var" '%s' "true"
                        ;;
                    [Aa])
                        log_info "Redirect aborted by user. Running existing local 'modules/${old_mod}' as-is..."
                        printf -v "$old_var" '%s' "true"
                        KEEP_DEPRECATED_AS_IS+=("$old_mod")
                        ;;
                    *)
                        log_info "Skipping deprecated module '${old_mod}'."
                        printf -v "$old_var" '%s' "false"
                        ;;
                esac
            else
                prompt_tty "Select action: [y] Redirect to ${new_flag} (${new_mod}) / [s] Skip module: " choice true
                case "$choice" in
                    [Yy])
                        log_info "Redirecting '${old_flag}' -> '${new_flag}' (${new_mod})."
                        printf -v "$old_var" '%s' "false"
                        printf -v "$new_var" '%s' "true"
                        ;;
                    *)
                        log_info "Skipping deprecated module '${old_mod}'."
                        printf -v "$old_var" '%s' "false"
                        ;;
                esac
            fi
        else
            log_warn "Non-interactive environment: Redirecting deprecated '${old_flag}' to '${new_flag}'."
            printf -v "$old_var" '%s' "false"
            printf -v "$new_var" '%s' "true"
        fi
    done
}

# Inspect ./modules/ for deprecated local script files and offer to remove, stub, or keep as-is.
check_deprecated_local_modules() {
    local suite_root="$1"
    if [[ ${#DEPRECATED_MODULES_REGISTRY[@]} -eq 0 ]]; then
        return 0
    fi

    local entry old_flag old_mod new_flag new_mod old_var new_var reason
    for entry in "${DEPRECATED_MODULES_REGISTRY[@]}"; do
        IFS='|' read -r old_flag old_mod new_flag new_mod old_var new_var reason <<< "$entry"
        local local_old_path="${suite_root}/modules/${old_mod}"

        if [[ ! -f "$local_old_path" ]]; then
            continue
        fi

        # Skip if already converted to a lightweight redirect stub or if user chose to keep as-is
        if grep -q "DEPRECATED_MODULE_STUB=true" "$local_old_path" 2>/dev/null; then
            continue
        fi
        if is_kept_as_is "$old_mod"; then
            continue
        fi

        echo -e "\n\e[33m[!] Deprecated local module file detected: modules/${old_mod}\e[0m"
        echo -e "    Superseded by: modules/${new_mod} (${new_flag}) — ${reason}"

        if [[ "${UNATTENDED:-false}" == true || "${AUTO_YES:-}" == "-y" ]]; then
            log_info "Unattended / -y mode: Replacing deprecated 'modules/${old_mod}' with lightweight redirect stub."
            write_deprecated_module_stub "$local_old_path" "$old_mod" "$new_mod" "$old_flag" "$new_flag" "$reason"
        elif [[ -r /dev/tty && -w /dev/tty ]]; then
            local file_action=""
            prompt_tty "Select action for 'modules/${old_mod}': [r]emove file / [s]tub with redirect / [k]eep & run as-is: " file_action true
            case "$file_action" in
                [Rr])
                    rm -f "$local_old_path" 2>/dev/null || true
                    log_success "Removed deprecated local module file: modules/${old_mod}"
                    ;;
                [Ss])
                    write_deprecated_module_stub "$local_old_path" "$old_mod" "$new_mod" "$old_flag" "$new_flag" "$reason"
                    log_success "Replaced 'modules/${old_mod}' with a lightweight redirect stub to '${new_mod}'."
                    ;;
                *)
                    log_info "Keeping existing local 'modules/${old_mod}' as-is."
                    KEEP_DEPRECATED_AS_IS+=("$old_mod")
                    ;;
            esac
        fi
    done
}

# Initialize a child module when invoked directly as a standalone script.
init_standalone_module() {
    local module_name="$1"
    shift

    if [[ "${ORCHESTRATED_RUN:-false}" == true ]]; then
        return 0
    fi

    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --reinstall) RUN_REINSTALL=true ;;
            --rebuild) RUN_REBUILD=true; RUN_REINSTALL=true ;;
            --debug) RUN_DEBUG=true ;;
            --unattended) UNATTENDED=true ;;
            --2fa|--mfa) RUN_2FA=true ;;
            --atomic|--silverblue) DISTRO_OVERRIDE="atomic" ;;
            --bazzite) DISTRO_OVERRIDE="bazzite" ;;
            --arch) DISTRO_OVERRIDE="arch" ;;
            --steamos) DISTRO_OVERRIDE="steamos" ;;
            --opensuse|--suse) DISTRO_OVERRIDE="opensuse" ;;
            --distro=*) DISTRO_OVERRIDE="${1#*=}" ;;
            --distro) shift; DISTRO_OVERRIDE="${1:-}" ;;
            --gnome) DESKTOP_ENV="GNOME" ;;
            --kde|--plasma) DESKTOP_ENV="KDE" ;;
            --cosmic) DESKTOP_ENV="COSMIC" ;;
            --xfce) DESKTOP_ENV="XFCE" ;;
            --cinnamon) DESKTOP_ENV="CINNAMON" ;;
            --de=*) DESKTOP_ENV="${1#*=}" ;;
            --de) shift; DESKTOP_ENV="${1^^}" ;;
            -y) AUTO_YES="-y" ;;
            -d) DOWNLOAD_ONLY_REQUESTED=true ;;
            --help|-h)
                echo "Usage: sudo ./${module_name} [--reinstall] [--rebuild] [-y] [-d] [--unattended] [--distro=<name>] [--de=<name>]"
                exit 0
                ;;
            *)
                log_warn "Ignoring unrecognized standalone option: $1"
                ;;
        esac
        shift
    done

    if [[ "$EUID" -ne 0 ]]; then
        log_error "Administrator permissions are required. Please run ${module_name} with sudo."
        exit 1
    fi

    detect_distro

    if [[ "$DOWNLOAD_ONLY_REQUESTED" == true ]]; then
        if [[ "$DISTRO_FAMILY" == "deb" ]]; then
            DOWNLOAD_ONLY="--download-only"
        else
            DOWNLOAD_ONLY="--downloadonly"
        fi
    fi

    if [[ "$UNATTENDED" == true ]]; then
        AUTO_YES="-y"
    fi

    if [[ "$RUN_DEBUG" == true ]]; then
        set -x
    fi

    bootstrap_prerequisites
}
