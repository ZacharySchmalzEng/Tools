#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ==============================================================================
# SYNOPSIS
#     Automated Linux provisioning and environment setup orchestrator (Modular Beta).
#
# DESCRIPTION
#     Main top-level runner for the v3.0-beta Modular Linux Deployment Tool.
#     Positioned at the top of the ./Beta directory so the Beta directory can be
#     downloaded as a simple tarball or fetched as a single runner script that
#     downloads missing child modules into ./lib/ and ./modules/ on-demand from
#     GitHub only when their applicable flags are called.
#
# AUTHOR
#     Zachary Schmalz
#     Repository:      https://github.com/ZacharySchmalzEng/Tools/
#     Issues/Requests: https://github.com/ZacharySchmalzEng/Tools/issues
#
# NOTES
#     Version:        3.0-beta
#     Branch:         beta/modular-v3
#     Requirements:   Bash, root/sudo privileges, active internet connection.
#     Supported OS:   Fedora, Nobara, Fedora Atomic (Silverblue/Bazzite),
#                     Arch Linux, SteamOS, openSUSE (Tumbleweed/Leap), Debian/Ubuntu.
#     Changelog:      See CHANGELOG.md for full version history, security
#                     mitigations, defect resolutions, and feature updates.
# ==============================================================================

set -euo pipefail
umask 077

# ------------------------------------------------------------------------------
# 1. DIRECTORY RESOLUTION & SHARED LIBRARY BOOTSTRAP
# Locate or download lib/common.sh relative to the top of the ./Beta directory.
# ------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
readonly SCRIPT_DIR
readonly SUITE_ROOT="${SCRIPT_DIR}"

GITHUB_RAW_BASE="${LDT_REPO_BASE_URL:-https://raw.githubusercontent.com/ZacharySchmalzEng/Tools/beta/modular-v3/Linux/Provisioning/Linux-Deployment-Tool/Beta}"
COMMON_LIB_PATH="${SUITE_ROOT}/lib/common.sh"

bootstrap_common_library() {
    if [[ -f "$COMMON_LIB_PATH" ]]; then
        chmod 0700 "$COMMON_LIB_PATH" 2>/dev/null || true
        # shellcheck disable=SC1090
        source "$COMMON_LIB_PATH"
        return 0
    fi

    echo -e "\e[36m[INFO] Shared core library (lib/common.sh) not found locally. Downloading on-demand from GitHub...\e[0m"
    mkdir -p "$(dirname "$COMMON_LIB_PATH")"
    chmod 0700 "$(dirname "$COMMON_LIB_PATH")" 2>/dev/null || true

    local tmp_lib="${COMMON_LIB_PATH}.tmp.$$"
    if command -v curl &>/dev/null; then
        if ! curl --connect-timeout 10 --max-time 60 --retry 3 -fsSL "${GITHUB_RAW_BASE}/lib/common.sh" -o "$tmp_lib"; then
            echo -e "\e[31m[ERROR] Failed to download lib/common.sh from ${GITHUB_RAW_BASE}/lib/common.sh\e[0m" >&2
            rm -f "$tmp_lib" 2>/dev/null || true
            exit 1
        fi
    elif command -v wget &>/dev/null; then
        if ! wget -q --timeout=60 --tries=3 -O "$tmp_lib" "${GITHUB_RAW_BASE}/lib/common.sh"; then
            echo -e "\e[31m[ERROR] Failed to download lib/common.sh from ${GITHUB_RAW_BASE}/lib/common.sh\e[0m" >&2
            rm -f "$tmp_lib" 2>/dev/null || true
            exit 1
        fi
    else
        echo -e "\e[31m[ERROR] Neither curl nor wget is available to download lib/common.sh.\e[0m" >&2
        exit 1
    fi

    chmod 0700 "$tmp_lib"
    mv -f "$tmp_lib" "$COMMON_LIB_PATH"
    # shellcheck disable=SC1090
    source "$COMMON_LIB_PATH"
}

bootstrap_common_library

# ------------------------------------------------------------------------------
# 2. HELP & USAGE MENU
# ------------------------------------------------------------------------------
print_usage() {
    echo -e "\n==============================================================="
    echo -e " Linux Provisioning & Deployment Environment Setup Script (v3.0-beta)"
    echo -e " Top-of-Beta Modular Runner (Tarball & On-Demand GitHub Modules)"
    echo -e "==============================================================="
    echo "Usage: sudo ./Linux-Deployment-Tool.sh [Options]"
    echo ""
    echo "MODULE OPTIONS (Each maps to ./modules/mod-<name>.sh):"
    echo "  --update            Upgrades system packages, Flatpak, and Snap (mod-update.sh)"
    echo "  --apps              Installs core QoL utilities & Flatpak apps (mod-apps.sh)"
    echo "  --devapps           Installs Dev tools: Git, jq, fzf, VS Code, pwsh (mod-devapps.sh)"
    echo "  --cyber             Installs Security tools: Wireshark, Nmap, TCPDump (mod-cyber.sh)"
    echo "  --sysadmin          Installs Sysadmin & network/storage diagnostics (mod-sysadmin.sh)"
    echo "  --maker             Installs 3D Printing Slicers: Prusa, Orca, Bambu (mod-maker.sh)"
    echo "  --creators          Installs Creative suite: GIMP, Krita, Blender, OBS (mod-creators.sh)"
    echo "  --gaming            Configures Steam, Lutris, Repos & GPU Drivers (mod-gaming.sh)"
    echo "  --ssh               Installs, enables, and verifies OpenSSH Server (mod-ssh.sh)"
    echo "  --discord           Configures Discord: Native RPM or Flatpak (mod-discord.sh)"
    echo ""
    echo "DISTRIBUTION OVERRIDES (Auto-detected if omitted):"
    echo "  --atomic            Force Fedora Atomic (Silverblue/Kinoite) rpm-ostree mode"
    echo "  --bazzite           Force Bazzite (Fedora Atomic Gaming) mode"
    echo "  --silverblue        Alias for --atomic"
    echo "  --arch              Force Arch Linux pacman mode"
    echo "  --steamos           Force SteamOS mode (Steam Deck immutable root toggle)"
    echo "  --opensuse          Force openSUSE (Tumbleweed/Leap) zypper mode"
    echo "  --distro=<name>     Explicit distribution override (atomic|bazzite|arch|steamos|opensuse|nobara|rpm|deb)"
    echo ""
    echo "DESKTOP ENVIRONMENT OVERRIDES (Auto-detected if omitted):"
    echo "  --gnome             Target GNOME desktop environment and QoL tools"
    echo "  --kde               Target KDE Plasma desktop environment and QoL tools"
    echo "  --cosmic            Target COSMIC desktop environment (System76) and tools"
    echo "  --xfce              Target XFCE desktop environment and utilities"
    echo "  --cinnamon          Target Cinnamon desktop environment and utilities"
    echo "  --de=<name>         Explicit desktop environment override (gnome|kde|cosmic|xfce|cinnamon)"
    echo ""
    echo "SECURITY & HARDENING:"
    echo "  --harden            Safe baseline: SELinux/AppArmor, Auto-Patching, CIS SSH (mod-harden.sh)"
    echo "  --harden-advanced   Strict: auditd, Sysctl network drops, No Password SSH (mod-harden-adv.sh)"
    echo "  --2fa               Modifies the --ssh module to enforce Google Auth MFA"
    echo ""
    echo "GLOBAL OPTIONS:"
    echo "  --all               Executes ALL standard modules (Excludes harden-advanced)"
    echo "  --reinstall         Reinstalls packages selected by other modules where supported"
    echo "  --rebuild           Reinstalls packages and rebuilds supported GPU modules/initramfs"
    echo "  -y                  Auto-install (answers yes to prompts)"
    echo "  -d                  Download only (applies to DNF/APT updates)"
    echo "  --debug             Enables command tracing (set -x) for troubleshooting"
    echo "  --unattended        Bypasses prompts, defaults to KDE, and auto-answers yes"
    echo "  --help              Displays this help menu"
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
RUN_SYSADMIN=false
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
DOWNLOAD_ONLY_REQUESTED=false
RUN_REINSTALL=false
RUN_REBUILD=false

if [[ "$#" -eq 0 ]]; then
    print_usage
    exit 0
fi

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --all) RUN_ALL=true ;;
        --update) RUN_UPDATE=true ;;
        --apps) RUN_APPS=true ;;
        --devapps) RUN_DEVAPPS=true ;;
        --cyber) RUN_CYBER=true ;;
        --sysadmin) RUN_SYSADMIN=true ;;
        --maker) RUN_MAKER=true ;;
        --creators) RUN_CREATORS=true ;;
        --gaming) RUN_GAMING=true ;;
        --ssh) RUN_SSH=true ;;
        --2fa|--mfa) RUN_2FA=true ;;
        --discord) RUN_DISCORD=true ;;
        --harden) RUN_HARDEN=true ;;
        --harden-advanced) RUN_HARDEN_ADV=true ;;
        --reinstall) RUN_REINSTALL=true ;;
        --rebuild) RUN_REBUILD=true; RUN_REINSTALL=true ;;
        --debug) RUN_DEBUG=true ;;
        --unattended) UNATTENDED=true ;;
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
                *) DESKTOP_ENV="${1:-}" ;;
            esac
            ;;
        -y) AUTO_YES="-y" ;;
        -d) DOWNLOAD_ONLY_REQUESTED=true ;;
        --help|-h) print_usage; exit 0 ;;
        *) log_error "Unknown parameter passed: $1"; print_usage; exit 1 ;;
    esac
    shift
done

detect_distro

if [[ "$DOWNLOAD_ONLY_REQUESTED" == true ]]; then
    if [[ "$DISTRO_FAMILY" == "deb" ]]; then
        DOWNLOAD_ONLY="--download-only"
    else
        DOWNLOAD_ONLY="--downloadonly"
    fi
fi

if [[ "$RUN_ALL" == true ]]; then
    RUN_UPDATE=true; RUN_APPS=true; RUN_DEVAPPS=true; RUN_CYBER=true; RUN_SYSADMIN=true;
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

log_success "Running with root privileges (v3.0-beta Modular Orchestrator)."
log_info "Logging execution to: $LOG_FILE"

if [[ "$RUN_REBUILD" == true ]]; then
    log_warn "Deep Recovery Mode (--rebuild) is ACTIVE. Rebuilding supported GPU modules and initramfs images."
elif [[ "$RUN_REINSTALL" == true ]]; then
    log_info "Safe Reinstall Mode (--reinstall) is ACTIVE. Refreshing packages via native managers."
fi

bootstrap_prerequisites

# ------------------------------------------------------------------------------
# 5. INTERACTIVE PROMPTS & DESKTOP ENVIRONMENT CONFIGURATION
# ------------------------------------------------------------------------------
if [[ "$RUN_APPS" == true || -n "${DESKTOP_ENV:-}" ]]; then
    resolve_desktop_environment
fi

if [[ "$RUN_HARDEN_ADV" == true && "$UNATTENDED" != true ]]; then
    echo -e "\n\e[31m[!] WARNING: Advanced hardening will disable SSH password authentication."
    echo -e "    Ensure you have an SSH Key provisioned before disconnecting.\e[0m"
    acknowledged=""
    prompt_tty "    Press Enter to acknowledge and continue..." acknowledged
fi

# ------------------------------------------------------------------------------
# 6. ON-DEMAND MODULE DISPATCHER
# Only downloads and executes child scripts whose flags were explicitly enabled.
# ------------------------------------------------------------------------------
export ORCHESTRATED_RUN=true
export COMMON_LIB_LOADED=true

run_module_if_enabled() {
    local enabled_flag="$1"
    local module_script="$2"

    if [[ "$enabled_flag" != true ]]; then
        return 0
    fi

    local local_module_path="${SUITE_ROOT}/modules/${module_script}"
    ensure_remote_script "modules/${module_script}" "$local_module_path"
    # shellcheck disable=SC1090
    source "$local_module_path"
}

run_module_if_enabled "$RUN_UPDATE"     "mod-update.sh"
run_module_if_enabled "$RUN_APPS"       "mod-apps.sh"
run_module_if_enabled "$RUN_DEVAPPS"    "mod-devapps.sh"
run_module_if_enabled "$RUN_SYSADMIN"   "mod-sysadmin.sh"
run_module_if_enabled "$RUN_CYBER"      "mod-cyber.sh"
run_module_if_enabled "$RUN_MAKER"      "mod-maker.sh"
run_module_if_enabled "$RUN_CREATORS"   "mod-creators.sh"
run_module_if_enabled "$RUN_HARDEN"     "mod-harden.sh"
run_module_if_enabled "$RUN_HARDEN_ADV" "mod-harden-adv.sh"
run_module_if_enabled "$RUN_SSH"        "mod-ssh.sh"
run_module_if_enabled "$RUN_DISCORD"    "mod-discord.sh"
run_module_if_enabled "$RUN_GAMING"     "mod-gaming.sh"

# ------------------------------------------------------------------------------
# 7. WRAP UP & REBOOT
# ------------------------------------------------------------------------------
if [[ "$RUN_DEBUG" == true ]]; then
    set +x
fi

echo -e "\n==============================================================="
log_success "Execution of selected modular child scripts is complete!"
log_info "Log file is saved at: $LOG_FILE"
echo -e "===============================================================\n"

if [[ "$UNATTENDED" == true ]]; then
    log_warn "Unattended mode: Skipping interactive reboot prompt. Please restart manually."
elif [[ -r /dev/tty && -w /dev/tty ]]; then
    REPLY=""
    prompt_tty "A reboot is recommended to apply kernel updates and drivers. Reboot now? (y/n): " REPLY true
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_warn "Rebooting system..."
        reboot
    else
        log_info "Reboot skipped. Please restart your computer manually later."
    fi
fi
