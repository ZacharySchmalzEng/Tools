#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ==============================================================================
# SYNOPSIS
#     Automated Linux provisioning and environment setup orchestrator (Modular Beta).
#
# DESCRIPTION
#     Main top-level runner for the v3.1.0-beta Modular Linux Deployment Tool.
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
#     Version:        3.1.0-beta
#     Branch:         main
#     Requirements:   Bash, root/sudo privileges, active internet connection.
#     Supported OS:   Fedora, Nobara, Fedora Atomic (Silverblue/Bazzite),
#                     Arch Linux, SteamOS, openSUSE (Tumbleweed/Leap), Debian/Ubuntu.
#     Changelog:      See ./CHANGELOG.md for full version history, security
#                     mitigations, defect resolutions, and feature updates.
# ==============================================================================

set -euo pipefail
umask 0022

# ------------------------------------------------------------------------------
# 1. DIRECTORY RESOLUTION & SHARED LIBRARY BOOTSTRAP
# Locate or download lib/common.sh relative to the top of the ./Beta directory.
# ------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
readonly SCRIPT_DIR
readonly SUITE_ROOT="${SCRIPT_DIR}"

GITHUB_RAW_BASE="${LDT_REPO_BASE_URL:-https://raw.githubusercontent.com/ZacharySchmalzEng/Tools/main/Linux/Provisioning/Linux-Deployment-Tool/Beta}"
COMMON_LIB_PATH="${SUITE_ROOT}/lib/common.sh"

bootstrap_common_library() {
    if [[ -f "$COMMON_LIB_PATH" ]]; then
        chmod 0755 "$COMMON_LIB_PATH" 2>/dev/null || true
        # shellcheck disable=SC1090
        source "$COMMON_LIB_PATH"
        return 0
    fi

    echo -e "\e[36m[INFO] Shared core library (lib/common.sh) not found locally. Downloading on-demand from GitHub...\e[0m"
    mkdir -p "$(dirname "$COMMON_LIB_PATH")"
    chmod 0755 "$(dirname "$COMMON_LIB_PATH")" 2>/dev/null || true

    local tmp_lib="${COMMON_LIB_PATH}.tmp.$$"
    if command -v curl &>/dev/null; then
        if ! curl --connect-timeout 10 --max-time 60 --retry 3 -fsSL "${GITHUB_RAW_BASE}/lib/common.sh" -o "$tmp_lib"; then
            echo -e "\e[31m[ERROR] Failed to download lib/common.sh from ${GITHUB_RAW_BASE}/lib/common.sh\e[0m" >&2
            echo -e "\e[33m[!] Note: If branch 'main' has not yet been pushed to GitHub, either:\e[0m" >&2
            echo -e "    1. Push the local branch: 'git push origin main'" >&2
            echo -e "    2. Download the full tarball containing lib/ and modules/: 'Linux-Deployment-Tool-Beta.tar.gz'" >&2
            echo -e "    3. Or override the base URL via: 'export LDT_REPO_BASE_URL=\"<url>\"'\n" >&2
            rm -f "$tmp_lib" 2>/dev/null || true
            exit 1
        fi
    elif command -v wget &>/dev/null; then
        if ! wget -q --timeout=60 --tries=3 -O "$tmp_lib" "${GITHUB_RAW_BASE}/lib/common.sh"; then
            echo -e "\e[31m[ERROR] Failed to download lib/common.sh from ${GITHUB_RAW_BASE}/lib/common.sh\e[0m" >&2
            echo -e "\e[33m[!] Note: If branch 'main' has not yet been pushed to GitHub, either:\e[0m" >&2
            echo -e "    1. Push the local branch: 'git push origin main'" >&2
            echo -e "    2. Download the full tarball containing lib/ and modules/: 'Linux-Deployment-Tool-Beta.tar.gz'" >&2
            echo -e "    3. Or override the base URL via: 'export LDT_REPO_BASE_URL=\"<url>\"'\n" >&2
            rm -f "$tmp_lib" 2>/dev/null || true
            exit 1
        fi
    else
        echo -e "\e[31m[ERROR] Neither curl nor wget is available to download lib/common.sh.\e[0m" >&2
        exit 1
    fi

    if ! head -n 1 "$tmp_lib" 2>/dev/null | grep -q "^#!"; then
        echo -e "\e[31m[ERROR] Downloaded file for lib/common.sh did not contain a valid script header.\e[0m" >&2
        rm -f "$tmp_lib" 2>/dev/null || true
        exit 1
    fi

    chmod 0755 "$tmp_lib"
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
    echo -e " Linux Provisioning & Deployment Environment Setup Script (v3.1.0-beta)"
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
    echo "  --gaming            Configures Steam, Lutris, Discord, Repos & GPU Drivers (mod-gaming.sh)"
    echo "  --ssh               Installs, enables, and verifies OpenSSH Server (mod-ssh.sh)"
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
    echo "  --no-update-check   Bypasses the automatic GitHub startup update check"
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
NO_UPDATE_CHECK=false

if [[ "$#" -eq 0 ]]; then
    print_usage
    exit 0
fi

ORIGINAL_ARGS=("$@")

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
        --no-update-check) NO_UPDATE_CHECK=true ;;
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
    RUN_HARDEN=true;
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
chmod 0777 "$LOG_DIR" 2>/dev/null || true

readonly TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
readonly LOG_FILE="${LOG_DIR}/installer_log_${TIMESTAMP}.log"
touch "$LOG_FILE" && chmod 0666 "$LOG_FILE" 2>/dev/null || true

exec > >(tee -i "$LOG_FILE") 2>&1

if [[ "$RUN_DEBUG" == true ]]; then
    log_warn "Debug mode enabled. Command tracing (set -x) is active."
    set -x
fi

log_success "Running with root privileges (v3.1.0-beta Modular Orchestrator)."
log_info "Logging execution to: $LOG_FILE"

if [[ "$RUN_REBUILD" == true ]]; then
    log_warn "Deep Recovery Mode (--rebuild) is ACTIVE. Rebuilding supported GPU modules and initramfs images."
elif [[ "$RUN_REINSTALL" == true ]]; then
    log_info "Safe Reinstall Mode (--reinstall) is ACTIVE. Refreshing packages via native managers."
fi

bootstrap_prerequisites

# ------------------------------------------------------------------------------
# 5. DEPRECATION RESOLUTION, GITHUB UPDATE DETECTION & SELF-UPDATING
# Resolves deprecated flags, checks if newer versions of the runner, shared library,
# or invoked child modules exist on GitHub, and prompts the user to update or abort
# updates and run existing local scripts as-is.
# ------------------------------------------------------------------------------
ABORTED_UPDATES_RUN_AS_IS=false

resolve_deprecated_flags "$SUITE_ROOT"

check_and_prompt_github_updates() {
    if [[ "$NO_UPDATE_CHECK" == true ]]; then
        log_info "Update check bypassed via --no-update-check."
        return 0
    fi

    log_info "Checking GitHub for script updates..."
    local candidate_files=()
    local candidate_targets=()
    local candidate_tmps=()

    # Scope 1: Main runner itself
    local runner_rel="Linux-Deployment-Tool.sh"
    local runner_target="${SCRIPT_DIR}/Linux-Deployment-Tool.sh"
    local tmp_runner=""
    if check_remote_script_update "$runner_rel" "$runner_target" tmp_runner; then
        :
    elif [[ $? -eq 1 && -n "$tmp_runner" ]]; then
        candidate_files+=("$runner_rel")
        candidate_targets+=("$runner_target")
        candidate_tmps+=("$tmp_runner")
    fi

    # Scope 2: Shared core library
    local lib_rel="lib/common.sh"
    local lib_target="${SUITE_ROOT}/lib/common.sh"
    local tmp_lib=""
    if check_remote_script_update "$lib_rel" "$lib_target" tmp_lib; then
        :
    elif [[ $? -eq 1 && -n "$tmp_lib" ]]; then
        candidate_files+=("$lib_rel")
        candidate_targets+=("$lib_target")
        candidate_tmps+=("$tmp_lib")
    fi

    # Scope 3: Invoked child modules
    check_mod() {
        local enabled="$1"
        local mod_name="$2"
        if [[ "$enabled" != true ]]; then return 0; fi
        if is_kept_as_is "$mod_name"; then
            log_info "Skipping remote update check for '${mod_name}' (running local copy as-is)."
            return 0
        fi
        local mod_rel="modules/${mod_name}"
        local mod_target="${SUITE_ROOT}/modules/${mod_name}"
        local tmp_m=""
        if check_remote_script_update "$mod_rel" "$mod_target" tmp_m; then
            :
        elif [[ $? -eq 1 && -n "$tmp_m" ]]; then
            candidate_files+=("$mod_rel")
            candidate_targets+=("$mod_target")
            candidate_tmps+=("$tmp_m")
        fi
    }

    check_mod "$RUN_UPDATE"     "mod-update.sh"
    check_mod "$RUN_APPS"       "mod-apps.sh"
    check_mod "$RUN_DEVAPPS"    "mod-devapps.sh"
    check_mod "$RUN_SYSADMIN"   "mod-sysadmin.sh"
    check_mod "$RUN_CYBER"      "mod-cyber.sh"
    check_mod "$RUN_MAKER"      "mod-maker.sh"
    check_mod "$RUN_CREATORS"   "mod-creators.sh"
    check_mod "$RUN_HARDEN"     "mod-harden.sh"
    check_mod "$RUN_HARDEN_ADV" "mod-harden-adv.sh"
    check_mod "$RUN_SSH"        "mod-ssh.sh"
    check_mod "$RUN_DISCORD"    "mod-discord.sh"
    check_mod "$RUN_GAMING"     "mod-gaming.sh"

    if [[ ${#candidate_files[@]} -eq 0 ]]; then
        log_success "All scripts are up-to-date with GitHub."
        return 0
    fi

    echo -e "\n\e[33m==============================================================="
    echo -e "[!] Upstream updates from GitHub are available for ${#candidate_files[@]} script(s):"
    for f in "${candidate_files[@]}"; do
        echo -e "    • ${f}"
    done
    echo -e "===============================================================\e[0m"

    local apply_update=false
    if [[ "$UNATTENDED" == true || "$AUTO_YES" == "-y" ]]; then
        log_info "Unattended / -y mode: Automatically applying available updates."
        apply_update=true
    elif [[ -r /dev/tty && -w /dev/tty ]]; then
        local user_reply=""
        prompt_tty "Select action: [y] Update now / [n] Abort updates & run as-is / [q] Quit: " user_reply true
        case "$user_reply" in
            [Yy])
                apply_update=true
                ;;
            [Qq])
                rm -f "${candidate_tmps[@]}" 2>/dev/null || true
                log_warn "Execution aborted by user prior to applying updates."
                exit 0
                ;;
            *)
                rm -f "${candidate_tmps[@]}" 2>/dev/null || true
                ABORTED_UPDATES_RUN_AS_IS=true
                log_info "Updates aborted by user. Running existing local scripts as-is..."
                ;;
        esac
    else
        rm -f "${candidate_tmps[@]}" 2>/dev/null || true
        ABORTED_UPDATES_RUN_AS_IS=true
        log_info "Non-interactive environment detected without controlling terminal. Running local scripts as-is."
    fi

    if [[ "$apply_update" == true ]]; then
        local runner_was_updated=false
        local i
        for ((i=0; i<${#candidate_files[@]}; i++)); do
            apply_script_update "${candidate_files[i]}" "${candidate_targets[i]}" "${candidate_tmps[i]}"
            if [[ "${candidate_files[i]}" == "Linux-Deployment-Tool.sh" ]]; then
                runner_was_updated=true
            fi
        done

        if [[ "$runner_was_updated" == true ]]; then
            log_warn "Main runner script was updated. Restarting execution with updated code..."
            exec "${candidate_targets[0]}" "${ORIGINAL_ARGS[@]}" --no-update-check
        fi
    fi
}

check_and_prompt_github_updates

if [[ "$ABORTED_UPDATES_RUN_AS_IS" != true ]]; then
    check_deprecated_local_modules "$SUITE_ROOT"
fi

# ------------------------------------------------------------------------------
# 6. INTERACTIVE PROMPTS & DESKTOP ENVIRONMENT CONFIGURATION
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
