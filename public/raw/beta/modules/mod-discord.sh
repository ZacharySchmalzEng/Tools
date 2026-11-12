#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ==============================================================================
# MODULE: DISCORD TRANSITION (mod-discord.sh)
# SYNOPSIS
#     Standalone & orchestrated Discord module for Linux-Deployment-Tool.
# DESCRIPTION
#     Configures filesystem-appropriate Discord packaging: maintains Flatpak on
#     immutable systems (Fedora Atomic, Bazzite, SteamOS) and non-RPM distros,
#     or transitions to native RPM via RPM Fusion on Fedora/Nobara.
# CHANGELOG
#     See ../CHANGELOG.md for release history.
# ==============================================================================
set -euo pipefail

if [[ "${COMMON_LIB_LOADED:-false}" != true ]]; then
    MOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
    if [[ -f "${MOD_DIR}/../lib/common.sh" ]]; then
        COMMON_PATH="${MOD_DIR}/../lib/common.sh"
    elif [[ -f "${MOD_DIR}/lib/common.sh" ]]; then
        COMMON_PATH="${MOD_DIR}/lib/common.sh"
    else
        COMMON_PATH="${MOD_DIR}/../lib/common.sh"
        mkdir -p "$(dirname "$COMMON_PATH")"
        REPO_BASE="${LDT_REPO_BASE_URL:-https://raw.githubusercontent.com/ZacharySchmalzEng/Tools/main/Linux/Provisioning/Linux-Deployment-Tool/Beta}"
        echo -e "\e[36m[INFO] Shared library not found locally. Downloading lib/common.sh from GitHub...\e[0m"
        if command -v curl &>/dev/null; then
            curl --connect-timeout 10 --max-time 60 --retry 3 -fsSL "${REPO_BASE}/lib/common.sh" -o "$COMMON_PATH"
        elif command -v wget &>/dev/null; then
            wget -q --timeout=60 --tries=3 -O "$COMMON_PATH" "${REPO_BASE}/lib/common.sh"
        else
            echo -e "\e[31m[ERROR] Neither curl nor wget is available to download lib/common.sh.\e[0m" >&2
            exit 1
        fi
        chmod 0700 "$COMMON_PATH"
    fi
    # shellcheck disable=SC1090
    source "$COMMON_PATH"
fi

init_standalone_module "mod-discord.sh" "$@"

echo -e "\n\e[35m[========== STARTING DISCORD TRANSITION MODULE ==========]\e[0m"
if [[ "$IS_ATOMIC" == true || "$IS_STEAMOS" == true ]]; then
    log_info "Atomic / SteamOS detected: Maintaining Flatpak Discord (safe for immutable filesystems)."
    install_flatpak_app com.discordapp.Discord
elif [[ "$DISTRO_FAMILY" == "rpm" ]]; then
    if flatpak list 2>/dev/null | grep -q "discord" || true; then
        flatpak uninstall ${AUTO_YES:+--assumeyes} "discord" 2>/dev/null || true
    fi
    if [[ "$IS_NOBARA" != true ]]; then
        fedora_ver=$(rpm -E %fedora 2>/dev/null || true)
        if [[ -z "$fedora_ver" || "$fedora_ver" == "%fedora" ]]; then
            fedora_ver="${VERSION_ID:-41}"
            fedora_ver="${fedora_ver%%.*}"
        fi
        pkg_install "https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-${fedora_ver}.noarch.rpm" || true
        pkg_install "https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-${fedora_ver}.noarch.rpm" || true
        CACHE_REFRESHED=false
    else
        log_info "Nobara detected: RPM Fusion repositories are already built-in."
    fi
    pkg_install discord
else
    log_info "Installing Flathub Discord on $DISTRO_NAME..."
    install_flatpak_app com.discordapp.Discord
fi
log_success "Discord transition complete."
