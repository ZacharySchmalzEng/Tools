#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ==============================================================================
# MODULE: APPS & SYSTEM QoL (mod-apps.sh)
# SYNOPSIS
#     Standalone & orchestrated QoL applications module for Linux-Deployment-Tool.
# DESCRIPTION
#     Installs common system utilities (timeshift, btop, bat, eza, plocate,
#     mediawriter, p7zip, vlc), Desktop Environment-specific utilities (GNOME,
#     KDE, COSMIC, XFCE, Cinnamon), and core Flathub desktop apps.
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
        chmod 0755 "$(dirname "$COMMON_PATH")" 2>/dev/null || true
        REPO_BASE="${LDT_REPO_BASE_URL:-https://raw.githubusercontent.com/ZacharySchmalzEng/Tools/main/Linux/Provisioning/Linux-Deployment-Tool/Beta}"
        TMP_COMMON="${COMMON_PATH}.tmp.$$"
        echo -e "\e[36m[INFO] Shared library not found locally. Downloading lib/common.sh from GitHub...\e[0m"
        if command -v curl &>/dev/null; then
            curl --connect-timeout 10 --max-time 60 --retry 3 -fsSL "${REPO_BASE}/lib/common.sh" -o "$TMP_COMMON"
        elif command -v wget &>/dev/null; then
            wget -q --timeout=60 --tries=3 -O "$TMP_COMMON" "${REPO_BASE}/lib/common.sh"
        else
            echo -e "\e[31m[ERROR] Neither curl nor wget is available to download lib/common.sh.\e[0m" >&2
            exit 1
        fi
        if ! head -n 1 "$TMP_COMMON" 2>/dev/null | grep -q "^#!"; then
            echo -e "\e[31m[ERROR] Downloaded lib/common.sh did not contain a valid script header.\e[0m" >&2
            rm -f "$TMP_COMMON" 2>/dev/null || true
            exit 1
        fi
        chmod 0755 "$TMP_COMMON"
        mv -f "$TMP_COMMON" "$COMMON_PATH"
    fi
    # shellcheck disable=SC1090
    source "$COMMON_PATH"
fi

init_standalone_module "mod-apps.sh" "$@"

if [[ -z "${DESKTOP_ENV:-}" ]]; then
    resolve_desktop_environment
fi

echo -e "\n\e[35m[========== STARTING APPS & QoL MODULE ==========]\e[0m"
QOL_APPS=(timeshift btop bat eza plocate mediawriter p7zip p7zip-plugins vlc)
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
FLATPAK_APPS=(com.brave.Browser com.google.Chrome md.obsidian.Obsidian org.signal.Signal)
for app in "${FLATPAK_APPS[@]}"; do
    install_flatpak_app "$app"
done

if command -v updatedb &>/dev/null; then
    updatedb || true
fi
log_success "Apps module complete."
