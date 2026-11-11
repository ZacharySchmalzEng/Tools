#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ==============================================================================
# MODULE: UPDATE & MAINTENANCE (mod-update.sh)
# SYNOPSIS
#     Standalone & orchestrated system update module for Linux-Deployment-Tool.
# DESCRIPTION
#     Upgrades native system packages (DNF, rpm-ostree, Pacman, SteamOS, Zypper,
#     APT), Flatpak applications, and Snap packages. Supports --rebuild recovery.
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
        REPO_BASE="${LDT_REPO_BASE_URL:-https://raw.githubusercontent.com/ZacharySchmalzEng/Tools/beta/modular-v3/Linux/Provisioning/Linux-Deployment-Tool/Beta}"
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

init_standalone_module "mod-update.sh" "$@"

echo -e "\n\e[35m[========== STARTING UPDATE MODULE ==========]\e[0m"
log_info "Running system package updates..."
if ! update_system; then
    log_warn "Package updates reported issues. Continuing..."
fi

if command -v flatpak &>/dev/null; then
    log_info "Running Flatpak updates..."
    flatpak upgrade ${AUTO_YES:+--assumeyes} || true
fi

if command -v snap &>/dev/null; then
    log_info "Running Snap refresh..."
    snap refresh || log_warn "Snap refresh returned a non-zero exit code. Continuing..."
fi
log_success "Update module complete."
