#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ==============================================================================
# MODULE: MAKER & 3D PRINTING (mod-maker.sh)
# SYNOPSIS
#     Standalone & orchestrated 3D Printing Maker module for Linux-Deployment-Tool.
# DESCRIPTION
#     Installs PrusaSlicer via native package manager and OrcaSlicer (with
#     legacy com.softfever fallback) + BambuStudio via Flathub.
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
        chmod 0755 "$COMMON_PATH"
    fi
    # shellcheck disable=SC1090
    source "$COMMON_PATH"
fi

init_standalone_module "mod-maker.sh" "$@"

echo -e "\n\e[35m[========== STARTING MAKER MODULE ==========]\e[0m"
if ! pkg_install prusa-slicer; then
    log_warn "The PrusaSlicer package could not be installed. Continuing..."
fi
ensure_flatpak
# OrcaSlicer upstream namespace transitioned from com.softfever to com.orcaslicer
install_flatpak_app "com.orcaslicer.OrcaSlicer" "com.softfever.OrcaSlicer"
install_flatpak_app "com.bambulab.BambuStudio"
log_success "Maker module complete."
