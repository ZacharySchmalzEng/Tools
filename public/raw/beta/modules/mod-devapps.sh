#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ==============================================================================
# MODULE: DEV APPS (mod-devapps.sh)
# SYNOPSIS
#     Standalone & orchestrated Developer Tools module for Linux-Deployment-Tool.
# DESCRIPTION
#     Installs baseline development CLIs (Python 3, OpenSSL, Git, jq, fzf,
#     tealdeer, rsync), Microsoft PowerShell (pwsh), and Visual Studio Code.
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

init_standalone_module "mod-devapps.sh" "$@"

echo -e "\n\e[35m[========== STARTING DEV APPS MODULE ==========]\e[0m"
if ! pkg_install python3 openssl git jq fzf tealdeer rsync; then
    log_warn "Some development packages could not be installed. Continuing..."
fi

# Install Microsoft PowerShell (pwsh) via official repository or Flathub fallback
install_powershell

ensure_flatpak
DEV_FLATPAKS=(com.visualstudio.code)
for app in "${DEV_FLATPAKS[@]}"; do
    install_flatpak_app "$app"
done
log_success "Dev Apps module complete."
