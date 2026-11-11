#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ==============================================================================
# MODULE: CYBERSECURITY (mod-cyber.sh)
# SYNOPSIS
#     Standalone & orchestrated Cybersecurity module for Linux-Deployment-Tool.
# DESCRIPTION
#     Installs packet-analysis and network reconnaissance tools (wireshark,
#     nmap, tcpdump, ncat) and adds SUDO_USER to the wireshark group.
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

init_standalone_module "mod-cyber.sh" "$@"

echo -e "\n\e[35m[========== STARTING CYBER MODULE ==========]\e[0m"
if [[ "${RUN_SYSADMIN:-false}" == true ]]; then
    log_info "Cybersecurity diagnostics are already included in the sysadmin package set."
else
    CYBER_PKGS=(wireshark-qt nmap tcpdump nmap-ncat)
    if ! pkg_install "${CYBER_PKGS[@]}"; then
        log_warn "Some cybersecurity packages could not be installed. Continuing..."
    fi
    if [[ -n "${SUDO_USER:-}" ]] && getent group wireshark &>/dev/null; then
        usermod -aG wireshark "$SUDO_USER" || true
    fi
fi
log_success "Cyber module complete."
