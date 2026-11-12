#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ==============================================================================
# MODULE: SYSTEM ADMINISTRATION (mod-sysadmin.sh)
# SYNOPSIS
#     Standalone & orchestrated Sysadmin module for Linux-Deployment-Tool.
# DESCRIPTION
#     Installs remote-access, session multiplexing, network analysis, storage,
#     and process diagnostic utilities (remmina, tmux, wireshark, nmap, tcpdump,
#     ncat, bind-utils, mtr, iperf3, sysstat, iotop, ncdu, smartmontools, lsof,
#     strace) and configures non-root Wireshark capture group membership.
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

init_standalone_module "mod-sysadmin.sh" "$@"

echo -e "\n\e[35m[========== STARTING SYSADMIN MODULE ==========]\e[0m"
SYSADMIN_PKGS=(remmina tmux wireshark-qt nmap tcpdump nmap-ncat bind-utils mtr iperf3 sysstat iotop ncdu smartmontools lsof strace)
if ! pkg_install "${SYSADMIN_PKGS[@]}"; then
    log_warn "Some sysadmin packages could not be installed. Continuing..."
fi
if [[ -n "${SUDO_USER:-}" ]] && getent group wireshark &>/dev/null; then
    usermod -aG wireshark "$SUDO_USER" || true
fi
log_success "Sysadmin module complete."
