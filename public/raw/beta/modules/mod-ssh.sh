#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ==============================================================================
# MODULE: NETWORKING (SSH) & 2FA (mod-ssh.sh)
# SYNOPSIS
#     Standalone & orchestrated OpenSSH + 2FA module for Linux-Deployment-Tool.
# DESCRIPTION
#     Installs, enables, and validates OpenSSH Server listener status, and
#     optionally enforces Google Authenticator PAM MFA when --2fa is passed.
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

init_standalone_module "mod-ssh.sh" "$@"

echo -e "\n\e[35m[========== STARTING SSH PROVISIONING MODULE ==========]\e[0m"
if [[ "$RUN_REINSTALL" == true ]] || { ! dpkg -s openssh-server &>/dev/null 2>&1 && ! rpm -q openssh-server &>/dev/null 2>&1 && ! command -v sshd &>/dev/null; }; then
    log_info "Installing/Re-installing OpenSSH Server..."
    pkg_install openssh-server
fi

if [[ "${RUN_2FA:-false}" == true ]]; then
    log_info "Configuring Google Authenticator MFA for SSH..."
    pkg_install google-authenticator

    backup_sshd_config "$SSHD_CONF"
    set_sshd_option "$SSHD_CONF" ChallengeResponseAuthentication yes
    set_sshd_option "$SSHD_CONF" KbdInteractiveAuthentication yes
    set_sshd_option "$SSHD_CONF" UsePAM yes

    # Idempotent PAM injection with nullok (secures login while avoiding lockout before key generation)
    if ! grep -q "pam_google_authenticator.so" "$PAM_CONF" 2>/dev/null; then
        echo "auth required pam_google_authenticator.so nullok" >> "$PAM_CONF"
        log_success "Enforced pam_google_authenticator.so (nullok transition mode) in $PAM_CONF."
    fi
fi

service_enable "$SSH_SERVICE"
validate_and_restart_sshd "$SSHD_CONF" || true

if systemctl is-active --quiet "$SSH_SERVICE"; then
    if ss -lt 2>/dev/null | grep -qE '(:ssh|:22)\b'; then
        log_success "SSH Status is online and actively listening."
    else
        log_warn "Service is running, but no SSH listener detected."
    fi
fi

if [[ "${RUN_2FA:-false}" == true ]]; then
    echo -e "\n\e[33m****************************************************************"
    echo -e "2FA WARNING: SSH MFA has been enforced at the system level."
    echo -e "You MUST run the command 'google-authenticator' on your standard"
    echo -e "user account (not root) to generate your QR code and tokens."
    echo -e "****************************************************************\e[0m\n"
fi
