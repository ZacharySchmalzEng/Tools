#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ==============================================================================
# MODULE: ADVANCED HARDENING (mod-harden-adv.sh)
# SYNOPSIS
#     Standalone & orchestrated Advanced Hardening module for Linux-Deployment-Tool.
# DESCRIPTION
#     Applies strict CIS Level 2 sysctl network drops & memory protection,
#     deploys auditd with identity/privilege watch rules, and disables SSH
#     password authentication and X11 forwarding.
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

init_standalone_module "mod-harden-adv.sh" "$@"

if [[ "${ORCHESTRATED_RUN:-false}" != true && "$UNATTENDED" != true ]]; then
    echo -e "\n\e[31m[!] WARNING: Advanced hardening will disable SSH password authentication."
    echo -e "    Ensure you have an SSH Key provisioned before disconnecting.\e[0m"
    acknowledged=""
    prompt_tty "    Press Enter to acknowledge and continue..." acknowledged || true
fi

echo -e "\n\e[35m[========== STARTING ADVANCED HARDENING ==========]\e[0m"

log_info "Applying Strict CIS Level 2 Sysctl Network Drops & Memory Protection..."
SYSCTL_CONF="/etc/sysctl.d/99-security.conf"
cat <<EOF > "$SYSCTL_CONF"
# CIS Linux Benchmark Network Hardening Controls & Memory Defense
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.icmp_echo_ignore_all = 1
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
EOF
chmod 0644 "$SYSCTL_CONF" 2>/dev/null || true
sysctl -p "$SYSCTL_CONF" || log_warn "Failed to apply sysctl parameters."
log_success "Kernel network hardening applied (Ping disabled, strict routing, martian logging, suid dump disabled)."

log_info "Deploying and Configuring Auditd..."
pkg_install audit
service_enable auditd
AUDIT_RULES="/etc/audit/rules.d/custom-security.rules"
cat <<EOF > "$AUDIT_RULES"
# CIS Benchmark Credential, Identity & Privilege Monitoring
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /var/log/tallylog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /etc/ssh/sshd_config -p wa -k sshd_config
EOF
chmod 0600 "$AUDIT_RULES" 2>/dev/null || true
augenrules --load || log_warn "Failed to load audit rules."
log_success "Audit daemon configured for high-fidelity credential/privilege event generation."

if dpkg -s openssh-server &>/dev/null 2>&1 || rpm -q openssh-server &>/dev/null 2>&1 || command -v sshd &>/dev/null; then
    log_info "Applying Strict SSH Hardening..."
    set_sshd_option "$SSHD_CONF" PasswordAuthentication no
    set_sshd_option "$SSHD_CONF" X11Forwarding no
    service_restart "$SSH_SERVICE"
    log_success "SSH Password Authentication and X11 Forwarding disabled."
fi
log_success "Advanced hardening complete."
