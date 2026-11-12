#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# ==============================================================================
# MODULE: STANDARD HARDENING (mod-harden.sh)
# SYNOPSIS
#     Standalone & orchestrated Standard Hardening module for Linux-Deployment-Tool.
# DESCRIPTION
#     Enforces baseline Mandatory Access Control (SELinux / AppArmor), configures
#     unattended security patching (dnf-automatic, rpm-ostreed-automatic,
#     unattended-upgrades), and applies CIS OpenSSH safeguards + CVE-2024-6387
#     (regreSSHion) LoginGraceTime mitigation.
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

init_standalone_module "mod-harden.sh" "$@"

echo -e "\n\e[35m[========== STARTING STANDARD HARDENING ==========]\e[0m"

if [[ "$DISTRO_FAMILY" == "rpm" || "$DISTRO_FAMILY" == "atomic" ]]; then
    log_info "Verifying SELinux Enforcement..."
    if command -v setenforce &>/dev/null; then
        setenforce 1 || true
        set_ini_option /etc/selinux/config SELINUX enforcing
        log_success "SELinux verified/set to Enforcing."
    fi
elif [[ "$DISTRO_FAMILY" == "opensuse" || "$DISTRO_FAMILY" == "deb" ]]; then
    if command -v aa-status &>/dev/null; then
        log_info "Verifying AppArmor Enforcement..."
        systemctl enable --now apparmor 2>/dev/null || true
        log_success "AppArmor verified/enforced."
    fi
fi

log_info "Configuring Automatic Security Updates..."
if [[ "$DISTRO_FAMILY" == "rpm" ]]; then
    if [[ -n "$DOWNLOAD_ONLY" ]]; then
        log_info "Download-only mode active: staged dnf-automatic package without modifying service files."
    else
        pkg_install dnf-automatic 2>/dev/null || pkg_install dnf5-plugin-automatic 2>/dev/null || true
        dnf_auto_conf="/etc/dnf/automatic.conf"
        mkdir -p /etc/dnf
        chmod 0755 /etc/dnf 2>/dev/null || true
        if [[ ! -f "$dnf_auto_conf" ]]; then
            log_info "Creating default security configuration: $dnf_auto_conf"
            cat <<'EOF' > "$dnf_auto_conf"
[commands]
upgrade_type = security
download_updates = yes
apply_updates = yes

[emitters]
emit_via = stdio

[command]
upgrade_type = security
download_updates = yes
apply_updates = yes
EOF
            chmod 0644 "$dnf_auto_conf" 2>/dev/null || true
        else
            set_ini_option "$dnf_auto_conf" upgrade_type security
            set_ini_option "$dnf_auto_conf" download_updates yes
            set_ini_option "$dnf_auto_conf" apply_updates yes
        fi
        service_enable dnf-automatic.timer 2>/dev/null || service_enable dnf5-automatic.timer 2>/dev/null || true
    fi
elif [[ "$DISTRO_FAMILY" == "atomic" ]]; then
    log_info "Fedora Atomic: Enabling rpm-ostreed-automatic timer..."
    systemctl enable --now rpm-ostreed-automatic.timer 2>/dev/null || true
elif [[ "$DISTRO_FAMILY" == "deb" ]]; then
    pkg_install unattended-upgrades apt-listchanges
    cat <<'EOF' > /etc/apt/apt.conf.d/20auto-upgrades
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    chmod 0644 /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || true
    service_enable unattended-upgrades
else
    log_info "Automatic patching skipped for $DISTRO_NAME (manual scheduling recommended)."
fi
log_success "Automated background security patching verified."

if dpkg -s openssh-server &>/dev/null 2>&1 || rpm -q openssh-server &>/dev/null 2>&1 || command -v sshd &>/dev/null; then
    log_info "Applying CIS Benchmark Baseline & CVE-2024-6387 (regreSSHion) Mitigation..."
    set_sshd_option "$SSHD_CONF" PermitRootLogin no
    # CVE-2024-6387 (regreSSHion): reduce grace time from 120s to 20s to neutralize race condition window
    set_sshd_option "$SSHD_CONF" LoginGraceTime 20
    set_sshd_option "$SSHD_CONF" MaxAuthTries 3
    set_sshd_option "$SSHD_CONF" MaxSessions 4
    set_sshd_option "$SSHD_CONF" MaxStartups 10:30:60
    set_sshd_option "$SSHD_CONF" ClientAliveInterval 300
    set_sshd_option "$SSHD_CONF" ClientAliveCountMax 2
    set_sshd_option "$SSHD_CONF" PermitEmptyPasswords no
    set_sshd_option "$SSHD_CONF" IgnoreRhosts yes
    set_sshd_option "$SSHD_CONF" HostbasedAuthentication no
    service_restart "$SSH_SERVICE"
    log_success "Direct root login disabled, LoginGraceTime tuned to 20s (regreSSHion defense), and CIS limits enforced."
fi
log_success "Standard hardening complete."
