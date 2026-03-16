#!/bin/bash
# ==============================================================================
# SYNOPSIS
#     Automated OpenSSH Server installation and configuration script.
#
# DESCRIPTION
#     This script automates the deployment of the OpenSSH Server daemon on 
#     Fedora/RHEL-based systems. It executes the following:
#     - Verifies root execution privileges.
#     - Checks for existing OpenSSH Server installations.
#     - Installs the openssh-server package via DNF if missing.
#     - Optionally installs and configures Google Authenticator for MFA.
#     - Enables and starts/restarts the sshd systemd service.
#     - Validates that the daemon is active and actively listening for connections.
#
# AUTHOR
#     Zachary Schmalz
#
# NOTES
#     Version:        1.1
#     Requirements:   Fedora/RHEL Linux, Bash, systemd.
#     Execution:      Must be run with sudo/root privileges.
# ==============================================================================

# Check if script is running with root permissions.
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

echo "Checking if OpenSSH server is installed."
if rpm -qa | grep -q openssh-server; then
    echo "OpenSSH Server is installed. Moving onto next steps..."
else
    echo "OpenSSH Server is not installed. Installing OpenSSH now..."
    dnf install openssh-server -y  
fi

# Ask the user if they want to configure 2FA
read -p "Would you like to enforce Google Authenticator 2FA for SSH? (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Configuring Google Authenticator MFA for SSH..."
    dnf install google-authenticator -y
    
    SSHD_CONF="/etc/ssh/sshd_config"
    PAM_CONF="/etc/pam.d/sshd"

    echo "Modifying $SSHD_CONF..."
    sed -i -E 's/^#?ChallengeResponseAuthentication.*/ChallengeResponseAuthentication yes/' "$SSHD_CONF"
    sed -i -E 's/^#?KbdInteractiveAuthentication.*/KbdInteractiveAuthentication yes/' "$SSHD_CONF"
    sed -i -E 's/^#?UsePAM.*/UsePAM yes/' "$SSHD_CONF"

    echo "Modifying $PAM_CONF..."
    if ! grep -q "pam_google_authenticator.so" "$PAM_CONF"; then
        echo "auth required pam_google_authenticator.so nullok" >> "$PAM_CONF"
        echo "PAM module updated with nullok fallback."
    else
        echo "PAM config already contains Google Authenticator entry. Skipping modification."
    fi
    ENABLE_2FA=true
else
    echo "Skipping 2FA configuration..."
    ENABLE_2FA=false
fi

echo "Enabling and restarting SSH daemon..."
systemctl enable sshd
systemctl restart sshd

echo "Checking SSH Status..."
if systemctl status sshd | grep -q "active (running)"; then
    if ss -lt | grep -q ssh; then
        echo "SSH Status is online."
    else
        echo "No SSH listener. Please troubleshoot network"
    fi
else
    echo "SSH daemon is not running. Please review system logs."
fi

if [[ "$ENABLE_2FA" == true ]]; then
    echo -e "\n\e[33m****************************************************************"
    echo -e "2FA WARNING: SSH MFA has been enforced at the system level."
    echo -e "You MUST run the command 'google-authenticator' on your standard"
    echo -e "user account (not root) to generate your QR code and tokens."
    echo -e "****************************************************************\e[0m\n"
fi

echo "Completed all tasks."