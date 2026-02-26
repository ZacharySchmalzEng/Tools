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
#     - Enables and starts the sshd systemd service.
#     - Validates that the daemon is active and actively listening for connections.
#
# AUTHOR
#     Zachary Schmalz
#
# NOTES
#     Version:        1.0
#     Date:           2026-02-26
#     Requirements:   Fedora/RHEL Linux, Bash, systemd.
#     Execution:      Must be run with sudo/root privileges.
# ==============================================================================

# Check if script is running with root permissions.
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

echo "Checking if OpenSSH server is installed."
if rpm -qa | grep openssh-server; then
    echo "OpenSSH Server is installed. Moving onto next steps..."
else
    echo "OpenSSH Server is not installed. Installing OpenSSH now..."
    dnf install openssh-server -y  
fi

echo "Enabling SSH deamon..."
systemctl enable sshd
systemctl start sshd

echo "Checking SSH Status..."
if
    systemctl status sshd | grep "active (running)"; then
        if
        ss -lt | grep ssh; then
            echo "SSH Status is online."
        else
            echo "No SSH listener. Please troubleshoot network"
        fi
    else
    echo "SSH deamon is not running. Please review system logs."
fi

echo "Completed all tasks."