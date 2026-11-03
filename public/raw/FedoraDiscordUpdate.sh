#!/bin/bash
# ==============================================================================
# SYNOPSIS
#     Automated Discord transition from Flatpak to RPM via RPM Fusion.
#
# DESCRIPTION
#     This script automates the process of removing the Flatpak version of 
#     Discord and installing the native RPM package on Fedora systems.
#     It executes the following:
#     - Verifies root execution privileges.
#     - Checks for and uninstalls the existing Discord Flatpak if present.
#     - Installs and enables the RPM Fusion (Free and Nonfree) repositories.
#     - Installs the native Discord package via DNF.
#
#     Source: https://docs.fedoraproject.org/en-US/quick-docs/rpmfusion-setup/
#
# AUTHOR
#     Zachary Schmalz
#
# NOTES
#     Version:        1.0
#     Date:           2026-02-26
#     Requirements:   Fedora Linux, Bash, Flatpak, DNF.
#     Execution:      Must be run with sudo/root privileges.
# ==============================================================================

# Check if script is running with root permissions.
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# Remove existing discord instance
if flatpak list | grep -q "discord"; then
    echo "Flatpak application 'discord' is installed. Removing it..."
    flatpak uninstall -y "discord"
    if [ $? -eq 0 ]; then
        echo "Successfully removed Discord."
    else
        echo "Failed to remove Discord."
    fi
else
    echo "Flatpak application Discord is not installed."
fi

# Add repos
dnf install https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm -y
dnf install https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm -y

# Install discord
dnf install discord -y