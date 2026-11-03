#!/bin/bash
# ==============================================================================
# SYNOPSIS
#     Automated system-wide package update script.
#
# DESCRIPTION
#     This script centralizes package management by updating DNF, Flatpak,
#     and Snap packages sequentially. It supports command-line flags for 
#     unattended installations and download-only operations, making it 
#     ideal for use as a custom terminal alias.
#
# AUTHOR
#     Zachary Schmalz
#
# NOTES
#     Version:        1.0
#     Date:           2026-02-26
#     Requirements:   Fedora/RHEL Linux, Bash, DNF, Flatpak, Snap.
#     Execution:      Must be run with sudo/root privileges.
# ==============================================================================

# Function to display usage if an invalid flag is passed
print_usage() {
  echo "Usage: $0 [-y] [-d]"
  echo "  -y    Auto-install (yes to all prompts)"
  echo "  -d    Download only (applies to DNF)"
}

# Check if script is running with root permissions.
if [ "$EUID" -ne 0 ]; then 
  echo "Please run as root"
  exit 1
fi

# Set flags for autoinstall and verbosity.
AutoInstall=''
DownloadOnly=''

while getopts 'yd' flag; do
    case "${flag}" in
        y) AutoInstall='-y' ;;
        d) DownloadOnly='--downloadonly' ;;
        *) print_usage
           exit 1 ;;
    esac
done

# Check all default dnf repositories
echo ''
echo 'Running dnf updates:'
dnf upgrade $AutoInstall $DownloadOnly

# Check all default flatpak repositories
echo ''
echo 'Running flatpak updates:'
flatpak upgrade $AutoInstall

# Refresh the snap cache
echo ''
echo 'Running snap refresh:'
snap refresh

# Exit code
echo ''
echo "All updates completed!"