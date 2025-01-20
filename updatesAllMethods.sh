#!/bin/bash
#Purpose: Update dnf, flatpak, and snap via
#one script that can be run via alias. 
#Author: Zachary Schmalz - SysEngIV

#Check if script is running with root permissions.
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

#Set flags for autoinstall and verbosity.
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

#Check all default dnf repositories
echo ''
echo 'Running dnf updates:'
dnf upgrade $AutoInstall $DownloadOnly

#Check all default flatpak repositories
echo ''
echo 'Running flatpak updates:'
flatpak upgrade $AutoInstall

#Refresh the snap cache
echo ''
echo 'Running snap refresh:'
snap refresh


#exit code
echo ''
echo "All updates completed!"