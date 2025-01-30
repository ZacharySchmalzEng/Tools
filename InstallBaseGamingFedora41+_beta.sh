#!/bin/bash
#Purpose: Install base gamming packages in Fedora build 41+
#Disclaimer: This is a beta and provides no guarantees 
#Author: ZacharyS - SysEng
#Additional documentation can be found at:
#https://docs.fedoraproject.org/en-US/quick-docs/rpmfusion-setup/
#https://docs.fedoraproject.org/en-US/gaming/proton/
#https://lutris.net/downloads
#https://github.com/gridhead/nvidia-auto-installer-for-fedora-linux


##Check if script is running with root permissions.##
if [ "$EUID" -ne 0 ]
  then echo "Please run with root privileges."
  exit
fi
##Enable prerequisites 
dnf install flatpak snap dnf-plugins-core -y
dnf install \https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm -y
dnf install \https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm -y
flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
dnf copr enable t0xic0der/nvidia-auto-installer-for-fedora -y
dnf group upgrade core -y
dnf4 group update core -y

##Wine
dnf install winetricks -y

##Steam function##
dnf config-manager setopt fedora-cisco-openh264.enabled=1
dnf install steam -y

##Lutris function##
dnf install lutris

##Discord function##
echo "The flatpak version of Discord has a known bug with streaming. Installing the RPM fusion version."
#remove existing discord instance
if flatpak list | grep -q "discord"; then
    echo "The flatpak version of 'discord' is installed. Removing it..."
    flatpak uninstall -y "discord"
    if [ $? -eq 0 ]; then
        echo "Successfully removed Discord."
    else
        echo "Failed to remove Discord."
    fi
else
    echo "Flatpak version of Discord is not installed."
fi

#Install the RPM Fusion verion of Discord. 
echo "Installing the RPM Fusion version of Discord now..."
dnf install discord -y

##Update firmware
fwupdmgr refresh --force
fwupdmgr get-devices # Lists devices with available updates.
fwupdmgr get-updates # Fetches list of available updates.
fwupdmgr update


##Install Nvidea Drivers - Full credit goes to gridhead.
#For more information https://github.com/gridhead/nvidia-auto-installer-for-fedora-linux
dnf install nvautoinstall -y
Compatability=$(nvautoinstall compat)
if [[ $Compatability == *"expected to work correctly"* ]]; then
    echo "GPU is compatable with nvidea drivers"
    nvautoinstall rpmadd 
    nvautoinstall driver 
    nvautoinstall nvrepo 
    nvautoinstall plcuda 
    nvautoinstall ffmpeg 
    nvautoinstall vulkan 
    nvautoinstall vidacc
else
    echo "No compatable nvidea GPU found."
fi

reboot 60