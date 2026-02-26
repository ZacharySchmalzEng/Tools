#!/bin/bash
# ==============================================================================
# SYNOPSIS
#     Automated Fedora 41+ gaming environment and dependency setup script.
#
# DESCRIPTION
#     This script performs a comprehensive post-installation setup for a fresh 
#     Fedora 41 (or newer) environment tailored specifically for gaming.
#     It executes the following:
#     - Enables third-party repositories (RPM Fusion, etc.)
#     - Installs core gaming dependencies and Vulkan drivers
#     - Configures performance tweaks (e.g., gamemode, kernel parameters)
#     - Deploys gaming platforms (Steam, Lutris, Wine, etc.)
#
# AUTHOR
#     Zachary Schmalz
#
# NOTES
#     Version:        1.0 (Beta)
#     Date:           2026-02-26
#     Requirements:   Fedora Linux 41+, Bash, Active Internet Connection.
#     Execution:      Must be run with sudo/root privileges.
# ==============================================================================



##Check if script is running with root permissions.##
if [ "$EUID" -ne 0 ]
  then echo "Please run with root privileges."
  exit
fi

# Sets a reboot flag to be used later.
touch /var/run/rebooting-for-updates
sudo reboot

# This script is designed to run before and after a reboot.
before_reboot(){
    ##Enable prerequisites 
    dnf install flatpak snap dnf-plugins-core -y
    dnf install \https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm -y
    dnf install \https://download1.rpmfusion.org/nonfree/fedora/rpmfusion-nonfree-release-$(rpm -E %fedora).noarch.rpm -y
    flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
    dnf copr enable t0xic0der/nvidia-auto-installer-for-fedora -y
    dnf group upgrade core -y
    dnf4 group update core -y
    dnf update -y
}

after_reboot_1(){
    ##Wine
    dnf install winetricks -y

    ##Steam function##
    dnf config-manager setopt fedora-cisco-openh264.enabled=1
    dnf install steam -y

    ##Lutris function##
    dnf install lutris -y

    ##Proton-QT##
    flatpak install ProtonUp-Qt

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
    
#Set a new reboot flag to be used later.
    touch /var/run/rebooting-for-updates
    sudo reboot
}    

#Reboot handling
if [ -f /var/run/rebooting-for-updates ]; then
    after_reboot
    rm /var/run/rebooting-for-updates
    update-rc.d myupdate remove
else
    before_reboot
    touch /var/run/rebooting-for-updates
    update-rc.d myupdate defaults
    sudo reboot
fi
echo "Installation complete."
#End of script