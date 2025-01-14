#!/bin/bash
#Purpose: Enable base SSH functions.
#Author: Zachary Schmalz - SysEngIV


#Check if script is running with root permissions.
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

#remove existing discord instance
echo "Checking if OpenSSH server is installed."
if rpm -qa | grep openssh-server; then
    echo "OpenSSH Server is installed. Moving onto next steps..."
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


else
    echo "OpenSSH Server is not installed. Installing OpenSSH now..."
    dnf install openssh-server
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
    
fi