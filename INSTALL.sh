#!/bin/bash

# YUNA Firewall Manager Installation Script

echo "Starting YUNA Firewall Manager installation..."

# Detect distribution
if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    echo "Detected Debian/Ubuntu system"
    PACKAGE_MANAGER="apt-get"
    INSTALL_CMD="sudo apt-get install -y"
    QMAKE_CMD="qmake"
elif [ -f /etc/fedora-release ]; then
    # Fedora
    echo "Detected Fedora system"
    PACKAGE_MANAGER="dnf"
    INSTALL_CMD="sudo dnf install -y"
    QMAKE_CMD="qmake-qt5"
elif [ -f /etc/redhat-release ]; then
    # CentOS/RHEL
    echo "Detected CentOS/RHEL system"
    PACKAGE_MANAGER="yum"
    INSTALL_CMD="sudo yum install -y"
    QMAKE_CMD="qmake-qt5"
else
    echo "Unsupported distribution. Exiting."
    exit 1
fi

# Update package repositories
echo "Updating package repositories..."
if [ "$PACKAGE_MANAGER" = "apt-get" ]; then
    sudo apt-get update
elif [ "$PACKAGE_MANAGER" = "dnf" ]; then
    sudo dnf check-update
elif [ "$PACKAGE_MANAGER" = "yum" ]; then
    sudo yum check-update
fi

# Install Qt dependencies
echo "Installing Qt dependencies..."
if [ "$PACKAGE_MANAGER" = "apt-get" ]; then
    $INSTALL_CMD qt5-default libqt5dbus5
elif [ "$PACKAGE_MANAGER" = "dnf" ] || [ "$PACKAGE_MANAGER" = "yum" ]; then
    $INSTALL_CMD qt5-qtbase qt5-qtbase-devel
fi

# Install network dependencies
echo "Installing network dependencies..."
$INSTALL_CMD firewalld openvpn iptables

# Install D-Bus development libraries
echo "Installing D-Bus development libraries..."
if [ "$PACKAGE_MANAGER" = "apt-get" ]; then
    $INSTALL_CMD libdbus-1-dev
elif [ "$PACKAGE_MANAGER" = "dnf" ] || [ "$PACKAGE_MANAGER" = "yum" ]; then
    $INSTALL_CMD dbus-devel
fi

# Install build tools
echo "Installing build tools..."
if [ "$PACKAGE_MANAGER" = "apt-get" ]; then
    $INSTALL_CMD build-essential make g++
elif [ "$PACKAGE_MANAGER" = "dnf" ] || [ "$PACKAGE_MANAGER" = "yum" ]; then
    $INSTALL_CMD gcc-c++ make
fi

# Build the application
echo "Building YUNA Firewall Manager..."
$QMAKE_CMD YUNA.pro
make

# Set permissions
echo "Setting executable permissions..."
chmod +x YUNA

# Create symlink in bin directory
echo "Creating symlink in /usr/local/bin..."
sudo ln -sf "$(pwd)/YUNA" /usr/local/bin/yuna

# Enable and start firewalld service
echo "Enabling and starting firewalld service..."
sudo systemctl enable firewalld
sudo systemctl start firewalld

echo "Installation complete. You can now run YUNA with the command 'yuna'"
echo "For help, run 'yuna --help'"
