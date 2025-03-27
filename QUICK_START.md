# YUNA Firewall Manager Quick Start Guide

This quick start guide will help you get up and running with YUNA Firewall Manager in just a few minutes.

## Installation

### Method 1: Using the Installation Script (Recommended)

```bash
# Make the installation script executable
chmod +x INSTALL.sh

# Run the installation script
sudo ./INSTALL.sh
```

### Method 2: Manual Installation

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y qt5-default libqt5dbus5 firewalld openvpn

# Build the application
chmod +x build.sh
./build.sh
```

## Common Tasks

### Basic Commands

```bash
# Start YUNA
./YUNA

# Get help
./YUNA --help

# Block a website
./YUNA --block-website facebook.com

# Add a port to the firewall
./YUNA --add-port 8080 tcp

# Remove a port from the firewall
./YUNA --remove-port 8080 tcp
```

### Firewall Management

```bash
# Restore default configuration
./YUNA --restore-default

# Block an IP address
./YUNA --block-ip 192.168.1.100

# Unblock an IP address
./YUNA --unblock-ip 192.168.1.100
```

### Security Features

```bash
# Enable panic mode (block all traffic)
./YUNA --panic-mode

# Disable panic mode
./YUNA --disable-panic

# Train the neural network
./YUNA --train-network
```

### VPN Management

```bash
# Connect to VPN
./YUNA --vpn-connect /path/to/config.ovpn

# Disconnect from VPN
./YUNA --vpn-disconnect

# Check VPN status
./YUNA --vpn-status
```

## Configuration

The configuration file is located at:
```
~/FirewallManagerConfig/config.txt
```

## Logs

Log files are stored at:
```
~/FirewallManagerLogs/firewall_manager.log
```

For more detailed information, please refer to the full [USER_GUIDE.md](USER_GUIDE.md).
