# YUNA Firewall Manager User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Getting Started](#getting-started)
4. [Command Line Options](#command-line-options)
5. [Basic Firewall Operations](#basic-firewall-operations)
6. [Advanced Features](#advanced-features)
7. [Traffic Monitoring](#traffic-monitoring)
8. [Network Security](#network-security)
9. [Troubleshooting](#troubleshooting)
10. [FAQ](#faq)

## Introduction

YUNA is an advanced firewall management system with AI capabilities that helps protect your system from network threats. It uses machine learning algorithms to detect anomalous traffic patterns and provides tools to manage your firewall rules efficiently.

### Key Features
- Intelligent threat detection using neural networks
- Rule-based firewall management
- Real-time traffic monitoring
- Automatic anomaly detection
- VPN connection management
- GeoIP-based filtering
- Self-healing capabilities

## Installation

### Prerequisites
Before installing YUNA, ensure your system has the following:
- Linux operating system (Ubuntu/Debian, Fedora, CentOS)
- Qt5 libraries
- D-Bus development libraries
- Firewalld service
- OpenVPN (for VPN functionality)
- Root/sudo access for firewall operations

### Installation Methods

#### Automated Installation
For most users, the automated installation script is recommended:

```bash
# Clone or download YUNA
cd ~/Downloads
git clone https://github.com/yourusername/YUNA-REBUILD.git
cd YUNA-REBUILD

# Make the installation script executable
chmod +x INSTALL.sh

# Run the installation script
sudo ./INSTALL.sh
```

#### Manual Installation
If you prefer to install manually:

1. Install dependencies:
   ```bash
   # For Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install -y qt5-default libqt5dbus5 firewalld openvpn iptables libdbus-1-dev build-essential

   # For Fedora/CentOS
   sudo dnf install -y qt5-qtbase qt5-qtbase-devel firewalld openvpn iptables dbus-devel gcc-c++ make
   ```

2. Build YUNA:
   ```bash
   # Run the build script
   chmod +x build.sh
   ./build.sh
   ```

3. Start the firewalld service:
   ```bash
   sudo systemctl enable firewalld
   sudo systemctl start firewalld
   ```

## Getting Started

### First Run

After installation, you can start YUNA from the command line:

```bash
yuna
```

When YUNA starts for the first time, it will:
1. Check if firewalld is running
2. Create necessary configuration directories
3. Initialize the neural network for threat detection
4. Load default firewall rules (if any)

### Configuration Files

YUNA uses the following directories for configuration and logging:
- `~/FirewallManagerConfig/` - Configuration files
- `~/FirewallManagerLogs/` - Log files

You can manually edit the configuration file at:
```
~/FirewallManagerConfig/config.txt
```

Example configuration:
```
vpnConfigPath=/path/to/vpn-config.ovpn
logLevel=INFO
defaultAction=ALLOW
```

## Command Line Options

YUNA supports various command line options for quick operations:

```bash
# Get help information
yuna --help

# Restore default firewall configuration
yuna --restore-default

# Block a specific website
yuna --block-website example.com

# Add a port to the firewall
yuna --add-port 8080 tcp

# Remove a port from the firewall
yuna --remove-port 8080 tcp
```

## Basic Firewall Operations

### Managing Firewall Rules

#### Adding a Rule
```bash
# From command line
yuna --add-rule block incoming 192.168.1.100 any any

# Or programmatically
FirewallManager.addFirewallRule("block", "in", "192.168.1.100", "any", "any");
```

#### Removing a Rule
```bash
# From command line
yuna --remove-rule block incoming 192.168.1.100 any any

# Or programmatically
FirewallManager.removeFirewallRule("block", "in", "192.168.1.100", "any", "any");
```

#### Listing All Rules
```bash
yuna --list-rules
```

### Managing Ports

#### Opening a Port
```bash
yuna --add-port 22 tcp
```

#### Closing a Port
```bash
yuna --remove-port 22 tcp
```

### IP Address Management

#### Blocking an IP Address
```bash
yuna --block-ip 192.168.1.100
```

#### Unblocking an IP Address
```bash
yuna --unblock-ip 192.168.1.100
```

### Website Blocking

To block access to a specific website:
```bash
yuna --block-website facebook.com
```

## Advanced Features

### VPN Management

YUNA can help you manage VPN connections:

#### Connecting to a VPN
```bash
yuna --vpn-connect /path/to/config.ovpn
```

#### Disconnecting from VPN
```bash
yuna --vpn-disconnect
```

#### Checking VPN Status
```bash
yuna --vpn-status
```

### GeoIP Filtering

YUNA can filter traffic based on geographic location:

```bash
# Block a country
yuna --block-country RU

# Allow a country
yuna --allow-country US
```

### Network Interface Management

```bash
# Add an interface to a zone
yuna --add-interface eth0 public

# Change the zone of an interface
yuna --change-zone eth0 trusted

# Remove an interface
yuna --remove-interface eth0
```

### NAT Configuration

```bash
# Configure NAT
yuna --configure-nat eth0 192.168.1.0/24

# Enable NAT
yuna --enable-nat eth0 192.168.1.0/24

# Disable NAT
yuna --disable-nat eth0 192.168.1.0/24
```

## Traffic Monitoring

### Viewing Traffic Statistics

```bash
yuna --traffic-stats
```

### Detecting Anomalies

YUNA continuously monitors network traffic for anomalies using its neural network. When an anomaly is detected, it will:
1. Log the event
2. Send a desktop notification
3. Take appropriate action (if configured)

To manually trigger anomaly detection:
```bash
yuna --detect-anomalies
```

### Training the Neural Network

YUNA's neural network learns from your network traffic patterns. To manually trigger training:
```bash
yuna --train-network
```

## Network Security

### Panic Mode

In case of emergency, you can activate panic mode to immediately block all traffic:
```bash
yuna --panic-mode
```

To disable panic mode:
```bash
yuna --disable-panic
```

### Scheduled Maintenance

You can schedule maintenance tasks:
```bash
yuna --schedule-maintenance "2023-12-31 23:59:59" "cleanupExpiredConnections,optimizeFirewallRules"
```

### Self-Healing

YUNA includes self-healing capabilities that can automatically detect and respond to threats:
```bash
yuna --auto-heal
```

## Troubleshooting

### Common Issues and Solutions

#### YUNA Fails to Start
```
Error: Unable to connect to D-Bus system bus
```
**Solution**: Ensure D-Bus is running and you have proper permissions:
```bash
sudo systemctl start dbus
```

#### Cannot Modify Firewall Rules
```
Error: Unable to add firewall rule
```
**Solution**: Make sure firewalld is running and you have sudo privileges:
```bash
sudo systemctl start firewalld
```

#### Neural Network Training Fails
```
Error: Insufficient data for training
```
**Solution**: Allow YUNA to collect more network data before training:
```bash
# Wait for more traffic data to accumulate, then:
yuna --train-network
```

### Log Files

YUNA keeps detailed logs to help troubleshoot issues:
```bash
# View the main log file
cat ~/FirewallManagerLogs/firewall_manager.log

# View panic mode events
cat ~/panic_modelog.txt
```

## FAQ

### Q: How does YUNA's neural network detect threats?
A: YUNA extracts features from network connections (packet rate, size, duration, port numbers) and uses a trained neural network to classify potential threats based on these patterns.

### Q: Does YUNA work with other firewalls like ufw or iptables?
A: YUNA primarily interfaces with firewalld, but can execute iptables commands directly for certain operations like NAT configuration.

### Q: Can I use YUNA on a desktop system?
A: Yes, YUNA works on both server and desktop environments. On desktop systems, it will display notifications for security events.

### Q: Is there a way to backup my firewall configuration?
A: Yes, use:
```bash
yuna --export-config /path/to/backup.conf
```
And restore with:
```bash
yuna --import-config /path/to/backup.conf
```

### Q: How resource-intensive is the neural network?
A: YUNA's neural network is designed to be lightweight. The training process may use more resources temporarily, but normal operation has minimal impact on system performance.

---

For more information or to report issues, please visit the GitHub repository or contact the developer.
