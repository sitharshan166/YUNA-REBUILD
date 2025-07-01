# YUNA - Advanced Firewall Management System

YUNA is an intelligent firewall management system that uses AI to detect threats and manage network security.

## Features

- Advanced firewall rule management
- Machine learning-based threat detection
- Real-time traffic monitoring
- Automatic anomaly detection
- VPN connection management
- GeoIP-based filtering
- System self-healing capabilities
- Scheduled maintenance

## Requirements

See `requirements.txt` for a complete list of dependencies.

## Installation

### Ubuntu/Debian

```bash
# Install Qt and system dependencies
sudo apt-get update
sudo apt-get install -y qt5-default libqt5dbus5 firewalld openvpn iptables

# Install D-Bus development libraries
sudo apt-get install -y libdbus-1-dev

# Build the application
cd YUNA-REBUILD
qmake YUNA.pro
make
```

### Fedora/CentOS

```bash
# Install Qt and system dependencies
sudo dnf install -y qt5-qtbase qt5-qtbase-devel firewalld openvpn iptables

# Install D-Bus development libraries
sudo dnf install -y dbus-devel

# Build the application
cd YUNA-REBUILD
qmake-qt5 YUNA.pro
make
```

### Build from Source

If you're having trouble with the MOC (Meta-Object Compiler), follow these steps:

```bash
# Manual build process
cd YUNA-REBUILD

# Generate the moc file for Qt classes with Q_OBJECT
moc YUNA.cpp -o moc_YUNA.cpp

# Compile the project
g++ -o YUNA YUNA.cpp moc_YUNA.cpp -I/usr/include/qt5 -I/usr/include/qt5/QtCore -I/usr/include/qt5/QtDBus -I/usr/include/qt5/QtNetwork -lQt5Core -lQt5DBus -lQt5Network -std=c++14
```

## Usage

```bash
# Run with default settings
./YUNA

# Run with specific options
./YUNA --block-website example.com

# Restore default configuration
./YUNA --restore-default

# Add a port to the firewall
./YUNA --add-port 8080 tcp
```

## Command Line Options

- `--restore-default`: Restore the default firewall configuration
- `--block-website <domain>`: Block a specific website domain
- `--add-port <port> <protocol>`: Add a port to the firewall
- `--remove-port <port> <protocol>`: Remove a port from the firewall

## Development

The project uses Qt with D-Bus for firewall management and contains a neural network for threat detection.

### Project Structure

- `YUNA.cpp`: Main application file
- `YUNA.pro`: Qt project file for building with qmake
- `firewallInterface.h`: D-Bus interface for firewall operations

