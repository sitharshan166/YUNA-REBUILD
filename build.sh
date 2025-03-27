#!/bin/bash

echo "Building YUNA Firewall Manager..."

# Check if qmake is installed
if ! command -v qmake &> /dev/null; then
    echo "qmake could not be found. Please install Qt5 development packages."
    exit 1
fi

# Check if make is installed
if ! command -v make &> /dev/null; then
    echo "make could not be found. Please install build tools."
    exit 1
fi

# Clean any previous build artifacts
if [ -f Makefile ]; then
    echo "Cleaning previous build..."
    make clean
    rm -f Makefile
fi

# Run qmake to generate Makefile
echo "Running qmake..."
qmake

# Build the project
echo "Compiling..."
make

# Check if build was successful
if [ -f YUNA ]; then
    echo "Build successful! You can run YUNA with: ./YUNA"
    # Make it executable
    chmod +x YUNA
else
    echo "Build failed. Please check the error messages above."
    exit 1
fi

exit 0
