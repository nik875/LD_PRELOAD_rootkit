#!/bin/bash

# Define the source and destination directories
SOURCE_DIR="$(dirname "$0")/binary_filters"
DEST_DIR="/usr/bin"

# Check if the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root." >&2
    exit 1
fi

# Iterate over each file in the binary_filters directory
for binary in "$SOURCE_DIR"/*; do
    # Extract the binary name (e.g., "apt", "dpkg")
    binary_name=$(basename "$binary")

    # Check if the binary exists in /usr/bin
    if [ -f "$DEST_DIR/$binary_name" ]; then
        echo "Found $DEST_DIR/$binary_name. Backing up and replacing..."

        # Backup the original binary as binary_name.organ
        if [ ! -f "$DEST_DIR/$binary_name.organ" ]; then
            mv "$DEST_DIR/$binary_name" "$DEST_DIR/$binary_name.organ"
            echo "Backed up original binary to $DEST_DIR/$binary_name.organ"
        else
            echo "Backup $DEST_DIR/$binary_name.organ already exists. Skipping backup."
        fi

        # Copy the filtered binary to /usr/bin
        cp "$binary" "$DEST_DIR/$binary_name"
        chmod 755 "$DEST_DIR/$binary_name"
        echo "Installed filtered binary: $DEST_DIR/$binary_name"
    else
        echo "Warning: $DEST_DIR/$binary_name does not exist. Skipping."
    fi
done

echo "Installation complete."

