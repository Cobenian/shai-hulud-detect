#!/bin/bash
# Shai-Hulud Detector v1.0.0 Installation Script

set -e

echo "🦀 Installing Shai-Hulud Detector v1.0.0..."

# Check if binary exists
if [ ! -f "shai-hulud-detector" ]; then
    echo "❌ Error: shai-hulud-detector binary not found in current directory"
    echo "Please download the complete release package"
    exit 1
fi

# Check if compromised-packages.txt exists
if [ ! -f "compromised-packages.txt" ]; then
    echo "❌ Error: compromised-packages.txt not found in current directory"
    echo "Please download the complete release package"
    exit 1
fi

# Make binary executable
chmod +x shai-hulud-detector

# Test the binary
echo "🧪 Testing installation..."
if ./shai-hulud-detector --help > /dev/null 2>&1; then
    echo "✅ Installation successful!"
    echo ""
    echo "📋 Usage:"
    echo "  ./shai-hulud-detector /path/to/scan"
    echo "  ./shai-hulud-detector --paranoid /path/to/scan"
    echo ""
    echo "📚 For more information, see README.md"
    echo ""
    echo "🛡️  Ready to detect Shai-Hulud and crypto theft attacks!"
else
    echo "❌ Installation test failed"
    echo "The binary may not be compatible with your system"
    exit 1
fi
