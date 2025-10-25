#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# MinIO Protection - Deployment Script
#
# This script automates the deployment of MinIO eBPF LSM protection:
# - Checks kernel requirements
# - Installs dependencies
# - Builds the eBPF program
# - Installs and configures systemd service

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROTECTED_UID=""
SERVICE_NAME="minio-protect"
INSTALL_PATH="/usr/local/bin/minio_protect"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

# Print functions
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

# Print usage
usage() {
    cat << EOF
MinIO Protection - Deployment Script

Usage: $0 -u <UID> [options]

Required:
  -u, --uid UID          UID to protect (MinIO user UID)

Options:
  -h, --help             Show this help message
  --uninstall            Uninstall the protection service
  --no-start             Don't start the service after installation

Examples:
  # Deploy and protect UID 1000
  sudo $0 -u 1000

  # Deploy without starting service
  sudo $0 -u 1000 --no-start

  # Uninstall
  sudo $0 --uninstall

EOF
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check kernel requirements
check_kernel() {
    print_header "Checking Kernel Requirements"

    # Check kernel version (need 5.7+)
    local kernel_version=$(uname -r | cut -d. -f1,2)
    local major=$(echo $kernel_version | cut -d. -f1)
    local minor=$(echo $kernel_version | cut -d. -f2)

    print_info "Kernel version: $(uname -r)"

    if [ "$major" -lt 5 ] || ([ "$major" -eq 5 ] && [ "$minor" -lt 7 ]); then
        print_error "Kernel 5.7+ required for eBPF LSM support (current: $(uname -r))"
        exit 1
    fi
    print_success "Kernel version is sufficient"

    # Check if BPF LSM is enabled
    if ! grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
        print_error "BPF LSM not enabled in kernel"
        print_info "Add 'lsm=...,bpf' to kernel boot parameters"
        exit 1
    fi
    print_success "BPF LSM is enabled"

    # Check BTF support
    if [ ! -f /sys/kernel/btf/vmlinux ]; then
        print_error "BTF (BPF Type Format) not available"
        print_info "Rebuild kernel with CONFIG_DEBUG_INFO_BTF=y"
        exit 1
    fi
    print_success "BTF support available"

    # Check debugfs (for trace_pipe)
    if [ ! -d /sys/kernel/debug/tracing ]; then
        print_warning "debugfs not mounted, mounting now..."
        mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
    fi
    print_success "All kernel requirements met"
}

# Install dependencies
install_dependencies() {
    print_header "Installing Dependencies"

    # Detect package manager
    if command -v dnf &> /dev/null; then
        PKG_MGR="dnf"
    elif command -v yum &> /dev/null; then
        PKG_MGR="yum"
    elif command -v apt-get &> /dev/null; then
        PKG_MGR="apt-get"
    else
        print_error "Unsupported package manager"
        exit 1
    fi

    print_info "Using package manager: $PKG_MGR"

    # Required packages
    local packages=(
        "clang"
        "llvm"
        "make"
        "gcc"
        "bpftool"
        "libbpf-devel"
        "elfutils-libelf-devel"
        "zlib-devel"
        "kernel-devel"
    )

    # Adjust package names for Debian/Ubuntu
    if [ "$PKG_MGR" = "apt-get" ]; then
        packages=(
            "clang"
            "llvm"
            "make"
            "gcc"
            "linux-tools-common"
            "linux-tools-$(uname -r)"
            "libbpf-dev"
            "libelf-dev"
            "zlib1g-dev"
            "linux-headers-$(uname -r)"
        )
    fi

    print_info "Installing required packages..."

    case $PKG_MGR in
        dnf|yum)
            $PKG_MGR install -y "${packages[@]}"
            ;;
        apt-get)
            apt-get update
            apt-get install -y "${packages[@]}"
            ;;
    esac

    print_success "Dependencies installed"
}

# Build the program
build_program() {
    print_header "Building MinIO Protection"

    # Check if Makefile exists
    if [ ! -f Makefile ]; then
        print_error "Makefile not found. Are you in the correct directory?"
        exit 1
    fi

    # Run make check-kernel first
    print_info "Running kernel checks..."
    if ! make check-kernel; then
        print_error "Kernel check failed"
        exit 1
    fi

    # Clean previous builds
    print_info "Cleaning previous builds..."
    make clean

    # Build
    print_info "Building eBPF program..."
    if ! make; then
        print_error "Build failed"
        exit 1
    fi

    # Verify binary exists
    if [ ! -f .output/minio_protect ]; then
        print_error "Binary not found after build"
        exit 1
    fi

    print_success "Build completed successfully"
}

# Install the binary
install_binary() {
    print_header "Installing Binary"

    print_info "Installing to $INSTALL_PATH"
    cp .output/minio_protect "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"

    print_success "Binary installed"
}

# Create systemd service
create_service() {
    print_header "Creating Systemd Service"

    if [ -z "$PROTECTED_UID" ]; then
        print_error "Protected UID not specified"
        exit 1
    fi

    print_info "Creating service file: $SERVICE_PATH"

    cat > "$SERVICE_PATH" << EOF
[Unit]
Description=MinIO eBPF LSM Protection
Documentation=https://github.com/minio/ebpf-lsm
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_PATH -u $PROTECTED_UID -s 300
Restart=always
RestartSec=10

# Security settings
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_BPF CAP_PERFMON
AmbientCapabilities=CAP_SYS_ADMIN CAP_BPF CAP_PERFMON

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=minio-protect

[Install]
WantedBy=multi-user.target
EOF

    print_success "Service file created"
    print_info "Protected UID: $PROTECTED_UID"
}

# Enable and start service
enable_service() {
    print_header "Enabling Service"

    print_info "Reloading systemd daemon..."
    systemctl daemon-reload

    print_info "Enabling service..."
    systemctl enable "$SERVICE_NAME"

    if [ "$NO_START" != "true" ]; then
        print_info "Starting service..."
        systemctl start "$SERVICE_NAME"

        # Wait a moment for service to start
        sleep 2

        # Check status
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            print_success "Service started successfully"
            print_info "Check status: sudo systemctl status $SERVICE_NAME"
            print_info "View logs: sudo journalctl -u $SERVICE_NAME -f"
            print_info "Monitor blocks: sudo cat /sys/kernel/debug/tracing/trace_pipe | grep minio_protect"
        else
            print_error "Service failed to start"
            print_info "Check logs: sudo journalctl -u $SERVICE_NAME -xe"
            exit 1
        fi
    else
        print_info "Service enabled but not started (--no-start specified)"
        print_info "Start manually: sudo systemctl start $SERVICE_NAME"
    fi
}

# Uninstall
uninstall() {
    print_header "Uninstalling MinIO Protection"

    print_info "Stopping service..."
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true

    print_info "Disabling service..."
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true

    print_info "Removing service file..."
    rm -f "$SERVICE_PATH"

    print_info "Removing binary..."
    rm -f "$INSTALL_PATH"

    print_info "Reloading systemd daemon..."
    systemctl daemon-reload

    print_success "Uninstallation complete"
    exit 0
}

# Print deployment summary
print_summary() {
    print_header "Deployment Summary"

    cat << EOF
${GREEN}MinIO Protection successfully deployed!${NC}

Protected UID: ${YELLOW}$PROTECTED_UID${NC}
Service Name: $SERVICE_NAME
Binary Path: $INSTALL_PATH

${BLUE}Quick Commands:${NC}
  Check status:    sudo systemctl status $SERVICE_NAME
  View logs:       sudo journalctl -u $SERVICE_NAME -f
  Monitor blocks:  sudo cat /sys/kernel/debug/tracing/trace_pipe | grep minio_protect
  Stop service:    sudo systemctl stop $SERVICE_NAME
  Start service:   sudo systemctl start $SERVICE_NAME
  Restart service: sudo systemctl restart $SERVICE_NAME

${BLUE}How It Works:${NC}
  • Files owned by UID $PROTECTED_UID can only be deleted by UID $PROTECTED_UID
  • Any other UID attempting to delete these files will be blocked
  • Only BLOCKED operations are logged (use -v in service file for verbose mode)

${BLUE}Test Protection:${NC}
  # Create a test file owned by protected UID
  sudo -u '#$PROTECTED_UID' touch /tmp/test-protected.txt

  # Try to delete as root (should be BLOCKED)
  sudo rm /tmp/test-protected.txt

  # Check logs for BLOCKED message
  sudo cat /sys/kernel/debug/tracing/trace_pipe | grep -i blocked

EOF
}

# Main deployment flow
main() {
    local UNINSTALL=false
    NO_START=false

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--uid)
                PROTECTED_UID="$2"
                shift 2
                ;;
            --uninstall)
                UNINSTALL=true
                shift
                ;;
            --no-start)
                NO_START=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                ;;
        esac
    done

    # Check if root
    check_root

    # Handle uninstall
    if [ "$UNINSTALL" = true ]; then
        uninstall
    fi

    # Validate UID is provided
    if [ -z "$PROTECTED_UID" ]; then
        print_error "Protected UID not specified"
        usage
    fi

    # Validate UID is a number
    if ! [[ "$PROTECTED_UID" =~ ^[0-9]+$ ]]; then
        print_error "Invalid UID: $PROTECTED_UID (must be a number)"
        exit 1
    fi

    print_header "MinIO Protection Deployment"
    print_info "Deploying protection for UID: $PROTECTED_UID"

    # Run deployment steps
    check_kernel
    install_dependencies
    build_program
    install_binary
    create_service
    enable_service

    print_summary
}

# Run main function
main "$@"
