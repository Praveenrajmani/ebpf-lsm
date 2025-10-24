#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# MinIO Protection Deployment Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="${SCRIPT_DIR}/.output/minio_protect"
INSTALL_PATH="/usr/local/bin/minio_protect"
SERVICE_FILE="${SCRIPT_DIR}/minio-protect.service"
SERVICE_INSTALL_PATH="/etc/systemd/system/minio-protect.service"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
}

# Check kernel requirements
check_kernel() {
    log_info "Checking kernel requirements..."

    local kernel_version=$(uname -r)
    local major=$(echo "$kernel_version" | cut -d. -f1)
    local minor=$(echo "$kernel_version" | cut -d. -f2)

    log_info "Kernel version: $kernel_version"

    # Check if kernel is 5.7+
    if [ "$major" -lt 5 ] || ([ "$major" -eq 5 ] && [ "$minor" -lt 7 ]); then
        log_error "Kernel 5.7+ required for eBPF LSM support"
        exit 1
    fi

    # Check if LSM BPF is enabled
    if [ -f /sys/kernel/security/lsm ]; then
        local lsm_list=$(cat /sys/kernel/security/lsm)
        log_info "Active LSMs: $lsm_list"

        if echo "$lsm_list" | grep -q "bpf"; then
            log_info "✓ LSM BPF is enabled"
        else
            log_error "✗ LSM BPF is NOT enabled"
            log_error ""
            log_error "To enable LSM BPF:"
            log_error "  1. Edit /etc/default/grub"
            log_error "  2. Add 'lsm=bpf' to GRUB_CMDLINE_LINUX"
            log_error "     Example: GRUB_CMDLINE_LINUX=\"... lsm=bpf\""
            log_error "  3. Rebuild grub config:"
            log_error "     grub2-mkconfig -o /boot/grub2/grub.cfg"
            log_error "  4. Reboot"
            exit 1
        fi
    else
        log_warn "/sys/kernel/security/lsm not found"
    fi

    # Check BTF support
    if [ -f /sys/kernel/btf/vmlinux ]; then
        log_info "✓ BTF support available"
    else
        log_warn "✗ BTF support not found (may cause issues)"
    fi
}

# Build the program
build_program() {
    log_info "Building minio_protect..."

    cd "$SCRIPT_DIR"
    make clean
    make

    if [ ! -f "$BINARY" ]; then
        log_error "Build failed: $BINARY not found"
        exit 1
    fi

    log_info "✓ Build successful"
}

# Install the binary
install_binary() {
    log_info "Installing binary to $INSTALL_PATH..."

    install -m 0755 "$BINARY" "$INSTALL_PATH"

    log_info "✓ Binary installed"
}

# Detect MinIO UID
detect_minio_uid() {
    local minio_uid=""

    # Try to find minio-user user
    if id minio-user &>/dev/null; then
        minio_uid=$(id -u minio-user)
        log_info "Found minio-user with UID: $minio_uid"
    # Try to find minio user
    elif id minio &>/dev/null; then
        minio_uid=$(id -u minio)
        log_info "Found minio with UID: $minio_uid"
    else
        log_warn "Could not auto-detect MinIO user"
        read -p "Enter MinIO UID (or press Enter to use 1000): " minio_uid
        minio_uid=${minio_uid:-1000}
    fi

    echo "$minio_uid"
}

# Install systemd service
install_service() {
    local minio_uid=$1

    log_info "Installing systemd service..."

    # Create service file with correct UID
    cat > "$SERVICE_INSTALL_PATH" <<EOF
[Unit]
Description=MinIO Protection eBPF LSM Service
Documentation=https://github.com/miniohq/ebpf-lsm
After=network.target
Wants=network.target

[Service]
Type=simple
Restart=on-failure
RestartSec=5s

# Run as root (required for eBPF)
User=root
Group=root

# Binary location (auto-configured by deploy.sh)
ExecStart=$INSTALL_PATH -u $minio_uid -s 300

# Security hardening
NoNewPrivileges=false
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/sys/fs/bpf

# Resource limits
LimitNOFILE=65536
LimitMEMLOCK=infinity

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=minio-protect

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd
    systemctl daemon-reload

    log_info "✓ Service installed"
}

# Start and enable service
enable_service() {
    log_info "Enabling and starting minio-protect.service..."

    systemctl enable minio-protect.service
    systemctl start minio-protect.service

    sleep 2

    # Check status
    if systemctl is-active --quiet minio-protect.service; then
        log_info "✓ Service is running"
    else
        log_error "Service failed to start"
        log_error "Check logs: journalctl -u minio-protect.service -n 50"
        exit 1
    fi
}

# Show status
show_status() {
    log_info ""
    log_info "==================================="
    log_info "MinIO Protection Status"
    log_info "==================================="
    systemctl status minio-protect.service --no-pager || true
    log_info ""
    log_info "Recent logs:"
    journalctl -u minio-protect.service -n 10 --no-pager || true
}

# Main deployment
main() {
    log_info "==================================="
    log_info "MinIO Protection Deployment"
    log_info "==================================="
    log_info ""

    check_root
    check_kernel
    build_program
    install_binary

    local minio_uid=$(detect_minio_uid)

    install_service "$minio_uid"
    enable_service
    show_status

    log_info ""
    log_info "==================================="
    log_info "Deployment Complete!"
    log_info "==================================="
    log_info ""
    log_info "MinIO Protection is now active and will:"
    log_info "  ✓ Allow UID $minio_uid to delete files"
    log_info "  ✗ Block all other users (including root)"
    log_info ""
    log_info "Useful commands:"
    log_info "  systemctl status minio-protect   - Check status"
    log_info "  journalctl -u minio-protect -f   - Follow logs"
    log_info "  systemctl stop minio-protect     - Stop protection"
    log_info "  systemctl start minio-protect    - Start protection"
    log_info "  dmesg | grep BLOCKED             - See blocked attempts"
    log_info ""
}

# Handle script arguments
case "${1:-}" in
    --uninstall)
        check_root
        log_info "Uninstalling MinIO Protection..."
        systemctl stop minio-protect.service 2>/dev/null || true
        systemctl disable minio-protect.service 2>/dev/null || true
        rm -f "$SERVICE_INSTALL_PATH"
        rm -f "$INSTALL_PATH"
        systemctl daemon-reload
        log_info "✓ Uninstallation complete"
        ;;
    --status)
        show_status
        ;;
    --help)
        echo "MinIO Protection Deployment Script"
        echo ""
        echo "Usage: $0 [option]"
        echo ""
        echo "Options:"
        echo "  (none)       Deploy and start MinIO Protection"
        echo "  --uninstall  Remove MinIO Protection"
        echo "  --status     Show current status"
        echo "  --help       Show this help message"
        echo ""
        ;;
    "")
        main
        ;;
    *)
        log_error "Unknown option: $1"
        log_error "Use --help for usage information"
        exit 1
        ;;
esac
