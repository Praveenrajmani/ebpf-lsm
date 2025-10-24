# MinIO Protection - eBPF LSM

**eBPF LSM-based deletion protection for MinIO storage**

Prevents accidental `rm -rf` operations on MinIO data directories while allowing normal MinIO operations using Linux Security Module (LSM) BPF hooks.

## How It Works

Uses LSM BPF hooks to intercept file deletion operations (`unlink`, `rmdir`, `rename`) at the kernel level:

```
User attempts: rm -rf /mnt/disk1/data/*
      ↓
Kernel: sys_unlink() syscall
      ↓
LSM Hook: inode_unlink()
      ↓
eBPF Program: Check UID against whitelist
      ↓
   Allowed UID? → Yes → Operation proceeds
                → No  → Return -EPERM (blocked)
```

**Key Insight**: eBPF LSM hooks run BEFORE the actual filesystem operation, allowing us to block deletions without any filesystem-level restrictions.

## Requirements

- **Kernel**: 5.7+ with LSM BPF enabled
- **Kernel command line**: Must include `lsm=bpf`
- **Build tools**: clang, bpftool, libbpf-devel, kernel-devel

```bash
# Install dependencies (Fedora/RHEL)
sudo dnf install clang bpftool libbpf-devel kernel-devel
```

## Setup Guide

### Step 1: Check Kernel Requirements

```bash
# Check kernel version (need 5.7+)
uname -r

# Check if LSM BPF is enabled (must show 'bpf')
cat /sys/kernel/security/lsm | grep bpf

# Check BTF support (file should exist)
ls /sys/kernel/btf/vmlinux

# Run automated check
make check-kernel
```

**If LSM BPF is not enabled:**
```bash
# 1. Edit /etc/default/grub and add lsm=bpf to GRUB_CMDLINE_LINUX
sudo nano /etc/default/grub
# Add: GRUB_CMDLINE_LINUX="... lsm=bpf"

# 2. Rebuild grub
sudo grub2-mkconfig -o /boot/grub2/grub.cfg

# 3. Reboot
sudo reboot

# 4. Verify
cat /sys/kernel/security/lsm | grep bpf
```

### Step 2: Check Build Tools

```bash
make check-tools
```

### Step 3: Build the Module

```bash
# Clean and build
make clean
make
```

### Step 4: Load and Run the Module

**Option A: Run directly (foreground)**
```bash
# Find MinIO user UID
id minio-user  # or: id minio

# Run with MinIO UID (example: 1000)
sudo .output/minio_protect -u 1000

# With verbose logging and stats every 10 seconds
sudo .output/minio_protect -u 1000 -v -s 10
```

**Option B: Install and run as systemd service**
```bash
# Install binary
sudo make install

# Create service file: /etc/systemd/system/minio-protect.service
sudo nano /etc/systemd/system/minio-protect.service
```

Service file content (replace UID 1000 with your MinIO UID):
```ini
[Unit]
Description=MinIO Protection eBPF LSM Service
After=network.target

[Service]
Type=simple
Restart=on-failure
RestartSec=5s
ExecStart=/usr/local/bin/minio_protect -u 1000 -s 300
LimitMEMLOCK=infinity
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl start minio-protect
sudo systemctl enable minio-protect
sudo systemctl status minio-protect
```

### Step 5: Verify It's Working

```bash
# Check if eBPF programs are loaded
sudo bpftool prog list | grep minio

# Monitor real-time logs (terminal 1)
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep -E 'BLOCKED|ALLOWED'

# Test protection (terminal 2)
sudo touch /tmp/test.txt
sudo rm /tmp/test.txt
# Should see "BLOCKED unlink: UID=0" in terminal 1
```

## Service Management

```bash
# Check status
sudo systemctl status minio-protect

# View logs
sudo journalctl -u minio-protect -f

# Stop protection
sudo systemctl stop minio-protect

# Start protection
sudo systemctl start minio-protect

# Restart after config changes
sudo systemctl daemon-reload
sudo systemctl restart minio-protect
```

## Runtime Control

```bash
# Disable protection temporarily
echo 0 | sudo tee /sys/fs/bpf/minio_protect_config/enable

# Re-enable protection
echo 1 | sudo tee /sys/fs/bpf/minio_protect_config/enable

# View real-time logs
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep -E 'BLOCKED|ALLOWED'
```

## Troubleshooting

```bash
# Check if LSM BPF is enabled
cat /sys/kernel/security/lsm | grep bpf

# Check if BTF support exists
ls /sys/kernel/btf/vmlinux

# Check if program is loaded
sudo bpftool prog list | grep minio

# Check if service is running
sudo systemctl status minio-protect

# Check if protection is enabled
cat /sys/fs/bpf/minio_protect_config/enable
```

## Uninstall

```bash
sudo systemctl stop minio-protect
sudo systemctl disable minio-protect
sudo rm /etc/systemd/system/minio-protect.service
sudo rm /usr/local/bin/minio_protect
sudo systemctl daemon-reload
```

## License

GPL-2.0
