# MinIO Protection - eBPF LSM

**eBPF LSM-based deletion protection for MinIO storage**

Prevents accidental `rm -rf` operations on MinIO data directories while allowing normal MinIO operations using Linux Security Module (LSM) BPF hooks.

## How It Works

Uses LSM BPF hooks to intercept file deletion operations (`unlink`, `rmdir`, `rename`) at the kernel level:

```
User attempts: rm -rf /tmp/clusterone/data/*
      ↓
Kernel: sys_unlink() syscall
      ↓
LSM Hook: inode_unlink()
      ↓
eBPF Program: Check if path matches protected prefix
      ↓
   Protected path? → No → Allow operation
                  → Yes → Check UID against whitelist
                          ↓
                       Allowed UID? → Yes → Operation proceeds
                                    → No  → Return -EPERM (blocked)
```

**Key Features**:
- **Path-based filtering**: Only protects specified paths (e.g., `/tmp/clusterone*`, `/mnt/disk1*`)
- **UID whitelist**: Allows only specific UIDs (e.g., MinIO service user) to delete files in protected paths
- **Kernel-level enforcement**: eBPF LSM hooks run BEFORE the filesystem operation, blocking deletions without any filesystem-level restrictions

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

# Protect files under 'clusterone1' directory, allow only UID 1000
sudo .output/minio_protect -u 1000 -p clusterone1

# Protect multiple directories (comma-separated)
sudo .output/minio_protect -u 1000 -p clusterone1,clusterone2,clusterone3

# With verbose logging and stats every 10 seconds
sudo .output/minio_protect -u 1000 -p clusterone1 -v -s 10
```

**IMPORTANT**: Pass only the directory name (e.g., `clusterone1`), NOT the full path (e.g., `/tmp/clusterone1`). The protection works by checking parent directory names in the file path. If you specify `-p clusterone1`, it will protect any file whose parent directory tree contains a directory named "clusterone1", regardless of where it is located (e.g., `/tmp/clusterone1/file.txt`, `/mnt/clusterone1/data/file.txt`).

**Option B: Install and run as systemd service**
```bash
# Install binary
sudo make install

# Create service file: /etc/systemd/system/minio-protect.service
sudo nano /etc/systemd/system/minio-protect.service
```

Service file content (replace UID and paths with your configuration):
```ini
[Unit]
Description=MinIO Protection eBPF LSM Service
After=network.target

[Service]
Type=simple
Restart=on-failure
RestartSec=5s
ExecStart=/usr/local/bin/minio_protect -u 1000 -p clusterone1,clusterone2,clusterone3 -s 300
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

# Test protection on protected path (terminal 2)
# Assuming you ran: sudo .output/minio_protect -u 1000 -p clusterone1
sudo mkdir -p /tmp/clusterone1
sudo touch /tmp/clusterone1/test.txt
sudo rm /tmp/clusterone1/test.txt
# Should see "BLOCKED unlink: UID=0" in terminal 1 (blocked because UID 0 != 1000)

# Test non-protected path (should work normally)
sudo touch /tmp/test.txt
sudo rm /tmp/test.txt
# Should succeed without blocking
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

## Known Limitations & TODO

### Current Limitation: Directory Name Matching Only

**Issue**: The current implementation only matches directory names, not full paths. This means:
- If you specify `-p clusterone1`, it will protect ANY file with `clusterone1` in its parent path
- Examples of what gets protected:
  - `/tmp/clusterone1/file.txt` ✓ (intended)
  - `/home/user/clusterone1/file.txt` ✓ (NOT intended!)
  - `/mnt/clusterone1/data.txt` ✓ (NOT intended!)

**Why**: To avoid eBPF verifier complexity limits, we simplified the path checking logic to only compare individual directory names instead of reconstructing full paths.

**TODO**: Implement proper full path matching using `bpf_d_path()` helper function (available in kernel 5.10+):
- Accept full paths like `-p /tmp/clusterone1`
- Match only files under that exact path prefix
- Use BPF helper to avoid manual path reconstruction loops
- Should eliminate verifier complexity issues while providing precise path matching

**Workaround**: Use unique directory names that won't appear elsewhere on your system (e.g., `minio-cluster1-data` instead of `clusterone1`).

## License

GPL-2.0
