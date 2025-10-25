# MinIO Protection - eBPF LSM

**eBPF LSM-based UID protection for MinIO storage**

Prevents accidental deletion of MinIO files by unauthorized users using Linux Security Module (LSM) BPF hooks. Simple rule: **only the file owner can delete their own files**.

## Quickstart

Deploy MinIO protection in one command:

```bash
# Get MinIO user UID
id -u minio

# Deploy protection (replace 1000 with your MinIO UID)
sudo ./deploy.sh -u 1000
```

That's it! The script will:
- ✓ Check kernel requirements (LSM BPF, BTF support)
- ✓ Install dependencies (clang, bpftool, libbpf, etc.)
- ✓ Build the eBPF program
- ✓ Install as systemd service
- ✓ Start protection immediately

Monitor protection in action:
```bash
# View blocked operations in real-time
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep minio_protect

# Check service status
sudo systemctl status minio-protect
```

## How It Works

Uses LSM BPF hooks to intercept file deletion operations (`unlink`, `rmdir`, `rename`) at the kernel level:

```
User attempts: rm /path/to/minio-file.txt
      ↓
Kernel: sys_unlink() syscall
      ↓
LSM Hook: inode_unlink()
      ↓
eBPF Program: Check file owner UID
      ↓
   File owner is protected UID? → No → Allow operation
                                → Yes → Check if deleter is owner
                                        ↓
                                     Same UID? → Yes → Allow
                                              → No  → BLOCK (-EPERM)
```

**Key Features**:
- **UID-based protection**: Protects ALL files owned by whitelisted UIDs (e.g., MinIO service user)
- **Simple and fast**: Only 2 UID checks - no complex path matching
- **Location-independent**: Protection follows the files, not paths
- **Kernel-level enforcement**: eBPF LSM hooks run BEFORE the filesystem operation, blocking deletions instantly

## Requirements

- **Kernel**: 5.7+ with LSM BPF enabled
- **Kernel command line**: Must include `lsm=bpf`
- **Build tools**: clang, bpftool, libbpf-devel, kernel-devel

```bash
# Install dependencies (Fedora/RHEL)
sudo dnf install clang bpftool libbpf-devel kernel-devel
```

## Setup Guide

**For automated deployment, use the [Quickstart](#quickstart) section above with `deploy.sh`**

For manual setup, follow these steps:

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

# Protect all files owned by UID 1000 (MinIO user)
sudo .output/minio_protect -u 1000

# Protect files owned by multiple UIDs
sudo .output/minio_protect -u 1000 -u 1001 -u 1002

# With verbose logging and stats every 10 seconds
sudo .output/minio_protect -u 1000 -v -s 10
```

**How it works**: Any file owned by the protected UID can ONLY be deleted by that same UID. Any other user (including root) trying to delete these files will be blocked.

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
# By default, only BLOCKED operations are logged
# Use -v flag to also see ALLOWED operations
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep minio_protect

# Test protection (terminal 2)
# Run without -v to see only BLOCKED logs (recommended for production)
# Run with -v to see both BLOCKED and ALLOWED logs (useful for debugging)
sudo .output/minio_protect -u 1000
# Create a file owned by UID 1000
sudo -u '#1000' touch /tmp/minio-test.txt

# Try to delete as root - should be BLOCKED
sudo rm /tmp/minio-test.txt
# Should see "BLOCKED unlink: process_UID=0" in terminal 1

# Try to delete as owner - should succeed (no log unless -v is used)
sudo -u '#1000' rm /tmp/minio-test.txt
# Should succeed silently (or see "ALLOWED" if you used -v flag)
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

Using deploy script (recommended):
```bash
sudo ./deploy.sh --uninstall
```

Or manually:
```bash
sudo systemctl stop minio-protect
sudo systemctl disable minio-protect
sudo rm /etc/systemd/system/minio-protect.service
sudo rm /usr/local/bin/minio_protect
sudo systemctl daemon-reload
```

## Implementation Details

### UID-Based Protection (Simplified Approach)

The implementation uses a pure UID-based protection model:

**How it works**:
1. Check if the file being deleted is owned by a protected UID
2. If yes, check if the process trying to delete is the same UID
3. Block if UIDs don't match

**Advantages**:
- **Extremely fast**: Only 2 UID checks (no path walking, no string comparisons)
- **No eBPF verifier issues**: Simple logic that always passes verification
- **Location-independent**: Protection follows the files wherever they are
- **No false positives**: Only protects files actually owned by MinIO

**Performance**: ~200ns per operation (vs ~10,000ns for path-based checking)

**Logging Behavior**:
- **Default (without `-v`)**: Only BLOCKED operations are logged - clean output for production
- **Verbose mode (`-v`)**: Both BLOCKED and ALLOWED operations are logged - useful for debugging
- **Recommendation**: Use verbose mode only during testing, then run without `-v` in production

**Use Case**: Perfect for MinIO where all data files are owned by the MinIO service user. Since MinIO runs as a dedicated user, protecting all files owned by that UID provides complete protection without needing to know file locations.

## License

GPL-2.0
