// SPDX-License-Identifier: GPL-2.0
/* MinIO Protection eBPF LSM Program
 *
 * This program uses LSM (Linux Security Module) BPF hooks to prevent
 * file deletions from unauthorized users while allowing MinIO to operate normally.
 *
 * Features:
 * - Blocks unlink/rmdir/rename operations from non-allowed UIDs
 * - Maintains whitelist of allowed UIDs (e.g., minio user)
 * - Tracks statistics (blocked/allowed operations)
 * - Real-time logging of blocked attempts
 *
 * Requirements:
 * - Kernel 5.7+ with CONFIG_BPF_LSM=y
 * - BTF enabled (CONFIG_DEBUG_INFO_BTF=y)
 * - lsm=bpf in kernel command line
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_ALLOWED_UIDS 32
#define EPERM 1  /* Operation not permitted */

/* Map: Allowed UIDs that can perform deletion operations
 * Key: UID (u32)
 * Value: 1 if allowed, 0 otherwise
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ALLOWED_UIDS);
	__type(key, __u32);
	__type(value, __u8);
} allowed_uids SEC(".maps");

/* Map: Per-UID statistics
 * Key: UID (u32)
 * Value: Number of blocked attempts
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} blocked_stats SEC(".maps");

/* Map: Global statistics
 * Index 0: Total blocked count
 * Index 1: Total allowed count
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} global_stats SEC(".maps");

enum {
	STAT_BLOCKED_TOTAL = 0,
	STAT_ALLOWED_TOTAL = 1,
};

/* Map: Configuration flags
 * Index 0: enable_protection (1 = active, 0 = disabled)
 * Index 1: log_allowed (1 = log allowed ops, 0 = only log blocked)
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u32);
} config_map SEC(".maps");

enum {
	CONFIG_ENABLE_PROTECTION = 0,
	CONFIG_LOG_ALLOWED = 1,
};

/* Check if protection is enabled */
static __always_inline bool is_protection_enabled(void)
{
	__u32 key = CONFIG_ENABLE_PROTECTION;
	__u32 *enabled = bpf_map_lookup_elem(&config_map, &key);
	return enabled && *enabled == 1;
}

/* Check if allowed operations should be logged */
static __always_inline bool should_log_allowed(void)
{
	__u32 key = CONFIG_LOG_ALLOWED;
	__u32 *log = bpf_map_lookup_elem(&config_map, &key);
	return log && *log == 1;
}

/* Update global statistics */
static __always_inline void update_global_stat(__u32 stat_type)
{
	__u64 *count = bpf_map_lookup_elem(&global_stats, &stat_type);
	if (count)
		__sync_fetch_and_add(count, 1);
}

/* Update per-UID blocked statistics */
static __always_inline void update_blocked_stat(__u32 uid)
{
	__u64 *count = bpf_map_lookup_elem(&blocked_stats, &uid);
	if (count) {
		__sync_fetch_and_add(count, 1);
	} else {
		__u64 initial = 1;
		bpf_map_update_elem(&blocked_stats, &uid, &initial, BPF_NOEXIST);
	}
}

/* Core deletion check logic */
static __always_inline int check_deletion_allowed(const char *op_name)
{
	/* If protection is disabled, allow everything */
	if (!is_protection_enabled())
		return 0;

	__u32 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

	/* Check if UID is in allowed list */
	__u8 *allowed = bpf_map_lookup_elem(&allowed_uids, &uid);
	if (allowed && *allowed == 1) {
		/* Update allowed counter */
		update_global_stat(STAT_ALLOWED_TOTAL);

		/* Optionally log allowed operations */
		if (should_log_allowed()) {
			char comm[16];
			bpf_get_current_comm(&comm, sizeof(comm));
			bpf_printk("ALLOWED %s: UID=%u comm=%s\n", op_name, uid,
				   comm);
		}

		return 0; /* Allow */
	}

	/* Block and log */
	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_printk("BLOCKED %s: UID=%u comm=%s\n", op_name, uid, comm);

	/* Update statistics */
	update_global_stat(STAT_BLOCKED_TOTAL);
	update_blocked_stat(uid);

	return -EPERM; /* Permission denied */
}

/* LSM Hook: inode_unlink
 * Called when a file is about to be unlinked
 */
SEC("lsm/inode_unlink")
int BPF_PROG(minio_protect_unlink, struct inode *dir, struct dentry *dentry,
	     int ret)
{
	/* If previous LSM already denied, respect that */
	if (ret != 0)
		return ret;

	return check_deletion_allowed("unlink");
}

/* LSM Hook: inode_rmdir
 * Called when a directory is about to be removed
 */
SEC("lsm/inode_rmdir")
int BPF_PROG(minio_protect_rmdir, struct inode *dir, struct dentry *dentry,
	     int ret)
{
	/* If previous LSM already denied, respect that */
	if (ret != 0)
		return ret;

	return check_deletion_allowed("rmdir");
}

/* LSM Hook: inode_rename
 * Called when a file/directory is about to be renamed
 * This is important because rename can effectively delete files
 * (when renaming over an existing file)
 */
SEC("lsm/inode_rename")
int BPF_PROG(minio_protect_rename, struct inode *old_dir,
	     struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry, int ret)
{
	/* If previous LSM already denied, respect that */
	if (ret != 0)
		return ret;

	return check_deletion_allowed("rename");
}

char LICENSE[] SEC("license") = "GPL";
