// SPDX-License-Identifier: GPL-2.0
/* MinIO Protection eBPF LSM Program
 *
 * SIMPLIFIED VERSION: Checks parent directory names instead of full path
 * This avoids complex path reconstruction and verifier issues.
 *
 * For path /tmp/clusterone1/.minio.sys/file.txt:
 * - We check if any parent directory matches protected prefix
 * - More practical for eBPF verifier limitations
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_ALLOWED_UIDS 32
#define MAX_PROTECTED_PATHS 16
#define MAX_PATH_LEN 256
#define EPERM 1  /* Operation not permitted */

/* Map: Allowed UIDs that can perform deletion operations */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ALLOWED_UIDS);
	__type(key, __u32);
	__type(value, __u8);
} allowed_uids SEC(".maps");

/* Map: Per-UID statistics */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} blocked_stats SEC(".maps");

/* Map: Global statistics */
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

/* Map: Configuration flags */
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

/* Path checking removed - Option B: Pure UID-based protection
 * We now simply protect ALL files owned by whitelisted UIDs, regardless of path.
 * This is much simpler, faster, and more secure. */

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

/* Core deletion check logic - SIMPLIFIED UID-ONLY PROTECTION
 * Simple rule: Only the owner (whitelisted UID) can delete their own files
 * No path checking needed! */
static __always_inline int check_deletion_allowed(const char *op_name, struct dentry *dentry, struct inode *inode)
{
	/* If protection is disabled, allow everything */
	if (!is_protection_enabled())
		return 0;

	/* Get process UID and file owner UID */
	__u32 process_uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	__u32 file_owner_uid = BPF_CORE_READ(inode, i_uid.val);

	/* Check if file is owned by a protected UID */
	__u8 *owner_protected = bpf_map_lookup_elem(&allowed_uids, &file_owner_uid);
	if (!owner_protected || *owner_protected != 1) {
		/* File is not owned by a protected UID - allow anyone to delete it */
		return 0;
	}

	/* File IS owned by a protected UID
	 * Only allow deletion if process UID matches file owner UID */
	if (process_uid == file_owner_uid) {
		/* Owner deleting their own file - allow */
		if (should_log_allowed()) {
			char comm[16];
			bpf_get_current_comm(&comm, sizeof(comm));
			bpf_printk("ALLOWED %s: UID=%u deleting own file\n",
				   op_name, process_uid);
		}
		return 0;
	}

	/* BLOCK: Someone trying to delete a file owned by protected UID */
	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));
	bpf_printk("BLOCKED %s: process_UID=%u trying to delete file owned by protected_UID=%u (comm=%s)\n",
		   op_name, process_uid, file_owner_uid, comm);

	/* Update statistics */
	update_global_stat(STAT_BLOCKED_TOTAL);
	update_blocked_stat(process_uid);

	return -EPERM; /* Permission denied */
}

/* LSM Hook: inode_unlink */
SEC("lsm/inode_unlink")
int BPF_PROG(minio_protect_unlink, struct inode *dir, struct dentry *dentry,
	     int ret)
{
	if (ret != 0)
		return ret;

	/* Get the inode being deleted to check its owner */
	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	if (!inode)
		return 0;

	return check_deletion_allowed("unlink", dentry, inode);
}

/* LSM Hook: inode_rmdir */
SEC("lsm/inode_rmdir")
int BPF_PROG(minio_protect_rmdir, struct inode *dir, struct dentry *dentry,
	     int ret)
{
	if (ret != 0)
		return ret;

	struct inode *inode = BPF_CORE_READ(dentry, d_inode);
	if (!inode)
		return 0;

	return check_deletion_allowed("rmdir", dentry, inode);
}

/* LSM Hook: inode_rename */
SEC("lsm/inode_rename")
int BPF_PROG(minio_protect_rename, struct inode *old_dir,
	     struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry, int ret)
{
	if (ret != 0)
		return ret;

	struct inode *inode = BPF_CORE_READ(old_dentry, d_inode);
	if (!inode)
		return 0;

	return check_deletion_allowed("rename", old_dentry, inode);
}

char LICENSE[] SEC("license") = "GPL";
