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

/* Map: Protected path prefixes */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_PROTECTED_PATHS);
	__type(key, __u32);
	__type(value, char[MAX_PATH_LEN]);
} protected_paths SEC(".maps");

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

/* Simple string comparison for path prefixes (up to 32 chars to avoid verifier issues) */
static __always_inline bool path_starts_with(const char *name, const char *prefix)
{
	#pragma unroll
	for (int i = 0; i < 32; i++) {
		if (prefix[i] == '\0')
			return true;  /* Reached end of prefix, it's a match */
		if (name[i] == '\0')
			return false; /* Name ended before prefix */
		if (name[i] != prefix[i])
			return false; /* Mismatch */
	}
	return true; /* All 32 chars matched */
}

/* Check if dentry or any parent matches protected path
 * We walk up parent directories checking each one */
static __always_inline bool is_protected_path(struct dentry *dentry)
{
	struct dentry *current = dentry;
	struct dentry *parent;
	struct qstr d_name;
	char name_buf[32];  /* Reduced to 32 to match string comparison limit */

	/* Walk up to 4 levels checking each directory name (reduced from 6) */
	#pragma unroll
	for (int level = 0; level < 4; level++) {
		if (!current)
			break;

		/* Read dentry name */
		int err = bpf_probe_read_kernel(&d_name, sizeof(d_name), &current->d_name);
		if (err)
			break;

		/* Copy name to buffer */
		err = bpf_probe_read_kernel_str(name_buf, sizeof(name_buf), d_name.name);
		if (err < 0)
			break;

		/* Debug: print the directory name we're checking */
		bpf_printk("Checking dir level %d: %s\n", level, name_buf);

		/* Check this directory name against all protected prefixes (reduced from 16 to 8) */
		#pragma unroll
		for (int i = 0; i < 8; i++) {
			__u32 idx = i;
			char *prefix = bpf_map_lookup_elem(&protected_paths, &idx);
			if (!prefix || prefix[0] == '\0')
				break;

			/* Debug: print what we're comparing */
			bpf_printk("Comparing '%s' with prefix '%s'\n", name_buf, prefix);

			/* Check if name starts with prefix */
			if (path_starts_with(name_buf, prefix)) {
				bpf_printk("MATCH FOUND!\n");
				return true;
			}
		}

		/* Move to parent */
		err = bpf_probe_read_kernel(&parent, sizeof(parent), &current->d_parent);
		if (err || parent == current)
			break;

		current = parent;
	}

	bpf_printk("No match found\n");
	return false;
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
static __always_inline int check_deletion_allowed(const char *op_name, struct dentry *dentry)
{
	/* If protection is disabled, allow everything */
	if (!is_protection_enabled())
		return 0;

	/* Check if this path is protected */
	if (!is_protected_path(dentry)) {
		/* Not a protected path, allow operation */
		return 0;
	}

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

/* LSM Hook: inode_unlink */
SEC("lsm/inode_unlink")
int BPF_PROG(minio_protect_unlink, struct inode *dir, struct dentry *dentry,
	     int ret)
{
	if (ret != 0)
		return ret;

	return check_deletion_allowed("unlink", dentry);
}

/* LSM Hook: inode_rmdir */
SEC("lsm/inode_rmdir")
int BPF_PROG(minio_protect_rmdir, struct inode *dir, struct dentry *dentry,
	     int ret)
{
	if (ret != 0)
		return ret;

	return check_deletion_allowed("rmdir", dentry);
}

/* LSM Hook: inode_rename */
SEC("lsm/inode_rename")
int BPF_PROG(minio_protect_rename, struct inode *old_dir,
	     struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry, int ret)
{
	if (ret != 0)
		return ret;

	return check_deletion_allowed("rename", old_dentry);
}

char LICENSE[] SEC("license") = "GPL";
