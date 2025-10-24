// SPDX-License-Identifier: GPL-2.0
/* MinIO Protection Userspace Loader
 *
 * This program loads the eBPF LSM hooks and manages the allowed UID whitelist.
 *
 * Usage:
 *   ./minio_protect [options]
 *
 * Options:
 *   -u, --uid UID         Add UID to allowed list (can be repeated)
 *   -d, --disable         Start with protection disabled
 *   -v, --verbose         Enable verbose logging (log allowed ops too)
 *   -s, --stats SECONDS   Print statistics every N seconds
 *   -h, --help            Show help message
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "minio_protect.skel.h"

#define MAX_ALLOWED_UIDS 32
#define MAX_PROTECTED_PATHS 16
#define MAX_PATH_LEN 256

static volatile bool exiting = false;

struct config {
	unsigned int allowed_uids[MAX_ALLOWED_UIDS];
	unsigned int num_uids;
	char protected_paths[MAX_PROTECTED_PATHS][MAX_PATH_LEN];
	unsigned int num_paths;
	bool protection_enabled;
	bool verbose;
	unsigned int stats_interval;
};

static void sig_handler(int sig)
{
	exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	return vfprintf(stderr, format, args);
}

/* Parse comma-separated paths */
static int parse_comma_separated_paths(const char *paths_str, struct config *cfg)
{
	char *paths_copy = strdup(paths_str);
	if (!paths_copy) {
		fprintf(stderr, "Out of memory\n");
		return -1;
	}

	char *token = strtok(paths_copy, ",");
	while (token != NULL) {
		/* Trim whitespace */
		while (*token == ' ' || *token == '\t')
			token++;

		char *end = token + strlen(token) - 1;
		while (end > token && (*end == ' ' || *end == '\t'))
			*end-- = '\0';

		if (strlen(token) == 0) {
			token = strtok(NULL, ",");
			continue;
		}

		if (cfg->num_paths >= MAX_PROTECTED_PATHS) {
			fprintf(stderr, "Too many paths (max %d)\n", MAX_PROTECTED_PATHS);
			free(paths_copy);
			return -1;
		}

		if (strlen(token) >= MAX_PATH_LEN) {
			fprintf(stderr, "Path too long (max %d): %s\n",
				MAX_PATH_LEN - 1, token);
			free(paths_copy);
			return -1;
		}

		strncpy(cfg->protected_paths[cfg->num_paths++], token, MAX_PATH_LEN - 1);
		printf("Added protected path: %s\n", token);

		token = strtok(NULL, ",");
	}

	free(paths_copy);
	return 0;
}

static void print_usage(const char *prog)
{
	fprintf(stderr,
		"MinIO Protection - eBPF LSM-based deletion protection\n\n"
		"Usage: %s [options]\n\n"
		"Options:\n"
		"  -u, --uid UID            Add UID to allowed list (can be repeated)\n"
		"  -p, --paths PATH1,PATH2  Comma-separated list of directory names to protect\n"
		"                           Examples: clusterone1,clusterone2,clusterone3\n"
		"  -d, --disable            Start with protection disabled (use for testing)\n"
		"  -v, --verbose            Enable verbose logging (log allowed ops too)\n"
		"  -s, --stats SECONDS      Print statistics every N seconds (default: 60)\n"
		"  -h, --help               Show this help message\n\n"
		"Examples:\n"
		"  # Protect files under 'clusterone1' directory, allow only UID 1000\n"
		"  %s -u 1000 -p clusterone1\n\n"
		"  # Protect multiple directories (comma-separated)\n"
		"  %s -u 1000 -p clusterone1,clusterone2,clusterone3\n\n"
		"  # Allow multiple UIDs\n"
		"  %s -u 1000 -u 0 -p clusterone1\n\n"
		"  # Start disabled for testing, print stats every 10 seconds\n"
		"  %s -u 1000 -p clusterone1 -d -s 10\n\n"
		"Note: Protection can be enabled/disabled at runtime using:\n"
		"  echo 1 > /sys/fs/bpf/minio_protect_config/enable  (enable)\n"
		"  echo 0 > /sys/fs/bpf/minio_protect_config/enable  (disable)\n",
		prog, prog, prog, prog, prog);
}

static int parse_args(int argc, char **argv, struct config *cfg)
{
	static struct option long_options[] = {
		{ "uid", required_argument, 0, 'u' },
		{ "path", required_argument, 0, 'p' },
		{ "disable", no_argument, 0, 'd' },
		{ "verbose", no_argument, 0, 'v' },
		{ "stats", required_argument, 0, 's' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	int opt, uid;

	/* Defaults */
	cfg->num_uids = 0;
	cfg->num_paths = 0;
	cfg->protection_enabled = true;
	cfg->verbose = false;
	cfg->stats_interval = 60;

	while ((opt = getopt_long(argc, argv, "u:p:dvs:h", long_options,
				  NULL)) != -1) {
		switch (opt) {
		case 'u':
			uid = atoi(optarg);
			if (uid < 0) {
				fprintf(stderr, "Invalid UID: %s\n", optarg);
				return -1;
			}
			if (cfg->num_uids >= MAX_ALLOWED_UIDS) {
				fprintf(stderr, "Too many UIDs (max %d)\n",
					MAX_ALLOWED_UIDS);
				return -1;
			}
			cfg->allowed_uids[cfg->num_uids++] = uid;
			break;
		case 'p':
			/* Parse comma-separated paths */
			if (parse_comma_separated_paths(optarg, cfg) != 0) {
				return -1;
			}
			break;
		case 'd':
			cfg->protection_enabled = false;
			break;
		case 'v':
			cfg->verbose = true;
			break;
		case 's':
			cfg->stats_interval = atoi(optarg);
			if (cfg->stats_interval == 0) {
				fprintf(stderr, "Invalid stats interval: %s\n",
					optarg);
				return -1;
			}
			break;
		case 'h':
			print_usage(argv[0]);
			exit(0);
		default:
			print_usage(argv[0]);
			return -1;
		}
	}

	if (cfg->num_uids == 0) {
		fprintf(stderr,
			"Error: At least one allowed UID required (-u)\n\n");
		print_usage(argv[0]);
		return -1;
	}

	if (cfg->num_paths == 0) {
		fprintf(stderr,
			"Error: At least one protected path required (-p)\n\n");
		print_usage(argv[0]);
		return -1;
	}

	return 0;
}

static int configure_maps(struct minio_protect_bpf *skel, struct config *cfg)
{
	int err;
	__u8 allowed = 1;
	__u32 enable_protection = cfg->protection_enabled ? 1 : 0;
	__u32 log_allowed = cfg->verbose ? 1 : 0;

	/* Add allowed UIDs */
	int allowed_fd = bpf_map__fd(skel->maps.allowed_uids);
	for (unsigned int i = 0; i < cfg->num_uids; i++) {
		__u32 uid = cfg->allowed_uids[i];
		err = bpf_map_update_elem(allowed_fd, &uid, &allowed, BPF_ANY);
		if (err) {
			fprintf(stderr, "Failed to add UID %u to allowed list: %d\n",
				uid, err);
			return err;
		}
		printf("Added UID %u to allowed list\n", uid);
	}

	/* Add protected path prefixes */
	int paths_fd = bpf_map__fd(skel->maps.protected_paths);
	for (unsigned int i = 0; i < cfg->num_paths; i++) {
		__u32 key = i;
		char path[MAX_PATH_LEN] = {};
		strncpy(path, cfg->protected_paths[i], MAX_PATH_LEN - 1);
		err = bpf_map_update_elem(paths_fd, &key, path, BPF_ANY);
		if (err) {
			fprintf(stderr, "Failed to add protected path '%s': %d\n",
				cfg->protected_paths[i], err);
			return err;
		}
		printf("Added protected path: %s\n", cfg->protected_paths[i]);
	}

	/* Configure protection enabled/disabled */
	int config_fd = bpf_map__fd(skel->maps.config_map);
	__u32 key = 0; /* CONFIG_ENABLE_PROTECTION */
	err = bpf_map_update_elem(config_fd, &key, &enable_protection, BPF_ANY);
	if (err) {
		fprintf(stderr, "Failed to set protection state: %d\n", err);
		return err;
	}

	/* Configure logging */
	key = 1; /* CONFIG_LOG_ALLOWED */
	err = bpf_map_update_elem(config_fd, &key, &log_allowed, BPF_ANY);
	if (err) {
		fprintf(stderr, "Failed to set logging mode: %d\n", err);
		return err;
	}

	return 0;
}

static void print_stats(struct minio_protect_bpf *skel)
{
	int global_fd = bpf_map__fd(skel->maps.global_stats);
	int blocked_fd = bpf_map__fd(skel->maps.blocked_stats);
	__u32 key;
	__u64 value;

	/* Print global statistics */
	key = 0; /* STAT_BLOCKED_TOTAL */
	if (bpf_map_lookup_elem(global_fd, &key, &value) == 0) {
		printf("\n=== MinIO Protection Statistics ===\n");
		printf("Total blocked operations: %llu\n", value);
	}

	key = 1; /* STAT_ALLOWED_TOTAL */
	if (bpf_map_lookup_elem(global_fd, &key, &value) == 0) {
		printf("Total allowed operations: %llu\n", value);
	}

	/* Print per-UID blocked statistics */
	printf("\nBlocked operations by UID:\n");
	__u32 uid = 0, next_uid;
	__u64 count;
	bool found = false;

	while (bpf_map_get_next_key(blocked_fd, &uid, &next_uid) == 0) {
		uid = next_uid;
		if (bpf_map_lookup_elem(blocked_fd, &uid, &count) == 0) {
			printf("  UID %u: %llu blocked attempts\n", uid, count);
			found = true;
		}
	}

	if (!found) {
		printf("  (none)\n");
	}

	printf("===================================\n\n");
}

int main(int argc, char **argv)
{
	struct minio_protect_bpf *skel;
	struct config cfg;
	int err;
	time_t last_stats = 0;

	/* Parse arguments */
	err = parse_args(argc, argv, &cfg);
	if (err)
		return 1;

	/* Set up libbpf logging */
	libbpf_set_print(libbpf_print_fn);

	/* Check if running as root */
	if (geteuid() != 0) {
		fprintf(stderr, "Error: This program must be run as root\n");
		return 1;
	}

	/* Open BPF application */
	skel = minio_protect_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Load and verify BPF programs */
	err = minio_protect_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
		fprintf(stderr,
			"\nPossible causes:\n"
			"1. Kernel doesn't support LSM BPF (need 5.7+)\n"
			"2. LSM BPF not enabled in kernel config (CONFIG_BPF_LSM=y)\n"
			"3. 'lsm=bpf' not in kernel command line\n"
			"4. BTF not available (CONFIG_DEBUG_INFO_BTF=y)\n\n"
			"To check:\n"
			"  cat /sys/kernel/security/lsm | grep bpf\n"
			"  ls /sys/kernel/btf/vmlinux\n");
		goto cleanup;
	}

	/* Configure maps */
	err = configure_maps(skel, &cfg);
	if (err)
		goto cleanup;

	/* Attach LSM hooks */
	err = minio_protect_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	printf("\n=== MinIO Protection Active ===\n");
	printf("Protection: %s\n",
	       cfg.protection_enabled ? "ENABLED" : "DISABLED");
	printf("Allowed UIDs: ");
	for (unsigned int i = 0; i < cfg.num_uids; i++) {
		printf("%u%s", cfg.allowed_uids[i],
		       i < cfg.num_uids - 1 ? ", " : "");
	}
	printf("\nProtected paths:\n");
	for (unsigned int i = 0; i < cfg.num_paths; i++) {
		printf("  - %s\n", cfg.protected_paths[i]);
	}
	printf("Verbose logging: %s\n", cfg.verbose ? "ON" : "OFF");
	printf("Stats interval: %u seconds\n", cfg.stats_interval);
	printf("\nBlocking unlink, rmdir, and rename operations from non-allowed users.\n");
	printf("Press Ctrl-C to exit and disable protection.\n\n");

	if (!cfg.protection_enabled) {
		printf("WARNING: Protection is currently DISABLED (started with -d flag)\n");
		printf("Enable with: echo 1 > /sys/fs/bpf/minio_protect_config/enable\n\n");
	}

	/* Set up signal handlers */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Main loop */
	while (!exiting) {
		sleep(1);

		/* Print statistics periodically */
		time_t now = time(NULL);
		if (now - last_stats >= cfg.stats_interval) {
			print_stats(skel);
			last_stats = now;
		}
	}

	printf("\nShutting down MinIO protection...\n");
	print_stats(skel);

cleanup:
	minio_protect_bpf__destroy(skel);
	return err != 0;
}
