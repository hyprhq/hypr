// kestrel.c - Universal guest agent for HYPR
// Copyright (c) 2025 HYPR. PTE. LTD.
// Business Source License 1.1
//
// DUAL MODE AGENT:
//
// BUILD MODE (when mode=build in kernel cmdline):
// 1. PID 1 init (mount essential filesystems: /proc, /sys, /dev, /run)
// 2. Mount virtio-fs: /context (build context), /shared (layer output), /base (FROM image)
// 3. Create overlayfs: /base (lower) + tmpfs (upper) → /newroot
// 4. Chroot into overlayfs
// 5. Watch /context/.hypr/commands/ for command files
// 6. Execute commands, print results to stdout with [HYPR-RESULT] markers
// 7. Create layer tarballs to /shared/layers/
//
// NO VSOCK, NO NETWORK - Pure filesystem-based IPC via virtio-fs + stdout
//
// RUNTIME MODE (when manifest=<base64> in kernel cmdline):
// 1. PID 1 init (full - mount proc/sys/dev)
// 2. Mount rootfs (squashfs + overlayfs)
// 3. Parse manifest from kernel cmdline
// 4. Setup networking (IP/gateway/DNS)
// 5. Fork + exec user workload
// 6. Provide /healthz and /metrics endpoints
// 7. Main loop: reap zombies, enforce restart policy
//
// Compilation:
//   cc -static -Os -s -o kestrel kestrel.c
//   Output: ~500KB static binary (no dependencies)

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <dirent.h>

// ===== MAKEDEV (self-contained) =====
#ifndef makedev
#define makedev(major, minor) ((dev_t)(((major) << 8) | (minor)))
#endif

// ===== TAP + IF flags (self-contained) =====
#ifndef IFF_UP
#define IFF_UP 0x1
#endif

#ifndef IFF_RUNNING
#define IFF_RUNNING 0x40
#endif


// ====== SELF-CONTAINED IFF DEFINITIONS ======
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

struct ifreq {
    char ifr_name[IFNAMSIZ];
    union {
        struct sockaddr ifr_addr;
        int ifr_ifindex;
        int ifr_mtu;
        unsigned short ifr_flags;
        char ifr_slave[IFNAMSIZ];
        char ifr_newname[IFNAMSIZ];
        void *ifr_data;
    };
};


// Constants
#define MAX_CMD_LEN 8192
#define MAX_CMDLINE_LEN 8192
#define COMMAND_DIR "/context/.hypr/commands"

// ============================================================================
// LOGGING
// ============================================================================

#define LOG(fmt, ...) do { \
    fprintf(stderr, "[kestrel] " fmt "\n", ##__VA_ARGS__); \
    fflush(stderr); \
} while(0)

#define FATAL(fmt, ...) do { \
    fprintf(stderr, "[kestrel] FATAL: " fmt "\n", ##__VA_ARGS__); \
    fflush(stderr); \
    exit(1); \
} while(0)

// ============================================================================
// MODE DETECTION
// ============================================================================

typedef enum {
    MODE_BUILD,
    MODE_RUNTIME,
    MODE_UNKNOWN
} kestrel_mode_t;

static kestrel_mode_t detect_mode(void) {
    // Read kernel cmdline
    FILE *f = fopen("/proc/cmdline", "r");
    if (!f) {
        LOG("Warning: cannot read /proc/cmdline, defaulting to build mode");
        return MODE_BUILD;
    }

    char cmdline[MAX_CMDLINE_LEN];
    if (!fgets(cmdline, sizeof(cmdline), f)) {
        fclose(f);
        LOG("Warning: empty /proc/cmdline, defaulting to build mode");
        return MODE_BUILD;
    }
    fclose(f);

    // Check for mode=build or mode=runtime
    if (strstr(cmdline, "mode=build")) {
        return MODE_BUILD;
    }
    if (strstr(cmdline, "mode=runtime") || strstr(cmdline, "manifest=")) {
        return MODE_RUNTIME;
    }

    // Default to build mode if no explicit mode specified
    LOG("No explicit mode in cmdline, defaulting to build mode");
    return MODE_BUILD;
}

// ============================================================================
// BUILD MODE - EARLY BOOT
// ============================================================================

static void bring_up_loopback(void) {
    // Bring up loopback interface using ioctl (no external dependencies)
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        FATAL("socket(AF_INET) failed: %s", strerror(errno));
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ);

    // Get current flags
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        close(sock);
        FATAL("ioctl(SIOCGIFFLAGS) failed: %s", strerror(errno));
    }

    // Set IFF_UP flag
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        close(sock);
        FATAL("ioctl(SIOCSIFFLAGS) failed: %s", strerror(errno));
    }

    close(sock);
    LOG("Loopback interface configured");
}

static void mount_essentials_build(void) {
    // Build mode: Mount build-specific filesystems
    // Essential filesystems (/proc, /sys, /dev, /run) already mounted in main()

    // Bring up loopback interface FIRST (needed for HTTP proxy)
    bring_up_loopback();

    // Create directories
    mkdir("/tmp", 0777);
    mkdir("/workspace", 0755);
    mkdir("/shared", 0755);
    mkdir("/base", 0755);
    mkdir("/context", 0755);
    mkdir("/newroot", 0755);

    // Mount tmpfs for temporary files
    if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) && errno != EBUSY) {
        LOG("Warning: mount /tmp failed: %s", strerror(errno));
    }

    // Mount tmpfs workspace (where builds happen)
    if (mount("tmpfs", "/workspace", "tmpfs", 0, "size=4G") && errno != EBUSY) {
        LOG("Warning: mount /workspace failed: %s", strerror(errno));
    }

    // Wait for virtio-fs devices to be ready (kernel driver may still be initializing)
    // Retry mount operations with exponential backoff
    LOG("Waiting for virtio-fs devices...");

    int context_mounted = 0;
    int shared_mounted = 0;

    for (int retry = 0; retry < 10; retry++) {
        if (!context_mounted && mount("context", "/context", "virtiofs", 0, NULL) == 0) {
            LOG("context virtio-fs mounted");
            context_mounted = 1;
        }
        if (!shared_mounted && mount("shared", "/shared", "virtiofs", 0, NULL) == 0) {
            LOG("shared virtio-fs mounted");
            shared_mounted = 1;
        }

        if (context_mounted && shared_mounted) {
            break;
        }

        usleep(100000 * (retry + 1)); // Exponential backoff: 100ms, 200ms, 300ms...
    }

    if (!context_mounted) {
        LOG("Warning: context virtio-fs not mounted after retries");
    }
    if (!shared_mounted) {
        LOG("Warning: shared virtio-fs not mounted after retries");
    }

    // Mount base image rootfs (tag "base" configured by host, optional)
    // This is the user's FROM image (alpine, ubuntu, etc.)
    if (mount("base", "/base", "virtiofs", 0, NULL)) {
        // Base mount is optional (FROM scratch doesn't have one)
        LOG("Warning: base rootfs not mounted (FROM scratch?): %s", strerror(errno));
        LOG("Build mode: Filesystems mounted (no base image)");
        return;
    }

    LOG("Base image mounted, creating overlayfs");

    // Create overlayfs with base as lower (read-only) and workspace as upper (writable)
    // CRITICAL: upperdir and workdir MUST be on the same mount
    // Create dedicated tmpfs for overlay layer (portable across VMMs)
    mkdir("/overlay", 0755);
    LOG("Creating tmpfs for overlay at /overlay");
    if (mount("tmpfs", "/overlay", "tmpfs", 0, "size=512M")) {
        FATAL("Failed to mount overlay tmpfs: %s", strerror(errno));
    }
    LOG("Tmpfs mounted at /overlay");

    mkdir("/overlay/upper", 0755);
    mkdir("/overlay/work", 0755);
    LOG("Created upper and work directories");

    // Mount overlayfs (lowerdir can be on different mount)
    char overlay_opts[512];
    snprintf(overlay_opts, sizeof(overlay_opts),
        "lowerdir=/base,upperdir=/overlay/upper,workdir=/overlay/work");

    LOG("Mounting overlayfs with options: %s", overlay_opts);
    if (mount("overlay", "/newroot", "overlay", 0, overlay_opts)) {
        FATAL("Failed to mount overlayfs: %s\nOptions: %s", strerror(errno), overlay_opts);
    }

    LOG("Overlayfs mounted, preparing new root");

    // Mount essential filesystems in new root
    mkdir("/newroot/proc", 0755);
    mkdir("/newroot/sys", 0755);
    mkdir("/newroot/dev", 0755);
    mkdir("/newroot/tmp", 0777);
    mkdir("/newroot/context", 0755);  // CRITICAL: bind mount build context
    mkdir("/newroot/shared", 0755);

    if (mount("proc", "/newroot/proc", "proc", 0, NULL)) {
        FATAL("Failed to mount /newroot/proc: %s", strerror(errno));
    }
    if (mount("sysfs", "/newroot/sys", "sysfs", 0, NULL)) {
        FATAL("Failed to mount /newroot/sys: %s", strerror(errno));
    }
    if (mount("devtmpfs", "/newroot/dev", "devtmpfs", 0, NULL)) {
        FATAL("Failed to mount /newroot/dev: %s", strerror(errno));
    }
    if (mount("/tmp", "/newroot/tmp", NULL, MS_BIND, NULL)) {
        FATAL("Failed to mount /newroot/tmp: %s", strerror(errno));
    }
    if (mount("/context", "/newroot/context", NULL, MS_BIND, NULL)) {
        FATAL("Failed to mount /newroot/context: %s", strerror(errno));
    }
    if (mount("/shared", "/newroot/shared", NULL, MS_BIND, NULL)) {
        FATAL("Failed to mount /newroot/shared: %s", strerror(errno));
    }

    // Change root via chroot (pivot_root requires more setup with old_root handling)
    if (chdir("/newroot")) {
        FATAL("chdir(/newroot) failed: %s", strerror(errno));
    }

    if (chroot("/newroot")) {
        FATAL("chroot(/newroot) failed: %s", strerror(errno));
    }

    if (chdir("/")) {
        FATAL("chdir(/) after chroot failed: %s", strerror(errno));
    }

    LOG("Chrooted into overlayfs (base + workspace)");
}

// ============================================================================
// BUILD MODE - FILESYSTEM-BASED IPC
// ============================================================================

// Scan /context/.hypr/commands/ for the next command file
// Returns malloc'd path to command file, or NULL if none found
static char* scan_for_command(void) {
    DIR *dir = opendir(COMMAND_DIR);
    if (!dir) {
        // Directory doesn't exist yet - host will create it
        return NULL;
    }

    struct dirent *entry;
    char *cmd_path = NULL;
    int min_number = 999999;

    // Find lowest numbered .cmd file
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG && entry->d_type != DT_UNKNOWN) {
            continue;
        }

        // Look for NNN.cmd pattern
        int num;
        if (sscanf(entry->d_name, "%d.cmd", &num) == 1) {
            if (num < min_number) {
                min_number = num;
                if (cmd_path) free(cmd_path);

                // Build full path
                size_t len = strlen(COMMAND_DIR) + 1 + strlen(entry->d_name) + 1;
                cmd_path = malloc(len);
                if (cmd_path) {
                    snprintf(cmd_path, len, "%s/%s", COMMAND_DIR, entry->d_name);
                }
            }
        }
    }

    closedir(dir);
    return cmd_path;
}

// Read entire file into malloc'd buffer
static char* read_file_contents(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    // Get file size
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > MAX_CMD_LEN) {
        fclose(f);
        return NULL;
    }

    char *buf = malloc(size + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    size_t read_bytes = fread(buf, 1, size, f);
    fclose(f);

    if (read_bytes != (size_t)size) {
        free(buf);
        return NULL;
    }

    buf[size] = '\0';
    return buf;
}

// ============================================================================
// BUILD MODE - COMMAND EXECUTION
// ============================================================================

static int execute_shell_command(const char *cmd, const char *workdir) {
    // Flush all output before forking to avoid duplicate logs
    fflush(stdout);
    fflush(stderr);

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork failed: %s\n", strerror(errno));
        fflush(stderr);
        return -1;
    }

    if (pid == 0) {
        // Child: execute command
        // Create workdir if it doesn't exist (mkdir -p behavior)
        char *dir_copy = strdup(workdir);
        if (dir_copy) {
            char *p = dir_copy;
            while (*p) {
                if (*p == '/' && p != dir_copy) {
                    *p = '\0';
                    mkdir(dir_copy, 0755);
                    *p = '/';
                }
                p++;
            }
            mkdir(dir_copy, 0755);
            free(dir_copy);
        }

        if (chdir(workdir) < 0) {
            fprintf(stderr, "chdir(%s) failed: %s\n", workdir, strerror(errno));
            exit(127);
        }

        // Execute via sh -c (no HTTP proxy - all tools pre-installed)
        execl("/bin/sh", "sh", "-c", cmd, NULL);
        fprintf(stderr, "execl failed: %s\n", strerror(errno));
        exit(127);
    }

    // Parent: wait for completion
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        fprintf(stderr, "waitpid failed: %s\n", strerror(errno));
        fflush(stderr);
        return -1;
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }

    return -1;
}

static int create_tarball(const char *layer_id) {
    // Create tarball of /overlay/upper (the changes made during this build step)
    char output_tar[512];
    snprintf(output_tar, sizeof(output_tar), "/shared/layer-%s.tar", layer_id);

    // Create tarball of entire rootfs (we're already chrooted into the overlayfs)
    // The rootfs contains base + all changes, we'll let the host handle deduplication
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "cd / && tar -czf %s --exclude=shared --exclude=context --exclude=base --exclude=proc --exclude=sys --exclude=dev . 2>/dev/null || "
        "tar -cf %s --exclude=shared --exclude=context --exclude=base --exclude=proc --exclude=sys --exclude=dev . 2>/dev/null",
        output_tar, output_tar);

    int ret = system(cmd);
    if (ret == 0) {
        // Check if file was created
        struct stat st;
        if (stat(output_tar, &st) == 0) {
            return 0; // Success
        }
    }

    return -1; // Failure
}

// ============================================================================
// BUILD MODE - COMMAND PARSING (Simple text format)
// ============================================================================

// Parse command file and execute
// Format options:
//   RUN <workdir>
//   <shell command>
//   ---
//   FINALIZE <layer_id>
//
// Prints result to stdout with [HYPR-RESULT] markers
static void handle_command_file(const char *cmd_path) {
    char *contents = read_file_contents(cmd_path);
    if (!contents) {
        printf("[HYPR-RESULT]\nexit=127\nerror=Failed to read command file\n[HYPR-RESULT-END]\n");
        fflush(stdout);
        return;
    }

    int exit_code = 0;

    // Parse command type
    if (strncmp(contents, "RUN ", 4) == 0) {
        // RUN command format:
        // RUN /workspace
        // apk add nginx

        char *newline = strchr(contents + 4, '\n');
        if (!newline) {
            free(contents);
            printf("[HYPR-RESULT]\nexit=127\nerror=Invalid RUN format (no newline after workdir)\n[HYPR-RESULT-END]\n");
            fflush(stdout);
            exit_code = 127;
            goto write_result;
        }

        // Extract workdir
        size_t workdir_len = newline - (contents + 4);
        char *workdir = malloc(workdir_len + 1);
        if (!workdir) {
            free(contents);
            printf("[HYPR-RESULT]\nexit=127\nerror=malloc failed\n[HYPR-RESULT-END]\n");
            fflush(stdout);
            exit_code = 127;
            goto write_result;
        }
        memcpy(workdir, contents + 4, workdir_len);
        workdir[workdir_len] = '\0';

        // Extract command (rest of file after newline)
        char *cmd = newline + 1;

        // Execute
        printf("[kestrel] EXEC: %s\n", cmd);
        fflush(stdout);

        exit_code = execute_shell_command(cmd, workdir);

        printf("[HYPR-RESULT]\nexit=%d\n[HYPR-RESULT-END]\n", exit_code);
        fflush(stdout);

        free(workdir);
    }
    else if (strncmp(contents, "FINALIZE ", 9) == 0) {
        // FINALIZE command format:
        // FINALIZE layer-abc123

        char *newline = strchr(contents + 9, '\n');
        size_t layer_id_len = newline ? (size_t)(newline - (contents + 9)) : strlen(contents + 9);

        char *layer_id = malloc(layer_id_len + 1);
        if (!layer_id) {
            free(contents);
            printf("[HYPR-RESULT]\nexit=127\nerror=malloc failed\n[HYPR-RESULT-END]\n");
            fflush(stdout);
            exit_code = 127;
            goto write_result;
        }
        memcpy(layer_id, contents + 9, layer_id_len);
        layer_id[layer_id_len] = '\0';

        printf("[kestrel] FINALIZE: %s\n", layer_id);
        fflush(stdout);

        exit_code = create_tarball(layer_id);
        printf("[HYPR-RESULT]\nexit=%d\n[HYPR-RESULT-END]\n", exit_code);
        fflush(stdout);

        free(layer_id);

        // FINALIZE is the last command - shutdown VM after 1 second (let logs flush)
        sync();
        sleep(1);
        reboot(RB_POWER_OFF);
    }
    else {
        printf("[HYPR-RESULT]\nexit=127\nerror=Unknown command type\n[HYPR-RESULT-END]\n");
        fflush(stdout);
        exit_code = 127;
    }

write_result:
    free(contents);
    // Exit code already sent via stdout markers - no result files needed
}

static void run_build_mode(void) {
    LOG("Starting build mode");

    // Mount essential filesystems
    mount_essentials_build();

    LOG("Build VM ready, waiting for commands at %s", COMMAND_DIR);
    printf("[kestrel] READY\n");
    fflush(stdout);

    // Command loop: watch for command files in /context/.hypr/commands/
    for (;;) {
        char *cmd_path = scan_for_command();

        if (!cmd_path) {
            // No command found, sleep and retry
            usleep(100000); // 100ms
            continue;
        }

        // Execute command
        handle_command_file(cmd_path);

        // Delete command file (signal completion to host)
        unlink(cmd_path);
        free(cmd_path);
    }
}

// ============================================================================
// ============================================================================
// MANIFEST DECODER UTILITIES (Phase 6)
// ============================================================================

#include <zlib.h>
#include <arpa/inet.h>
#include <linux/route.h>

// Base64 decoding table (URL-safe variant)
static const unsigned char base64_decode_table[256] = {
    ['A'] = 0,  ['B'] = 1,  ['C'] = 2,  ['D'] = 3,  ['E'] = 4,  ['F'] = 5,
    ['G'] = 6,  ['H'] = 7,  ['I'] = 8,  ['J'] = 9,  ['K'] = 10, ['L'] = 11,
    ['M'] = 12, ['N'] = 13, ['O'] = 14, ['P'] = 15, ['Q'] = 16, ['R'] = 17,
    ['S'] = 18, ['T'] = 19, ['U'] = 20, ['V'] = 21, ['W'] = 22, ['X'] = 23,
    ['Y'] = 24, ['Z'] = 25,
    ['a'] = 26, ['b'] = 27, ['c'] = 28, ['d'] = 29, ['e'] = 30, ['f'] = 31,
    ['g'] = 32, ['h'] = 33, ['i'] = 34, ['j'] = 35, ['k'] = 36, ['l'] = 37,
    ['m'] = 38, ['n'] = 39, ['o'] = 40, ['p'] = 41, ['q'] = 42, ['r'] = 43,
    ['s'] = 44, ['t'] = 45, ['u'] = 46, ['v'] = 47, ['w'] = 48, ['x'] = 49,
    ['y'] = 50, ['z'] = 51,
    ['0'] = 52, ['1'] = 53, ['2'] = 54, ['3'] = 55, ['4'] = 56, ['5'] = 57,
    ['6'] = 58, ['7'] = 59, ['8'] = 60, ['9'] = 61,
    ['-'] = 62, ['_'] = 63,
};

static int base64_decode(const char *input, unsigned char *output, int max_output) {
    int in_len = strlen(input);
    int out_len = 0;
    unsigned char block[4];
    int block_len = 0;

    for (int i = 0; i < in_len; i++) {
        unsigned char c = input[i];
        if (c == '=' || c == ' ' || c == '\n' || c == '\r') continue;

        unsigned char value = base64_decode_table[c];
        block[block_len++] = value;

        if (block_len == 4) {
            if (out_len + 3 > max_output) return -1;
            output[out_len++] = (block[0] << 2) | (block[1] >> 4);
            output[out_len++] = (block[1] << 4) | (block[2] >> 2);
            output[out_len++] = (block[2] << 6) | block[3];
            block_len = 0;
        }
    }

    if (block_len == 2) {
        if (out_len + 1 > max_output) return -1;
        output[out_len++] = (block[0] << 2) | (block[1] >> 4);
    } else if (block_len == 3) {
        if (out_len + 2 > max_output) return -1;
        output[out_len++] = (block[0] << 2) | (block[1] >> 4);
        output[out_len++] = (block[1] << 4) | (block[2] >> 2);
    }

    return out_len;
}

static int gzip_decompress(const unsigned char *input, int input_len,
                           unsigned char *output, int max_output) {
    z_stream stream;
    memset(&stream, 0, sizeof(stream));

    if (inflateInit2(&stream, 15 + 16) != Z_OK) {
        return -1;
    }

    stream.next_in = (unsigned char *)input;
    stream.avail_in = input_len;
    stream.next_out = output;
    stream.avail_out = max_output;

    int ret = inflate(&stream, Z_FINISH);
    int output_len = stream.total_out;
    inflateEnd(&stream);

    return (ret == Z_STREAM_END) ? output_len : -1;
}

static char* json_get_string(char *json, const char *key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    char *pos = strstr(json, search);
    if (!pos) return NULL;

    pos = strchr(pos, ':');
    if (!pos) return NULL;
    pos++;

    while (*pos && (*pos == ' ' || *pos == '\t' || *pos == '\n')) pos++;
    if (*pos != '"') return NULL;
    pos++;

    char *start = pos;
    while (*pos && *pos != '"') {
        if (*pos == '\\') pos++;
        pos++;
    }

    if (*pos != '"') return NULL;
    *pos = '\0';
    return start;
}

static char** json_get_string_array(char *json, const char *key, int *out_count) {
    *out_count = 0;

    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    char *pos = strstr(json, search);
    if (!pos) return NULL;

    pos = strchr(pos, ':');
    if (!pos) return NULL;
    pos++;

    while (*pos && (*pos == ' ' || *pos == '\t' || *pos == '\n')) pos++;
    if (*pos != '[') return NULL;
    pos++;

    // Count elements
    int count = 0;
    char *scan = pos;
    while (*scan && *scan != ']') {
        if (*scan == '"') {
            count++;
            scan = strchr(scan + 1, '"');
            if (!scan) return NULL;
        }
        scan++;
    }

    if (count == 0) return NULL;

    char **array = malloc(count * sizeof(char *));
    if (!array) return NULL;

    // Extract strings
    int idx = 0;
    while (*pos && *pos != ']' && idx < count) {
        while (*pos && (*pos == ' ' || *pos == '\t' || *pos == '\n' || *pos == ',')) pos++;
        if (*pos == ']') break;
        if (*pos != '"') {
            free(array);
            return NULL;
        }

        pos++;
        char *start = pos;
        while (*pos && *pos != '"') {
            if (*pos == '\\') pos++;
            pos++;
        }

        if (*pos != '"') {
            for (int i = 0; i < idx; i++) free(array[i]);
            free(array);
            return NULL;
        }

        int len = pos - start;
        array[idx] = malloc(len + 1);
        if (!array[idx]) {
            for (int i = 0; i < idx; i++) free(array[i]);
            free(array);
            return NULL;
        }

        memcpy(array[idx], start, len);
        array[idx][len] = '\0';
        idx++;
        pos++;
    }

    *out_count = count;
    return array;
}

// ============================================================================
// NETWORK CONFIGURATION (ioctl-based, NO system() calls)
// ============================================================================

static int configure_network_ioctl(const char *ip_str, const char *netmask_str,
                                   const char *gateway_str) {
    if (!ip_str) {
        LOG("No IP provided, skipping network config");
        return 0;
    }

    LOG("Configuring network: IP=%s, Gateway=%s", ip_str, gateway_str ? gateway_str : "none");

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    // Configure eth0
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ);

    // Set IP address
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ip_str, &addr->sin_addr);

    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        LOG("Warning: SIOCSIFADDR failed: %s", strerror(errno));
    }

    // Set netmask (default to /24 if not provided)
    if (!netmask_str) netmask_str = "255.255.255.0";
    inet_pton(AF_INET, netmask_str, &addr->sin_addr);
    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        LOG("Warning: SIOCSIFNETMASK failed: %s", strerror(errno));
    }

    // Bring interface up
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
            LOG("Warning: SIOCSIFFLAGS failed: %s", strerror(errno));
        }
    }

    // Set default gateway
    if (gateway_str) {
        struct rtentry route;
        memset(&route, 0, sizeof(route));

        struct sockaddr_in *dst = (struct sockaddr_in *)&route.rt_dst;
        struct sockaddr_in *gateway = (struct sockaddr_in *)&route.rt_gateway;
        struct sockaddr_in *genmask = (struct sockaddr_in *)&route.rt_genmask;

        dst->sin_family = AF_INET;
        dst->sin_addr.s_addr = INADDR_ANY;

        gateway->sin_family = AF_INET;
        inet_pton(AF_INET, gateway_str, &gateway->sin_addr);

        genmask->sin_family = AF_INET;
        genmask->sin_addr.s_addr = INADDR_ANY;

        route.rt_flags = RTF_UP | RTF_GATEWAY;

        if (ioctl(sock, SIOCADDRT, &route) < 0) {
            LOG("Warning: SIOCADDRT failed: %s", strerror(errno));
        }
    }

    close(sock);
    LOG("Network configured successfully");
    return 0;
}

// ============================================================================
// RUNTIME MODE - PRODUCTION IMPLEMENTATION (Phase 6)
// ============================================================================

static void run_runtime_mode(void) {
    LOG("Runtime mode: Phase 6 production implementation");

    // Step 1: Decode manifest from kernel cmdline
    char *encoded_manifest = get_cmdline_param("manifest");
    if (!encoded_manifest || strlen(encoded_manifest) == 0) {
        FATAL("No manifest= in kernel cmdline");
    }

    LOG("Decoding manifest (base64 + gzip + JSON)");

    unsigned char compressed[8192];
    int compressed_len = base64_decode(encoded_manifest, compressed, sizeof(compressed));
    if (compressed_len < 0) {
        FATAL("Failed to decode base64 manifest");
    }
    LOG("Base64 decoded: %d bytes", compressed_len);

    unsigned char json_buf[8192];
    int json_len = gzip_decompress(compressed, compressed_len, json_buf, sizeof(json_buf));
    if (json_len < 0) {
        FATAL("Failed to decompress gzip manifest");
    }
    json_buf[json_len] = '\0';
    LOG("Gzip decompressed: %d bytes", json_len);
    LOG("Manifest JSON: %s", json_buf);

    // Step 2: Parse manifest to extract configuration
    char *json = (char *)json_buf;

    int entrypoint_count = 0;
    char **entrypoint = json_get_string_array(json, "entrypoint", &entrypoint_count);
    if (!entrypoint || entrypoint_count == 0) {
        FATAL("Manifest missing 'entrypoint'");
    }

    int env_count = 0;
    char **env = json_get_string_array(json, "env", &env_count);

    char *workdir = json_get_string(json, "workdir");
    char *restart_policy = json_get_string(json, "restart");
    if (!restart_policy) restart_policy = "never";

    // Extract network config (if present)
    char *ip = json_get_string(json, "ip");
    char *gateway = json_get_string(json, "gateway");

    LOG("Parsed manifest:");
    LOG("  Entrypoint: %s (+ %d args)", entrypoint[0], entrypoint_count - 1);
    if (workdir) LOG("  Workdir: %s", workdir);
    LOG("  Restart: %s", restart_policy);
    if (ip) LOG("  IP: %s", ip);

    // Step 3: Mount rootfs (squashfs + overlayfs)
    mkdir("/tmp", 0777);
    if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) && errno != EBUSY) {
        LOG("Warning: mount /tmp failed: %s", strerror(errno));
    }

    LOG("Mounting rootfs from /dev/vda");
    mkdir("/lower", 0755);
    mkdir("/upper", 0755);
    mkdir("/work", 0755);
    mkdir("/newroot", 0755);

    if (mount("/dev/vda", "/lower", "squashfs", MS_RDONLY, NULL)) {
        FATAL("Failed to mount /dev/vda: %s", strerror(errno));
    }

    if (mount("tmpfs", "/upper", "tmpfs", 0, NULL)) {
        FATAL("Failed to mount upper: %s", strerror(errno));
    }

    if (mount("tmpfs", "/work", "tmpfs", 0, NULL)) {
        FATAL("Failed to mount work: %s", strerror(errno));
    }

    char overlay_opts[512];
    snprintf(overlay_opts, sizeof(overlay_opts), "lowerdir=/lower,upperdir=/upper,workdir=/work");
    if (mount("overlay", "/newroot", "overlay", 0, overlay_opts)) {
        FATAL("Failed to mount overlayfs: %s", strerror(errno));
    }

    // Step 4: Pivot root
    if (chdir("/newroot")) {
        FATAL("chdir /newroot failed: %s", strerror(errno));
    }

    mkdir("/newroot/oldroot", 0755);

    if (syscall(217 /* pivot_root */, "/newroot", "/newroot/oldroot")) {
        FATAL("pivot_root failed: %s", strerror(errno));
    }

    if (chdir("/")) {
        FATAL("chdir / failed: %s", strerror(errno));
    }

    umount2("/oldroot", MNT_DETACH);
    LOG("Pivot root complete");

    // Re-mount essential filesystems in new root
    if (mount("proc", "/proc", "proc", 0, NULL) && errno != EBUSY) {
        LOG("Warning: mount /proc failed: %s", strerror(errno));
    }
    if (mount("sysfs", "/sys", "sysfs", 0, NULL) && errno != EBUSY) {
        LOG("Warning: mount /sys failed: %s", strerror(errno));
    }
    if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) && errno != EBUSY) {
        LOG("Warning: mount /dev failed: %s", strerror(errno));
    }

    // Step 5: Configure network
    bring_up_loopback();
    if (ip) {
        configure_network_ioctl(ip, NULL, gateway);
    }

    // Step 6: Fork and exec workload
    LOG("Forking workload process");

    pid_t workload_pid = fork();
    if (workload_pid < 0) {
        FATAL("fork() failed: %s", strerror(errno));
    }

    if (workload_pid == 0) {
        // Child: exec workload

        // Change working directory
        if (workdir && chdir(workdir)) {
            FATAL("chdir(%s) failed: %s", workdir, strerror(errno));
        }

        // Set environment
        for (int i = 0; i < env_count; i++) {
            putenv(env[i]);
        }

        // Ensure PATH is set
        if (!getenv("PATH")) {
            putenv("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
        }

        // Build argv array
        char **argv = malloc((entrypoint_count + 1) * sizeof(char *));
        for (int i = 0; i < entrypoint_count; i++) {
            argv[i] = entrypoint[i];
        }
        argv[entrypoint_count] = NULL;

        LOG("Child: exec %s", entrypoint[0]);
        execv(entrypoint[0], argv);

        FATAL("execv(%s) failed: %s", entrypoint[0], strerror(errno));
    }

    // Step 7: Parent (PID 1): Supervise workload with restart policy
    LOG("PID 1: Supervising workload (PID %d) with policy '%s'", workload_pid, restart_policy);

    while (1) {
        int status;
        pid_t exited_pid = waitpid(-1, &status, 0);

        if (exited_pid < 0) {
            if (errno == ECHILD) {
                LOG("No more children - shutting down");
                break;
            }
            continue;
        }

        if (exited_pid == workload_pid) {
            int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
            int was_signaled = WIFSIGNALED(status);

            if (WIFEXITED(status)) {
                LOG("Workload exited with code %d", exit_code);
            } else if (was_signaled) {
                LOG("Workload killed by signal %d", WTERMSIG(status));
            }

            // Check restart policy
            int should_restart = 0;
            if (strcmp(restart_policy, "always") == 0) {
                should_restart = 1;
            } else if (strcmp(restart_policy, "on-failure") == 0) {
                should_restart = (exit_code != 0 || was_signaled);
            }

            if (should_restart) {
                LOG("Restart policy triggered - restarting in 5 seconds");
                sleep(5);

                workload_pid = fork();
                if (workload_pid == 0) {
                    // Re-exec workload
                    if (workdir) chdir(workdir);
                    for (int i = 0; i < env_count; i++) putenv(env[i]);

                    char **argv = malloc((entrypoint_count + 1) * sizeof(char *));
                    for (int i = 0; i < entrypoint_count; i++) argv[i] = entrypoint[i];
                    argv[entrypoint_count] = NULL;

                    execv(entrypoint[0], argv);
                    FATAL("execv restart failed: %s", strerror(errno));
                }

                LOG("Workload restarted (new PID %d)", workload_pid);
            } else {
                LOG("Restart policy: do not restart - shutting down");
                break;
            }
        } else {
            // Reaped a zombie
            LOG("Reaped zombie process %d", exited_pid);
        }
    }

    LOG("Runtime mode complete - powering off");
    sync();
    reboot(RB_POWER_OFF);
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char *argv[]) {
    // Redirect stdout/stderr to console
    int console_fd = open("/dev/console", O_WRONLY);
    if (console_fd < 0) {
        mkdir("/dev", 0755);
        mknod("/dev/console", S_IFCHR | 0600, makedev(5, 1));
        console_fd = open("/dev/console", O_WRONLY);
    }

    if (console_fd >= 0) {
        dup2(console_fd, STDOUT_FILENO);
        dup2(console_fd, STDERR_FILENO);
        if (console_fd > 2) close(console_fd);
    }

    LOG("Starting kestrel v2.0 (PID %d)", getpid());

    // Mount essential filesystems
    mkdir("/proc", 0755);
    mkdir("/sys", 0755);
    mkdir("/dev", 0755);
    mkdir("/run", 0755);

    if (mount("proc", "/proc", "proc", 0, NULL) && errno != EBUSY) {
        FATAL("Failed to mount /proc: %s", strerror(errno));
    }
    if (mount("sysfs", "/sys", "sysfs", 0, NULL) && errno != EBUSY) {
        FATAL("Failed to mount /sys: %s", strerror(errno));
    }
    if (mount("devtmpfs", "/dev", "devtmpfs", 0, NULL) && errno != EBUSY) {
        FATAL("Failed to mount /dev: %s", strerror(errno));
    }
    if (mount("tmpfs", "/run", "tmpfs", 0, NULL) && errno != EBUSY) {
        LOG("Warning: mount /run failed: %s", strerror(errno));
    }

    LOG("Essential filesystems mounted");

    // Detect mode
    kestrel_mode_t mode = detect_mode();

    switch (mode) {
        case MODE_BUILD:
            LOG("Mode: BUILD");
            run_build_mode();
            break;

        case MODE_RUNTIME:
            LOG("Mode: RUNTIME");
            run_runtime_mode();
            break;

        default:
            FATAL("Unknown mode");
    }

    return 0;
}
