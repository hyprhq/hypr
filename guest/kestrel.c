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
#include <netinet/in.h>
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

// ====== SELF-CONTAINED ROUTING DEFINITIONS ======
#ifndef RTF_UP
#define RTF_UP 0x0001
#endif

#ifndef RTF_GATEWAY
#define RTF_GATEWAY 0x0002
#endif

struct rtentry {
    unsigned long rt_pad1;
    struct sockaddr rt_dst;
    struct sockaddr rt_gateway;
    struct sockaddr rt_genmask;
    unsigned short rt_flags;
    short rt_pad2;
    unsigned long rt_pad3;
    void *rt_pad4;
    short rt_metric;
    char *rt_dev;
    unsigned long rt_mtu;
    unsigned long rt_window;
    unsigned short rt_irtt;
};


// Constants
#define MAX_CMD_LEN 8192
#define MAX_CMDLINE_LEN 8192
#define COMMAND_DIR "/context/.hypr/commands"

#include <sys/statvfs.h>

// Log disk space for debugging
static void log_disk_space(const char *label) {
    struct statvfs stat;
    if (statvfs("/", &stat) == 0) {
        unsigned long long total = (unsigned long long)stat.f_blocks * stat.f_frsize;
        unsigned long long avail = (unsigned long long)stat.f_bavail * stat.f_frsize;
        unsigned long long used = total - avail;
        printf("[kestrel] Disk (%s): %.1f MB used / %.1f MB total (%.1f MB free)\n",
               label,
               (double)used / (1024.0 * 1024.0),
               (double)total / (1024.0 * 1024.0),
               (double)avail / (1024.0 * 1024.0));
        fflush(stdout);
    }
}

// Signal handler for debugging unexpected signals
static void signal_handler(int sig) {
    printf("[kestrel] FATAL: Received signal %d (%s)\n", sig,
           sig == SIGTERM ? "SIGTERM" :
           sig == SIGKILL ? "SIGKILL" :
           sig == SIGSEGV ? "SIGSEGV" :
           sig == SIGBUS ? "SIGBUS" :
           sig == SIGABRT ? "SIGABRT" : "unknown");
    fflush(stdout);
    _exit(128 + sig);
}

// Forward declarations for network functions (defined in RUNTIME MODE section)
static int parse_ipv4(const char *str, unsigned int *out);
static int configure_interface(const char *ifname, unsigned int ip, unsigned int netmask);
static int add_default_route(unsigned int gateway, const char *ifname);
static const char* find_net_interface(void);

// Base64 URL-safe decode (no padding)
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int b64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

static char* base64_decode(const char *input, size_t *out_len) {
    size_t in_len = strlen(input);
    size_t alloc_len = (in_len * 3) / 4 + 4;
    char *output = malloc(alloc_len);
    if (!output) return NULL;

    size_t j = 0;
    unsigned int buf = 0;
    int bits = 0;

    for (size_t i = 0; i < in_len; i++) {
        int val = b64_decode_char(input[i]);
        if (val < 0) continue;  // Skip invalid chars (including padding =)

        buf = (buf << 6) | val;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            output[j++] = (buf >> bits) & 0xFF;
        }
    }

    output[j] = '\0';
    if (out_len) *out_len = j;
    return output;
}

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

    // Bring up loopback interface
    bring_up_loopback();

    // Configure network for package downloads (bun install, npm install, etc.)
    // Use static IP for vfkit NAT: 192.168.64.0/24, gateway 192.168.64.1
    const char *ifname = find_net_interface();
    if (ifname && strcmp(ifname, "lo") != 0) {
        LOG("Configuring network interface %s for builds...", ifname);
        unsigned int ip, netmask, gateway;
        // vfkit NAT defaults: 192.168.64.0/24
        parse_ipv4("192.168.64.10", &ip);      // Use .10 for build VMs
        parse_ipv4("255.255.255.0", &netmask);
        parse_ipv4("192.168.64.1", &gateway);

        if (configure_interface(ifname, ip, netmask) == 0) {
            LOG("Network interface %s configured: 192.168.64.10", ifname);
            if (add_default_route(gateway, ifname) == 0) {
                LOG("Default route added via 192.168.64.1");
            }
            // Set up DNS (use common public DNS)
            FILE *resolv = fopen("/etc/resolv.conf", "w");
            if (resolv) {
                fprintf(resolv, "nameserver 8.8.8.8\nnameserver 1.1.1.1\n");
                fclose(resolv);
                LOG("DNS configured (8.8.8.8, 1.1.1.1)");
            }
        } else {
            LOG("Warning: Failed to configure network interface");
        }
    }

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
    // Use retry logic like context/shared mounts - device may not be ready immediately
    mkdir("/base", 0755);
    LOG("Attempting to mount base image via virtiofs (tag 'base')...");
    int base_mounted = 0;
    for (int retry = 0; retry < 10; retry++) {
        if (mount("base", "/base", "virtiofs", 0, NULL) == 0) {
            base_mounted = 1;
            LOG("Base image mounted at /base (attempt %d)", retry + 1);
            break;
        }
        usleep(100000 * (retry + 1)); // Exponential backoff: 100ms, 200ms, 300ms...
    }

    if (!base_mounted) {
        // Base mount failed - this is only OK for FROM scratch
        // For real images, the host should have set up the virtio-fs mount
        LOG("WARNING: base rootfs not mounted after 10 retries: %s", strerror(errno));
        LOG("This is only expected for FROM scratch builds.");
        LOG("If using a real base image (e.g., oven/bun), this is a bug!");
        LOG("Build will continue but may produce an incomplete image.");

        // For FROM scratch, create a minimal rootfs structure
        LOG("Creating minimal rootfs structure for scratch build...");
        mkdir("/tmp", 0777);
        mkdir("/etc", 0755);
        // Continue without overlayfs - just use the current root
        return;
    }

    LOG("Creating overlayfs with base as lowerdir...");

    // Create overlayfs with base as lower (read-only) and workspace as upper (writable)
    // CRITICAL: upperdir and workdir MUST be on the same mount
    // Create dedicated tmpfs for overlay layer (portable across VMMs)
    // Size must be large enough for node_modules and build artifacts (4GB)
    mkdir("/overlay", 0755);
    LOG("Creating tmpfs for overlay at /overlay");
    if (mount("tmpfs", "/overlay", "tmpfs", 0, "size=4G")) {
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
        LOG("scan_for_command: cannot open %s: %s", COMMAND_DIR, strerror(errno));
        return NULL;
    }

    struct dirent *entry;
    char *cmd_path = NULL;
    int min_number = 999999;
    int files_found = 0;

    // Find lowest numbered .cmd file
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_REG && entry->d_type != DT_UNKNOWN) {
            continue;
        }

        // Look for NNN.cmd pattern
        int num;
        if (sscanf(entry->d_name, "%d.cmd", &num) == 1) {
            files_found++;
            LOG("scan_for_command: found %s (num=%d)", entry->d_name, num);
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
    if (files_found == 0) {
        LOG("scan_for_command: no .cmd files found");
    } else {
        LOG("scan_for_command: selected %s (min=%d, total=%d files)", cmd_path ? cmd_path : "NULL", min_number, files_found);
    }
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
    char output_tar[512];
    snprintf(output_tar, sizeof(output_tar), "/shared/layer-%s.tar", layer_id);

    // Log current directory contents for debugging
    LOG("Creating tarball of rootfs...");

    // Check what's in the root directory
    DIR *dir = opendir("/");
    if (dir) {
        struct dirent *entry;
        LOG("Root directory contents:");
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] != '.') {
                LOG("  /%s", entry->d_name);
            }
        }
        closedir(dir);
    }

    // Create tarball of entire rootfs (we're chrooted into the overlayfs)
    // Use uncompressed tar for reliability (host can handle it)
    // IMPORTANT: Use ./name patterns to only exclude root-level dirs, not nested ones
    // (e.g., exclude ./shared but NOT ./app/node_modules/next/dist/shared)
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "cd / && tar -cf %s --exclude=./shared --exclude=./context --exclude=./base --exclude=./proc --exclude=./sys --exclude=./dev .",
        output_tar);

    LOG("Running: %s", cmd);
    int ret = system(cmd);

    if (ret != 0) {
        LOG("tar command failed with exit code %d", ret);
        return -1;
    }

    // Check file was created and get size
    struct stat st;
    if (stat(output_tar, &st) != 0) {
        LOG("Tarball not created at %s: %s", output_tar, strerror(errno));
        return -1;
    }

    LOG("Tarball created: %s (%.2f MB)", output_tar, (double)st.st_size / (1024.0 * 1024.0));

    // Warn if suspiciously small (< 10MB suggests base image not included)
    if (st.st_size < 10 * 1024 * 1024) {
        LOG("WARNING: Tarball is only %.2f MB - base image may not be mounted!",
            (double)st.st_size / (1024.0 * 1024.0));
    }

    return 0;
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

    // Install signal handlers for debugging
    signal(SIGTERM, signal_handler);
    signal(SIGSEGV, signal_handler);
    signal(SIGBUS, signal_handler);
    signal(SIGABRT, signal_handler);

    // Mount essential filesystems
    mount_essentials_build();

    LOG("Build VM ready, waiting for commands at %s", COMMAND_DIR);
    log_disk_space("after mount");
    printf("[kestrel] READY\n");
    fflush(stdout);

    // Command loop: watch for command files in /context/.hypr/commands/
    int cmd_count = 0;
    for (;;) {
        char *cmd_path = scan_for_command();

        if (!cmd_path) {
            // No command found, sleep and retry
            usleep(100000); // 100ms
            continue;
        }

        cmd_count++;
        LOG("Found command %d: %s", cmd_count, cmd_path);
        log_disk_space("before cmd");

        // Execute command
        handle_command_file(cmd_path);
        log_disk_space("after cmd");

        LOG("Completed command %d, deleting %s", cmd_count, cmd_path);

        // Delete command file (signal completion to host)
        unlink(cmd_path);
        free(cmd_path);
    }
}

// ============================================================================
// RUNTIME MODE - NETWORK CONFIGURATION
// ============================================================================

// Parse a key=value parameter from /proc/cmdline
// Returns malloc'd value or NULL if not found
static char* parse_cmdline_param(const char *cmdline, const char *key) {
    size_t key_len = strlen(key);
    const char *pos = cmdline;

    while ((pos = strstr(pos, key)) != NULL) {
        // Check that we're at word boundary (start of string or after space)
        if (pos != cmdline && *(pos - 1) != ' ') {
            pos++;
            continue;
        }

        // Check for '=' after key
        if (pos[key_len] == '=') {
            const char *value_start = pos + key_len + 1;
            const char *value_end = value_start;

            // Find end of value (space or end of string)
            while (*value_end && *value_end != ' ' && *value_end != '\n') {
                value_end++;
            }

            size_t value_len = value_end - value_start;
            char *value = malloc(value_len + 1);
            if (value) {
                memcpy(value, value_start, value_len);
                value[value_len] = '\0';
            }
            return value;
        }
        pos++;
    }
    return NULL;
}

// Convert dotted IP string to network byte order uint32_t
static int parse_ipv4(const char *str, unsigned int *out) {
    unsigned int a, b, c, d;
    if (sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return -1;
    }
    if (a > 255 || b > 255 || c > 255 || d > 255) {
        return -1;
    }
    // Network byte order (big endian)
    *out = (a) | (b << 8) | (c << 16) | (d << 24);
    return 0;
}

// Set up a sockaddr_in structure for IP configuration
static void set_sockaddr_in(struct sockaddr *sa, unsigned int ip) {
    struct sockaddr_in *sin = (struct sockaddr_in *)sa;
    memset(sin, 0, sizeof(*sin));
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip;
}

// Configure a network interface with IP, netmask, and bring it up
static int configure_interface(const char *ifname, unsigned int ip, unsigned int netmask) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG("socket() failed: %s", strerror(errno));
        return -1;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    // Set IP address
    set_sockaddr_in(&ifr.ifr_addr, ip);
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        LOG("SIOCSIFADDR failed for %s: %s", ifname, strerror(errno));
        close(sock);
        return -1;
    }

    // Set netmask
    set_sockaddr_in(&ifr.ifr_addr, netmask);
    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        LOG("SIOCSIFNETMASK failed for %s: %s", ifname, strerror(errno));
        close(sock);
        return -1;
    }

    // Bring interface up
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        LOG("SIOCGIFFLAGS failed for %s: %s", ifname, strerror(errno));
        close(sock);
        return -1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        LOG("SIOCSIFFLAGS failed for %s: %s", ifname, strerror(errno));
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}

// Add default route via gateway
static int add_default_route(unsigned int gateway, const char *ifname) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG("socket() failed: %s", strerror(errno));
        return -1;
    }

    struct rtentry rt;
    memset(&rt, 0, sizeof(rt));

    // Destination: 0.0.0.0 (default)
    set_sockaddr_in(&rt.rt_dst, 0);

    // Gateway
    set_sockaddr_in(&rt.rt_gateway, gateway);

    // Genmask: 0.0.0.0
    set_sockaddr_in(&rt.rt_genmask, 0);

    // Flags: UP + GATEWAY
    rt.rt_flags = RTF_UP | RTF_GATEWAY;

    // Device (cast away const for legacy API)
    rt.rt_dev = (char *)ifname;

    if (ioctl(sock, SIOCADDRT, &rt) < 0) {
        // EEXIST is OK - route already exists
        if (errno != EEXIST) {
            LOG("SIOCADDRT failed: %s", strerror(errno));
            close(sock);
            return -1;
        }
    }

    close(sock);
    return 0;
}

// Find first virtio network interface (eth0, enp0s*, etc.)
static const char* find_net_interface(void) {
    // Try common interface names in order
    static const char *candidates[] = {"eth0", "enp0s1", "enp0s2", "ens3", NULL};

    for (int i = 0; candidates[i]; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/sys/class/net/%s", candidates[i]);
        struct stat st;
        if (stat(path, &st) == 0) {
            return candidates[i];
        }
    }

    // Fallback: scan /sys/class/net for first non-lo interface
    DIR *dir = opendir("/sys/class/net");
    if (!dir) return "eth0";  // Default fallback

    static char ifname[IFNAMSIZ];
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.' || strcmp(entry->d_name, "lo") == 0) {
            continue;
        }
        strncpy(ifname, entry->d_name, IFNAMSIZ - 1);
        ifname[IFNAMSIZ - 1] = '\0';
        closedir(dir);
        return ifname;
    }
    closedir(dir);
    return "eth0";  // Default fallback
}

// Mount rootfs from squashfs and set up overlayfs
static int mount_runtime_rootfs(void) {
    // Create mount points
    mkdir("/mnt", 0755);
    mkdir("/mnt/rootfs", 0755);
    mkdir("/mnt/overlay", 0755);
    mkdir("/mnt/overlay/upper", 0755);
    mkdir("/mnt/overlay/work", 0755);
    mkdir("/newroot", 0755);

    // Wait for virtio-blk device to appear
    LOG("Waiting for rootfs device...");
    const char *rootfs_dev = NULL;
    static const char *candidates[] = {"/dev/vda", "/dev/sda", NULL};

    for (int retry = 0; retry < 30; retry++) {
        for (int i = 0; candidates[i]; i++) {
            struct stat st;
            if (stat(candidates[i], &st) == 0 && S_ISBLK(st.st_mode)) {
                rootfs_dev = candidates[i];
                break;
            }
        }
        if (rootfs_dev) break;
        usleep(100000);  // 100ms
    }

    if (!rootfs_dev) {
        LOG("No rootfs device found");
        return -1;
    }

    LOG("Found rootfs device: %s", rootfs_dev);

    // Mount squashfs (read-only)
    if (mount(rootfs_dev, "/mnt/rootfs", "squashfs", MS_RDONLY, NULL) < 0) {
        LOG("Failed to mount squashfs: %s", strerror(errno));
        return -1;
    }
    LOG("Squashfs mounted at /mnt/rootfs");

    // Mount tmpfs for overlay upper/work
    if (mount("tmpfs", "/mnt/overlay", "tmpfs", 0, "size=512M") < 0) {
        LOG("Failed to mount overlay tmpfs: %s", strerror(errno));
        return -1;
    }
    mkdir("/mnt/overlay/upper", 0755);
    mkdir("/mnt/overlay/work", 0755);

    // Mount overlayfs
    char overlay_opts[256];
    snprintf(overlay_opts, sizeof(overlay_opts),
             "lowerdir=/mnt/rootfs,upperdir=/mnt/overlay/upper,workdir=/mnt/overlay/work");

    if (mount("overlay", "/newroot", "overlay", 0, overlay_opts) < 0) {
        LOG("Failed to mount overlayfs: %s", strerror(errno));
        return -1;
    }
    LOG("Overlayfs mounted at /newroot");

    // Mount essential filesystems in newroot
    mkdir("/newroot/proc", 0755);
    mkdir("/newroot/sys", 0755);
    mkdir("/newroot/dev", 0755);
    mkdir("/newroot/tmp", 0777);
    mkdir("/newroot/run", 0755);

    mount("proc", "/newroot/proc", "proc", 0, NULL);
    mount("sysfs", "/newroot/sys", "sysfs", 0, NULL);
    mount("devtmpfs", "/newroot/dev", "devtmpfs", 0, NULL);
    mount("tmpfs", "/newroot/tmp", "tmpfs", 0, NULL);
    mount("tmpfs", "/newroot/run", "tmpfs", 0, NULL);

    return 0;
}

// ============================================================================
// RUNTIME MODE - MAIN ENTRY POINT
// ============================================================================

static void run_runtime_mode(void) {
    LOG("Starting runtime mode");

    // Read kernel cmdline
    FILE *f = fopen("/proc/cmdline", "r");
    if (!f) {
        FATAL("Cannot read /proc/cmdline");
    }

    char cmdline[MAX_CMDLINE_LEN];
    if (!fgets(cmdline, sizeof(cmdline), f)) {
        fclose(f);
        FATAL("Empty /proc/cmdline");
    }
    fclose(f);

    LOG("Kernel cmdline: %s", cmdline);

    // Parse network parameters
    char *ip_str = parse_cmdline_param(cmdline, "ip");
    char *netmask_str = parse_cmdline_param(cmdline, "netmask");
    char *gateway_str = parse_cmdline_param(cmdline, "gateway");

    // Bring up loopback first
    bring_up_loopback();

    // Configure network if IP was provided
    if (ip_str) {
        unsigned int ip, netmask, gateway;

        if (parse_ipv4(ip_str, &ip) < 0) {
            LOG("Invalid IP address: %s", ip_str);
            free(ip_str);
            if (netmask_str) free(netmask_str);
            if (gateway_str) free(gateway_str);
            FATAL("Invalid IP address");
        }

        // Default netmask if not provided
        if (netmask_str && parse_ipv4(netmask_str, &netmask) < 0) {
            LOG("Invalid netmask: %s, using default", netmask_str);
            netmask = 0x00FFFFFF;  // 255.255.255.0 in network byte order
        } else if (!netmask_str) {
            netmask = 0x00FFFFFF;  // 255.255.255.0
        }

        // Gateway is optional
        if (gateway_str && parse_ipv4(gateway_str, &gateway) < 0) {
            LOG("Invalid gateway: %s", gateway_str);
            gateway = 0;
        } else if (!gateway_str) {
            gateway = 0;
        }

        // Find network interface
        const char *ifname = find_net_interface();
        LOG("Configuring interface: %s", ifname);

        // Configure interface
        if (configure_interface(ifname, ip, netmask) < 0) {
            LOG("Failed to configure network interface");
        } else {
            LOG("Network interface %s configured: %s", ifname, ip_str);

            // Add default route if gateway provided
            if (gateway != 0) {
                if (add_default_route(gateway, ifname) < 0) {
                    LOG("Failed to add default route");
                } else {
                    LOG("Default route added via %s", gateway_str);
                }
            }
        }

        free(ip_str);
        if (netmask_str) free(netmask_str);
        if (gateway_str) free(gateway_str);
    } else {
        LOG("No IP address in cmdline, skipping network configuration");
    }

    // Mount rootfs
    if (mount_runtime_rootfs() < 0) {
        LOG("Failed to mount rootfs, continuing without chroot");
    } else {
        // Chroot into newroot
        if (chdir("/newroot") == 0 && chroot("/newroot") == 0) {
            chdir("/");
            LOG("Chrooted into rootfs");
        } else {
            LOG("Chroot failed: %s", strerror(errno));
        }
    }

    // Print ready message
    LOG("Runtime mode ready");
    printf("[kestrel] RUNTIME_READY\n");
    fflush(stdout);

    // Parse cmd= from cmdline (base64-encoded command)
    char *cmd_b64 = parse_cmdline_param(cmdline, "cmd");
    char *workdir = parse_cmdline_param(cmdline, "workdir");

    if (cmd_b64) {
        // Decode base64 command
        size_t cmd_len;
        char *cmd = base64_decode(cmd_b64, &cmd_len);
        free(cmd_b64);

        if (cmd && cmd_len > 0) {
            LOG("Executing workload: %s", cmd);

            // Change to workdir if specified
            if (workdir && workdir[0] != '\0') {
                if (chdir(workdir) < 0) {
                    LOG("Warning: chdir to %s failed: %s", workdir, strerror(errno));
                } else {
                    LOG("Changed to workdir: %s", workdir);
                }
            }

            // Fork and exec the workload
            pid_t child_pid = fork();
            if (child_pid < 0) {
                LOG("Fork failed: %s", strerror(errno));
            } else if (child_pid == 0) {
                // Child process - exec the command
                execl("/bin/sh", "sh", "-c", cmd, NULL);
                // If exec fails, try busybox sh
                execl("/bin/busybox", "sh", "-c", cmd, NULL);
                fprintf(stderr, "[kestrel] exec failed: %s\n", strerror(errno));
                _exit(127);
            } else {
                // Parent - workload is running
                LOG("Workload started with PID %d", child_pid);
            }

            free(cmd);
        }

        if (workdir) free(workdir);
    } else {
        LOG("No cmd= in cmdline, idling");
    }

    // Main loop: reap zombies, wait for shutdown
    for (;;) {
        int status;
        pid_t pid = waitpid(-1, &status, WNOHANG);
        if (pid > 0) {
            if (WIFEXITED(status)) {
                LOG("Process %d exited with code %d", pid, WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                LOG("Process %d killed by signal %d", pid, WTERMSIG(status));
            }
        }
        sleep(1);
    }
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char *argv[]) {
    // CRITICAL: Redirect stdout/stderr to console FIRST (before any LOG())
    // In initramfs, default stdout/stderr go nowhere
    // Try multiple console devices in order of preference:
    // 1. /dev/hvc0 - virtio-serial (vfkit on macOS, major 229 minor 0)
    // 2. /dev/ttyS0 - legacy serial (cloud-hypervisor on Linux, major 4 minor 64)
    // 3. /dev/console - fallback (major 5 minor 1)
    mkdir("/dev", 0755);
    
    int console_fd = -1;
    
    // Try hvc0 first (virtio-serial for vfkit/macOS)
    mknod("/dev/hvc0", S_IFCHR | 0600, makedev(229, 0));
    console_fd = open("/dev/hvc0", O_WRONLY);
    
    if (console_fd < 0) {
        // Try ttyS0 (legacy serial for cloud-hypervisor/Linux)
        mknod("/dev/ttyS0", S_IFCHR | 0600, makedev(4, 64));
        console_fd = open("/dev/ttyS0", O_WRONLY);
    }
    
    if (console_fd < 0) {
        // Fallback to /dev/console
        mknod("/dev/console", S_IFCHR | 0600, makedev(5, 1));
        console_fd = open("/dev/console", O_WRONLY);
    }

    if (console_fd >= 0) {
        dup2(console_fd, STDOUT_FILENO);
        dup2(console_fd, STDERR_FILENO);
        if (console_fd > 2) close(console_fd);
    }

    LOG("Starting kestrel v2.0 (PID %d)", getpid());

    // PID1 tasks mount essential filesystems
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

    // Now detect mode from kernel cmdline (requires /proc)
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
            FATAL("Unknown mode detected");
    }

    return 0;
}
