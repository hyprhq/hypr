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
#include <sys/inotify.h>
#include <limits.h>  // NAME_MAX
#include <sys/select.h>
#include <termios.h>
#include <pty.h>      // For forkpty()

// ===== VSOCK (self-contained) =====
#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

#ifndef VMADDR_CID_ANY
#define VMADDR_CID_ANY -1U
#endif

#ifndef VMADDR_CID_HOST
#define VMADDR_CID_HOST 2
#endif

struct sockaddr_vm {
    sa_family_t svm_family;
    unsigned short svm_reserved1;
    unsigned int svm_port;
    unsigned int svm_cid;
    unsigned char svm_zero[sizeof(struct sockaddr) - sizeof(sa_family_t) - sizeof(unsigned short) - sizeof(unsigned int) - sizeof(unsigned int)];
};

// Exec server constants
#define EXEC_VSOCK_PORT 1024
#define EXEC_MAX_SESSIONS 16
#define EXEC_BUF_SIZE 4096

// Message types (matching protocol.rs)
#define MSG_EXEC_REQUEST  0x01
#define MSG_EXEC_RESPONSE 0x02
#define MSG_STDIN         0x03
#define MSG_STDOUT        0x04
#define MSG_STDERR        0x05
#define MSG_SIGNAL        0x06
#define MSG_RESIZE        0x07
#define MSG_CLOSE         0x08

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

// Buffer size for inotify events
#define INOTIFY_BUF_LEN (10 * (sizeof(struct inotify_event) + NAME_MAX + 1))

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

    // Ensure command directory exists
    mkdir(COMMAND_DIR, 0755);

    // Try to set up inotify (may not work on virtio-fs, will fallback to polling)
    int inotify_fd = inotify_init1(IN_NONBLOCK);
    int watch_fd = -1;
    int use_inotify = 0;

    if (inotify_fd >= 0) {
        watch_fd = inotify_add_watch(inotify_fd, COMMAND_DIR,
            IN_CREATE | IN_MOVED_TO | IN_CLOSE_WRITE);
        if (watch_fd >= 0) {
            use_inotify = 1;
            LOG("Using inotify for command directory watch");
        } else {
            LOG("inotify_add_watch failed: %s, falling back to polling", strerror(errno));
            close(inotify_fd);
            inotify_fd = -1;
        }
    } else {
        LOG("inotify_init failed: %s, using polling", strerror(errno));
    }

    char inotify_buf[INOTIFY_BUF_LEN];
    int cmd_count = 0;
    int poll_count = 0;

    // Command loop: watch for command files in /context/.hypr/commands/
    for (;;) {
        // First, check for any existing command files
        char *cmd_path = scan_for_command();

        if (cmd_path) {
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
            poll_count = 0;  // Reset poll counter after successful command
            continue;
        }

        // No command found, wait for new files
        if (use_inotify) {
            // Use inotify with timeout
            fd_set fds;
            FD_ZERO(&fds);
            FD_SET(inotify_fd, &fds);

            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 500000;  // 500ms timeout (inotify may not work on virtio-fs)

            int ret = select(inotify_fd + 1, &fds, NULL, NULL, &tv);
            if (ret > 0 && FD_ISSET(inotify_fd, &fds)) {
                // Read and discard inotify events (we'll re-scan the directory)
                ssize_t len = read(inotify_fd, inotify_buf, sizeof(inotify_buf));
                if (len > 0) {
                    LOG("inotify: received %zd bytes of events", len);
                }
            } else if (ret == 0) {
                // Timeout - do a poll anyway (virtio-fs may not trigger inotify)
                poll_count++;
                if (poll_count > 10) {
                    // After 5 seconds without inotify events, disable it
                    LOG("inotify appears unreliable on virtio-fs, switching to polling");
                    use_inotify = 0;
                    close(inotify_fd);
                    inotify_fd = -1;
                }
            }
        } else {
            // Pure polling fallback
            usleep(100000);  // 100ms
        }
    }

    // Cleanup (never reached in normal operation)
    if (inotify_fd >= 0) {
        if (watch_fd >= 0) inotify_rm_watch(inotify_fd, watch_fd);
        close(inotify_fd);
    }
}

// ============================================================================
// JSON PARSING (minimal implementation for RuntimeManifest)
// ============================================================================
//
// SECURITY: These parsers use a state machine to track JSON structure depth.
// This prevents injection attacks where keys could be spoofed inside string values.
// Example attack: {"description": "fake \"ip\": \"malicious\"", "ip": "192.168.1.1"}
// Without depth tracking, strstr() might find the fake "ip" inside the description.

// JSON parser state for tracking string context
typedef enum {
    JSON_STATE_VALUE,      // Outside strings (parsing structure)
    JSON_STATE_STRING,     // Inside a quoted string
    JSON_STATE_ESCAPE      // After backslash inside string
} json_state_t;

// Internal: Skip whitespace
static const char* json_skip_ws(const char *p) {
    while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    return p;
}

// Internal: Check if we're at a specific key pattern at current position
// Returns pointer past the colon if matched, NULL otherwise
static const char* json_match_key(const char *pos, const char *key) {
    if (*pos != '"') return NULL;
    pos++;

    size_t key_len = strlen(key);
    if (strncmp(pos, key, key_len) != 0) return NULL;
    pos += key_len;

    if (*pos != '"') return NULL;
    pos++;

    pos = json_skip_ws(pos);
    if (*pos != ':') return NULL;
    pos++;

    return json_skip_ws(pos);
}

// Extract a string value from JSON by key using depth-aware parsing
// target_depth: The brace depth at which to search (1 = inside root object)
// Returns malloc'd string or NULL
static char* json_get_string_at_depth(const char *json, const char *key, int target_depth) {
    if (!json || !key) return NULL;

    json_state_t state = JSON_STATE_VALUE;
    int brace_depth = 0;
    int bracket_depth = 0;

    const char *pos = json;
    while (*pos) {
        switch (state) {
            case JSON_STATE_VALUE:
                if (*pos == '"') {
                    // Check if this starts our target key at the correct depth
                    if (brace_depth == target_depth) {
                        const char *value_start = json_match_key(pos, key);
                        if (value_start && *value_start == '"') {
                            // Found key at correct depth, extract string value
                            value_start++;  // Skip opening quote

                            const char *end = value_start;
                            while (*end && *end != '"') {
                                if (*end == '\\' && *(end + 1)) end++;
                                end++;
                            }
                            if (!*end) return NULL;

                            size_t len = end - value_start;
                            char *result = malloc(len + 1);
                            if (!result) return NULL;
                            memcpy(result, value_start, len);
                            result[len] = '\0';
                            return result;
                        }
                    }
                    // Enter string state (skip this string)
                    state = JSON_STATE_STRING;
                } else if (*pos == '{') {
                    brace_depth++;
                } else if (*pos == '}') {
                    brace_depth--;
                } else if (*pos == '[') {
                    bracket_depth++;
                } else if (*pos == ']') {
                    bracket_depth--;
                }
                break;

            case JSON_STATE_STRING:
                if (*pos == '\\') {
                    state = JSON_STATE_ESCAPE;
                } else if (*pos == '"') {
                    state = JSON_STATE_VALUE;
                }
                break;

            case JSON_STATE_ESCAPE:
                state = JSON_STATE_STRING;
                break;
        }
        pos++;
    }
    return NULL;
}

// Convenience wrapper: search at depth 1 (inside root object)
// This is the correct depth for: {"key": "value"} where we want "key"
static char* json_get_string(const char *json, const char *key) {
    return json_get_string_at_depth(json, key, 1);
}

// Extract array of strings from JSON by key using depth-aware parsing
// target_depth: The brace depth at which to search (1 = inside root object)
// Only handles: "key": ["val1", "val2"]
static char** json_get_string_array_at_depth(const char *json, const char *key, int *count, int target_depth) {
    if (!json || !key || !count) return NULL;
    *count = 0;

    json_state_t state = JSON_STATE_VALUE;
    int brace_depth = 0;
    int bracket_depth = 0;
    const char *array_start = NULL;

    // First pass: find the array at the correct depth
    const char *pos = json;
    while (*pos) {
        switch (state) {
            case JSON_STATE_VALUE:
                if (*pos == '"') {
                    // Check if this starts our target key at the correct depth
                    if (brace_depth == target_depth) {
                        const char *value_start = json_match_key(pos, key);
                        if (value_start && *value_start == '[') {
                            array_start = value_start + 1;  // Skip '['
                            goto found_array;
                        }
                    }
                    // Enter string state (skip this string)
                    state = JSON_STATE_STRING;
                } else if (*pos == '{') {
                    brace_depth++;
                } else if (*pos == '}') {
                    brace_depth--;
                } else if (*pos == '[') {
                    bracket_depth++;
                } else if (*pos == ']') {
                    bracket_depth--;
                }
                break;

            case JSON_STATE_STRING:
                if (*pos == '\\') {
                    state = JSON_STATE_ESCAPE;
                } else if (*pos == '"') {
                    state = JSON_STATE_VALUE;
                }
                break;

            case JSON_STATE_ESCAPE:
                state = JSON_STATE_STRING;
                break;
        }
        pos++;
    }
    return NULL;  // Key not found

found_array:
    // Second pass: count and extract elements from the array
    // At this point we're inside the array, so string parsing is safe
    pos = array_start;

    // Count elements first (simple count of top-level strings in array)
    int n = 0;
    const char *scan = pos;
    int arr_depth = 0;
    state = JSON_STATE_VALUE;

    while (*scan && !(*scan == ']' && arr_depth == 0 && state == JSON_STATE_VALUE)) {
        switch (state) {
            case JSON_STATE_VALUE:
                if (*scan == '"') {
                    if (arr_depth == 0) n++;  // Count top-level strings
                    state = JSON_STATE_STRING;
                } else if (*scan == '[') {
                    arr_depth++;
                } else if (*scan == ']') {
                    arr_depth--;
                }
                break;
            case JSON_STATE_STRING:
                if (*scan == '\\') {
                    state = JSON_STATE_ESCAPE;
                } else if (*scan == '"') {
                    state = JSON_STATE_VALUE;
                }
                break;
            case JSON_STATE_ESCAPE:
                state = JSON_STATE_STRING;
                break;
        }
        scan++;
    }

    if (n == 0) return NULL;

    char **result = malloc(sizeof(char*) * (n + 1));
    if (!result) return NULL;

    // Extract elements
    int i = 0;
    scan = pos;
    arr_depth = 0;
    state = JSON_STATE_VALUE;

    while (*scan && i < n) {
        switch (state) {
            case JSON_STATE_VALUE:
                if (*scan == '"') {
                    if (arr_depth == 0) {
                        // Extract this string
                        scan++;  // Skip opening quote
                        const char *end = scan;
                        while (*end && !(*end == '"' && *(end-1) != '\\')) {
                            if (*end == '\\' && *(end + 1)) end++;
                            end++;
                        }

                        size_t len = end - scan;
                        result[i] = malloc(len + 1);
                        if (result[i]) {
                            memcpy(result[i], scan, len);
                            result[i][len] = '\0';
                            i++;
                        }
                        scan = end;  // Points to closing quote, will be incremented past it
                        // Stay in VALUE state - we already processed this string
                    } else {
                        // Inside nested array - use state machine to skip strings
                        state = JSON_STATE_STRING;
                    }
                } else if (*scan == '[') {
                    arr_depth++;
                } else if (*scan == ']') {
                    if (arr_depth == 0) goto done_extracting;
                    arr_depth--;
                }
                break;
            case JSON_STATE_STRING:
                if (*scan == '\\') {
                    state = JSON_STATE_ESCAPE;
                } else if (*scan == '"') {
                    state = JSON_STATE_VALUE;
                }
                break;
            case JSON_STATE_ESCAPE:
                state = JSON_STATE_STRING;
                break;
        }
        scan++;
    }

done_extracting:
    result[i] = NULL;
    *count = i;
    return result;
}

// Convenience wrapper: search at depth 1 (inside root object)
static char** json_get_string_array(const char *json, const char *key, int *count) {
    return json_get_string_array_at_depth(json, key, count, 1);
}

// Free string array
static void free_string_array(char **arr, int count) {
    if (!arr) return;
    for (int i = 0; i < count; i++) {
        if (arr[i]) free(arr[i]);
    }
    free(arr);
}

// Get nested JSON object as string using depth-aware parsing (returns malloc'd string or NULL)
// target_depth: The brace depth at which to search (1 = inside root object)
static char* json_get_object_at_depth(const char *json, const char *key, int target_depth) {
    if (!json || !key) return NULL;

    json_state_t state = JSON_STATE_VALUE;
    int brace_depth = 0;

    const char *pos = json;
    while (*pos) {
        switch (state) {
            case JSON_STATE_VALUE:
                if (*pos == '"') {
                    // Check if this starts our target key at the correct depth
                    if (brace_depth == target_depth) {
                        const char *value_start = json_match_key(pos, key);
                        if (value_start && *value_start == '{') {
                            // Found key at correct depth, extract object
                            const char *obj_start = value_start;
                            const char *obj_end = value_start + 1;
                            int obj_depth = 1;
                            json_state_t obj_state = JSON_STATE_VALUE;

                            while (*obj_end && obj_depth > 0) {
                                switch (obj_state) {
                                    case JSON_STATE_VALUE:
                                        if (*obj_end == '{') obj_depth++;
                                        else if (*obj_end == '}') obj_depth--;
                                        else if (*obj_end == '"') obj_state = JSON_STATE_STRING;
                                        break;
                                    case JSON_STATE_STRING:
                                        if (*obj_end == '\\') obj_state = JSON_STATE_ESCAPE;
                                        else if (*obj_end == '"') obj_state = JSON_STATE_VALUE;
                                        break;
                                    case JSON_STATE_ESCAPE:
                                        obj_state = JSON_STATE_STRING;
                                        break;
                                }
                                obj_end++;
                            }

                            size_t len = obj_end - obj_start;
                            char *result = malloc(len + 1);
                            if (!result) return NULL;
                            memcpy(result, obj_start, len);
                            result[len] = '\0';
                            return result;
                        }
                    }
                    // Enter string state (skip this string)
                    state = JSON_STATE_STRING;
                } else if (*pos == '{') {
                    brace_depth++;
                } else if (*pos == '}') {
                    brace_depth--;
                }
                break;

            case JSON_STATE_STRING:
                if (*pos == '\\') {
                    state = JSON_STATE_ESCAPE;
                } else if (*pos == '"') {
                    state = JSON_STATE_VALUE;
                }
                break;

            case JSON_STATE_ESCAPE:
                state = JSON_STATE_STRING;
                break;
        }
        pos++;
    }
    return NULL;
}

// Convenience wrapper: search at depth 1 (inside root object)
static char* json_get_object(const char *json, const char *key) {
    return json_get_object_at_depth(json, key, 1);
}

// ============================================================================
// USER/GROUP SWITCHING
// ============================================================================

#include <pwd.h>
#include <grp.h>

// Parse user spec: "username", "uid", "uid:gid", "username:group"
// Returns 0 on success, -1 on error
static int parse_user_spec(const char *spec, uid_t *uid, gid_t *gid) {
    if (!spec || !uid || !gid) return -1;

    *uid = 0;
    *gid = 0;

    // Check for colon (uid:gid or user:group format)
    const char *colon = strchr(spec, ':');

    char user_part[256] = {0};
    char group_part[256] = {0};

    if (colon) {
        size_t user_len = colon - spec;
        if (user_len >= sizeof(user_part)) return -1;
        memcpy(user_part, spec, user_len);
        user_part[user_len] = '\0';
        strncpy(group_part, colon + 1, sizeof(group_part) - 1);
    } else {
        strncpy(user_part, spec, sizeof(user_part) - 1);
    }

    // Parse user part (numeric or name)
    char *endptr;
    long user_num = strtol(user_part, &endptr, 10);
    if (*endptr == '\0' && user_part[0] != '\0') {
        // Numeric UID
        *uid = (uid_t)user_num;
    } else {
        // Username - look up in /etc/passwd
        struct passwd *pw = getpwnam(user_part);
        if (!pw) {
            LOG("User not found: %s", user_part);
            return -1;
        }
        *uid = pw->pw_uid;
        *gid = pw->pw_gid;  // Use primary group from passwd
    }

    // Parse group part if specified
    if (group_part[0] != '\0') {
        long group_num = strtol(group_part, &endptr, 10);
        if (*endptr == '\0') {
            // Numeric GID
            *gid = (gid_t)group_num;
        } else {
            // Group name - look up in /etc/group
            struct group *gr = getgrnam(group_part);
            if (!gr) {
                LOG("Group not found: %s", group_part);
                return -1;
            }
            *gid = gr->gr_gid;
        }
    }

    return 0;
}

// Switch to user/group, returns 0 on success
static int switch_user(uid_t uid, gid_t gid) {
    if (uid == 0 && gid == 0) {
        return 0;  // Already root, nothing to do
    }

    // Set supplementary groups (clear them for security)
    if (setgroups(0, NULL) < 0 && errno != EPERM) {
        LOG("Warning: setgroups failed: %s", strerror(errno));
    }

    // Set GID first (before dropping root)
    if (gid != 0) {
        if (setgid(gid) < 0) {
            LOG("Failed to setgid(%d): %s", gid, strerror(errno));
            return -1;
        }
        if (setegid(gid) < 0) {
            LOG("Failed to setegid(%d): %s", gid, strerror(errno));
            return -1;
        }
    }

    // Set UID last
    if (uid != 0) {
        if (setuid(uid) < 0) {
            LOG("Failed to setuid(%d): %s", uid, strerror(errno));
            return -1;
        }
        if (seteuid(uid) < 0) {
            LOG("Failed to seteuid(%d): %s", uid, strerror(errno));
            return -1;
        }
    }

    LOG("Switched to uid=%d gid=%d", uid, gid);
    return 0;
}

// ============================================================================
// EXEC SERVER - VSOCK-BASED REMOTE EXECUTION
// ============================================================================
//
// Implements a vsock server that allows the host to execute commands inside
// the guest VM. Uses a binary protocol matching hypr-core/src/exec/protocol.rs.
//
// Protocol: Length-prefixed messages
//   [4 bytes: length (big-endian)] [length bytes: message body]
//
// Message body format:
//   [1 byte: type] [4 bytes: session_id (big-endian)] [payload...]

// Exec session state
typedef struct {
    uint32_t session_id;
    pid_t pid;
    int master_fd;      // PTY master (or pipe for non-tty)
    int stdout_fd;      // stdout pipe (non-tty mode only)
    int stderr_fd;      // stderr pipe (non-tty mode only)
    int is_tty;
    int active;
} exec_session_t;

// Global exec server state
static int g_exec_listen_fd = -1;
static int g_exec_client_fd = -1;
static exec_session_t g_exec_sessions[EXEC_MAX_SESSIONS];

// Helper: Read exactly n bytes from fd
static int read_exact(int fd, void *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t r = read(fd, (char *)buf + total, n - total);
        if (r <= 0) {
            if (r == 0) return -1;  // EOF
            if (errno == EINTR) continue;
            return -1;
        }
        total += r;
    }
    return 0;
}

// Helper: Write exactly n bytes to fd
static int write_exact(int fd, const void *buf, size_t n) {
    size_t total = 0;
    while (total < n) {
        ssize_t w = write(fd, (const char *)buf + total, n - total);
        if (w <= 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        total += w;
    }
    return 0;
}

// Helper: Read big-endian u32
static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

// Helper: Read big-endian u16
static uint16_t read_be16(const uint8_t *p) {
    return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

// Helper: Write big-endian u32
static void write_be32(uint8_t *p, uint32_t v) {
    p[0] = (v >> 24) & 0xFF;
    p[1] = (v >> 16) & 0xFF;
    p[2] = (v >> 8) & 0xFF;
    p[3] = v & 0xFF;
}

// Helper: Write big-endian i32
static void write_be32_signed(uint8_t *p, int32_t v) {
    write_be32(p, (uint32_t)v);
}

// Send a length-prefixed message
static int exec_send_message(int fd, const uint8_t *data, size_t len) {
    uint8_t header[4];
    write_be32(header, len);
    if (write_exact(fd, header, 4) < 0) return -1;
    if (len > 0 && write_exact(fd, data, len) < 0) return -1;
    return 0;
}

// Send ExecResponse message
static int exec_send_response(int fd, uint32_t session_id, int has_pid, uint32_t pid,
                               int has_exit_code, int32_t exit_code) {
    uint8_t buf[32];
    size_t pos = 0;

    buf[pos++] = MSG_EXEC_RESPONSE;
    write_be32(buf + pos, session_id); pos += 4;

    // Flags: bit 0 = has_pid, bit 1 = has_exit_code
    uint8_t flags = 0;
    if (has_pid) flags |= 1;
    if (has_exit_code) flags |= 2;
    buf[pos++] = flags;

    if (has_pid) {
        write_be32(buf + pos, pid);
        pos += 4;
    }
    if (has_exit_code) {
        write_be32_signed(buf + pos, exit_code);
        pos += 4;
    }

    return exec_send_message(fd, buf, pos);
}

// Send stdout/stderr data
static int exec_send_output(int fd, uint8_t msg_type, const uint8_t *data, size_t len) {
    if (len == 0) return 0;

    uint8_t *buf = malloc(5 + len);
    if (!buf) return -1;

    buf[0] = msg_type;
    write_be32(buf + 1, len);
    memcpy(buf + 5, data, len);

    int ret = exec_send_message(fd, buf, 5 + len);
    free(buf);
    return ret;
}

// Find session by ID
static exec_session_t* exec_find_session(uint32_t session_id) {
    for (int i = 0; i < EXEC_MAX_SESSIONS; i++) {
        if (g_exec_sessions[i].active && g_exec_sessions[i].session_id == session_id) {
            return &g_exec_sessions[i];
        }
    }
    return NULL;
}

// Find free session slot
static exec_session_t* exec_alloc_session(void) {
    for (int i = 0; i < EXEC_MAX_SESSIONS; i++) {
        if (!g_exec_sessions[i].active) {
            memset(&g_exec_sessions[i], 0, sizeof(exec_session_t));
            g_exec_sessions[i].active = 1;
            g_exec_sessions[i].master_fd = -1;
            g_exec_sessions[i].stdout_fd = -1;
            g_exec_sessions[i].stderr_fd = -1;
            return &g_exec_sessions[i];
        }
    }
    return NULL;
}

// Clean up session
static void exec_free_session(exec_session_t *sess) {
    if (!sess || !sess->active) return;

    if (sess->master_fd >= 0) close(sess->master_fd);
    if (sess->stdout_fd >= 0) close(sess->stdout_fd);
    if (sess->stderr_fd >= 0) close(sess->stderr_fd);

    // Kill process if still running
    if (sess->pid > 0) {
        kill(sess->pid, SIGTERM);
        usleep(10000);  // Give it 10ms
        kill(sess->pid, SIGKILL);
    }

    sess->active = 0;
}

// Handle ExecRequest message
static int exec_handle_request(int client_fd, const uint8_t *payload, size_t len) {
    if (len < 13) {
        LOG("ExecRequest too short: %zu bytes", len);
        return -1;
    }

    size_t pos = 0;
    uint32_t session_id = read_be32(payload + pos); pos += 4;
    uint8_t flags = payload[pos++];
    int want_tty = (flags & 1) != 0;
    uint16_t rows = read_be16(payload + pos); pos += 2;
    uint16_t cols = read_be16(payload + pos); pos += 2;

    // Read command
    uint32_t cmd_len = read_be32(payload + pos); pos += 4;
    if (pos + cmd_len > len) {
        LOG("ExecRequest command truncated");
        return -1;
    }

    char *command = malloc(cmd_len + 1);
    if (!command) return -1;
    memcpy(command, payload + pos, cmd_len);
    command[cmd_len] = '\0';
    pos += cmd_len;

    LOG("ExecRequest: session=%u tty=%d rows=%u cols=%u cmd='%s'",
        session_id, want_tty, rows, cols, command);

    // Parse environment variables
    char **env_vars = NULL;
    int env_count = 0;

    if (pos + 4 <= len) {
        env_count = read_be32(payload + pos); pos += 4;
        if (env_count > 0 && env_count < 256) {
            env_vars = malloc(sizeof(char*) * (env_count + 1));
            if (env_vars) {
                for (int i = 0; i < env_count && pos + 2 <= len; i++) {
                    uint16_t key_len = read_be16(payload + pos); pos += 2;
                    if (pos + key_len > len) break;
                    char *key = malloc(key_len + 1);
                    if (!key) break;
                    memcpy(key, payload + pos, key_len);
                    key[key_len] = '\0';
                    pos += key_len;

                    if (pos + 2 > len) { free(key); break; }
                    uint16_t val_len = read_be16(payload + pos); pos += 2;
                    if (pos + val_len > len) { free(key); break; }

                    // Format as KEY=VALUE
                    env_vars[i] = malloc(key_len + 1 + val_len + 1);
                    if (env_vars[i]) {
                        memcpy(env_vars[i], key, key_len);
                        env_vars[i][key_len] = '=';
                        memcpy(env_vars[i] + key_len + 1, payload + pos, val_len);
                        env_vars[i][key_len + 1 + val_len] = '\0';
                    }
                    free(key);
                    pos += val_len;
                }
                env_vars[env_count] = NULL;
            }
        }
    }

    // Allocate session
    exec_session_t *sess = exec_alloc_session();
    if (!sess) {
        LOG("No free exec sessions");
        free(command);
        if (env_vars) {
            for (int i = 0; i < env_count; i++) if (env_vars[i]) free(env_vars[i]);
            free(env_vars);
        }
        exec_send_response(client_fd, session_id, 0, 0, 1, 126);
        return 0;
    }

    sess->session_id = session_id;
    sess->is_tty = want_tty;

    if (want_tty) {
        // Use forkpty for TTY mode
        struct winsize ws = { .ws_row = rows, .ws_col = cols };
        pid_t pid = forkpty(&sess->master_fd, NULL, NULL, &ws);

        if (pid < 0) {
            LOG("forkpty failed: %s", strerror(errno));
            exec_free_session(sess);
            free(command);
            if (env_vars) {
                for (int i = 0; i < env_count; i++) if (env_vars[i]) free(env_vars[i]);
                free(env_vars);
            }
            exec_send_response(client_fd, session_id, 0, 0, 1, 126);
            return 0;
        }

        if (pid == 0) {
            // Child - set environment and exec
            if (env_vars) {
                for (int i = 0; i < env_count && env_vars[i]; i++) {
                    putenv(env_vars[i]);
                }
            }
            execl("/bin/sh", "sh", "-c", command, NULL);
            _exit(127);
        }

        // Parent
        sess->pid = pid;

        // Set non-blocking
        int fl = fcntl(sess->master_fd, F_GETFL);
        fcntl(sess->master_fd, F_SETFL, fl | O_NONBLOCK);

    } else {
        // Non-TTY mode: use pipes
        int stdout_pipe[2], stderr_pipe[2], stdin_pipe[2];

        if (pipe(stdout_pipe) < 0 || pipe(stderr_pipe) < 0 || pipe(stdin_pipe) < 0) {
            LOG("pipe failed: %s", strerror(errno));
            exec_free_session(sess);
            free(command);
            if (env_vars) {
                for (int i = 0; i < env_count; i++) if (env_vars[i]) free(env_vars[i]);
                free(env_vars);
            }
            exec_send_response(client_fd, session_id, 0, 0, 1, 126);
            return 0;
        }

        pid_t pid = fork();
        if (pid < 0) {
            LOG("fork failed: %s", strerror(errno));
            close(stdout_pipe[0]); close(stdout_pipe[1]);
            close(stderr_pipe[0]); close(stderr_pipe[1]);
            close(stdin_pipe[0]); close(stdin_pipe[1]);
            exec_free_session(sess);
            free(command);
            if (env_vars) {
                for (int i = 0; i < env_count; i++) if (env_vars[i]) free(env_vars[i]);
                free(env_vars);
            }
            exec_send_response(client_fd, session_id, 0, 0, 1, 126);
            return 0;
        }

        if (pid == 0) {
            // Child
            close(stdin_pipe[1]);
            close(stdout_pipe[0]);
            close(stderr_pipe[0]);

            dup2(stdin_pipe[0], STDIN_FILENO);
            dup2(stdout_pipe[1], STDOUT_FILENO);
            dup2(stderr_pipe[1], STDERR_FILENO);

            close(stdin_pipe[0]);
            close(stdout_pipe[1]);
            close(stderr_pipe[1]);

            if (env_vars) {
                for (int i = 0; i < env_count && env_vars[i]; i++) {
                    putenv(env_vars[i]);
                }
            }
            execl("/bin/sh", "sh", "-c", command, NULL);
            _exit(127);
        }

        // Parent
        close(stdin_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);

        sess->pid = pid;
        sess->master_fd = stdin_pipe[1];  // stdin write end
        sess->stdout_fd = stdout_pipe[0];
        sess->stderr_fd = stderr_pipe[0];

        // Set non-blocking
        fcntl(sess->stdout_fd, F_SETFL, fcntl(sess->stdout_fd, F_GETFL) | O_NONBLOCK);
        fcntl(sess->stderr_fd, F_SETFL, fcntl(sess->stderr_fd, F_GETFL) | O_NONBLOCK);
    }

    LOG("Started process PID %d for session %u", sess->pid, session_id);

    // Send response with PID
    exec_send_response(client_fd, session_id, 1, sess->pid, 0, 0);

    free(command);
    // Note: env_vars strings are used by putenv, don't free
    if (env_vars) free(env_vars);

    return 0;
}

// Handle Stdin message
static int exec_handle_stdin(const uint8_t *payload, size_t len) {
    if (len < 4) return -1;

    uint32_t data_len = read_be32(payload);
    if (4 + data_len > len) return -1;

    const uint8_t *data = payload + 4;

    // Find the active session and write to its stdin
    // For now, write to first active session (single session support)
    for (int i = 0; i < EXEC_MAX_SESSIONS; i++) {
        exec_session_t *sess = &g_exec_sessions[i];
        if (sess->active && sess->master_fd >= 0) {
            write(sess->master_fd, data, data_len);
            break;
        }
    }

    return 0;
}

// Handle Signal message
static int exec_handle_signal(const uint8_t *payload, size_t len) {
    if (len < 5) return -1;

    uint32_t session_id = read_be32(payload);
    uint8_t sig = payload[4];

    exec_session_t *sess = exec_find_session(session_id);
    if (sess && sess->pid > 0) {
        LOG("Sending signal %d to PID %d", sig, sess->pid);
        kill(sess->pid, sig);
    }

    return 0;
}

// Handle Resize message
static int exec_handle_resize(const uint8_t *payload, size_t len) {
    if (len < 8) return -1;

    uint32_t session_id = read_be32(payload);
    uint16_t rows = read_be16(payload + 4);
    uint16_t cols = read_be16(payload + 6);

    exec_session_t *sess = exec_find_session(session_id);
    if (sess && sess->is_tty && sess->master_fd >= 0) {
        struct winsize ws = { .ws_row = rows, .ws_col = cols };
        ioctl(sess->master_fd, TIOCSWINSZ, &ws);
    }

    return 0;
}

// Initialize vsock exec server
static int exec_server_init(void) {
    // Create vsock socket
    g_exec_listen_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (g_exec_listen_fd < 0) {
        LOG("Warning: vsock socket failed: %s (exec disabled)", strerror(errno));
        return -1;
    }

    // Bind to VMADDR_CID_ANY (accept from any CID) on our port
    struct sockaddr_vm addr = {0};
    addr.svm_family = AF_VSOCK;
    addr.svm_cid = VMADDR_CID_ANY;
    addr.svm_port = EXEC_VSOCK_PORT;

    if (bind(g_exec_listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG("Warning: vsock bind failed: %s (exec disabled)", strerror(errno));
        close(g_exec_listen_fd);
        g_exec_listen_fd = -1;
        return -1;
    }

    if (listen(g_exec_listen_fd, 5) < 0) {
        LOG("Warning: vsock listen failed: %s (exec disabled)", strerror(errno));
        close(g_exec_listen_fd);
        g_exec_listen_fd = -1;
        return -1;
    }

    // Set non-blocking
    int fl = fcntl(g_exec_listen_fd, F_GETFL);
    fcntl(g_exec_listen_fd, F_SETFL, fl | O_NONBLOCK);

    LOG("Exec server listening on vsock port %d", EXEC_VSOCK_PORT);
    return 0;
}

// Process incoming exec messages
static void exec_server_poll(void) {
    if (g_exec_listen_fd < 0) return;

    // Accept new connections
    if (g_exec_client_fd < 0) {
        struct sockaddr_vm peer;
        socklen_t peer_len = sizeof(peer);
        int client = accept(g_exec_listen_fd, (struct sockaddr *)&peer, &peer_len);
        if (client >= 0) {
            LOG("Exec client connected from CID %u", peer.svm_cid);
            g_exec_client_fd = client;
            fcntl(g_exec_client_fd, F_SETFL, fcntl(g_exec_client_fd, F_GETFL) | O_NONBLOCK);
        }
    }

    if (g_exec_client_fd < 0) return;

    // Try to read a message from client
    uint8_t len_buf[4];
    ssize_t r = recv(g_exec_client_fd, len_buf, 4, MSG_PEEK);
    if (r == 4) {
        uint32_t msg_len = read_be32(len_buf);
        if (msg_len > 0 && msg_len < 1024 * 1024) {  // Sanity limit: 1MB
            uint8_t *msg_buf = malloc(4 + msg_len);
            if (msg_buf) {
                r = recv(g_exec_client_fd, msg_buf, 4 + msg_len, MSG_PEEK);
                if (r == (ssize_t)(4 + msg_len)) {
                    // Got complete message, consume it
                    read(g_exec_client_fd, msg_buf, 4 + msg_len);

                    uint8_t *payload = msg_buf + 4;
                    if (msg_len >= 1) {
                        uint8_t msg_type = payload[0];
                        uint8_t *msg_payload = payload + 1;
                        size_t payload_len = msg_len - 1;

                        switch (msg_type) {
                            case MSG_EXEC_REQUEST:
                                exec_handle_request(g_exec_client_fd, msg_payload, payload_len);
                                break;
                            case MSG_STDIN:
                                exec_handle_stdin(msg_payload, payload_len);
                                break;
                            case MSG_SIGNAL:
                                exec_handle_signal(msg_payload, payload_len);
                                break;
                            case MSG_RESIZE:
                                exec_handle_resize(msg_payload, payload_len);
                                break;
                            case MSG_CLOSE:
                                LOG("Exec client sent close");
                                close(g_exec_client_fd);
                                g_exec_client_fd = -1;
                                // Clean up all sessions
                                for (int i = 0; i < EXEC_MAX_SESSIONS; i++) {
                                    exec_free_session(&g_exec_sessions[i]);
                                }
                                break;
                        }
                    }
                }
                free(msg_buf);
            }
        }
    } else if (r == 0) {
        // Client disconnected
        LOG("Exec client disconnected");
        close(g_exec_client_fd);
        g_exec_client_fd = -1;
    }

    // Relay output from active sessions to client
    for (int i = 0; i < EXEC_MAX_SESSIONS; i++) {
        exec_session_t *sess = &g_exec_sessions[i];
        if (!sess->active) continue;

        uint8_t buf[EXEC_BUF_SIZE];
        ssize_t n;

        if (sess->is_tty && sess->master_fd >= 0) {
            // PTY mode: read from master
            n = read(sess->master_fd, buf, sizeof(buf));
            if (n > 0 && g_exec_client_fd >= 0) {
                exec_send_output(g_exec_client_fd, MSG_STDOUT, buf, n);
            }
        } else {
            // Pipe mode: read from stdout and stderr separately
            if (sess->stdout_fd >= 0) {
                n = read(sess->stdout_fd, buf, sizeof(buf));
                if (n > 0 && g_exec_client_fd >= 0) {
                    exec_send_output(g_exec_client_fd, MSG_STDOUT, buf, n);
                }
            }
            if (sess->stderr_fd >= 0) {
                n = read(sess->stderr_fd, buf, sizeof(buf));
                if (n > 0 && g_exec_client_fd >= 0) {
                    exec_send_output(g_exec_client_fd, MSG_STDERR, buf, n);
                }
            }
        }

        // Check if process exited
        int status;
        pid_t result = waitpid(sess->pid, &status, WNOHANG);
        if (result == sess->pid) {
            int exit_code = WIFEXITED(status) ? WEXITSTATUS(status) :
                           (WIFSIGNALED(status) ? 128 + WTERMSIG(status) : -1);

            LOG("Session %u process exited with code %d", sess->session_id, exit_code);

            // Drain any remaining output
            if (sess->is_tty && sess->master_fd >= 0) {
                while ((n = read(sess->master_fd, buf, sizeof(buf))) > 0) {
                    if (g_exec_client_fd >= 0) {
                        exec_send_output(g_exec_client_fd, MSG_STDOUT, buf, n);
                    }
                }
            } else {
                if (sess->stdout_fd >= 0) {
                    while ((n = read(sess->stdout_fd, buf, sizeof(buf))) > 0) {
                        if (g_exec_client_fd >= 0) {
                            exec_send_output(g_exec_client_fd, MSG_STDOUT, buf, n);
                        }
                    }
                }
                if (sess->stderr_fd >= 0) {
                    while ((n = read(sess->stderr_fd, buf, sizeof(buf))) > 0) {
                        if (g_exec_client_fd >= 0) {
                            exec_send_output(g_exec_client_fd, MSG_STDERR, buf, n);
                        }
                    }
                }
            }

            // Send exit response
            if (g_exec_client_fd >= 0) {
                exec_send_response(g_exec_client_fd, sess->session_id, 1, sess->pid, 1, exit_code);
            }

            exec_free_session(sess);
        }
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
// ROSETTA x86_64 EMULATION (macOS ARM64 Mixed Mode)
// ============================================================================
//
// On macOS ARM64, Apple's Rosetta 2 can translate x86_64 binaries transparently.
// This enables running x86_64 container images on ARM64 hosts.
//
// How it works:
// 1. vfkit exposes the Rosetta runtime via virtio-fs share (mountTag=rosetta)
// 2. We mount that share and register it with binfmt_misc
// 3. Linux kernel delegates x86_64 ELF execution to Rosetta binary
//
// This is optional - if the share isn't available, we silently skip.

static void setup_rosetta(void) {
    // 1. Create mount point for the Rosetta binary
    mkdir("/mnt", 0755);
    mkdir("/mnt/rosetta", 0755);

    // 2. Try to mount the virtio-fs share exposed by vfkit
    // If this fails (not on macOS ARM64, or Rosetta not enabled), just return
    if (mount("rosetta", "/mnt/rosetta", "virtiofs", MS_RDONLY, NULL) != 0) {
        // Not running in Mixed Mode - this is fine, just skip
        return;
    }

    LOG("Rosetta share mounted, configuring x86_64 emulation...");

    // 3. Mount binfmt_misc filesystem (interface to register binary interpreters)
    // This may already be mounted, so EBUSY is acceptable
    if (mount("binfmt_misc", "/proc/sys/fs/binfmt_misc", "binfmt_misc", 0, NULL) != 0) {
        if (errno != EBUSY) {
            LOG("WARNING: binfmt_misc mount failed: %s", strerror(errno));
            return;
        }
    }

    // 4. Register Rosetta as the interpreter for x86_64 ELF binaries
    //
    // Format: :name:type:offset:magic:mask:interpreter:flags
    //
    // Magic bytes identify x86_64 ELF:
    //   \x7fELF     - ELF magic
    //   \x02        - 64-bit (ELFCLASS64)
    //   \x01        - Little endian (ELFDATA2LSB)
    //   \x01        - ELF version 1
    //   ... padding ...
    //   \x02\x00    - ET_EXEC or ET_DYN (executable)
    //   \x3e\x00    - EM_X86_64 (AMD64 architecture)
    //
    // Flags:
    //   O - Open binary immediately (for performance)
    //   C - Use credentials of the original binary
    //   F - Fix binary (required for containers/chroot - preserves interpreter across mounts)
    //
    const char *rule = ":rosetta:M::\\x7fELF\\x02\\x01\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x02\\x00\\x3e\\x00:\\xff\\xff\\xff\\xff\\xff\\xfe\\xfe\\x00\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xfe\\xff\\xff\\xff:/mnt/rosetta/rosetta:OCF";

    int fd = open("/proc/sys/fs/binfmt_misc/register", O_WRONLY);
    if (fd < 0) {
        LOG("WARNING: Failed to open binfmt_misc register: %s", strerror(errno));
        return;
    }

    ssize_t written = write(fd, rule, strlen(rule));
    if (written < 0) {
        // EEXIST means already registered, which is fine
        if (errno != EEXIST) {
            LOG("WARNING: Failed to register Rosetta binfmt rule: %s", strerror(errno));
        }
    } else {
        LOG("Rosetta x86_64 emulation enabled");
    }

    close(fd);
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

    // Bring up loopback first
    bring_up_loopback();

    // Try to parse RuntimeManifest first (new format)
    char *manifest_b64 = parse_cmdline_param(cmdline, "manifest");
    char *manifest_json = NULL;
    char *workload_obj = NULL;
    char *network_obj = NULL;

    // Parsed manifest fields
    char **entrypoint = NULL;
    int entrypoint_count = 0;
    char **env_vars = NULL;
    int env_count = 0;
    char *workdir = NULL;
    char *user_spec = NULL;
    char *ip_str = NULL;
    char *netmask_str = NULL;
    char *gateway_str = NULL;

    if (manifest_b64) {
        // Decode base64 manifest
        size_t manifest_len;
        manifest_json = base64_decode(manifest_b64, &manifest_len);
        free(manifest_b64);

        if (manifest_json && manifest_len > 0) {
            LOG("Parsed RuntimeManifest (%zu bytes)", manifest_len);

            // Extract workload object
            workload_obj = json_get_object(manifest_json, "workload");
            if (workload_obj) {
                entrypoint = json_get_string_array(workload_obj, "entrypoint", &entrypoint_count);
                env_vars = json_get_string_array(workload_obj, "env", &env_count);
                workdir = json_get_string(workload_obj, "workdir");
                user_spec = json_get_string(workload_obj, "user");

                LOG("Workload: entrypoint=%d args, env=%d vars, workdir=%s, user=%s",
                    entrypoint_count, env_count,
                    workdir ? workdir : "(none)",
                    user_spec ? user_spec : "(root)");
            }

            // Extract network object
            network_obj = json_get_object(manifest_json, "network");
            if (network_obj) {
                ip_str = json_get_string(network_obj, "ip");
                netmask_str = json_get_string(network_obj, "netmask");
                gateway_str = json_get_string(network_obj, "gateway");

                LOG("Network: ip=%s netmask=%s gateway=%s",
                    ip_str ? ip_str : "(none)",
                    netmask_str ? netmask_str : "(none)",
                    gateway_str ? gateway_str : "(none)");
            }
        }
    } else {
        // Fallback to legacy format (cmd=, workdir=, ip=, etc.)
        LOG("No manifest= found, using legacy format");
        ip_str = parse_cmdline_param(cmdline, "ip");
        netmask_str = parse_cmdline_param(cmdline, "netmask");
        gateway_str = parse_cmdline_param(cmdline, "gateway");
    }

    // Configure network if IP was provided
    if (ip_str) {
        unsigned int ip, netmask, gateway;

        if (parse_ipv4(ip_str, &ip) < 0) {
            LOG("Invalid IP address: %s", ip_str);
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
    } else {
        LOG("No IP address, skipping network configuration");
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

    // Set up Rosetta x86_64 emulation if available (macOS ARM64 Mixed Mode)
    // This must be called after /proc is mounted but before executing workloads
    setup_rosetta();

    // Initialize vsock exec server (allows host to run commands in guest)
    exec_server_init();

    // Print ready message
    LOG("Runtime mode ready");
    printf("[kestrel] RUNTIME_READY\n");
    fflush(stdout);

    // Determine command to execute
    char *cmd = NULL;

    if (entrypoint && entrypoint_count > 0) {
        // Build command from entrypoint array
        size_t total_len = 0;
        for (int i = 0; i < entrypoint_count; i++) {
            total_len += strlen(entrypoint[i]) + 3;  // quotes + space
        }
        cmd = malloc(total_len + 1);
        if (cmd) {
            cmd[0] = '\0';
            for (int i = 0; i < entrypoint_count; i++) {
                if (i > 0) strcat(cmd, " ");
                // Quote if needed
                if (strchr(entrypoint[i], ' ') || strchr(entrypoint[i], ';')) {
                    strcat(cmd, "\"");
                    strcat(cmd, entrypoint[i]);
                    strcat(cmd, "\"");
                } else {
                    strcat(cmd, entrypoint[i]);
                }
            }
        }
    } else {
        // Fallback to legacy cmd= parameter
        char *cmd_b64 = parse_cmdline_param(cmdline, "cmd");
        if (cmd_b64) {
            size_t cmd_len;
            cmd = base64_decode(cmd_b64, &cmd_len);
            free(cmd_b64);
        }

        // Legacy workdir
        if (!workdir) {
            workdir = parse_cmdline_param(cmdline, "workdir");
        }
    }

    if (cmd) {
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
            // Child process

            // Set environment variables
            if (env_vars && env_count > 0) {
                for (int i = 0; i < env_count; i++) {
                    if (env_vars[i]) {
                        putenv(env_vars[i]);  // Note: putenv doesn't copy, but we're about to exec
                    }
                }
                LOG("Set %d environment variables", env_count);
            }

            // Switch user/group if specified
            if (user_spec) {
                uid_t uid;
                gid_t gid;
                if (parse_user_spec(user_spec, &uid, &gid) == 0) {
                    if (switch_user(uid, gid) < 0) {
                        LOG("Warning: failed to switch user, continuing as root");
                    }
                } else {
                    LOG("Warning: failed to parse user spec '%s'", user_spec);
                }
            }

            // Exec the command
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
    } else {
        LOG("No command to execute, idling");
    }

    // Cleanup
    if (workdir) free(workdir);
    if (user_spec) free(user_spec);
    if (ip_str) free(ip_str);
    if (netmask_str) free(netmask_str);
    if (gateway_str) free(gateway_str);
    if (workload_obj) free(workload_obj);
    if (network_obj) free(network_obj);
    if (manifest_json) free(manifest_json);
    free_string_array(entrypoint, entrypoint_count);
    // Note: env_vars are used by putenv, don't free them

    // Main loop: reap zombies, handle exec requests, wait for shutdown
    // As PID 1, we must reap ALL orphaned processes (not just direct children).
    // Using a while loop ensures we drain all pending zombies before sleeping,
    // because SIGCHLD signals are not queued - multiple exits may coalesce.
    for (;;) {
        int status;
        pid_t pid;

        // Drain ALL available zombies in one iteration
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            if (WIFEXITED(status)) {
                LOG("Process %d exited with code %d", pid, WEXITSTATUS(status));
            } else if (WIFSIGNALED(status)) {
                LOG("Process %d killed by signal %d", pid, WTERMSIG(status));
            }
        }

        // Poll exec server for incoming commands and relay I/O
        exec_server_poll();

        // Short sleep for responsiveness (exec I/O needs frequent polling)
        usleep(10000);  // 10ms
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
        // Try ttyAMA0 (PL011 UART for ARM64, major 204 minor 64)
        mknod("/dev/ttyAMA0", S_IFCHR | 0600, makedev(204, 64));
        console_fd = open("/dev/ttyAMA0", O_WRONLY);
    }

    if (console_fd < 0) {
        // Try ttyS0 (legacy serial for cloud-hypervisor/Linux x86_64)
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
