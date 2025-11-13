// kestrel.c - Universal guest agent for HYPR
// Copyright (c) 2025 HYPR. PTE. LTD.
// Business Source License 1.1
//
// DUAL MODE AGENT:
//
// BUILD MODE (when mode=build in kernel cmdline):
// 1. PID 1 init (minimal - mount essential filesystems)
// 2. Mount virtio-fs at /shared
// 3. Forward HTTP via vsock to host proxy (port 41010)
// 4. Listen on vsock for build commands from host (port 41011)
// 5. Execute shell commands in base image chroot
// 6. Create layer tarballs
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
#include <sys/select.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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


// ====== SELF-CONTAINED VSOCK DEFINITIONS (portable) ======
#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

#ifndef VMADDR_CID_ANY
#define VMADDR_CID_ANY (~0U)
#endif

#ifndef VMADDR_CID_HOST
#define VMADDR_CID_HOST 2
#endif

struct sockaddr_vm {
    sa_family_t svm_family;   // AF_VSOCK
    unsigned short svm_reserved1;
    unsigned int svm_port;    // Guest/host port
    unsigned int svm_cid;     // Context ID
};

// ====== SELF-CONTAINED IFF/TAP DEFINITIONS ======
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


// Port definitions (aligned with hypr-core/src/ports.rs)
#define VSOCK_PORT_BUILD_AGENT 41011  // Build commands
#define VSOCK_PORT_HTTP_PROXY  41010  // HTTP proxy forwarding
#define MAX_CMD_LEN 8192
#define MAX_CMDLINE_LEN 8192

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
    // This allows RUN commands to modify the filesystem while preserving base image
    // overlayfs options: lowerdir=/base,upperdir=/workspace,workdir=/overlay-work

    mkdir("/overlay-work", 0755);

    // Mount overlayfs
    char overlay_opts[512];
    snprintf(overlay_opts, sizeof(overlay_opts),
        "lowerdir=/base,upperdir=/workspace,workdir=/overlay-work");

    if (mount("overlay", "/newroot", "overlay", 0, overlay_opts)) {
        FATAL("Failed to mount overlayfs: %s\nOptions: %s", strerror(errno), overlay_opts);
    }

    LOG("Overlayfs mounted, preparing new root");

    // Mount essential filesystems in new root
    mkdir("/newroot/proc", 0755);
    mkdir("/newroot/sys", 0755);
    mkdir("/newroot/dev", 0755);
    mkdir("/newroot/tmp", 0777);
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
// BUILD MODE - HTTP PROXY (Direct vsock forwarding, no socat)
// ============================================================================

// Forward data from one fd to another
static ssize_t forward_data(int from_fd, int to_fd, char *buf, size_t bufsize) {
    ssize_t n = read(from_fd, buf, bufsize);
    if (n <= 0) return n;

    ssize_t written = 0;
    while (written < n) {
        ssize_t w = write(to_fd, buf + written, n - written);
        if (w <= 0) return -1;
        written += w;
    }
    return n;
}

// Handle one HTTP proxy connection: TCP client <-> vsock host
static void handle_http_proxy_connection(int client_fd) {
    // Connect to host vsock:41010
    int vsock_fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (vsock_fd < 0) {
        LOG("HTTP proxy: socket(AF_VSOCK) failed: %s", strerror(errno));
        close(client_fd);
        return;
    }

    struct sockaddr_vm host_addr = {
        .svm_family = AF_VSOCK,
        .svm_cid = 2, // Host CID
        .svm_port = VSOCK_PORT_HTTP_PROXY,
    };

    if (connect(vsock_fd, (struct sockaddr*)&host_addr, sizeof(host_addr)) < 0) {
        LOG("HTTP proxy: connect to host vsock:%d failed: %s",
            VSOCK_PORT_HTTP_PROXY, strerror(errno));
        close(vsock_fd);
        close(client_fd);
        return;
    }

    // Set non-blocking for select()
    fcntl(client_fd, F_SETFL, O_NONBLOCK);
    fcntl(vsock_fd, F_SETFL, O_NONBLOCK);

    // Bidirectional forwarding loop
    char buf[8192];
    fd_set readfds;
    int maxfd = (client_fd > vsock_fd) ? client_fd : vsock_fd;

    for (;;) {
        FD_ZERO(&readfds);
        FD_SET(client_fd, &readfds);
        FD_SET(vsock_fd, &readfds);

        struct timeval timeout = {.tv_sec = 300, .tv_usec = 0}; // 5 min timeout
        int ret = select(maxfd + 1, &readfds, NULL, NULL, &timeout);

        if (ret < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (ret == 0) break; // Timeout

        // Forward client → host
        if (FD_ISSET(client_fd, &readfds)) {
            ssize_t n = forward_data(client_fd, vsock_fd, buf, sizeof(buf));
            if (n <= 0) break;
        }

        // Forward host → client
        if (FD_ISSET(vsock_fd, &readfds)) {
            ssize_t n = forward_data(vsock_fd, client_fd, buf, sizeof(buf));
            if (n <= 0) break;
        }
    }

    close(vsock_fd);
    close(client_fd);
}

// Background process: HTTP proxy server (TCP localhost:41010 → vsock host:41010)
static pid_t start_http_proxy(void) {
    pid_t pid = fork();
    if (pid < 0) {
        FATAL("Failed to fork for HTTP proxy: %s", strerror(errno));
    }

    if (pid > 0) {
        // Parent: return child PID
        LOG("HTTP proxy started (pid=%d): TCP localhost:41010 → vsock host:41010", pid);
        return pid;
    }

    // Child: run HTTP proxy server
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        FATAL("HTTP proxy: socket() failed: %s", strerror(errno));
    }

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(VSOCK_PORT_HTTP_PROXY),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };

    if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        FATAL("HTTP proxy: bind(localhost:41010) failed: %s", strerror(errno));
    }

    if (listen(listen_fd, 128) < 0) {
        FATAL("HTTP proxy: listen() failed: %s", strerror(errno));
    }

    LOG("HTTP proxy listening on localhost:41010");

    // Accept loop
    for (;;) {
        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            LOG("HTTP proxy: accept() failed: %s", strerror(errno));
            continue;
        }

        // Fork per connection (simple, no thread pool needed for builds)
        pid_t conn_pid = fork();
        if (conn_pid == 0) {
            // Connection handler child
            close(listen_fd);
            handle_http_proxy_connection(client_fd);
            exit(0);
        }

        close(client_fd); // Parent closes its copy

        // Reap finished connections (non-blocking)
        while (waitpid(-1, NULL, WNOHANG) > 0);
    }

    exit(0); // Never reached
}

// ============================================================================
// BUILD MODE - COMMAND EXECUTION
// ============================================================================

static int execute_shell_command(const char *cmd, const char *workdir) {
    LOG("Executing: %s (workdir=%s)", cmd, workdir);

    pid_t pid = fork();
    if (pid < 0) {
        LOG("fork failed: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        // Child: execute command
        if (chdir(workdir) < 0) {
            fprintf(stderr, "chdir(%s) failed: %s\n", workdir, strerror(errno));
            exit(127);
        }

        // Set HTTP proxy environment (forwarded via vsock to host)
        setenv("http_proxy", "http://localhost:41010", 1);
        setenv("https_proxy", "http://localhost:41010", 1);
        setenv("HTTP_PROXY", "http://localhost:41010", 1);
        setenv("HTTPS_PROXY", "http://localhost:41010", 1);

        // Execute via sh -c
        execl("/bin/sh", "sh", "-c", cmd, NULL);
        fprintf(stderr, "execl failed: %s\n", strerror(errno));
        exit(127);
    }

    // Parent: wait for completion
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        LOG("waitpid failed: %s", strerror(errno));
        return -1;
    }

    if (WIFEXITED(status)) {
        int exit_code = WEXITSTATUS(status);
        LOG("Command exited with code %d", exit_code);
        return exit_code;
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        LOG("Command killed by signal %d", sig);
        return 128 + sig;
    }

    return -1;
}

static int create_tarball(const char *source_dir, const char *output_tar) {
    LOG("Creating tarball: %s → %s", source_dir, output_tar);

    // Use tar to create tarball of source_dir
    char cmd[2048];
    snprintf(cmd, sizeof(cmd),
        "tar -C %s -cf %s . 2>/dev/null",
        source_dir, output_tar);

    int ret = system(cmd);
    if (ret == 0) {
        // Check if file was created
        struct stat st;
        if (stat(output_tar, &st) == 0) {
            LOG("Tarball created: %ld bytes", st.st_size);
            return 0;
        }
    }

    LOG("Failed to create tarball");
    return -1;
}

// ============================================================================
// BUILD MODE - JSON PARSING (Minimal, no library)
// ============================================================================

// Extract string value from JSON field
// Input: {"Run":{"command":"apk add nginx","workdir":"/workspace"}}
// json_get_string(input, "command") → "apk add nginx"
static char* json_get_string(const char *json, const char *key) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":\"", key);

    char *start = strstr(json, search);
    if (!start) return NULL;

    start += strlen(search);
    char *end = strchr(start, '"');
    if (!end) return NULL;

    size_t len = end - start;
    char *value = malloc(len + 1);
    if (!value) return NULL;

    memcpy(value, start, len);
    value[len] = '\0';
    return value;
}

// ============================================================================
// BUILD MODE - VSOCK SERVER
// ============================================================================

static void handle_build_command(int conn) {
    char buffer[MAX_CMD_LEN];
    ssize_t n = read(conn, buffer, sizeof(buffer) - 1);
    if (n <= 0) return;

    buffer[n] = '\0';
    LOG("Received command: %.*s", (n > 100 ? 100 : (int)n), buffer);

    char *response = NULL;

    // Parse and handle command
    if (strstr(buffer, "\"Ping\"")) {
        // Health check
        response = strdup("{\"Pong\":{}}");
    }
    else if (strstr(buffer, "\"Run\"")) {
        // Execute RUN instruction
        char *cmd = json_get_string(buffer, "command");
        char *workdir = json_get_string(buffer, "workdir");

        if (!workdir) workdir = strdup("/workspace");

        if (cmd) {
            int exit_code = execute_shell_command(cmd, workdir);

            if (exit_code == 0) {
                response = strdup("{\"Ok\":{}}");
            } else {
                char err[256];
                snprintf(err, sizeof(err),
                    "{\"Error\":{\"message\":\"Command failed\",\"exit_code\":%d}}",
                    exit_code);
                response = strdup(err);
            }

            free(cmd);
        } else {
            response = strdup("{\"Error\":{\"message\":\"Missing command\"}}");
        }

        free(workdir);
    }
    else if (strstr(buffer, "\"Finalize\"")) {
        // Create layer tarball
        char *layer_id = json_get_string(buffer, "layer_id");
        if (!layer_id) {
            response = strdup("{\"Error\":{\"message\":\"Missing layer_id\"}}");
        } else {
            char output_tar[512];
            snprintf(output_tar, sizeof(output_tar), "/shared/layers/%s.tar", layer_id);

            // Ensure layers directory exists
            mkdir("/shared/layers", 0755);

            int ret = create_tarball("/workspace", output_tar);
            if (ret == 0) {
                response = strdup("{\"Ok\":{}}");
            } else {
                response = strdup("{\"Error\":{\"message\":\"Failed to create tarball\"}}");
            }

            free(layer_id);
        }
    }
    else {
        response = strdup("{\"Error\":{\"message\":\"Unknown command\"}}");
    }

    // Send response
    if (response) {
        write(conn, response, strlen(response));
        write(conn, "\n", 1);
        free(response);
    }
}

static void run_build_mode(void) {
    LOG("Starting build mode");

    // Mount essential filesystems
    mount_essentials_build();

    // Start HTTP proxy (TCP localhost:41010 → vsock host:41010)
    start_http_proxy();

    // Give proxy a moment to start listening
    usleep(100000); // 100ms

    // Connect to host via vsock (guest connects, host listens)
    // This is the correct model for cloud-hypervisor and vfkit vsock
    int sock = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sock < 0) {
        FATAL("socket(AF_VSOCK) failed: %s", strerror(errno));
    }

    struct sockaddr_vm addr = {
        .svm_family = AF_VSOCK,
        .svm_port = VSOCK_PORT_BUILD_AGENT,
        .svm_cid = VMADDR_CID_HOST,  // Connect to host (CID 2)
    };

    LOG("Connecting to host via vsock port %d", VSOCK_PORT_BUILD_AGENT);

    // Retry connection (host might not be listening yet)
    int connected = 0;
    for (int retry = 0; retry < 30; retry++) {
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            connected = 1;
            break;
        }
        usleep(100000); // 100ms
    }

    if (!connected) {
        FATAL("connect(vsock:%d) failed after retries: %s", VSOCK_PORT_BUILD_AGENT, strerror(errno));
    }

    LOG("Connected to host builder on vsock port %d", VSOCK_PORT_BUILD_AGENT);

    // Command loop (persistent connection)
    for (;;) {
        handle_build_command(sock);
    }
}

// ============================================================================
// RUNTIME MODE - STUB (TO BE IMPLEMENTED IN PHASE 6)
// ============================================================================

static void run_runtime_mode(void) {
    FATAL("Runtime mode not yet implemented (Phase 6 feature)");
    // Future implementation:
    // 1. Mount proc/sys/dev
    // 2. Parse manifest from /proc/cmdline (base64+gzip)
    // 3. Mount rootfs (squashfs + overlayfs)
    // 4. Setup networking (configure IP/gateway/DNS)
    // 5. Fork + exec user workload
    // 6. Start health check server (/healthz on port 8080)
    // 7. Start metrics server (/metrics)
    // 8. Main loop: reap zombies, enforce restart policy
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char *argv[]) {
    // CRITICAL: Redirect stdout/stderr to console FIRST (before any LOG())
    // In initramfs, default stdout/stderr go nowhere
    int console_fd = open("/dev/console", O_WRONLY);
    if (console_fd < 0) {
        // /dev/console might not exist yet, try creating /dev manually
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
