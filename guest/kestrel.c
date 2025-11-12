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
#include <linux/vm_sockets.h>  // AF_VSOCK
#include <netinet/in.h>
#include <arpa/inet.h>

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

static void mount_essentials_build(void) {
    // Minimal mounts for build mode
    // (proc, sys, dev usually already mounted by kernel/initramfs)

    // Create directories
    mkdir("/tmp", 0777);
    mkdir("/workspace", 0755);
    mkdir("/shared", 0755);
    mkdir("/base", 0755);
    mkdir("/newroot", 0755);

    // Mount tmpfs for temporary files
    if (mount("tmpfs", "/tmp", "tmpfs", 0, NULL) && errno != EBUSY) {
        LOG("Warning: mount /tmp failed: %s", strerror(errno));
    }

    // Mount tmpfs workspace (where builds happen)
    if (mount("tmpfs", "/workspace", "tmpfs", 0, "size=4G") && errno != EBUSY) {
        LOG("Warning: mount /workspace failed: %s", strerror(errno));
    }

    // Mount virtio-fs (tag "shared" configured by host)
    if (mount("shared", "/shared", "virtiofs", 0, NULL)) {
        FATAL("Failed to mount virtio-fs shared: %s", strerror(errno));
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
// TODO: Implement direct HTTP proxy via vsock
// For now, this is a placeholder. The host proxy runs on vsock:41010.
// Build commands will set http_proxy=http://localhost:41010 which requires
// a local listener that forwards to vsock. This can be implemented later
// as a background thread or we rely on the host to handle it differently.
//
// Current approach: Commands will connect to localhost:41010, which will
// fail if not implemented. For MVP, we'll document this limitation.

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

        // Set HTTP proxy environment
        // NOTE: Currently requires local listener on 41010 (not implemented yet)
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

    // TODO: Start HTTP proxy forwarding thread (vsock → host:41010)
    // For now, this is not implemented. Build commands that need HTTP
    // will fail unless the base image has networking configured differently.

    // Start vsock server for build commands
    int sock = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sock < 0) {
        FATAL("socket(AF_VSOCK) failed: %s", strerror(errno));
    }

    struct sockaddr_vm addr = {
        .svm_family = AF_VSOCK,
        .svm_port = VSOCK_PORT_BUILD_AGENT,
        .svm_cid = VMADDR_CID_ANY,
    };

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        FATAL("bind(vsock:%d) failed: %s", VSOCK_PORT_BUILD_AGENT, strerror(errno));
    }

    if (listen(sock, 5) < 0) {
        FATAL("listen failed: %s", strerror(errno));
    }

    LOG("Listening on vsock port %d", VSOCK_PORT_BUILD_AGENT);

    // Accept loop (blocks forever)
    for (;;) {
        struct sockaddr_vm client_addr;
        socklen_t client_len = sizeof(client_addr);

        int conn = accept(sock, (struct sockaddr*)&client_addr, &client_len);
        if (conn < 0) {
            LOG("accept failed: %s", strerror(errno));
            continue;
        }

        handle_build_command(conn);
        close(conn);
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
    LOG("Starting kestrel v2.0");

    // Detect mode from kernel cmdline
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
