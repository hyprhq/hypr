// builder-agent.c - Alpine VM build agent for HYPR
// Copyright (c) 2025 HYPR. PTE. LTD.
// Business Source License 1.1
//
// Responsibilities:
// 1. PID 1 init (minimal - just mount essential filesystems)
// 2. Mount virtio-fs at /shared
// 3. Start socat TCP→vsock bridge for HTTP proxy
// 4. Listen on vsock for build commands from host
// 5. Execute shell commands
// 6. Create layer tarballs
//
// Compilation:
//   Linux:  gcc -static -O2 -o builder-agent builder-agent.c
//   macOS:  docker run --rm -v $(pwd):/work alpine:3.19 sh -c \
//           'apk add gcc musl-dev && cd /work && gcc -static -O2 -o builder-agent builder-agent.c'
//   Script: ./build-builder-agent.sh (requires Linux)

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

#define VSOCK_PORT 41011
#define MAX_CMD_LEN 8192

// ============================================================================
// LOGGING
// ============================================================================

#define LOG(fmt, ...) do { \
    fprintf(stderr, "[builder-agent] " fmt "\n", ##__VA_ARGS__); \
    fflush(stderr); \
} while(0)

#define FATAL(fmt, ...) do { \
    fprintf(stderr, "[builder-agent] FATAL: " fmt "\n", ##__VA_ARGS__); \
    fflush(stderr); \
    exit(1); \
} while(0)

// ============================================================================
// EARLY BOOT
// ============================================================================

static void mount_essentials(void) {
    // Minimal mounts (proc, sys, dev usually already mounted by kernel/vfkit)

    // Create directories
    mkdir("/tmp", 0777);
    mkdir("/workspace", 0755);
    mkdir("/shared", 0755);

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
        FATAL("Failed to mount virtio-fs: %s", strerror(errno));
    }

    LOG("Filesystems mounted successfully");
}

// ============================================================================
// SOCAT BRIDGE (TCP → vsock for HTTP proxy)
// ============================================================================

static pid_t start_socat_bridge(void) {
    pid_t pid = fork();
    if (pid < 0) {
        FATAL("Failed to fork for socat: %s", strerror(errno));
    }

    if (pid == 0) {
        // Child: exec socat
        // Bridge TCP localhost:41010 → vsock CID 2 (host) port 41010
        execl("/usr/bin/socat", "socat",
              "TCP-LISTEN:41010,reuseaddr,fork",
              "VSOCK-CONNECT:2:41010",
              NULL);

        FATAL("Failed to exec socat: %s", strerror(errno));
    }

    LOG("socat bridge started (pid=%d): TCP localhost:41010 → vsock host:41010", pid);
    return pid;
}

// ============================================================================
// COMMAND EXECUTION
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
// JSON PARSING (Minimal, no library)
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
// VSOCK SERVER
// ============================================================================

static void handle_client(int conn) {
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

static void run_vsock_server(void) {
    int sock = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (sock < 0) {
        FATAL("socket(AF_VSOCK) failed: %s", strerror(errno));
    }

    struct sockaddr_vm addr = {
        .svm_family = AF_VSOCK,
        .svm_port = VSOCK_PORT,
        .svm_cid = VMADDR_CID_ANY,
    };

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        FATAL("bind(vsock:%d) failed: %s", VSOCK_PORT, strerror(errno));
    }

    if (listen(sock, 5) < 0) {
        FATAL("listen failed: %s", strerror(errno));
    }

    LOG("Listening on vsock port %d", VSOCK_PORT);

    // Accept loop (blocks forever)
    for (;;) {
        struct sockaddr_vm client_addr;
        socklen_t client_len = sizeof(client_addr);

        int conn = accept(sock, (struct sockaddr*)&client_addr, &client_len);
        if (conn < 0) {
            LOG("accept failed: %s", strerror(errno));
            continue;
        }

        handle_client(conn);
        close(conn);
    }
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char *argv[]) {
    LOG("Starting builder-agent v1.0");

    // Early boot: mount filesystems
    mount_essentials();

    // Start HTTP proxy bridge (socat)
    start_socat_bridge();

    // Give socat a moment to start
    sleep(1);

    // Start vsock server (blocks forever)
    run_vsock_server();

    return 0;
}
