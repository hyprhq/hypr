# Development Environment & Commands

## Build & Test
*   **Check:** `cargo check` (Must pass with ZERO warnings).
*   **Build Host:** `cargo build`.
*   **Build Guest:** `cc -static -Os -s -o kestrel guest/kestrel.c`.
*   **Test:** `cargo test`.
*   **Lint:** `cargo clippy`.

## Running HYPR
*   **Daemon:** `cargo run --bin hypr-daemon`.
*   **CLI:** `cargo run --bin hypr -- <args>`.

## Project Rules (The Covenant)
1.  **Zero Warnings:** No `#[allow(dead_code)]` unless temporary.
2.  **Observability:** Use `#[instrument]` on all major async functions.
3.  **No Hallucinations:** Verify files exist before editing.

## Key Files for Networking Task
*   `hypr-daemon/src/api/server.rs`: Orchestrates VM creation and IP allocation.
*   `hypr-core/src/adapters/hvf.rs`: macOS Hypervisor adapter.
*   `hypr-core/src/adapters/cloudhypervisor.rs`: Linux Hypervisor adapter.
*   `guest/kestrel.c`: The Guest Agent (needs C coding).
