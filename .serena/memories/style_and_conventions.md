# Style and Conventions

## Engineering Covenant (Non-Negotiable)
1.  **Zero Warnings:** `cargo check` must pass cleanly. No `#[allow(dead_code)]` unless explicitly temporary.
2.  **Observability:** Every major function gets `#[instrument]` (tracing).
3.  **No Hallucinations:** Always use tools (`serena-mcp`) to read files before editing. Do not guess struct fields.

## Code Style
*   **Rust:** Follow standard Rust idioms. Run `cargo fmt`.
*   **C (Kestrel):** Keep it minimal and static. The agent goal is <50ms boot and ~20KB size. Avoid heavy dependencies.

## Development Flow
*   Verify changes with `cargo check` and `cargo test`.
*   Use `cargo clippy` for linting (implied by zero warnings goal).
