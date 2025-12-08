# Task Completion Protocol

When a task is completed:
1.  **Verify:** Ensure `cargo check` passes with **zero warnings**.
2.  **Test:** Run `cargo test` to ensure no regressions.
3.  **Format:** Run `cargo fmt` to ensure code style compliance.
4.  **Done:** Only mark the task as done when the verification steps pass.
