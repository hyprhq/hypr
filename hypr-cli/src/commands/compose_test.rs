//! Tests for compose CLI commands.

#[cfg(test)]
mod tests {
    use super::super::compose::*;

    #[test]
    fn test_format_duration() {
        use std::time::Duration;

        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m");
        assert_eq!(format_duration(Duration::from_secs(3700)), "1h");
        assert_eq!(format_duration(Duration::from_secs(90000)), "1d");
    }

    #[test]
    fn test_colorize_status() {
        // Just test that it doesn't panic
        colorize_status("running");
        colorize_status("stopped");
        colorize_status("failed");
        colorize_status("creating");
        colorize_status("unknown");
    }

    // Note: Integration tests that require a running daemon are in tests/integration_test.rs
}
