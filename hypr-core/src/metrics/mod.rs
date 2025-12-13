//! VM metrics collection module.
//!
//! Receives metrics pushed from Kestrel (guest agent) via vsock.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐     vsock:1025     ┌─────────────────┐
//! │   Guest (VM)    │ ──────────────────►│   Host (daemon) │
//! │                 │                    │                 │
//! │  Kestrel Agent  │  VmMetricsPacket   │  MetricsCollector
//! │  └─ metrics_push│                    │  ├─ listen()    │
//! │                 │                    │  ├─ parse()     │
//! │                 │                    │  └─ cache       │
//! └─────────────────┘                    └─────────────────┘
//! ```

mod collector;

pub use collector::{MetricsCollector, VmMetrics, VmMetricsPacket};
