//! VM metrics collection and history module.
//!
//! Receives metrics pushed from Kestrel (guest agent) via vsock and stores
//! historical data for querying.
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
//! └─────────────────┘                    │                 │
//!                                        │  MetricsHistory │
//!                                        │  └─ SQLite      │
//!                                        └─────────────────┘
//! ```

mod collector;
mod history;

pub use collector::{MetricsCollector, VmMetrics, VmMetricsPacket};
pub use history::{MetricsDataPoint, MetricsHistory, MetricsResolution};
