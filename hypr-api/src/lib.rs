//! HYPR gRPC API
//!
//! This crate defines the gRPC protocol for HYPR daemon ↔ CLI communication.
//! The protobuf definitions are in `proto/hypr.proto` and code-generated via `tonic-build`.

// Include the generated code
pub mod hypr {
    pub mod v1 {
        tonic::include_proto!("hypr.v1");
    }
}
