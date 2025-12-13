//! Image building system for HYPR.
//!
//! This module provides Dockerfile parsing, build graph construction,
//! caching, and build execution for creating HYPR images.
//!
//! ## Centralized Build API
//!
//! The primary entry point for building images is [`build::build_image`], which
//! provides a unified API used by CLI, daemon, and compose. After building,
//! use [`build::register_image`] to save the image to the database.
//!
//! ```ignore
//! use hypr_core::builder::build::{build_image, register_image, BuildOptions};
//!
//! let options = BuildOptions {
//!     context_path: PathBuf::from("."),
//!     dockerfile: "Dockerfile".to_string(),
//!     name: "myapp".to_string(),
//!     tag: "latest".to_string(),
//!     ..Default::default()
//! };
//!
//! let result = build_image(options).await?;
//! let image = register_image(&result, "myapp", "latest", true, &state).await?;
//! ```

pub mod build;
pub mod cache;
pub mod cas;
pub mod embedded;
pub mod executor;
pub mod graph;
pub mod http_proxy;
pub mod initramfs;
pub mod manifest;
pub mod oci;
pub mod output_stream;
pub mod parser;
pub mod vm_builder;

// Re-export centralized build API
pub use build::{build_image, register_image, BuildOptions, BuildResult};

pub use cache::{CacheError, CacheLookupResult, CacheManager, LayerMetadata};
pub use cas::{CasStore, FileEntry, LayerManifest};
pub use executor::{
    create_builder, BuildContext, BuildError, BuildExecutor, BuildOutput,
    BuildResult as ExecutorBuildResult, ImageConfig, ImageManifest,
};
pub use graph::{BuildGraph, BuildNode, GraphError};
pub use http_proxy::BuilderHttpProxy;
pub use manifest::{ManifestError, ManifestGenerator, ManifestResult};
pub use parser::{Dockerfile, Instruction, ParseError};
pub use vm_builder::{BuildLayerInfo, BuildStep, VmBuilder};
