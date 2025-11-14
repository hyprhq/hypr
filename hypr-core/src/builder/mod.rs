//! Image building system for HYPR.
//!
//! This module provides Dockerfile parsing, build graph construction,
//! caching, and build execution for creating HYPR images.

pub mod cache;
pub mod embedded;
pub mod executor;
pub mod graph;
pub mod http_proxy;
pub mod initramfs;
pub mod manifest;
pub mod oci;
pub mod parser;
pub mod vm_builder;

pub use cache::{CacheError, CacheLookupResult, CacheManager, LayerMetadata};
pub use executor::{
    create_builder, BuildContext, BuildError, BuildExecutor, BuildOutput, BuildResult, ImageConfig,
    ImageManifest,
};
pub use graph::{BuildGraph, BuildNode, GraphError};
pub use http_proxy::BuilderHttpProxy;
pub use manifest::{ManifestError, ManifestGenerator, ManifestResult};
pub use parser::{Dockerfile, Instruction, ParseError};
pub use vm_builder::{BuildLayerInfo, BuildStep, VmBuilder};
