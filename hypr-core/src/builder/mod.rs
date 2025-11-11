//! Image building system for HYPR.
//!
//! This module provides Dockerfile parsing, build graph construction,
//! caching, and build execution for creating HYPR images.

pub mod cache;
pub mod executor;
pub mod graph;
pub mod parser;

pub use cache::{CacheError, CacheLookupResult, CacheManager, LayerMetadata};
pub use executor::{
    BuildContext, BuildError, BuildExecutor, BuildOutput, BuildResult, ImageConfig,
    ImageManifest, create_builder,
};
pub use graph::{BuildGraph, BuildNode, GraphError};
pub use parser::{Dockerfile, Instruction, ParseError};
