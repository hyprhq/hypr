//! Docker Compose file parsing and conversion.
//!
//! This module provides support for parsing docker-compose.yml files (v2/v3 format)
//! and converting them into HYPR's internal VM configuration format.

pub mod parser;
pub mod types;

#[cfg(test)]
mod parser_tests;

pub use parser::ComposeParser;
pub use types::*;
