//! Stack orchestration module.
//!
//! Provides high-level orchestration for deploying and managing multi-VM stacks
//! from docker-compose files.

pub mod stack;

pub use stack::{StackInfo, StackOrchestrator, StackState};
