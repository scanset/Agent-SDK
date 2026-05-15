//! # ESP Agent SDK
//!
//! Library API for the ESP compliance agent. The same source tree powers
//! the `esp_agent` CLI binary and an embeddable library — pick whichever
//! interface fits your integration.
//!
//! ## Embedding the agent in your own Rust code
//!
//! ```ignore
//! use agent::contract_kit::execution_api::{scan_file, CtnStrategyRegistry};
//! use agent::registry::build_default_registry;
//! use std::sync::Arc;
//!
//! let registry = Arc::new(build_default_registry()?);
//! let result = scan_file("policy.esp", registry)?;
//! ```
//!
//! ## Module layout
//!
//! - [`cli`]          — command-line argument parsing for the binary
//! - [`config`]       — `ScanConfig`, `OutputFormat`, exit-code logic
//! - [`contract_kit`] — CTN contracts / collectors / executors / command sandboxes,
//!   and the high-level `execution_api` (`scan_file`, `compile_file`, …)
//! - [`discovery`]    — recursive `.esp` file discovery
//! - [`output`]       — `AssessorPackage` envelope construction and console rendering
//! - [`registry`]     — the default `CtnStrategyRegistry` wiring
//! - [`scanner`]      — the per-file scan loop used by the CLI
//! - [`signing`]      — ECDSA-P256 signing backend that produces the envelope signature

pub mod cli;
pub mod config;
pub mod contract_kit;
pub mod discovery;
pub mod output;
pub mod registry;
pub mod scanner;
pub mod signing;
