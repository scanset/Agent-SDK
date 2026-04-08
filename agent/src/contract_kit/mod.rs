//! # ESP Contract Kit
//!
//! Extended scanner strategies for ESP compliance validation.
//! Provides collectors, executors, contracts, and a high-level API for executing scans.
//!
//! ## Modules
//!
//! - `collectors` - Data collection from system (files, commands, sysctl, systemd)
//! - `executors` - Validation logic for each CTN type
//! - `contracts` - CTN type definitions and field mappings
//! - `commands` - Platform-specific command whitelists
//! - `execution_api` - High-level scan execution API

pub mod collectors;
pub mod commands;
pub mod contracts;
pub mod execution_api;
pub mod executors;
