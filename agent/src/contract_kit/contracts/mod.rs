//! # CTN Contracts Module

// Cross-platform contracts
pub mod computed_values;
pub mod file_contracts;
pub mod json_contracts;
pub mod tcp_listener_contracts;

// Linux-only contracts
#[cfg(target_os = "linux")]
pub mod crypto_policy;
#[cfg(target_os = "linux")]
pub mod fips_mode;
#[cfg(target_os = "linux")]
pub mod grub_config;
#[cfg(target_os = "linux")]
pub mod os_release;
#[cfg(target_os = "linux")]
pub mod rpm_package;
#[cfg(target_os = "linux")]
pub mod sysctl_parameter_contracts;
#[cfg(target_os = "linux")]
pub mod systemd_service_contracts;

// Cross-platform re-exports
pub use computed_values::create_computed_values_contract;
pub use file_contracts::{create_file_content_contract, create_file_metadata_contract};
pub use json_contracts::create_json_record_contract;
pub use tcp_listener_contracts::create_tcp_listener_contract;

// Linux-only re-exports
#[cfg(target_os = "linux")]
pub use crypto_policy::create_crypto_policy_contract;
#[cfg(target_os = "linux")]
pub use fips_mode::create_fips_mode_contract;
#[cfg(target_os = "linux")]
pub use grub_config::create_grub_config_contract;
#[cfg(target_os = "linux")]
pub use os_release::create_os_release_contract;
#[cfg(target_os = "linux")]
pub use rpm_package::create_rpm_package_contract;
#[cfg(target_os = "linux")]
pub use sysctl_parameter_contracts::create_sysctl_parameter_contract;
#[cfg(target_os = "linux")]
pub use systemd_service_contracts::create_systemd_service_contract;
