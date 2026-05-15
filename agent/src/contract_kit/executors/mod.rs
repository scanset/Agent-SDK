//! # Executors Module

// Cross-platform executors
pub mod computed_values;
pub mod file_content;
pub mod file_metadata;
pub mod json_record;
pub mod linux_tcp_listener;

// Linux-only executors
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
pub mod sysctl_parameter;
#[cfg(target_os = "linux")]
pub mod systemd_service;

// Cross-platform re-exports
pub use computed_values::ComputedValuesExecutor;
pub use file_content::FileContentExecutor;
pub use file_metadata::FileMetadataExecutor;
pub use json_record::JsonRecordExecutor;
pub use linux_tcp_listener::LinuxTcpListenerExecutor;

// Linux-only re-exports
#[cfg(target_os = "linux")]
pub use crypto_policy::CryptoPolicyExecutor;
#[cfg(target_os = "linux")]
pub use fips_mode::FipsModeExecutor;
#[cfg(target_os = "linux")]
pub use grub_config::GrubConfigExecutor;
#[cfg(target_os = "linux")]
pub use os_release::OsReleaseExecutor;
#[cfg(target_os = "linux")]
pub use rpm_package::RpmPackageExecutor;
#[cfg(target_os = "linux")]
pub use sysctl_parameter::SysctlParameterExecutor;
#[cfg(target_os = "linux")]
pub use systemd_service::SystemdServiceExecutor;
