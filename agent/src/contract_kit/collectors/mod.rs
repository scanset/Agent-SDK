//! # Data Collectors Module

// Cross-platform collectors
pub mod computed_values;
pub mod filesystem;
pub mod linux_tcp_listener;

// Linux-only collectors
#[cfg(target_os = "linux")]
pub mod fips_crypto;
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
pub use computed_values::ComputedValuesCollector;
pub use filesystem::FileSystemCollector;
pub use linux_tcp_listener::LinuxTcpListenerCollector;

// Linux-only re-exports
#[cfg(target_os = "linux")]
pub use fips_crypto::{CryptoPolicyCollector, FipsModeCollector};
#[cfg(target_os = "linux")]
pub use grub_config::GrubConfigCollector;
#[cfg(target_os = "linux")]
pub use os_release::OsReleaseCollector;
#[cfg(target_os = "linux")]
pub use rpm_package::RpmPackageCollector;
#[cfg(target_os = "linux")]
pub use sysctl_parameter::SysctlParameterCollector;
#[cfg(target_os = "linux")]
pub use systemd_service::SystemdServiceCollector;
