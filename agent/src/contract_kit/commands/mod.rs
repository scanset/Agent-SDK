//! Command execution configurations for different platforms
//!
//! Provides whitelisted command executors for secure system scanning.

// Cross-platform commands
pub mod filesystem;
pub mod tcp_listener;

// Linux-only commands
#[cfg(target_os = "linux")]
pub mod r9;

// Cross-platform re-exports
pub use filesystem::{
    FileMetadata, FileSystemError, FileSystemResult, file_exists, get_file_metadata,
    read_file_content,
};
pub use tcp_listener::{
    TcpListenerError, TcpListenerResult, check_port_listening, get_all_listening_ports,
};

// Linux-only re-exports
#[cfg(target_os = "linux")]
pub use r9::{
    create_crypto_policy_executor, create_fips_executor, create_rpm_executor,
    create_sysctl_executor, create_systemctl_executor,
};
