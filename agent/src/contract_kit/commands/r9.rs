//! Rocky 9-specific command executors for compliance scanning.
//!
//! Provides whitelisted command executors for host-level compliance scanning.

use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Create command executor for systemctl
pub fn create_systemctl_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(10));
    executor.allow_commands(&["systemctl", "/usr/bin/systemctl"]);
    executor
}

/// Create command executor for sysctl
pub fn create_sysctl_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(5));
    executor.allow_commands(&["sysctl", "/usr/sbin/sysctl", "/sbin/sysctl"]);
    executor
}

// Add these to commands/r9.rs alongside the existing create_systemctl_executor
// and create_sysctl_executor functions

/// Create command executor for rpm
pub fn create_rpm_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(10));
    executor.allow_commands(&["rpm", "/usr/bin/rpm"]);
    executor
}

/// Create command executor for fips-mode-setup
pub fn create_fips_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(10));
    executor.allow_commands(&[
        "fips-mode-setup",
        "/usr/bin/fips-mode-setup",
        "/sbin/fips-mode-setup",
    ]);
    executor
}

/// Create command executor for update-crypto-policies
pub fn create_crypto_policy_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(10));
    executor.allow_commands(&[
        "update-crypto-policies",
        "/usr/bin/update-crypto-policies",
        "/usr/sbin/update-crypto-policies",
    ]);
    executor
}
