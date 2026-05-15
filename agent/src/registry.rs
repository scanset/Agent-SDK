//! Scanner Registry Setup

use crate::contract_kit::execution_api::strategies::{CtnStrategyRegistry, StrategyError};
use crate::contract_kit::{collectors, commands, contracts, executors};

/// Create a registry with all available strategies
pub fn create_scanner_registry() -> Result<CtnStrategyRegistry, StrategyError> {
    let mut registry = CtnStrategyRegistry::new();

    // Register file system strategies
    let metadata_contract = contracts::create_file_metadata_contract();
    let content_contract = contracts::create_file_content_contract();
    let json_contract = contracts::create_json_record_contract();
    let computed_values_contract = contracts::create_computed_values_contract();

    registry.register_ctn_strategy(
        Box::new(collectors::FileSystemCollector::new()),
        Box::new(executors::FileMetadataExecutor::new(metadata_contract)),
    )?;

    registry.register_ctn_strategy(
        Box::new(collectors::FileSystemCollector::new()),
        Box::new(executors::FileContentExecutor::new(content_contract)),
    )?;

    registry.register_ctn_strategy(
        Box::new(collectors::ComputedValuesCollector::new()),
        Box::new(executors::ComputedValuesExecutor::new(
            computed_values_contract,
        )),
    )?;

    registry.register_ctn_strategy(
        Box::new(collectors::FileSystemCollector::new()),
        Box::new(executors::JsonRecordExecutor::new(json_contract)),
    )?;

    // Register linux_tcp_listener strategy (scanner-local /proc/net/tcp probe).
    registry.register_ctn_strategy(
        Box::new(collectors::LinuxTcpListenerCollector::new()),
        Box::new(executors::LinuxTcpListenerExecutor::new(
            contracts::create_linux_tcp_listener_contract(),
        )),
    )?;

    // Linux-only strategies
    #[cfg(target_os = "linux")]
    {
        // Systemd service
        registry.register_ctn_strategy(
            Box::new(collectors::SystemdServiceCollector::new(
                "systemd-collector",
                commands::create_systemctl_executor(),
            )),
            Box::new(executors::SystemdServiceExecutor::new(
                contracts::create_systemd_service_contract(),
            )),
        )?;

        // Sysctl parameter
        registry.register_ctn_strategy(
            Box::new(collectors::SysctlParameterCollector::new(
                "sysctl-collector",
                commands::create_sysctl_executor(),
            )),
            Box::new(executors::SysctlParameterExecutor::new(
                contracts::create_sysctl_parameter_contract(),
            )),
        )?;

        // OS Release
        registry.register_ctn_strategy(
            Box::new(collectors::OsReleaseCollector::new()),
            Box::new(executors::OsReleaseExecutor::new(
                contracts::create_os_release_contract(),
            )),
        )?;

        // RPM Package
        registry.register_ctn_strategy(
            Box::new(collectors::RpmPackageCollector::new(
                "rpm-collector",
                commands::create_rpm_executor(),
            )),
            Box::new(executors::RpmPackageExecutor::new(
                contracts::create_rpm_package_contract(),
            )),
        )?;

        // GRUB Config
        registry.register_ctn_strategy(
            Box::new(collectors::GrubConfigCollector::new()),
            Box::new(executors::GrubConfigExecutor::new(
                contracts::create_grub_config_contract(),
            )),
        )?;

        // FIPS Mode
        registry.register_ctn_strategy(
            Box::new(collectors::FipsModeCollector::new(
                "fips-collector",
                commands::create_fips_executor(),
            )),
            Box::new(executors::FipsModeExecutor::new(
                contracts::create_fips_mode_contract(),
            )),
        )?;

        // Crypto Policy
        registry.register_ctn_strategy(
            Box::new(collectors::CryptoPolicyCollector::new(
                "crypto-policy-collector",
                commands::create_crypto_policy_executor(),
            )),
            Box::new(executors::CryptoPolicyExecutor::new(
                contracts::create_crypto_policy_contract(),
            )),
        )?;
    }

    Ok(registry)
}
