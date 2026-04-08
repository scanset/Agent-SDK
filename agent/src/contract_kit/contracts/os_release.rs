//! OS Release CTN Contract
//!
//! Validates operating system release information via /etc/os-release.
//! Parses key=value pairs from the os-release file.
//!
//! STIG Coverage:
//!   SV-257777 — RHEL 9 must be a vendor-supported release (cat /etc/redhat-release)
//!
//! Distro-agnostic: works on any Linux distribution that provides /etc/os-release.
//! Rocky Linux 9 maps to: ID=rocky, VERSION_ID=9.x, NAME="Rocky Linux"

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_os_release_contract() -> CtnContract {
    let mut contract = CtnContract::new("os_release".to_string());

    // No object fields required — reads /etc/os-release always
    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "release_file".to_string(),
            data_type: DataType::String,
            description: "Path to os-release file (default: /etc/os-release)".to_string(),
            example_values: vec![
                "/etc/os-release".to_string(),
                "/etc/redhat-release".to_string(),
            ],
            validation_notes: Some("Overrides default path if provided".to_string()),
        });

    let str_ops = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::Contains,
        Operation::StartsWith,
    ];
    let bool_ops = vec![Operation::Equals, Operation::NotEqual];

    for (name, desc, examples) in &[
        (
            "name",
            "OS name (NAME field)",
            vec!["Rocky Linux", "Red Hat Enterprise Linux"],
        ),
        (
            "version",
            "Full version string (VERSION field)",
            vec!["9.5 (Blue Onyx)"],
        ),
        (
            "version_id",
            "Version number only (VERSION_ID field)",
            vec!["9.5", "9"],
        ),
        ("id", "Distribution ID (ID field)", vec!["rocky", "rhel"]),
        (
            "id_like",
            "Compatible distributions (ID_LIKE field)",
            vec!["rhel centos fedora"],
        ),
        (
            "pretty_name",
            "Full human-readable name (PRETTY_NAME field)",
            vec!["Rocky Linux 9.5 (Blue Onyx)"],
        ),
        (
            "platform_id",
            "Platform identifier (PLATFORM_ID field)",
            vec!["platform:el9"],
        ),
    ] {
        contract
            .state_requirements
            .add_optional_field(StateFieldSpec {
                name: name.to_string(),
                data_type: DataType::String,
                allowed_operations: str_ops.clone(),
                description: desc.to_string(),
                example_values: examples.iter().map(|s| s.to_string()).collect(),
                validation_notes: None,
            });
    }

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "supported".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops,
            description: "Derived: whether the OS version is within a known supported range"
                .to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Set to true when VERSION_ID is 9.x for Rocky/RHEL 9. Collector derives this."
                    .to_string(),
            ),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("release_file".to_string(), "release_file".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["id".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "name".to_string(),
        "version".to_string(),
        "version_id".to_string(),
        "id_like".to_string(),
        "pretty_name".to_string(),
        "platform_id".to_string(),
        "supported".to_string(),
    ];

    for field in &[
        "name",
        "version",
        "version_id",
        "id",
        "id_like",
        "pretty_name",
        "platform_id",
        "supported",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    contract.collection_strategy = CollectionStrategy {
        collector_type: "os_release".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["file_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(10),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
