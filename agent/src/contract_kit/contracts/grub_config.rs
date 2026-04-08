//! GRUB Config CTN Contract
//!
//! Validates GRUB2 bootloader configuration via file content parsing.
//! Reads /etc/grub2.cfg or /boot/grub2/grub.cfg to check superuser settings.
//!
//! STIG Coverage:
//!   SV-257789 — Unique superuser name required (not root/admin/administrator)
//!
//! Distro-agnostic name — works on any system using GRUB2.

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_grub_config_contract() -> CtnContract {
    let mut contract = CtnContract::new("grub_config".to_string());

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "config_path".to_string(),
            data_type: DataType::String,
            description: "Path to grub config file".to_string(),
            example_values: vec![
                "/etc/grub2.cfg".to_string(),
                "/boot/grub2/grub.cfg".to_string(),
            ],
            validation_notes: Some("Defaults to /etc/grub2.cfg if not specified".to_string()),
        });

    let bool_ops = vec![Operation::Equals, Operation::NotEqual];
    let str_ops = vec![
        Operation::Equals,
        Operation::NotEqual,
        Operation::Contains,
        Operation::StartsWith,
    ];

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether the grub config file was found".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: None,
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_superuser".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops.clone(),
            description: "Whether a superusers entry is defined".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived: true when 'set superusers=' line is present".to_string(),
            ),
        });

    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "superuser_name".to_string(),
        data_type: DataType::String,
        allowed_operations: str_ops.clone(),
        description: "The configured superuser account name".to_string(),
        example_values: vec!["grubadmin".to_string()],
        validation_notes: Some(
            "Extracted from 'set superusers=\"<name>\"' line. Must not be root, admin, or administrator.".to_string(),
        ),
    });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "has_password".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: bool_ops,
            description: "Whether a password_pbkdf2 entry exists for the superuser".to_string(),
            example_values: vec!["true".to_string()],
            validation_notes: Some(
                "Derived: true when password_pbkdf2 line references the superuser name".to_string(),
            ),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "superuser_is_common_name".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Derived: true when superuser name is a common/guessable name".to_string(),
            example_values: vec!["false".to_string()],
            validation_notes: Some(
                "Checks against: root, admin, administrator, grub, boot. Should be false."
                    .to_string(),
            ),
        });

    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("config_path".to_string(), "config_path".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["found".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "has_superuser".to_string(),
        "superuser_name".to_string(),
        "has_password".to_string(),
        "superuser_is_common_name".to_string(),
    ];

    for field in &[
        "found",
        "has_superuser",
        "superuser_name",
        "has_password",
        "superuser_is_common_name",
    ] {
        contract
            .field_mappings
            .validation_mappings
            .state_to_data
            .insert(field.to_string(), field.to_string());
    }

    contract.collection_strategy = CollectionStrategy {
        collector_type: "grub_config".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["file_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(50),
            memory_usage_mb: Some(2),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: true,
        },
    };

    contract
}
