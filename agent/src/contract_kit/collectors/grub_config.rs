//! GRUB Config Collector
//!
//! Reads /etc/grub2.cfg and parses superuser configuration.
//! Derives has_superuser, superuser_name, has_password, superuser_is_common_name.
//!
//! STIG: SV-257789

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::fs;

const DEFAULT_GRUB_PATH: &str = "/etc/grub2.cfg";
const COMMON_NAMES: &[&str] = &["root", "admin", "administrator", "grub", "boot"];

pub struct GrubConfigCollector {
    id: String,
}

impl GrubConfigCollector {
    pub fn new() -> Self {
        Self {
            id: "grub_config_collector".to_string(),
        }
    }

    fn extract_string_field(&self, object: &ExecutableObject, field_name: &str) -> Option<String> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == field_name {
                    if let ResolvedValue::String(s) = value {
                        return Some(s.clone());
                    }
                }
            }
        }
        None
    }

    /// Extract superuser name from: set superusers="<name>"
    fn parse_superuser_name(content: &str) -> Option<String> {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("set superusers=") {
                let val = line
                    .strip_prefix("set superusers=")
                    .unwrap_or("")
                    .trim_matches('"')
                    .trim_matches('\'')
                    .trim()
                    .to_string();
                if !val.is_empty() {
                    return Some(val);
                }
            }
        }
        None
    }

    /// Check whether password_pbkdf2 line exists for the given superuser
    fn has_password_entry(content: &str, superuser: &str) -> bool {
        content.lines().any(|line| {
            let line = line.trim();
            line.starts_with("password_pbkdf2") && line.contains(superuser)
        })
    }

    /// Check whether the name is a common/guessable name
    fn is_common_name(name: &str) -> bool {
        COMMON_NAMES.contains(&name.to_lowercase().as_str())
    }
}

impl Default for GrubConfigCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for GrubConfigCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let config_path = self
            .extract_string_field(object, "config_path")
            .unwrap_or_else(|| DEFAULT_GRUB_PATH.to_string());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "grub_config".to_string(),
            self.id.clone(),
        );

        data.set_method(
            CollectionMethod::builder()
                .method_type(CollectionMethodType::FileRead)
                .description("Parse GRUB2 configuration for superuser settings")
                .target(&config_path)
                .command(format!("grep -A1 superusers {}", config_path))
                .input("config_path", &config_path)
                .build(),
        );

        match fs::read_to_string(&config_path) {
            Err(_) => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(false));
                data.add_field("has_superuser".to_string(), ResolvedValue::Boolean(false));
                data.add_field("has_password".to_string(), ResolvedValue::Boolean(false));
                data.add_field(
                    "superuser_is_common_name".to_string(),
                    ResolvedValue::Boolean(false),
                );
            }
            Ok(content) => {
                data.add_field("found".to_string(), ResolvedValue::Boolean(true));

                match Self::parse_superuser_name(&content) {
                    None => {
                        data.add_field("has_superuser".to_string(), ResolvedValue::Boolean(false));
                        data.add_field("has_password".to_string(), ResolvedValue::Boolean(false));
                        data.add_field(
                            "superuser_is_common_name".to_string(),
                            ResolvedValue::Boolean(false),
                        );
                    }
                    Some(name) => {
                        data.add_field("has_superuser".to_string(), ResolvedValue::Boolean(true));
                        data.add_field(
                            "superuser_name".to_string(),
                            ResolvedValue::String(name.clone()),
                        );

                        let has_pwd = Self::has_password_entry(&content, &name);
                        data.add_field("has_password".to_string(), ResolvedValue::Boolean(has_pwd));

                        let is_common = Self::is_common_name(&name);
                        data.add_field(
                            "superuser_is_common_name".to_string(),
                            ResolvedValue::Boolean(is_common),
                        );
                    }
                }
            }
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["grub_config".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "grub_config" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'grub_config', got '{}'",
                    contract.ctn_type
                ),
            });
        }
        Ok(())
    }

    fn collector_id(&self) -> &str {
        &self.id
    }
    fn supports_batch_collection(&self) -> bool {
        false
    }
}
