//! OS Release Collector
//!
//! Reads /etc/os-release and parses key=value pairs.
//! Derives 'supported' boolean for Rocky/RHEL 9 validation.
//!
//! STIG: SV-257777

use common::results::{CollectionMethod, CollectionMethodType};
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use std::collections::HashMap;
use std::fs;

pub struct OsReleaseCollector {
    id: String,
}

impl OsReleaseCollector {
    pub fn new() -> Self {
        Self {
            id: "os_release_collector".to_string(),
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

    /// Parse /etc/os-release key=value format
    fn parse_os_release(content: &str) -> HashMap<String, String> {
        let mut map = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, val)) = line.split_once('=') {
                let val = val.trim_matches('"').trim_matches('\'').to_string();
                map.insert(key.to_string(), val);
            }
        }
        map
    }

    /// Derive whether the OS version is supported (Rocky/RHEL 9.x)
    fn derive_supported(fields: &HashMap<String, String>) -> bool {
        let id = fields.get("ID").map(|s| s.as_str()).unwrap_or("");
        let version_id = fields.get("VERSION_ID").map(|s| s.as_str()).unwrap_or("");
        let id_like = fields.get("ID_LIKE").map(|s| s.as_str()).unwrap_or("");

        // Rocky/RHEL/AlmaLinux 9.x
        let is_el9_family =
            id == "rocky" || id == "rhel" || id == "almalinux" || id_like.contains("rhel");

        if !is_el9_family {
            return false;
        }

        // VERSION_ID must start with "9."
        version_id.starts_with("9.")
    }
}

impl Default for OsReleaseCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CtnDataCollector for OsReleaseCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        self.validate_ctn_compatibility(contract)?;

        let release_file = self
            .extract_string_field(object, "release_file")
            .unwrap_or_else(|| "/etc/os-release".to_string());

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "os_release".to_string(),
            self.id.clone(),
        );

        data.set_method(
            CollectionMethod::builder()
                .method_type(CollectionMethodType::FileRead)
                .description("Parse OS release information from /etc/os-release")
                .target(&release_file)
                .command(format!("cat {}", release_file))
                .input("release_file", &release_file)
                .build(),
        );

        let content =
            fs::read_to_string(&release_file).map_err(|e| CollectionError::CollectionFailed {
                object_id: object.identifier.clone(),
                reason: format!("Failed to read {}: {}", release_file, e),
            })?;

        let fields = Self::parse_os_release(&content);

        let field_map = [
            ("NAME", "name"),
            ("VERSION", "version"),
            ("VERSION_ID", "version_id"),
            ("ID", "id"),
            ("ID_LIKE", "id_like"),
            ("PRETTY_NAME", "pretty_name"),
            ("PLATFORM_ID", "platform_id"),
        ];

        for (os_key, data_key) in &field_map {
            if let Some(val) = fields.get(*os_key) {
                data.add_field(data_key.to_string(), ResolvedValue::String(val.clone()));
            }
        }

        let supported = Self::derive_supported(&fields);
        data.add_field("supported".to_string(), ResolvedValue::Boolean(supported));

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["os_release".to_string()]
    }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "os_release" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!(
                    "Incompatible CTN type: expected 'os_release', got '{}'",
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
