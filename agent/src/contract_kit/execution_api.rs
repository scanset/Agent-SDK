//! # Agent Core API
//!
//! High-level API for executing ESP compliance scans.
//!
//! Supports two entry points:
//! - **File-based** (`scan_file`, `scan_file_with_logging`): compiles a local `.esp`
//!   file through all four phases — compile → convert → resolve → execute.
//! - **AST-based** (`scan_ast`, `scan_ast_manifest`): skips compilation for
//!   pre-compiled ASTs supplied by the caller.
//!
//! ## Example
//!
//! ```ignore
//! use crate::contract_kit::execution_api::{scan_file, ScanError, CtnStrategyRegistry};
//! use std::sync::Arc;
//!
//! fn main() -> Result<(), ScanError> {
//!     let registry = Arc::new(create_my_registry()?);
//!     let result = scan_file("policy.esp", registry)?;
//!
//!     if result.tree_passed {
//!         println!("Compliance check passed!");
//!     }
//!     Ok(())
//! }
//! ```

use std::path::Path;
use std::sync::Arc;

// ============================================================================
// Internal imports
// ============================================================================

use compiler::pipeline;
use execution_engine::conversion::convert_ast_to_scanner_types;
use execution_engine::execution::ExecutionEngine;
use execution_engine::resolution::engine::ResolutionEngine;
use execution_engine::types::ResolutionContext;

// ============================================================================
// Re-exports
// ============================================================================

// Strategy registry types
pub use execution_engine::strategies::{
    CollectedData, CollectionError, CollectorPerformanceProfile, CtnDataCollector,
    CtnStrategyRegistry, StrategyError,
};

// Re-export the full strategies module for registry creation
pub use execution_engine::strategies;

// AST types
pub use common::ast::nodes::EspFile;

// Metadata
pub use common::metadata::MetaDataBlock;

// Execution result
pub use execution_engine::execution::engine::PolicyExecutionResult as ScanResult;

// Manifest type for advanced usage
pub use execution_engine::types::ExecutionManifest;

// Logging utilities
pub use common::logging;
pub use common::{log_error, log_info, log_success};

// ============================================================================
// Error Type
// ============================================================================

/// Error type for scan operations
#[derive(Debug)]
pub enum ScanError {
    /// File I/O error
    IoError(std::io::Error),
    /// ESP compilation failed
    CompilationFailed(String),
    /// AST conversion failed
    ConversionFailed(String),
    /// Resolution phase failed
    ResolutionFailed(String),
    /// Scan execution failed
    ExecutionFailed(String),
    /// Registry error
    RegistryError(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "I/O error: {}", e),
            Self::CompilationFailed(msg) => write!(f, "Compilation failed: {}", msg),
            Self::ConversionFailed(msg) => write!(f, "AST conversion failed: {}", msg),
            Self::ResolutionFailed(msg) => write!(f, "Resolution failed: {}", msg),
            Self::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
            Self::RegistryError(msg) => write!(f, "Registry error: {}", msg),
        }
    }
}

impl std::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ScanError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<execution_engine::strategies::StrategyError> for ScanError {
    fn from(err: execution_engine::strategies::StrategyError) -> Self {
        Self::RegistryError(err.to_string())
    }
}

impl From<execution_engine::conversion::ConversionError> for ScanError {
    fn from(err: execution_engine::conversion::ConversionError) -> Self {
        Self::ConversionFailed(err.to_string())
    }
}

// ============================================================================
// Public API
// ============================================================================

/// Scan a pre-compiled ESP AST and return the result.
///
/// Entry point for daemon mode. The AST arrives from the orchestrator
/// gRPC service, already compiled on the server. Runs phases 2-4:
/// conversion → resolution → execution.
///
/// # Arguments
/// * `ast` - The compiled ESP AST (deserialized from gRPC response)
/// * `registry` - Strategy registry with scanner implementations
pub fn scan_ast(
    ast: &EspFile,
    registry: Arc<CtnStrategyRegistry>,
) -> Result<ScanResult, ScanError> {
    let manifest = scan_ast_manifest(ast, registry)?;
    Ok(manifest.into())
}

/// Scan a pre-compiled ESP AST and return the raw execution manifest.
///
/// Use this when you need access to the full `ExecutionManifest` rather
/// than the legacy `ScanResult`.
pub fn scan_ast_manifest(
    ast: &EspFile,
    registry: Arc<CtnStrategyRegistry>,
) -> Result<ExecutionManifest, ScanError> {
    // Phase 2: Convert AST to scanner types
    let (variables, states, objects, runtime_operations, sets, criteria_root, metadata) =
        convert_ast_to_scanner_types(ast)?;

    // Phase 3: Build resolution context and resolve
    let mut resolution_context = ResolutionContext::from_ast_with_criteria_root(
        variables,
        states,
        objects,
        runtime_operations,
        sets,
        criteria_root,
        metadata,
    );

    let mut resolution_engine = ResolutionEngine::new();
    let execution_context = resolution_engine
        .resolve_context(&mut resolution_context)
        .map_err(|e| ScanError::ResolutionFailed(e.to_string()))?;

    // Phase 4: Execute scan
    let mut engine = ExecutionEngine::new(execution_context, registry);
    let manifest = engine
        .execute()
        .map_err(|e| ScanError::ExecutionFailed(e.to_string()))?;

    Ok(manifest)
}

/// Scan a local `.esp` file and return the result.
///
/// Runs all four phases: compile → convert → resolve → execute.
///
/// # Arguments
/// * `path` - Path to the `.esp` file
/// * `registry` - Strategy registry with scanner implementations
pub fn scan_file<P: AsRef<Path>>(
    path: P,
    registry: Arc<CtnStrategyRegistry>,
) -> Result<ScanResult, ScanError> {
    let path_str = path.as_ref().display().to_string();
    let pipeline_result = pipeline::process_file(&path_str)
        .map_err(|e| ScanError::CompilationFailed(e.to_string()))?;
    scan_ast(&pipeline_result.ast, registry)
}

/// Scan a local `.esp` file with logging enabled.
///
/// Same as `scan_file` but emits progress via the global logging system.
/// Call `logging::init_global_logging()` before using this.
pub fn scan_file_with_logging<P: AsRef<Path>>(
    path: P,
    registry: Arc<CtnStrategyRegistry>,
) -> Result<ScanResult, ScanError> {
    let path_str = path.as_ref().display().to_string();

    log_info!("Scanning ESP file", "path" => &path_str);

    log_info!("Phase 1: Compiling ESP file");
    let pipeline_result = pipeline::process_file(&path_str).map_err(|e| {
        log_error!(
            common::logging::codes::file_processing::FILE_NOT_FOUND,
            "ESP compilation failed",
            "error" => e.to_string()
        );
        ScanError::CompilationFailed(e.to_string())
    })?;

    log_success!(
        common::logging::codes::success::FILE_PROCESSING_SUCCESS,
        "ESP compilation successful"
    );

    let result = scan_ast(&pipeline_result.ast, registry)?;

    if result.tree_passed {
        log_success!(
            common::logging::codes::success::STRUCTURAL_VALIDATION_COMPLETE,
            "Compliance scan passed",
            "criteria" => result.criteria_counts.total,
            "passed" => result.criteria_counts.passed
        );
    } else {
        log_error!(
            common::logging::codes::structural::INCOMPLETE_DEFINITION_STRUCTURE,
            "Compliance scan failed",
            "failed_criteria" => result.criteria_counts.failed,
            "findings" => result.findings.len()
        );
    }

    Ok(result)
}

/// Compile a local `.esp` file without executing it.
///
/// Useful for validation or extracting metadata before a scan.
pub fn compile_file<P: AsRef<Path>>(path: P) -> Result<EspFile, ScanError> {
    let path_str = path.as_ref().display().to_string();
    let pipeline_result = pipeline::process_file(&path_str)
        .map_err(|e| ScanError::CompilationFailed(e.to_string()))?;
    Ok(pipeline_result.ast)
}

/// Extract metadata from a compiled AST without running a scan.
pub fn extract_metadata(ast: &EspFile) -> MetaDataBlock {
    if let Some(meta) = &ast.metadata {
        let mut fields = std::collections::HashMap::new();
        for field in &meta.fields {
            fields.insert(field.name.clone(), field.value.clone());
        }
        MetaDataBlock { fields }
    } else {
        MetaDataBlock::default()
    }
}

// ============================================================================
// Result helpers
// ============================================================================

/// Check if a scan result indicates compliance.
#[inline]
pub fn is_compliant(result: &ScanResult) -> bool {
    result.tree_passed
}

/// Get the pass rate as a percentage (0.0 - 100.0).
#[inline]
pub fn pass_rate(result: &ScanResult) -> f64 {
    if result.criteria_counts.total == 0 {
        0.0
    } else {
        (result.criteria_counts.passed as f64 / result.criteria_counts.total as f64) * 100.0
    }
}

/// Format a scan result as a human-readable summary string.
pub fn format_summary(result: &ScanResult) -> String {
    let status = if result.tree_passed {
        "COMPLIANT"
    } else {
        "NON-COMPLIANT"
    };
    format!(
        "Status: {} | Criteria: {}/{} passed ({:.1}%) | Findings: {}",
        status,
        result.criteria_counts.passed,
        result.criteria_counts.total,
        pass_rate(result),
        result.findings.len()
    )
}

/// Format a scan result as a detailed report.
pub fn format_report(result: &ScanResult) -> String {
    let mut report = String::new();
    let status = if result.tree_passed {
        "COMPLIANT"
    } else {
        "NON-COMPLIANT"
    };

    report.push_str("=== Scan Results ===\n");
    report.push_str(&format!("Status: {}\n", status));
    report.push_str(&format!(
        "Total Criteria: {}\n",
        result.criteria_counts.total
    ));
    report.push_str(&format!("Passed: {}\n", result.criteria_counts.passed));
    report.push_str(&format!("Failed: {}\n", result.criteria_counts.failed));
    report.push_str(&format!("Errors: {}\n", result.criteria_counts.error));
    report.push_str(&format!("Pass Rate: {:.1}%\n", pass_rate(result)));
    report.push_str(&format!("Findings: {}\n", result.findings.len()));

    if !result.findings.is_empty() {
        report.push_str("\n=== Findings ===\n");
        for finding in &result.findings {
            report.push_str(&format!(
                "[{:?}] {}: {}\n",
                finding.severity, finding.finding_id, finding.title
            ));
            if !finding.description.is_empty() {
                report.push_str(&format!("    {}\n", finding.description));
            }
        }
    }

    report
}
