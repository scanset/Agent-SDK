//! Configuration types for the ESP agent.

use std::path::PathBuf;

/// Default output filename when `--output` is specified without a value.
pub const DEFAULT_OUTPUT_FILENAME: &str = "assessor_package.json";

/// Configuration for a scan run. v2.x of the engine produces a single
/// `AssessorPackage` envelope per scan — there is no longer a choice of
/// output format, so the only knobs are input path, optional output file,
/// and quiet mode.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Input path (file or directory of `.esp` policies).
    pub input_path: PathBuf,
    /// Output file path. `None` means console-only output.
    pub output_file: Option<PathBuf>,
    /// Suppress progress / console output.
    pub quiet: bool,
}

/// Roll-up result of a scan run.
#[derive(Debug)]
pub struct ScanSummary {
    pub total_files: usize,
    pub passed: usize,
    pub failed: usize,
    pub errors: usize,
    #[allow(dead_code)]
    pub duration: std::time::Duration,
}

impl ScanSummary {
    pub fn new(total_files: usize) -> Self {
        Self {
            total_files,
            passed: 0,
            failed: 0,
            errors: 0,
            duration: std::time::Duration::ZERO,
        }
    }

    /// Exit code:
    /// - `0` — all policies passed
    /// - `1` — one or more policies failed
    /// - `2` — execution error
    pub fn exit_code(&self) -> i32 {
        if self.errors > 0 {
            2
        } else if self.failed > 0 {
            1
        } else {
            0
        }
    }
}
