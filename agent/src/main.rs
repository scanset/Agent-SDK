//! # ESP Compliance Agent
//!
//! Compliance scanning agent using ESP (Endpoint State Policy) files.
//!
//! ## Usage
//!
//! ```bash
//! # Scan a single file (console output)
//! esp_agent policy.esp
//!
//! # Scan a directory (console output)
//! esp_agent /path/to/policies/
//!
//! # Save the signed AssessorPackage envelope to a file
//! esp_agent --output assessor_package.json policy.esp
//! ```
//!
//! Every scan produces one signed `AssessorPackage` envelope covering all
//! policies the run touched. See `output/` for the envelope construction
//! and `signing/` for how the per-deployment signer key is derived.

use agent::cli::{parse_args, print_help, CliResult};
use agent::config;
use agent::contract_kit::execution_api::logging;
use agent::{discovery, scanner};

fn main() {
    // Initialize logging
    if let Err(e) = logging::init_global_logging() {
        eprintln!("Failed to initialize logging: {}", e);
        std::process::exit(2);
    }

    // Parse CLI arguments
    let args: Vec<String> = std::env::args().collect();
    let program_name = args.first().map(|s| s.as_str()).unwrap_or("esp-agent");

    let exit_code = match parse_args(&args) {
        CliResult::Help => {
            print_help(program_name);
            0
        }
        CliResult::Error(msg) => {
            eprintln!("Error: {}", msg);
            2
        }
        CliResult::Run(config) => match run(config) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("Error: {}", e);
                2
            }
        },
    };

    // Print logging summary if not quiet
    // Note: We can't easily check quiet here, but the logging summary
    // is useful for debugging so we always print it on non-zero exit
    if exit_code != 0 {
        logging::print_cargo_style_summary();
    }

    std::process::exit(exit_code);
}

/// Run the scan with the given configuration
fn run(config: config::ScanConfig) -> Result<i32, Box<dyn std::error::Error>> {
    // Discover ESP files
    let esp_files = discovery::discover_esp_files(&config.input_path)?;

    if esp_files.is_empty() {
        if !config.quiet {
            println!("No ESP files found in: {}", config.input_path.display());
        }
        return Ok(0);
    }

    // Run the scan
    let exit_code = scanner::run_scan(&config, &esp_files)?;

    // Print logging summary
    if !config.quiet {
        logging::print_cargo_style_summary();
    }

    Ok(exit_code)
}
