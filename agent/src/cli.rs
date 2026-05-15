//! Command-line interface parsing.
//!
//! v2.x of the engine produces a single `AssessorPackage` envelope per scan,
//! so there is no `--format` flag — the only options are quiet mode and an
//! optional output filename.

use std::path::PathBuf;

use crate::config::ScanConfig;

/// CLI parsing result.
pub enum CliResult {
    Run(ScanConfig),
    Help,
    Error(String),
}

/// Parse command-line arguments.
pub fn parse_args(args: &[String]) -> CliResult {
    let program_name = args.first().map(|s| s.as_str()).unwrap_or("esp-agent");

    let mut input_path: Option<&str> = None;
    let mut output_file: Option<PathBuf> = None;
    let mut quiet = false;

    let mut i = 1;
    while i < args.len() {
        match args.get(i).map(|s| s.as_str()) {
            Some("--help" | "-h") => return CliResult::Help,
            Some("--quiet" | "-q") => {
                quiet = true;
            }
            Some("--output" | "-o") => {
                i += 1;
                match args.get(i) {
                    Some(val) => output_file = Some(PathBuf::from(val)),
                    None => return CliResult::Error("--output requires a filename".to_string()),
                }
            }
            Some(arg) if !arg.starts_with('-') => {
                input_path = Some(arg);
            }
            Some(arg) => return CliResult::Error(format!("Unknown option: {}", arg)),
            None => break,
        }
        i += 1;
    }

    let input_path = match input_path {
        Some(p) => PathBuf::from(p),
        None => {
            return CliResult::Error(format!(
                "Missing input path\nUsage: {} [OPTIONS] <file.esp|directory>",
                program_name
            ));
        }
    };

    if !input_path.exists() {
        return CliResult::Error(format!("Path not found: {}", input_path.display()));
    }

    CliResult::Run(ScanConfig {
        input_path,
        output_file,
        quiet,
    })
}

#[allow(dead_code)]
pub fn print_usage(program_name: &str) {
    eprintln!("Usage: {} [OPTIONS] <file.esp|directory>", program_name);
    eprintln!("       {} --help", program_name);
}

pub fn print_help(program_name: &str) {
    println!("ESP Compliance Agent v{}", env!("CARGO_PKG_VERSION"));
    println!("Compliance scanning using ESP policy files\n");

    println!("USAGE:");
    println!(
        "    {} [OPTIONS] <file.esp>       Scan single ESP file",
        program_name
    );
    println!(
        "    {} [OPTIONS] <directory>      Scan all ESP files in directory",
        program_name
    );
    println!(
        "    {} --help                     Show this help message\n",
        program_name
    );

    println!("OPTIONS:");
    println!("    -h, --help                  Show this help message");
    println!("    -q, --quiet                 Suppress console output");
    println!("    -o, --output <file>         Write the signed AssessorPackage JSON to <file>");
    println!();

    println!("OUTPUT:");
    println!("    Results are printed to the console unless --quiet is set.");
    println!("    Use --output to additionally save the signed AssessorPackage envelope");
    println!("    to a JSON file. Every scan produces one envelope covering all policies.");
    println!();

    println!("EXIT CODES:");
    println!("    0    All policies passed");
    println!("    1    One or more policies failed");
    println!("    2    Execution error");
    println!();

    println!("EXAMPLES:");
    println!(
        "    {} policy.esp                                  # Console output only",
        program_name
    );
    println!(
        "    {} --output results.json policy.esp            # Console + file",
        program_name
    );
    println!(
        "    {} --quiet -o results.json /path/to/policies/  # File only, no console",
        program_name
    );
}
