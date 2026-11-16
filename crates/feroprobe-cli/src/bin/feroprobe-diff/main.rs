//! `feroprobe-diff`: compare two saved scan reports and show what changed,
//! like nmap's ndiff. It reads two XML reports (FeroProbe's `-oX`, or
//! nmap's) and prints the differences: hosts that came up or went down,
//! ports that opened or closed, services, versions and OS matches that
//! changed, and script output.
//!
//! Exit status, as ndiff's: 0 when the scans are the same in everything
//! compared, 1 when they differ, 2 on an error.

mod diff;
mod scan;
mod text;
mod xmlout;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use diff::ScanDiff;
use scan::Scan;

const HELP: &str = "\
FeroProbe-diff {version} ( https://github.com/jkobierczynski/FeroProbe )
Usage: feroprobe-diff [options] FILE1 FILE2
Compare two FeroProbe or nmap XML reports (-oX) and show their differences:
host state changes, port state changes, and changes to services, versions,
OS matches and script output.

  -h, --help     show this help
  -V, --version  show the version
  -v, --verbose  also show hosts and ports that haven't changed
  --text         show the differences as text (default)
  --xml          show the differences as XML

Lines starting with - are only in FILE1, lines starting with + only in FILE2.
Exit status: 0 when the scans are the same, 1 when they differ, 2 on an error.
";

#[derive(Debug, Parser)]
#[command(
    name = "feroprobe-diff",
    version,
    override_help = HELP.replace("{version}", env!("CARGO_PKG_VERSION")),
    args_override_self = true
)]
struct Args {
    /// The earlier report and the later one.
    #[arg(num_args = 2, required = true, value_name = "FILE")]
    files: Vec<PathBuf>,

    #[arg(short, long)]
    verbose: bool,

    #[arg(long, conflicts_with = "xml")]
    text: bool,

    #[arg(long)]
    xml: bool,
}

fn load(path: &PathBuf) -> Result<Scan> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("can't open file {}", path.display()))?;
    let (scan, warnings) =
        Scan::parse(&text).with_context(|| format!("can't read {}", path.display()))?;
    for w in warnings {
        eprintln!("Warning: {}: {w}", path.display());
    }
    Ok(scan)
}

fn run(args: &Args) -> Result<bool> {
    let a = load(&args.files[0])?;
    let b = load(&args.files[1])?;
    let d = ScanDiff::new(&a, &b, args.verbose);
    let out = if args.xml {
        xmlout::render(&d)
    } else {
        text::render(&d)
    };
    let mut stdout = std::io::stdout().lock();
    // A closed pipe (| head) is not an error worth a message.
    if let Err(e) = stdout
        .write_all(out.as_bytes())
        .and_then(|()| stdout.flush())
        && e.kind() != std::io::ErrorKind::BrokenPipe
    {
        return Err(e).context("can't write the output");
    }
    Ok(d.cost > 0)
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(false) => ExitCode::from(0),
        Ok(true) => ExitCode::from(1),
        Err(e) => {
            eprintln!("feroprobe-diff: {e:#}");
            ExitCode::from(2)
        }
    }
}
