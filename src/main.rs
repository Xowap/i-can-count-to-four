//! i-can-count-to-four -- hunt a filesystem for traces of the compromised eMudhra
//! intermediate CA certificates (CVE-2026-111943 / RHSB-2026-012).

mod matches;
mod provenance;
mod remediate;
mod render;
mod report;
mod scan;
mod sniff;
mod targets;
mod walk;

use std::io::{IsTerminal, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use crossbeam_channel::unbounded;
use ignore::{WalkBuilder, WalkState};

use crate::matches::Matchers;
use crate::report::FileReport;
#[derive(Parser, Debug)]
#[command(
    name = "i-can-count-to-four",
    version,
    about = "Scan a filesystem for traces of the compromised eMudhra \
             intermediate CA certificates (CVE-2026-111943 / RHSB-2026-012)"
)]
struct Cli {
    /// Directories to scan (default: /).
    #[arg(value_name = "ROOT", default_value = "/")]
    roots: Vec<PathBuf>,

    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long)]
    json: bool,

    /// Stay on one filesystem; do not cross mount points.
    #[arg(long)]
    one_file_system: bool,

    /// Follow symbolic links (off by default to avoid loops and duplicates).
    #[arg(long)]
    follow_links: bool,

    /// Maximum directory depth.
    #[arg(long, value_name = "N")]
    max_depth: Option<usize>,

    /// Skip files larger than this many bytes (default: no limit). Useful on
    /// machines with multi-gigabyte model/disk-image files.
    #[arg(long, value_name = "BYTES", default_value_t = 0)]
    max_file_size: u64,

    /// Worker threads (default: number of CPUs).
    #[arg(long, value_name = "N")]
    threads: Option<usize>,

    /// Read every file in full, disabling the content-sniffing shortcut.
    /// Slower, but no file is only partially read.
    #[arg(long)]
    thorough: bool,

    /// Suppress the progress line.
    #[arg(short, long)]
    quiet: bool,

    /// Exit with status 2 when at least one high-confidence finding is present.
    #[arg(long)]
    fail_on_found: bool,

    /// Print the embedded target certificates and exit.
    #[arg(long)]
    list_targets: bool,

    /// Disable colors in the human-readable report.
    #[arg(long)]
    no_color: bool,

    /// Re-render the grouped report from a JSON file produced by --json,
    /// without scanning the filesystem again.
    #[arg(long, value_name = "FILE")]
    from_json: Option<PathBuf>,

    /// Also write a self-contained colored HTML report to this file.
    #[arg(long, value_name = "FILE")]
    html: Option<PathBuf>,
}

enum ScanOutcome {
    Clean { sampled: bool },
    Candidate { report: FileReport, sampled: bool },
    Error,
}

struct ScanOpts {
    roots: Vec<PathBuf>,
    one_file_system: bool,
    follow_links: bool,
    max_depth: Option<usize>,
    max_file_size: u64,
    thorough: bool,
}

struct Counters {
    files: AtomicU64,
    bytes: AtomicU64,
    candidates: AtomicU64,
    sampled: AtomicU64,
    errors: AtomicU64,
    too_big: AtomicU64,
}

fn main() {
    // Don't die with a panic when stdout is closed early, e.g. `... | head`.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();

    if cli.list_targets {
        print_targets();
        return;
    }

    let style = render::Style::new(use_color(cli.no_color));

    if let Some(file) = &cli.from_json {
        match report::load_json(file) {
            Ok((mut reports, summary)) => {
                report::sort_reports(&mut reports);
                render::render(&reports, &summary, &style);
                write_html(&cli, &reports, &summary);
                if cli.fail_on_found && summary.high > 0 {
                    std::process::exit(2);
                }
                return;
            }
            Err(e) => {
                eprintln!("error: cannot read {}: {e}", file.display());
                std::process::exit(3);
            }
        }
    }

    let start = Instant::now();
    let matchers = Arc::new(Matchers::new());
    let skip = Arc::new(walk::pseudo_mount_points());
    let counters = Arc::new(Counters {
        files: AtomicU64::new(0),
        bytes: AtomicU64::new(0),
        candidates: AtomicU64::new(0),
        sampled: AtomicU64::new(0),
        errors: AtomicU64::new(0),
        too_big: AtomicU64::new(0),
    });

    let threads = cli.threads.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    });

    let (tx, rx) = unbounded::<FileReport>();
    let done = Arc::new(AtomicBool::new(false));

    let progress = if !cli.quiet && !cli.json {
        let counters = counters.clone();
        let done = done.clone();
        Some(std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(500));
                if done.load(Ordering::Relaxed) {
                    break;
                }
                eprint!(
                    "\r\x1b[K[scanning] {} files, {:.2} GiB, {} candidates",
                    counters.files.load(Ordering::Relaxed),
                    counters.bytes.load(Ordering::Relaxed) as f64 / 1_073_741_824.0,
                    counters.candidates.load(Ordering::Relaxed),
                );
            }
        }))
    } else {
        None
    };

    let opts = ScanOpts {
        roots: cli.roots.clone(),
        one_file_system: cli.one_file_system,
        follow_links: cli.follow_links,
        max_depth: cli.max_depth,
        max_file_size: cli.max_file_size,
        thorough: cli.thorough,
    };

    let walker = {
        let matchers = matchers.clone();
        let skip = skip.clone();
        let counters = counters.clone();
        let tx = tx.clone();
        std::thread::spawn(move || {
            run_walk(opts, skip, matchers, counters, threads, tx);
        })
    };
    drop(tx);

    let mut reports: Vec<FileReport> = Vec::new();
    while let Ok(r) = rx.recv() {
        reports.push(r);
    }
    walker.join().expect("walker thread panicked");
    let elapsed = start.elapsed();

    done.store(true, Ordering::Relaxed);
    if let Some(p) = progress {
        let _ = p.join();
        eprintln!();
    }

    report::sort_reports(&mut reports);

    let high = reports.iter().filter(|r| r.is_high_confidence()).count();

    if cli.json {
        let findings: Vec<serde_json::Value> = reports.iter().map(|r| r.to_json()).collect();
        let out = serde_json::json!({
            "summary": {
                "files_scanned": counters.files.load(Ordering::Relaxed),
                "bytes_scanned": counters.bytes.load(Ordering::Relaxed),
                "candidates": counters.candidates.load(Ordering::Relaxed),
                "findings": reports.len(),
                "high_confidence": high,
                "unreadable": counters.errors.load(Ordering::Relaxed),
                "too_large": counters.too_big.load(Ordering::Relaxed),
                "partially_read": counters.sampled.load(Ordering::Relaxed),
                "thorough": cli.thorough,
                "elapsed_secs": elapsed.as_secs_f64(),
            },
            "findings": findings,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        let summary = render::Summary {
            files: counters.files.load(Ordering::Relaxed),
            bytes: counters.bytes.load(Ordering::Relaxed),
            elapsed: elapsed.as_secs_f64(),
            high,
            partial: counters.sampled.load(Ordering::Relaxed),
            thorough: cli.thorough,
        };
        render::render(&reports, &summary, &style);
        write_html(&cli, &reports, &summary);
    }

    if cli.fail_on_found && high > 0 {
        std::process::exit(2);
    }
}

fn run_walk(
    opts: ScanOpts,
    skip: Arc<std::collections::HashSet<PathBuf>>,
    matchers: Arc<Matchers>,
    counters: Arc<Counters>,
    threads: usize,
    tx: crossbeam_channel::Sender<FileReport>,
) {
    for root in &opts.roots {
        let root = match root.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("warning: cannot access {}: {}", root.display(), e);
                continue;
            }
        };

        let mut builder = WalkBuilder::new(&root);
        builder
            .hidden(false)
            .ignore(false)
            .git_ignore(false)
            .git_global(false)
            .git_exclude(false)
            .parents(false)
            .follow_links(opts.follow_links)
            .same_file_system(opts.one_file_system)
            .threads(threads);

        if let Some(depth) = opts.max_depth {
            builder.max_depth(Some(depth));
        }

        let skip_dirs = skip.clone();
        builder.filter_entry(move |entry| {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                !skip_dirs.contains(entry.path())
            } else {
                true
            }
        });

        let max_needle = matchers.max_needle_len();
        let max_file_size = opts.max_file_size;
        let thorough = opts.thorough;
        let m0 = matchers.clone();
        let c0 = counters.clone();
        let t0 = tx.clone();
        builder.build_parallel().run(move || {
            let matchers = m0.clone();
            let counters = c0.clone();
            let tx = t0.clone();
            // One reusable set of buffers per worker thread.
            let mut worker = Worker::new(max_needle);
            Box::new(move |result| {
                let entry = match result {
                    Ok(e) => e,
                    Err(_) => {
                        counters.errors.fetch_add(1, Ordering::Relaxed);
                        return WalkState::Continue;
                    }
                };

                let is_file = entry.file_type().map(|t| t.is_file()).unwrap_or(false);
                if !is_file {
                    return WalkState::Continue;
                }

                counters.files.fetch_add(1, Ordering::Relaxed);
                let path = entry.path();
                let size = match entry.metadata() {
                    Ok(md) => md.len(),
                    Err(_) => {
                        counters.errors.fetch_add(1, Ordering::Relaxed);
                        return WalkState::Continue;
                    }
                };
                counters.bytes.fetch_add(size, Ordering::Relaxed);

                if max_file_size > 0 && size > max_file_size {
                    counters.too_big.fetch_add(1, Ordering::Relaxed);
                    return WalkState::Continue;
                }

                match scan_file(&mut worker, &matchers, path, size, thorough) {
                    ScanOutcome::Candidate { report, sampled } => {
                        counters.candidates.fetch_add(1, Ordering::Relaxed);
                        if sampled {
                            counters.sampled.fetch_add(1, Ordering::Relaxed);
                        }
                        let _ = tx.send(report);
                    }
                    ScanOutcome::Clean { sampled } => {
                        if sampled {
                            counters.sampled.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    ScanOutcome::Error => {
                        counters.errors.fetch_add(1, Ordering::Relaxed);
                    }
                }

                WalkState::Continue
            })
        });
    }
}

/// Streaming buffer size (per worker thread).
const CHUNK: usize = 8 * 1024 * 1024;

/// How much of a file's head we read to classify it.
const HEAD_SNIFF: u64 = 64 * 1024;
/// How much of a large opaque file's tail we still inspect.
const TAIL_WINDOW: u64 = 64 * 1024;
/// Files at or below this size are always read in full (they are cheap, and
/// most binaries/libraries/archives fall in this range).
const SMALL_FILE: u64 = 16 * 1024 * 1024;
/// Upper bound for reading a text file in full before falling back to windows.
const TEXT_MAX: u64 = 64 * 1024 * 1024;
/// Upper bound for reading a certificate container in full.
const CONTAINER_MAX: u64 = 512 * 1024 * 1024;

/// Reusable per-thread buffers.
struct Worker {
    stream: Vec<u8>,
    head: Vec<u8>,
    tail: Vec<u8>,
}

impl Worker {
    fn new(max_needle: usize) -> Self {
        Worker {
            stream: vec![0u8; CHUNK + max_needle],
            head: vec![0u8; HEAD_SNIFF as usize],
            tail: vec![0u8; TAIL_WINDOW as usize],
        }
    }
}

enum Plan {
    /// Read the whole file.
    Full,
    /// Read only the head and tail.
    Windows,
}

/// Decide how much of a file to read. Content, not names.
fn read_plan(size: u64, thorough: bool, kind: sniff::ContentKind) -> Plan {
    use sniff::ContentKind::*;
    if thorough || size <= SMALL_FILE {
        return Plan::Full;
    }
    match kind {
        CertContainer if size <= CONTAINER_MAX => Plan::Full,
        Text if size <= TEXT_MAX => Plan::Full,
        _ => Plan::Windows,
    }
}

/// Everything a scan pass learned about a file.
#[derive(Default)]
struct StreamedScan {
    analysis: scan::Analysis,
    saw_pem_header: bool,
    starts_der: bool,
}

/// Fill `buf` (looping over short reads); returns the number of bytes read.
fn read_into(file: &mut std::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Fold the hits in one buffer into the running result.
fn accumulate(
    matchers: &Matchers,
    bytes: &[u8],
    base: u64,
    out: &mut StreamedScan,
    text_budget: &mut usize,
) {
    for (target, off) in matchers.der_hits(bytes) {
        scan::record_der(&mut out.analysis, target, base + off as u64);
    }
    if *text_budget > 0 {
        for (class, _off) in matchers.text_hits(bytes, *text_budget) {
            if scan::record_text(&mut out.analysis, class) {
                out.saw_pem_header = true;
            }
            *text_budget -= 1;
        }
    }
}

/// Read the file in bounded chunks and collect hits, carrying a needle-sized
/// overlap across chunk boundaries. Memory stays flat for files of any size.
fn stream_scan(
    matchers: &Matchers,
    file: &mut std::fs::File,
    buf: &mut [u8],
) -> std::io::Result<StreamedScan> {
    let overlap = matchers.max_needle_len().saturating_sub(1);
    let chunk = buf.len() - overlap;
    let mut carry = 0usize;
    let mut base = 0u64;
    let mut budget = scan::MAX_HITS;
    let mut first = true;
    let mut out = StreamedScan::default();

    loop {
        let n = file.read(&mut buf[carry..carry + chunk])?;
        if n == 0 {
            break;
        }
        let total = carry + n;
        let window = &buf[..total];

        if first {
            out.starts_der = window.first() == Some(&0x30);
            first = false;
        }

        accumulate(matchers, window, base, &mut out, &mut budget);

        let keep = overlap.min(total);
        base += (total - keep) as u64;
        buf.copy_within(total - keep..total, 0);
        carry = keep;
    }

    Ok(out)
}

fn scan_file(
    worker: &mut Worker,
    matchers: &Matchers,
    path: &Path,
    size: u64,
    thorough: bool,
) -> ScanOutcome {
    if size == 0 {
        return ScanOutcome::Clean { sampled: false };
    }

    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return ScanOutcome::Error,
    };

    // Peek the head and classify by content.
    let head_len = size.min(HEAD_SNIFF) as usize;
    if read_into(&mut file, &mut worker.head[..head_len]).is_err() {
        return ScanOutcome::Error;
    }
    let kind = sniff::classify(&worker.head[..head_len]);

    let mut sampled = false;
    let mut streamed = StreamedScan::default();

    match read_plan(size, thorough, kind) {
        Plan::Full => {
            if file.seek(SeekFrom::Start(0)).is_err() {
                return ScanOutcome::Error;
            }
            streamed = match stream_scan(matchers, &mut file, &mut worker.stream) {
                Ok(s) => s,
                Err(_) => return ScanOutcome::Error,
            };
        }
        Plan::Windows => {
            let mut budget = scan::MAX_HITS;
            accumulate(
                matchers,
                &worker.head[..head_len],
                0,
                &mut streamed,
                &mut budget,
            );
            sampled = true;

            if size > HEAD_SNIFF {
                let tail_len = (size - HEAD_SNIFF).min(TAIL_WINDOW) as usize;
                if tail_len > 0 {
                    let start = size - tail_len as u64;
                    if file.seek(SeekFrom::Start(start)).is_ok()
                        && read_into(&mut file, &mut worker.tail[..tail_len]).is_ok()
                    {
                        accumulate(
                            matchers,
                            &worker.tail[..tail_len],
                            start,
                            &mut streamed,
                            &mut budget,
                        );
                    }
                }
            }
        }
    }

    // Small files that need decoding (a PEM container or a bare DER
    // certificate) get a full in-memory analysis for rich metadata.
    let mut analysis = streamed.analysis;
    if !sampled && size <= scan::MAX_HEAP_READ && (streamed.saw_pem_header || streamed.starts_der) {
        if let Ok(bytes) = std::fs::read(path) {
            analysis = scan::analyze(matchers, &bytes);
        }
    }

    scan::finalize(&mut analysis);
    if analysis.is_empty() {
        ScanOutcome::Clean { sampled }
    } else {
        ScanOutcome::Candidate {
            report: FileReport {
                path: path.to_path_buf(),
                size,
                analysis,
            },
            sampled,
        }
    }
}

fn write_html(cli: &Cli, reports: &[FileReport], summary: &render::Summary) {
    if let Some(path) = &cli.html {
        let html = render::render_html(reports, summary);
        match std::fs::write(path, html) {
            Ok(()) => eprintln!("[html] wrote {}", path.display()),
            Err(e) => eprintln!("error: cannot write {}: {e}", path.display()),
        }
    }
}

/// Decide whether to colorize: `--no-color` wins, then `CLICOLOR_FORCE`, then
/// `NO_COLOR`, otherwise only when stdout is a terminal.
fn use_color(no_color: bool) -> bool {
    if no_color {
        return false;
    }
    if let Ok(v) = std::env::var("CLICOLOR_FORCE") {
        if !v.is_empty() && v != "0" {
            return true;
        }
    }
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    std::io::stdout().is_terminal()
}

fn print_targets() {
    println!("Embedded compromised eMudhra intermediate certificates (CVE-2026-111943):");
    println!();
    for t in targets::TARGETS {
        println!("  {}", t.name);
        println!("    organization : {}", t.org);
        println!("    serial       : {}", t.serial);
        println!("    cert sha256  : {}", t.cert_sha256);
        println!("    spki sha256  : {}", t.spki_sha256);
        println!();
    }
}
