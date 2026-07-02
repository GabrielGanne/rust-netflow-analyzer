//! Reference OS-socket integration (Phase 1).
//!
//! Binds a UDP socket, feeds every received datagram into the engine, prints
//! emitted flows from the background aging thread, and reports telemetry.
//!
//! Run with:
//!     cargo run -p netflow_analyzer_core --example udp_listener -- --address 0.0.0.0 --port 2055
//!
//! Then point any NetFlow v9 / IPFIX exporter (or `nfreplay`) at that port.
//! Pass `--help` for the full list of options.

use std::net::UdpSocket;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use netflow_analyzer_core::records::FlowRecord;
use netflow_analyzer_core::FlowContext;

const DEFAULT_ADDRESS: &str = "0.0.0.0";
const DEFAULT_PORT: u16 = 2055;
const DEFAULT_STATS_INTERVAL_SECS: u64 = 5;

/// Command-line options parsed from `std::env::args`.
struct Options {
    address: String,
    port: u16,
    verbose: bool,
    stats_interval: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            address: DEFAULT_ADDRESS.to_string(),
            port: DEFAULT_PORT,
            verbose: false,
            stats_interval: Duration::from_secs(DEFAULT_STATS_INTERVAL_SECS),
        }
    }
}

fn print_help(program: &str) {
    println!(
        "netflow-analyzer udp_listener\n\
         \n\
         Binds a UDP socket, feeds every datagram into the flow engine, prints\n\
         emitted flows, and periodically reports telemetry counters.\n\
         \n\
         USAGE:\n    \
             {program} [OPTIONS]\n\
         \n\
         OPTIONS:\n    \
             -a, --address <ADDR>       Address to bind to (default: {DEFAULT_ADDRESS})\n    \
             -p, --port <PORT>          UDP port to bind to (default: {DEFAULT_PORT})\n    \
             -i, --interval <SECONDS>   Seconds between stats reports (default: {DEFAULT_STATS_INTERVAL_SECS})\n    \
             -v, --verbose              Dump all parsed flow info as it is emitted\n    \
             -h, --help                 Print this help message\n"
    );
}

/// Parses CLI arguments. Returns `Ok(None)` when help was requested and the
/// program should exit successfully without running.
fn parse_args() -> Result<Option<Options>, String> {
    let mut args = std::env::args();
    let program = args.next().unwrap_or_else(|| "udp_listener".to_string());
    let mut opts = Options::default();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help(&program);
                return Ok(None);
            }
            "-v" | "--verbose" => opts.verbose = true,
            "-a" | "--address" => {
                opts.address = args
                    .next()
                    .ok_or_else(|| format!("{arg} requires a value"))?;
            }
            "-p" | "--port" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{arg} requires a value"))?;
                opts.port = value
                    .parse()
                    .map_err(|_| format!("invalid port: {value}"))?;
            }
            "-i" | "--interval" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{arg} requires a value"))?;
                let secs: u64 = value
                    .parse()
                    .map_err(|_| format!("invalid interval: {value}"))?;
                opts.stats_interval = Duration::from_secs(secs);
            }
            // Backwards-compatible positional "ADDR:PORT" form.
            other if !other.starts_with('-') => {
                if let Some((addr, port)) = other.rsplit_once(':') {
                    opts.address = addr.to_string();
                    opts.port = port
                        .parse()
                        .map_err(|_| format!("invalid port in {other}"))?;
                } else {
                    opts.address = other.to_string();
                }
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(Some(opts))
}

fn format_ip(addr: &[u8; 16]) -> String {
    // Heuristic: if the first 12 bytes are zero, render as IPv4 (mapped layout).
    if addr[..12].iter().all(|&b| b == 0) {
        format!("{}.{}.{}.{}", addr[12], addr[13], addr[14], addr[15])
    } else {
        let mut groups = Vec::with_capacity(8);
        for chunk in addr.chunks(2) {
            groups.push(format!("{:02x}{:02x}", chunk[0], chunk[1]));
        }
        groups.join(":")
    }
}

fn print_flow(record: &FlowRecord) {
    println!(
        "[flow] {}:{} -> {}:{} proto={} bytes={} packets={}",
        format_ip(&record.src_ip),
        record.src_port,
        format_ip(&record.dst_ip),
        record.dst_port,
        record.proto,
        record.bytes,
        record.packets,
    );
}

/// Verbose variant of [`print_flow`] that dumps every decoded field, including
/// the flow identity and both effective and original timestamps.
fn print_flow_verbose(record: &FlowRecord) {
    let flow_id = record
        .flow_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| "-".to_string());
    println!(
        "[flow] {}:{} -> {}:{} proto={} bytes={} packets={} flow_id={} \
         start_ns={} end_ns={} orig_start_ns={} orig_end_ns={}",
        format_ip(&record.src_ip),
        record.src_port,
        format_ip(&record.dst_ip),
        record.dst_port,
        record.proto,
        record.bytes,
        record.packets,
        flow_id,
        record.start_time_ns,
        record.end_time_ns,
        record.original_start_time_ns,
        record.original_end_time_ns,
    );
}

fn print_stats(ctx: &FlowContext) {
    let s = ctx.stats();
    println!(
        "[stats] parsed={} parse_errors={} clock_dropped={} clock_fallback={} \
         templates={} records={} active={} output={} dropped={}",
        s.pkts_parsed,
        s.pkts_parse_error,
        s.clock_dropped_packets,
        s.clock_fallback_packets,
        s.templates_received,
        s.data_records_processed,
        s.active_flows,
        s.flows_output,
        s.flows_dropped,
    );
}

/// Set by the SIGINT handler so the main loop can exit and flush cleanly.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Installs a minimal Ctrl-C (SIGINT) handler. The handler only performs an
/// async-signal-safe atomic store; the main loop polls the flag and flushes.
#[cfg(unix)]
fn install_shutdown_handler() {
    extern "C" fn on_sigint(_sig: i32) {
        SHUTDOWN.store(true, Ordering::SeqCst);
    }
    extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }
    // SAFETY: registering a SIGINT (2) handler whose only action is an atomic store.
    unsafe {
        signal(2, on_sigint as extern "C" fn(i32) as usize);
    }
}

#[cfg(not(unix))]
fn install_shutdown_handler() {}

fn run(opts: Options) -> std::io::Result<()> {
    // IPv6 literals must be bracketed when combined with a port.
    let bind_addr = if opts.address.contains(':') {
        format!("[{}]:{}", opts.address, opts.port)
    } else {
        format!("{}:{}", opts.address, opts.port)
    };
    let socket = UdpSocket::bind(&bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    println!("netflow-analyzer listening on udp://{bind_addr}");
    if opts.verbose {
        println!("verbose mode enabled: dumping all parsed flow info");
    }

    install_shutdown_handler();

    let ctx = FlowContext::new();
    // Emitted flows (idle eviction / active rollover) are printed as they occur.
    let printer: fn(&FlowRecord) = if opts.verbose {
        print_flow_verbose
    } else {
        print_flow
    };
    ctx.start_aging(printer);

    // Reusable receive buffer. The parser borrows from it directly (zero-copy);
    // we never allocate per-packet on the heap.
    let mut buf = [0u8; 65_535];
    let mut last_report = Instant::now();

    while !SHUTDOWN.load(Ordering::SeqCst) {
        match socket.recv_from(&mut buf) {
            Ok((len, peer)) => match ctx.process_packet(&buf[..len]) {
                Ok(records) if opts.verbose => {
                    println!("[packet] {len} bytes from {peer} -> {records} data record(s)");
                }
                Ok(_) => {}
                Err(err) if opts.verbose => {
                    println!("[packet] {len} bytes from {peer} -> error: {err}");
                }
                Err(_) => {}
            },
            // WouldBlock/TimedOut are the read-timeout firing; Interrupted is a
            // signal (e.g. Ctrl-C) waking the call. All three loop back to
            // re-check the shutdown flag.
            Err(ref e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }

        // Periodic telemetry dump.
        if last_report.elapsed() >= opts.stats_interval {
            print_stats(&ctx);
            last_report = Instant::now();
        }
    }

    // Ctrl-C: stop aging, then drain and dump every flow still in the cache.
    println!("\nshutting down: flushing residual flows");
    ctx.stop_aging();
    ctx.flush(printer);
    print_stats(&ctx);
    Ok(())
}

fn main() -> ExitCode {
    let opts = match parse_args() {
        Ok(Some(opts)) => opts,
        Ok(None) => return ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            eprintln!("run with --help for usage");
            return ExitCode::FAILURE;
        }
    };

    match run(opts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
