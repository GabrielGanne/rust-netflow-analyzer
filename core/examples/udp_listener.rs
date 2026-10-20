// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Reference OS-socket integration (Phase 1).
//!
//! Binds a UDP socket, feeds every received datagram into the engine, prints
//! emitted flows from the background aging thread, and reports telemetry.
//!
//! Each admitted source endpoint and protocol scope is given a distinct
//! exporter key. Idle peers are purged when capacity is needed or they return,
//! and evidence of a restart rotates only the affected scope's key after the
//! aging worker stops (see `docs/exporter-identity.md`).
//!
//! Run with:
//!     cargo run -p netflow_analyzer_core --example udp_listener -- --address 10.0.0.10 --allow-exporter 10.0.0.1
//!
//! Without `--allow-exporter`, only loopback source IPs are admitted. The source
//! IP allow-list is only meaningful behind a network boundary that prevents
//! spoofing. Then point a trusted NetFlow or IPFIX exporter at that port.
//! Pass `--help` for the full list of options.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use netflow_analyzer_core::records::FlowRecord;
use netflow_analyzer_core::scope::{ExporterKey, Scope};
use netflow_analyzer_core::FlowContext;

const DEFAULT_ADDRESS: &str = "0.0.0.0";
const DEFAULT_PORT: u16 = 2055;
const DEFAULT_STATS_INTERVAL_SECS: u64 = 5;
const DEFAULT_MAX_PEERS: usize = 1024;
const DEFAULT_PEER_IDLE_SECS: u64 = 30 * 60;
const MAX_SCOPES_PER_PEER: usize = 64;
const REORDER_WINDOW: u32 = 64;
const RESTART_SEQUENCE_FLOOR: u32 = 1024;
const RESTART_SEQUENCE_CEILING: u32 = 32;
const RESTART_QUIET_PERIOD: Duration = Duration::from_secs(2);
const UPTIME_TOLERANCE_MS: u32 = 60_000;
const MAX_PENDING_RESTART_BYTES_PER_PEER: usize = 256 * 1024;
const MIN_PURGE_SPACING: Duration = Duration::from_secs(6);

fn normalized_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

#[derive(Clone, Copy)]
struct HeaderInfo {
    scope: Scope,
    sequence: u32,
    export_seconds: u32,
    uptime_ms: Option<u32>,
}

fn header_info(packet: &[u8]) -> Option<HeaderInfo> {
    let field = |offset: usize| -> Option<u32> {
        Some(u32::from_be_bytes(
            packet.get(offset..offset + 4)?.try_into().ok()?,
        ))
    };
    let version = u16::from_be_bytes(packet.get(..2)?.try_into().ok()?);
    match version {
        5 if packet.len() >= 24 => Some(HeaderInfo {
            scope: Scope::V5Engine {
                engine_type: packet[20],
                engine_id: packet[21],
            },
            sequence: field(16)?,
            export_seconds: field(8)?,
            uptime_ms: Some(field(4)?),
        }),
        9 if packet.len() >= 20 => Some(HeaderInfo {
            scope: Scope::V9Domain(field(16)?),
            sequence: field(12)?,
            export_seconds: field(8)?,
            uptime_ms: Some(field(4)?),
        }),
        10 if packet.len() >= 16 => {
            let declared = u16::from_be_bytes(packet.get(2..4)?.try_into().ok()?) as usize;
            if declared < 16 || declared > packet.len() {
                return None;
            }
            let mut sets = &packet[16..declared];
            while !sets.is_empty() {
                let set_length = u16::from_be_bytes(sets.get(2..4)?.try_into().ok()?) as usize;
                if set_length < 4 || set_length > sets.len() {
                    return None;
                }
                sets = &sets[set_length..];
            }
            Some(HeaderInfo {
                scope: Scope::IpfixDomain(field(12)?),
                sequence: field(8)?,
                export_seconds: field(4)?,
                uptime_ms: None,
            })
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SequenceDecision {
    Accept,
    Stale,
    Restart,
}

fn sequence_decision(previous: HeaderInfo, current: HeaderInfo) -> SequenceDecision {
    let advance = current.sequence.wrapping_sub(previous.sequence);
    let backwards = advance > u32::MAX / 2;
    let behind = previous.sequence.wrapping_sub(current.sequence);
    let uptime_reset = match (previous.uptime_ms, current.uptime_ms) {
        (Some(before), Some(after)) => {
            let elapsed_ms = current
                .export_seconds
                .saturating_sub(previous.export_seconds)
                .saturating_mul(1000);
            let expected = before.wrapping_add(elapsed_ms);
            let error = expected
                .wrapping_sub(after)
                .min(after.wrapping_sub(expected));
            error > UPTIME_TOLERANCE_MS && backwards && behind > REORDER_WINDOW
        }
        _ => false,
    };
    let near_zero_reset = backwards
        && behind > REORDER_WINDOW
        && previous.sequence >= RESTART_SEQUENCE_FLOOR
        && current.sequence <= RESTART_SEQUENCE_CEILING;
    if uptime_reset || (near_zero_reset && current.export_seconds >= previous.export_seconds) {
        SequenceDecision::Restart
    } else if backwards || current.export_seconds < previous.export_seconds {
        SequenceDecision::Stale
    } else {
        SequenceDecision::Accept
    }
}

struct PeerState {
    keys: HashMap<Scope, ExporterKey>,
    last_seen: Instant,
    scopes: HashMap<Scope, HeaderInfo>,
    pending_restart: HashMap<Scope, RestartCandidate>,
    quiet_until: HashMap<Scope, Instant>,
}

impl PeerState {
    fn new(scope: Scope, key: ExporterKey, now: Instant) -> Self {
        Self {
            keys: HashMap::from([(scope, key)]),
            last_seen: now,
            scopes: HashMap::new(),
            pending_restart: HashMap::new(),
            quiet_until: HashMap::new(),
        }
    }

    fn effective_last_seen(&self) -> Instant {
        self.quiet_until
            .values()
            .copied()
            .max()
            .map_or(self.last_seen, |until| self.last_seen.max(until))
    }
}

struct RestartCandidate {
    header: HeaderInfo,
    observed_at: Instant,
    packets: Vec<Vec<u8>>,
}

fn confirms_restart(
    candidate: &RestartCandidate,
    previous: HeaderInfo,
    current: HeaderInfo,
) -> bool {
    let progress = current.sequence.wrapping_sub(candidate.header.sequence);
    let uptime_coherent = match (candidate.header.uptime_ms, current.uptime_ms) {
        (Some(before), Some(after)) => {
            let elapsed_ms = current
                .export_seconds
                .saturating_sub(candidate.header.export_seconds)
                .saturating_mul(1000);
            let expected = before.wrapping_add(elapsed_ms);
            expected
                .wrapping_sub(after)
                .min(after.wrapping_sub(expected))
                <= UPTIME_TOLERANCE_MS
        }
        _ => true,
    };
    current.export_seconds >= candidate.header.export_seconds
        && progress < u32::MAX / 2
        && (progress > 0 || current.export_seconds > candidate.header.export_seconds)
        && ((current.sequence < previous.sequence
            && previous.sequence.wrapping_sub(current.sequence) > REORDER_WINDOW)
            || (candidate.header.export_seconds > previous.export_seconds
                && current.sequence.wrapping_sub(previous.sequence) > REORDER_WINDOW))
        && uptime_coherent
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    Accept(ExporterKey),
    Restarted(ExporterKey),
    AtCapacity,
    ScopeLimit,
    RestartCandidate,
    Quiet,
    PurgeDeferred,
}

struct PeerTable {
    peers: HashMap<SocketAddr, PeerState>,
    next_key: ExporterKey,
    max_peers: usize,
    idle_timeout: Duration,
    rotations: u64,
    idle_retirements: u64,
    last_purge_at: Option<Instant>,
}

impl PeerTable {
    fn new(max_peers: usize, idle_timeout: Duration) -> Self {
        Self {
            peers: HashMap::new(),
            next_key: 1,
            max_peers,
            idle_timeout,
            rotations: 0,
            idle_retirements: 0,
            last_purge_at: None,
        }
    }

    fn purge_due(&self, now: Instant) -> bool {
        self.last_purge_at
            .is_none_or(|last| now.saturating_duration_since(last) >= MIN_PURGE_SPACING)
    }

    fn allocate_key(&mut self) -> std::io::Result<ExporterKey> {
        let key = self.next_key;
        self.next_key = key.checked_add(1).ok_or_else(|| {
            std::io::Error::other("exporter key space exhausted; keys cannot be reused")
        })?;
        Ok(key)
    }

    fn purge_keys(
        &self,
        ctx: &FlowContext,
        keys: &[ExporterKey],
        printer: fn(&FlowRecord),
    ) -> std::io::Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        ctx.stop_aging();
        for &key in keys {
            ctx.purge_exporter(key, printer);
        }
        ctx.try_start_aging(printer)
    }

    fn retire_idle(
        &mut self,
        now: Instant,
        ctx: &FlowContext,
        printer: fn(&FlowRecord),
    ) -> std::io::Result<()> {
        if !self.purge_due(now) {
            return Ok(());
        }
        let mut retired = Vec::new();
        let mut retired_peers = 0;
        self.peers.retain(|_, state| {
            if now.saturating_duration_since(state.effective_last_seen()) >= self.idle_timeout {
                retired.extend(state.keys.values().copied());
                retired_peers += 1;
                false
            } else {
                true
            }
        });
        self.idle_retirements += retired_peers;
        self.purge_keys(ctx, &retired, printer)?;
        if !retired.is_empty() {
            self.last_purge_at = Some(Instant::now());
        }
        Ok(())
    }

    fn rotate_scope(
        &mut self,
        peer: SocketAddr,
        scope: Scope,
        ctx: &FlowContext,
        printer: fn(&FlowRecord),
    ) -> std::io::Result<Admission> {
        let old_key = self.peers[&peer].keys[&scope];
        self.purge_keys(ctx, &[old_key], printer)?;
        self.last_purge_at = Some(Instant::now());
        self.rotations += 1;
        let key = self.allocate_key()?;
        let now = Instant::now();
        let state = self.peers.get_mut(&peer).expect("rotating a tracked peer");
        state.keys.insert(scope, key);
        state.scopes.remove(&scope);
        state.pending_restart.remove(&scope);
        state.quiet_until.insert(scope, now + RESTART_QUIET_PERIOD);
        state.last_seen = now;
        Ok(Admission::Quiet)
    }

    fn retire_peer(
        &mut self,
        peer: SocketAddr,
        scope: Scope,
        ctx: &FlowContext,
        printer: fn(&FlowRecord),
    ) -> std::io::Result<Admission> {
        let retired = self.peers.remove(&peer).expect("retiring a tracked peer");
        let keys: Vec<_> = retired.keys.values().copied().collect();
        self.purge_keys(ctx, &keys, printer)?;
        self.last_purge_at = Some(Instant::now());
        self.idle_retirements += 1;
        self.rotations += 1;
        let key = self.allocate_key()?;
        self.peers
            .insert(peer, PeerState::new(scope, key, Instant::now()));
        Ok(Admission::Accept(key))
    }

    fn packet_key(
        &mut self,
        peer: SocketAddr,
        header: HeaderInfo,
        now: Instant,
        ctx: &FlowContext,
        printer: fn(&FlowRecord),
    ) -> std::io::Result<Admission> {
        if let Some(state) = self.peers.get_mut(&peer) {
            if let Some(until) = state.quiet_until.get(&header.scope).copied() {
                if now < until {
                    return Ok(Admission::Quiet);
                }
                state.quiet_until.remove(&header.scope);
                state.last_seen = state.last_seen.max(until);
            }
            if let Some(&previous) = state.scopes.get(&header.scope) {
                if state
                    .pending_restart
                    .get(&header.scope)
                    .is_some_and(|candidate| confirms_restart(candidate, previous, header))
                {
                    if !self.purge_due(now) {
                        return Ok(Admission::PurgeDeferred);
                    }
                    return self.rotate_scope(peer, header.scope, ctx, printer);
                }
            }
            if now.saturating_duration_since(state.effective_last_seen()) >= self.idle_timeout {
                if !self.purge_due(now) {
                    return Ok(Admission::PurgeDeferred);
                }
                return self.retire_peer(peer, header.scope, ctx, printer);
            }
            if let Some(&previous) = state.scopes.get(&header.scope) {
                return match sequence_decision(previous, header) {
                    SequenceDecision::Accept => Ok(Admission::Accept(state.keys[&header.scope])),
                    SequenceDecision::Stale => Ok(Admission::Accept(state.keys[&header.scope])),
                    SequenceDecision::Restart => {
                        state.last_seen = now;
                        state
                            .pending_restart
                            .entry(header.scope)
                            .or_insert_with(|| RestartCandidate {
                                header,
                                observed_at: now,
                                packets: Vec::new(),
                            });
                        Ok(Admission::RestartCandidate)
                    }
                };
            }
            if let Some(&key) = state.keys.get(&header.scope) {
                return Ok(Admission::Accept(key));
            }
        }

        if let Some(state) = self.peers.get(&peer) {
            if state.keys.len() >= MAX_SCOPES_PER_PEER {
                return Ok(Admission::ScopeLimit);
            }
            let key = self.allocate_key()?;
            self.peers
                .get_mut(&peer)
                .unwrap()
                .keys
                .insert(header.scope, key);
            return Ok(Admission::Accept(key));
        }

        if self.peers.len() >= self.max_peers {
            self.retire_idle(now, ctx, printer)?;
        }
        if self.peers.len() >= self.max_peers {
            return Ok(Admission::AtCapacity);
        }
        let key = self.allocate_key()?;
        self.peers
            .insert(peer, PeerState::new(header.scope, key, now));
        Ok(Admission::Accept(key))
    }

    fn packet_key_with_packet(
        &mut self,
        peer: SocketAddr,
        header: HeaderInfo,
        packet: &[u8],
        now: Instant,
        ctx: &FlowContext,
        printer: fn(&FlowRecord),
    ) -> std::io::Result<Admission> {
        let old_key = self
            .peers
            .get(&peer)
            .and_then(|state| state.keys.get(&header.scope).copied());
        let replay = self.peers.get(&peer).and_then(|state| {
            state
                .pending_restart
                .get(&header.scope)
                .and_then(|candidate| {
                    confirms_restart(candidate, *state.scopes.get(&header.scope)?, header).then(
                        || {
                            candidate
                                .packets
                                .iter()
                                .map(|packet| {
                                    (candidate.observed_at, candidate.header, packet.clone())
                                })
                                .collect::<Vec<_>>()
                        },
                    )
                })
        });
        let admission = self.packet_key(peer, header, now, ctx, printer)?;
        if admission == Admission::RestartCandidate {
            let state = self.peers.get_mut(&peer).expect("candidate has peer state");
            let mut used: usize = state
                .pending_restart
                .values()
                .flat_map(|candidate| candidate.packets.iter())
                .map(Vec::len)
                .sum();
            while used + packet.len() > MAX_PENDING_RESTART_BYTES_PER_PEER {
                let oldest = state
                    .pending_restart
                    .iter()
                    .filter(|(scope, candidate)| {
                        **scope != header.scope && !candidate.packets.is_empty()
                    })
                    .min_by_key(|(_, candidate)| candidate.observed_at)
                    .map(|(scope, _)| *scope);
                let Some(oldest) = oldest else {
                    if state.pending_restart[&header.scope].packets.is_empty() {
                        state.pending_restart.remove(&header.scope);
                    }
                    return Ok(Admission::PurgeDeferred);
                };
                used -= state
                    .pending_restart
                    .remove(&oldest)
                    .unwrap()
                    .packets
                    .iter()
                    .map(Vec::len)
                    .sum::<usize>();
            }
            state
                .pending_restart
                .get_mut(&header.scope)
                .unwrap()
                .packets
                .push(packet.to_vec());
        }
        if let (Some(old_key), Some(mut replay)) = (old_key, replay) {
            if let Some(state) = self.peers.get_mut(&peer) {
                let key = state.keys[&header.scope];
                if key != old_key && admission == Admission::Quiet {
                    replay.sort_by_key(|(observed_at, _, _)| *observed_at);
                    for (_, candidate_header, candidate_packet) in replay {
                        if ctx.process_packet_from(key, &candidate_packet).is_ok() {
                            state
                                .scopes
                                .insert(candidate_header.scope, candidate_header);
                        }
                    }
                    return Ok(Admission::Restarted(key));
                }
            }
        }
        Ok(admission)
    }

    fn record(&mut self, peer: SocketAddr, header: HeaderInfo, now: Instant) {
        if let Some(state) = self.peers.get_mut(&peer) {
            state.last_seen = now;
            if state.scopes.get(&header.scope).is_none_or(|&previous| {
                sequence_decision(previous, header) == SequenceDecision::Accept
            }) {
                state.scopes.insert(header.scope, header);
                state.pending_restart.remove(&header.scope);
            }
        }
    }
}

/// Command-line options parsed from `std::env::args`.
struct Options {
    address: String,
    port: u16,
    verbose: bool,
    stats_interval: Duration,
    trusted_exporters: HashSet<IpAddr>,
    default_loopback: bool,
    max_peers: usize,
    peer_idle_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            address: DEFAULT_ADDRESS.to_string(),
            port: DEFAULT_PORT,
            verbose: false,
            stats_interval: Duration::from_secs(DEFAULT_STATS_INTERVAL_SECS),
            trusted_exporters: HashSet::from([
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ]),
            default_loopback: true,
            max_peers: DEFAULT_MAX_PEERS,
            peer_idle_timeout: Duration::from_secs(DEFAULT_PEER_IDLE_SECS),
        }
    }
}

impl Options {
    fn allows_exporter(&self, ip: IpAddr) -> bool {
        let ip = normalized_ip(ip);
        (self.default_loopback && ip.is_loopback()) || self.trusted_exporters.contains(&ip)
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
             -e, --allow-exporter <IP> Admit this source IP (repeatable; default: loopback only)\n    \
             -m, --max-peers <COUNT>    Maximum tracked endpoints (default: {DEFAULT_MAX_PEERS})\n    \
             --peer-idle <SECONDS>      Retire inactive endpoints (default: {DEFAULT_PEER_IDLE_SECS})\n    \
             -v, --verbose              Dump all parsed flow info as it is emitted\n    \
             -h, --help                 Print this help message\n"
    );
}

/// Parses CLI arguments. Returns `Ok(None)` when help was requested and the
/// program should exit successfully without running.
fn parse_args() -> Result<Option<Options>, String> {
    parse_args_from(std::env::args())
}

fn parse_args_from(mut args: impl Iterator<Item = String>) -> Result<Option<Options>, String> {
    let program = args.next().unwrap_or_else(|| "udp_listener".to_string());
    let mut opts = Options::default();
    let mut explicit_trust = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help(&program);
                return Ok(None);
            }
            "-v" | "--verbose" => opts.verbose = true,
            "-e" | "--allow-exporter" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{arg} requires a value"))?;
                let ip = value
                    .parse()
                    .map_err(|_| format!("invalid exporter IP: {value}"))?;
                if !explicit_trust {
                    opts.trusted_exporters.clear();
                    opts.default_loopback = false;
                    explicit_trust = true;
                }
                opts.trusted_exporters.insert(normalized_ip(ip));
            }
            "-m" | "--max-peers" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{arg} requires a value"))?;
                opts.max_peers = value
                    .parse()
                    .map_err(|_| format!("invalid peer limit: {value}"))?;
                if opts.max_peers == 0 {
                    return Err("peer limit must be greater than zero".to_string());
                }
            }
            "--peer-idle" => {
                let value = args
                    .next()
                    .ok_or_else(|| format!("{arg} requires a value"))?;
                let seconds: u64 = value
                    .parse()
                    .map_err(|_| format!("invalid peer idle timeout: {value}"))?;
                if seconds == 0 {
                    return Err("peer idle timeout must be greater than zero".to_string());
                }
                opts.peer_idle_timeout = Duration::from_secs(seconds);
            }
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
        "[flow] exporter={} {}:{} -> {}:{} proto={} bytes={} packets={}",
        record.exporter,
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
        "[flow] exporter={} scope={:?} {}:{} -> {}:{} proto={} bytes={} packets={} flow_id={} \
         start_ns={} end_ns={} orig_start_ns={} orig_end_ns={}",
        record.exporter,
        record.scope,
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

struct DropCounters {
    denied: u64,
    malformed: u64,
    capacity: u64,
    scope_limit: u64,
    restart_candidates: u64,
    quiet: u64,
    purge_deferred: u64,
}

fn print_stats(ctx: &FlowContext, peers: &PeerTable, drops: &DropCounters) {
    let s = ctx.stats();
    println!(
        "[stats] parsed={} parse_errors={} clock_dropped={} clock_fallback={} \
         templates={} records={} active={} output={} dropped={} peers={} rotations={} \
         idle_retired={} denied={} malformed_headers={} peer_cap={} scope_cap={} restart_candidates={} quiet={} purge_deferred={}",
        s.pkts_parsed,
        s.pkts_parse_error,
        s.clock_dropped_packets,
        s.clock_fallback_packets,
        s.templates_received,
        s.data_records_processed,
        s.active_flows,
        s.flows_output,
        s.flows_dropped,
        peers.peers.len(),
        peers.rotations,
        peers.idle_retirements,
        drops.denied,
        drops.malformed,
        drops.capacity,
        drops.scope_limit,
        drops.restart_candidates,
        drops.quiet,
        drops.purge_deferred,
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
    ctx.try_start_aging(printer)?;

    // Reusable receive buffer. The parser borrows from it directly (zero-copy);
    // we never allocate per-packet on the heap.
    let mut buf = [0u8; 65_535];
    let mut last_report = Instant::now();

    let mut peers = PeerTable::new(opts.max_peers, opts.peer_idle_timeout);
    let mut drops = DropCounters {
        denied: 0,
        malformed: 0,
        capacity: 0,
        scope_limit: 0,
        restart_candidates: 0,
        quiet: 0,
        purge_deferred: 0,
    };

    while !SHUTDOWN.load(Ordering::SeqCst) {
        match socket.recv_from(&mut buf) {
            Ok((len, peer)) => {
                if !opts.allows_exporter(peer.ip()) {
                    drops.denied += 1;
                } else if let Some(header) = header_info(&buf[..len]) {
                    match peers.packet_key_with_packet(
                        peer,
                        header,
                        &buf[..len],
                        Instant::now(),
                        &ctx,
                        printer,
                    )? {
                        Admission::Accept(key) | Admission::Restarted(key) => {
                            match ctx.process_packet_from(key, &buf[..len]) {
                                Ok(records) => {
                                    peers.record(peer, header, Instant::now());
                                    if opts.verbose {
                                        println!("[packet] {len} bytes from {peer} (key {key}) -> {records} data record(s)");
                                    }
                                }
                                Err(err) if opts.verbose => {
                                    println!("[packet] {len} bytes from {peer} (key {key}) -> error: {err}");
                                }
                                Err(_) => {}
                            }
                        }
                        Admission::AtCapacity => drops.capacity += 1,
                        Admission::ScopeLimit => drops.scope_limit += 1,
                        Admission::RestartCandidate => drops.restart_candidates += 1,
                        Admission::Quiet => drops.quiet += 1,
                        Admission::PurgeDeferred => drops.purge_deferred += 1,
                    }
                } else {
                    drops.malformed += 1;
                }
            }
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
            print_stats(&ctx, &peers, &drops);
            last_report = Instant::now();
        }
    }

    // Ctrl-C: stop aging, then drain and dump every flow still in the cache.
    println!(
        "\nshutting down: flushing residual flows ({} exporter(s) tracked)",
        peers.peers.len()
    );
    ctx.stop_aging();
    ctx.flush(printer);
    print_stats(&ctx, &peers, &drops);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn v9_header(domain: u32, sequence: u32, uptime_ms: u32, export_seconds: u32) -> HeaderInfo {
        HeaderInfo {
            scope: Scope::V9Domain(domain),
            sequence,
            export_seconds,
            uptime_ms: Some(uptime_ms),
        }
    }

    fn template_packet(header: HeaderInfo) -> Vec<u8> {
        let Scope::V9Domain(domain) = header.scope else {
            panic!("expected NetFlow v9 scope");
        };
        let mut packet = Vec::new();
        packet.extend_from_slice(&9u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&header.uptime_ms.unwrap().to_be_bytes());
        packet.extend_from_slice(&header.export_seconds.to_be_bytes());
        packet.extend_from_slice(&header.sequence.to_be_bytes());
        packet.extend_from_slice(&domain.to_be_bytes());
        packet.extend_from_slice(&0u16.to_be_bytes());
        packet.extend_from_slice(&12u16.to_be_bytes());
        packet.extend_from_slice(&256u16.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&8u16.to_be_bytes());
        packet.extend_from_slice(&4u16.to_be_bytes());
        packet
    }

    fn header_only_packet(header: HeaderInfo) -> Vec<u8> {
        let mut packet = template_packet(header);
        packet.truncate(20);
        packet[2..4].copy_from_slice(&0u16.to_be_bytes());
        packet
    }

    fn ipfix_packet(header: HeaderInfo, set: Option<(u16, &[u8])>) -> Vec<u8> {
        let Scope::IpfixDomain(domain) = header.scope else {
            panic!("expected IPFIX scope");
        };
        let length = 16 + set.map_or(0, |(_, body)| 4 + body.len());
        let mut packet = Vec::new();
        packet.extend_from_slice(&10u16.to_be_bytes());
        packet.extend_from_slice(&(length as u16).to_be_bytes());
        packet.extend_from_slice(&header.export_seconds.to_be_bytes());
        packet.extend_from_slice(&header.sequence.to_be_bytes());
        packet.extend_from_slice(&domain.to_be_bytes());
        if let Some((id, body)) = set {
            packet.extend_from_slice(&id.to_be_bytes());
            packet.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
            packet.extend_from_slice(body);
        }
        packet
    }

    #[test]
    fn peer_cap_reclaims_idle_keys_without_reuse() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(2, Duration::from_secs(60));
        let now = Instant::now();
        let header = v9_header(42, 1, 1000, 100);
        let a: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:2055".parse().unwrap();
        let c: SocketAddr = "10.0.0.3:2055".parse().unwrap();
        assert_eq!(
            peers.packet_key(a, header, now, &ctx, print_flow).unwrap(),
            Admission::Accept(1)
        );
        peers.record(a, header, now);
        assert_eq!(
            peers.packet_key(b, header, now, &ctx, print_flow).unwrap(),
            Admission::Accept(2)
        );
        peers.record(b, header, now);
        assert_eq!(
            peers.packet_key(a, header, now, &ctx, print_flow).unwrap(),
            Admission::Accept(1)
        );
        assert_eq!(
            peers.packet_key(c, header, now, &ctx, print_flow).unwrap(),
            Admission::AtCapacity
        );
        assert_eq!(peers.peers.len(), 2);

        assert_eq!(
            peers
                .packet_key(c, header, now + Duration::from_secs(61), &ctx, print_flow)
                .unwrap(),
            Admission::Accept(3)
        );
        assert_eq!(peers.peers.len(), 1);
        assert_eq!(peers.idle_retirements, 2);
        ctx.stop_aging();
    }

    #[test]
    fn retiring_idle_peer_purges_every_scope_key() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(60));
        let now = Instant::now();
        let a: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:2055".parse().unwrap();
        for (domain, key) in [(1, 1), (2, 2)] {
            let header = v9_header(domain, 1, 1000, 100);
            assert_eq!(
                peers.packet_key(a, header, now, &ctx, print_flow).unwrap(),
                Admission::Accept(key)
            );
            ctx.process_packet_from(key, &template_packet(header))
                .unwrap();
            peers.record(a, header, now);
        }
        assert_eq!(ctx.active_templates(), 2);
        let header = v9_header(3, 1, 1000, 100);
        assert_eq!(
            peers
                .packet_key(b, header, now + Duration::from_secs(61), &ctx, print_flow)
                .unwrap(),
            Admission::Accept(3)
        );
        assert_eq!(ctx.active_templates(), 0);
        assert_eq!(peers.idle_retirements, 1);
        ctx.stop_aging();
    }

    #[test]
    fn restart_rotates_key_and_purges_old_template_state() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(2, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let before = v9_header(42, 2000, 1_000_000, 1_700_000_000);
        assert_eq!(
            peers
                .packet_key(peer, before, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        ctx.process_packet_from(1, &template_packet(before))
            .unwrap();
        peers.record(peer, before, now);
        assert_eq!(ctx.active_templates(), 1);

        let after = v9_header(42, 0, 1000, 1_700_000_010);
        let confirmed = v9_header(42, 1, 2000, 1_700_000_011);
        assert_eq!(
            peers
                .packet_key(peer, after, now + Duration::from_secs(10), &ctx, print_flow)
                .unwrap(),
            Admission::RestartCandidate
        );
        assert_eq!(ctx.active_templates(), 1);
        assert_eq!(
            peers
                .packet_key(
                    peer,
                    confirmed,
                    now + Duration::from_secs(11),
                    &ctx,
                    print_flow
                )
                .unwrap(),
            Admission::Quiet
        );
        assert_eq!(ctx.active_templates(), 0);
        assert_eq!(peers.peers[&peer].keys[&before.scope], 2);
        assert_eq!(peers.rotations, 1);
        let quiet_until = peers.peers[&peer].quiet_until[&after.scope];
        assert_eq!(
            peers
                .packet_key(
                    peer,
                    after,
                    quiet_until - Duration::from_millis(1),
                    &ctx,
                    print_flow
                )
                .unwrap(),
            Admission::Quiet
        );
        assert_eq!(
            peers
                .packet_key(peer, confirmed, quiet_until, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(2)
        );
        ctx.stop_aging();
    }

    #[test]
    fn restart_replays_first_template_after_purging_old_key() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let before = v9_header(42, 2000, 1_000_000, 100);
        let first = v9_header(42, 0, 1000, 101);
        let second = v9_header(42, 1, 2000, 102);
        assert_eq!(
            peers
                .packet_key_with_packet(
                    peer,
                    before,
                    &template_packet(before),
                    now,
                    &ctx,
                    print_flow
                )
                .unwrap(),
            Admission::Accept(1)
        );
        ctx.process_packet_from(1, &template_packet(before))
            .unwrap();
        peers.record(peer, before, now);
        assert_eq!(
            peers
                .packet_key_with_packet(
                    peer,
                    first,
                    &template_packet(first),
                    now + Duration::from_secs(1),
                    &ctx,
                    print_flow,
                )
                .unwrap(),
            Admission::RestartCandidate
        );
        assert_eq!(ctx.active_templates(), 1);
        assert_eq!(
            peers
                .packet_key_with_packet(
                    peer,
                    second,
                    &header_only_packet(second),
                    now + Duration::from_secs(2),
                    &ctx,
                    print_flow,
                )
                .unwrap(),
            Admission::Restarted(2)
        );
        assert_eq!(ctx.active_templates(), 1);
        assert!(peers.peers[&peer].quiet_until.contains_key(&before.scope));
        ctx.stop_aging();
    }

    #[test]
    fn ipfix_restart_keeps_template_candidate_when_data_shares_its_sequence() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let before = HeaderInfo {
            scope: Scope::IpfixDomain(42),
            sequence: 2000,
            export_seconds: 100,
            uptime_ms: None,
        };
        let first = HeaderInfo {
            sequence: 0,
            export_seconds: 101,
            ..before
        };
        let second = HeaderInfo {
            sequence: 1,
            ..first
        };
        let template = ipfix_packet(first, Some((2, &[1, 0, 0, 1, 0, 8, 0, 4])));
        let data = ipfix_packet(first, Some((256, &[192, 0, 2, 1])));
        assert_eq!(
            peers
                .packet_key(peer, before, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, before, now);
        assert_eq!(
            peers
                .packet_key_with_packet(peer, first, &template, now, &ctx, print_flow)
                .unwrap(),
            Admission::RestartCandidate
        );
        assert_eq!(
            peers
                .packet_key_with_packet(peer, first, &data, now, &ctx, print_flow)
                .unwrap(),
            Admission::RestartCandidate
        );
        assert_eq!(
            peers.peers[&peer].pending_restart[&first.scope].packets,
            vec![template, data]
        );
        assert_eq!(
            peers
                .packet_key_with_packet(
                    peer,
                    second,
                    &ipfix_packet(second, None),
                    now,
                    &ctx,
                    print_flow,
                )
                .unwrap(),
            Admission::Restarted(2)
        );
        assert_eq!(ctx.active_templates(), 1);
        ctx.stop_aging();
    }

    #[test]
    fn ipfix_restart_replays_multiple_template_messages_with_one_sequence() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let before = HeaderInfo {
            scope: Scope::IpfixDomain(42),
            sequence: 2000,
            export_seconds: 100,
            uptime_ms: None,
        };
        let first = HeaderInfo {
            sequence: 0,
            export_seconds: 101,
            ..before
        };
        let second = HeaderInfo {
            sequence: 1,
            ..first
        };
        assert_eq!(
            peers
                .packet_key(peer, before, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, before, now);
        for id in [256u16, 257u16] {
            let mut body = Vec::new();
            body.extend_from_slice(&id.to_be_bytes());
            body.extend_from_slice(&1u16.to_be_bytes());
            body.extend_from_slice(&8u16.to_be_bytes());
            body.extend_from_slice(&4u16.to_be_bytes());
            assert_eq!(
                peers
                    .packet_key_with_packet(
                        peer,
                        first,
                        &ipfix_packet(first, Some((2, &body))),
                        now,
                        &ctx,
                        print_flow,
                    )
                    .unwrap(),
                Admission::RestartCandidate
            );
        }
        assert_eq!(
            peers
                .packet_key_with_packet(
                    peer,
                    second,
                    &ipfix_packet(second, None),
                    now,
                    &ctx,
                    print_flow,
                )
                .unwrap(),
            Admission::Restarted(2)
        );
        assert_eq!(ctx.active_templates(), 2);
        ctx.stop_aging();
    }

    #[test]
    fn sparse_exporter_confirms_restart_after_long_packet_gap() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let before = v9_header(42, 2000, 1_000_000, 100);
        let first = v9_header(42, 0, 1000, 101);
        let second = v9_header(42, 1, 61_000, 161);
        assert_eq!(
            peers
                .packet_key(peer, before, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, before, now);
        assert_eq!(
            peers
                .packet_key(peer, first, now, &ctx, print_flow)
                .unwrap(),
            Admission::RestartCandidate
        );
        assert_eq!(
            peers
                .packet_key(
                    peer,
                    second,
                    now + Duration::from_secs(60),
                    &ctx,
                    print_flow
                )
                .unwrap(),
            Admission::Quiet
        );
        assert_eq!(peers.peers[&peer].keys[&before.scope], 2);
        ctx.stop_aging();
    }

    #[test]
    fn quiet_window_survives_short_idle_timeout_and_idle_retirement() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let before = v9_header(42, 2000, 1_000_000, 100);
        let first = v9_header(42, 0, 1000, 101);
        let second = v9_header(42, 1, 2000, 102);
        assert_eq!(
            peers
                .packet_key(peer, before, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, before, now);
        assert_eq!(
            peers
                .packet_key(peer, first, now, &ctx, print_flow)
                .unwrap(),
            Admission::RestartCandidate
        );
        assert_eq!(
            peers
                .packet_key(peer, second, now, &ctx, print_flow)
                .unwrap(),
            Admission::Quiet
        );
        let quiet_until = peers.peers[&peer].quiet_until[&second.scope];
        peers
            .retire_idle(quiet_until - Duration::from_millis(1), &ctx, print_flow)
            .unwrap();
        assert_eq!(
            peers
                .packet_key(
                    peer,
                    second,
                    quiet_until - Duration::from_millis(1),
                    &ctx,
                    print_flow,
                )
                .unwrap(),
            Admission::Quiet
        );
        assert_eq!(peers.peers[&peer].keys[&before.scope], 2);
        assert_eq!(
            peers
                .packet_key(peer, second, quiet_until, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(2)
        );
        ctx.stop_aging();
    }

    #[test]
    fn peer_returning_long_after_quiet_window_gets_fresh_key() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let before = v9_header(42, 2000, 1_000_000, 100);
        let first = v9_header(42, 0, 1000, 101);
        let second = v9_header(42, 1, 2000, 102);
        assert_eq!(
            peers
                .packet_key(peer, before, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, before, now);
        assert_eq!(
            peers
                .packet_key(peer, first, now, &ctx, print_flow)
                .unwrap(),
            Admission::RestartCandidate
        );
        assert_eq!(
            peers
                .packet_key(peer, second, now, &ctx, print_flow)
                .unwrap(),
            Admission::Quiet
        );
        let quiet_until = peers.peers[&peer].quiet_until[&second.scope];
        assert_eq!(
            peers
                .packet_key(
                    peer,
                    second,
                    quiet_until + MIN_PURGE_SPACING + Duration::from_secs(1),
                    &ctx,
                    print_flow,
                )
                .unwrap(),
            Admission::Accept(3)
        );
        assert_eq!(peers.idle_retirements, 1);
        ctx.stop_aging();
    }

    #[test]
    fn repeated_idle_purges_are_spaced_for_aging_sweeps() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let header = v9_header(42, 1, 1000, 100);
        assert_eq!(
            peers
                .packet_key(peer, header, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, header, now);
        assert_eq!(
            peers
                .packet_key(peer, header, now + Duration::from_secs(2), &ctx, print_flow)
                .unwrap(),
            Admission::Accept(2)
        );
        peers.record(peer, header, now + Duration::from_secs(2));
        assert_eq!(
            peers
                .packet_key(peer, header, now + Duration::from_secs(4), &ctx, print_flow)
                .unwrap(),
            Admission::PurgeDeferred
        );
        assert_eq!(peers.peers[&peer].keys[&header.scope], 2);
        assert_eq!(
            peers
                .packet_key(peer, header, now + Duration::from_secs(8), &ctx, print_flow)
                .unwrap(),
            Admission::Accept(3)
        );
        ctx.stop_aging();
    }

    #[test]
    fn one_reset_looking_packet_does_not_retire_a_live_peer() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let before = v9_header(42, 2000, 1_000_000, 100);
        assert_eq!(
            peers
                .packet_key(peer, before, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, before, now);

        let delayed = v9_header(42, 0, 1000, 101);
        assert_eq!(
            peers
                .packet_key(
                    peer,
                    delayed,
                    now + Duration::from_secs(1),
                    &ctx,
                    print_flow
                )
                .unwrap(),
            Admission::RestartCandidate
        );
        let next = v9_header(42, 2001, 1_002_000, 102);
        assert_eq!(
            peers
                .packet_key(peer, next, now + Duration::from_secs(2), &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, next, now + Duration::from_secs(2));
        assert!(peers.peers[&peer].pending_restart.is_empty());
        assert_eq!(peers.rotations, 0);
    }

    #[test]
    fn reordered_packet_is_dispatched_without_moving_sequence_high_water() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let newest = v9_header(42, 1000, 20_000, 100);
        let delayed = v9_header(42, 998, 19_000, 100);
        assert_eq!(
            peers
                .packet_key(peer, newest, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, newest, now);
        assert_eq!(
            peers
                .packet_key(peer, delayed, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, delayed, now);
        assert_eq!(peers.peers[&peer].scopes[&newest.scope].sequence, 1000);
    }

    #[test]
    fn interleaved_domains_confirm_a_restart_independently() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        for domain in [1, 2] {
            let header = v9_header(domain, 2000, 1_000_000, 100);
            assert_eq!(
                peers
                    .packet_key(peer, header, now, &ctx, print_flow)
                    .unwrap(),
                Admission::Accept(domain as ExporterKey)
            );
            peers.record(peer, header, now);
        }
        for domain in [1, 2] {
            assert_eq!(
                peers
                    .packet_key(
                        peer,
                        v9_header(domain, 0, 1000, 101),
                        now + Duration::from_secs(1),
                        &ctx,
                        print_flow
                    )
                    .unwrap(),
                Admission::RestartCandidate
            );
        }
        assert_eq!(peers.peers[&peer].pending_restart.len(), 2);
        assert_eq!(
            peers
                .packet_key(
                    peer,
                    v9_header(1, 1, 2000, 101),
                    now + Duration::from_secs(2),
                    &ctx,
                    print_flow
                )
                .unwrap(),
            Admission::Quiet
        );
        assert_eq!(peers.peers[&peer].keys[&Scope::V9Domain(1)], 3);
        assert_eq!(peers.peers[&peer].keys[&Scope::V9Domain(2)], 2);
        assert!(peers.peers[&peer]
            .pending_restart
            .contains_key(&Scope::V9Domain(2)));
        ctx.stop_aging();
    }

    #[test]
    fn rotating_one_domain_preserves_other_domain_and_its_unconfirmed_candidate() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let a = v9_header(1, 2000, 1_000_000, 100);
        let b = v9_header(2, 2000, 1_000_000, 100);
        for (header, key) in [(a, 1), (b, 2)] {
            assert_eq!(
                peers
                    .packet_key(peer, header, now, &ctx, print_flow)
                    .unwrap(),
                Admission::Accept(key)
            );
            ctx.process_packet_from(key, &template_packet(header))
                .unwrap();
            peers.record(peer, header, now);
        }
        assert_eq!(ctx.active_templates(), 2);

        let a_reset = v9_header(1, 0, 1000, 101);
        let b_delayed = v9_header(2, 0, 1000, 101);
        assert_eq!(
            peers
                .packet_key_with_packet(
                    peer,
                    a_reset,
                    &template_packet(a_reset),
                    now,
                    &ctx,
                    print_flow,
                )
                .unwrap(),
            Admission::RestartCandidate
        );
        let mut old_b_template = template_packet(b_delayed);
        old_b_template[24..26].copy_from_slice(&257u16.to_be_bytes());
        assert_eq!(
            peers
                .packet_key_with_packet(peer, b_delayed, &old_b_template, now, &ctx, print_flow,)
                .unwrap(),
            Admission::RestartCandidate
        );
        let a_confirmed = v9_header(1, 1, 2000, 102);
        assert_eq!(
            peers
                .packet_key_with_packet(
                    peer,
                    a_confirmed,
                    &header_only_packet(a_confirmed),
                    now,
                    &ctx,
                    print_flow,
                )
                .unwrap(),
            Admission::Restarted(3)
        );
        assert_eq!(ctx.active_templates(), 2);
        assert_eq!(peers.peers[&peer].keys[&b.scope], 2);
        assert!(peers.peers[&peer].pending_restart.contains_key(&b.scope));
        assert_eq!(
            peers.packet_key(peer, b, now, &ctx, print_flow).unwrap(),
            Admission::Accept(2)
        );
        ctx.stop_aging();
    }

    #[test]
    fn returning_idle_peer_keeps_its_first_packet() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(60));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let header = v9_header(42, 1, 1000, 100);
        assert_eq!(
            peers
                .packet_key(peer, header, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        ctx.process_packet_from(1, &template_packet(header))
            .unwrap();
        peers.record(peer, header, now);
        assert_eq!(ctx.active_templates(), 1);
        assert_eq!(
            peers
                .packet_key(
                    peer,
                    header,
                    now + Duration::from_secs(61),
                    &ctx,
                    print_flow
                )
                .unwrap(),
            Admission::Accept(2)
        );
        assert_eq!(ctx.active_templates(), 0);
        ctx.stop_aging();
    }

    #[test]
    fn sequence_wrap_and_reordering_do_not_rotate() {
        let before = v9_header(42, u32::MAX - 2, u32::MAX - 2000, 100);
        let wrapped = v9_header(42, 3, 3000, 105);
        assert_eq!(sequence_decision(before, wrapped), SequenceDecision::Accept);

        let recent = v9_header(42, 1000, 20_000, 100);
        let delayed = v9_header(42, 998, 19_000, 100);
        assert_eq!(sequence_decision(recent, delayed), SequenceDecision::Stale);
    }

    #[test]
    fn ipfix_sequence_reset_can_start_within_one_export_second() {
        let before = HeaderInfo {
            scope: Scope::IpfixDomain(42),
            sequence: 2000,
            export_seconds: 100,
            uptime_ms: None,
        };
        let mut reset = HeaderInfo {
            sequence: 0,
            export_seconds: 101,
            ..before
        };
        assert_eq!(sequence_decision(before, reset), SequenceDecision::Restart);
        reset.export_seconds = 100;
        assert_eq!(sequence_decision(before, reset), SequenceDecision::Restart);
        reset.sequence = 1999;
        assert_eq!(sequence_decision(before, reset), SequenceDecision::Stale);
    }

    #[test]
    fn ipfix_restart_confirmation_accepts_sequence_progress_within_same_second() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let before = HeaderInfo {
            scope: Scope::IpfixDomain(42),
            sequence: 2000,
            export_seconds: 100,
            uptime_ms: None,
        };
        assert_eq!(
            peers
                .packet_key(peer, before, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, before, now);
        let first = HeaderInfo {
            sequence: 0,
            ..before
        };
        let second = HeaderInfo {
            sequence: 50,
            ..before
        };
        assert_eq!(
            peers
                .packet_key(peer, first, now, &ctx, print_flow)
                .unwrap(),
            Admission::RestartCandidate
        );
        assert_eq!(
            peers
                .packet_key(peer, second, now, &ctx, print_flow)
                .unwrap(),
            Admission::Quiet
        );
        assert_eq!(peers.peers[&peer].keys[&before.scope], 2);
        ctx.stop_aging();
    }

    #[test]
    fn ipfix_restart_confirms_after_new_sequence_passes_old_high_water() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let before = HeaderInfo {
            scope: Scope::IpfixDomain(42),
            sequence: 2000,
            export_seconds: 100,
            uptime_ms: None,
        };
        assert_eq!(
            peers
                .packet_key(peer, before, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, before, now);
        let first = HeaderInfo {
            sequence: 0,
            export_seconds: 101,
            ..before
        };
        let second = HeaderInfo {
            sequence: 2500,
            ..first
        };
        assert_eq!(
            peers
                .packet_key(peer, first, now, &ctx, print_flow)
                .unwrap(),
            Admission::RestartCandidate
        );
        assert_eq!(
            peers
                .packet_key(peer, second, now, &ctx, print_flow)
                .unwrap(),
            Admission::Quiet
        );
        assert_eq!(peers.peers[&peer].keys[&before.scope], 2);
        ctx.stop_aging();
    }

    #[test]
    fn ipfix_old_sequence_progress_does_not_confirm_a_delayed_candidate() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let before = HeaderInfo {
            scope: Scope::IpfixDomain(42),
            sequence: 2000,
            export_seconds: 100,
            uptime_ms: None,
        };
        assert_eq!(
            peers
                .packet_key(peer, before, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, before, now);
        let delayed = HeaderInfo {
            sequence: 0,
            export_seconds: 101,
            ..before
        };
        let next = HeaderInfo {
            sequence: 2001,
            ..delayed
        };
        assert_eq!(
            peers
                .packet_key(peer, delayed, now, &ctx, print_flow)
                .unwrap(),
            Admission::RestartCandidate
        );
        assert_eq!(
            peers.packet_key(peer, next, now, &ctx, print_flow).unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, next, now);
        assert!(peers.peers[&peer].pending_restart.is_empty());
        assert_eq!(peers.rotations, 0);
    }

    #[test]
    fn delayed_old_ipfix_packet_near_high_water_does_not_confirm_restart() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let before = HeaderInfo {
            scope: Scope::IpfixDomain(42),
            sequence: 2000,
            export_seconds: 100,
            uptime_ms: None,
        };
        let candidate = HeaderInfo {
            sequence: 0,
            ..before
        };
        let delayed = HeaderInfo {
            sequence: 1999,
            ..before
        };
        assert_eq!(
            peers
                .packet_key(peer, before, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, before, now);
        assert_eq!(
            peers
                .packet_key(peer, candidate, now, &ctx, print_flow)
                .unwrap(),
            Admission::RestartCandidate
        );
        assert_eq!(
            peers
                .packet_key(peer, delayed, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        assert_eq!(peers.rotations, 0);
    }

    #[test]
    fn ipfix_same_second_reordering_with_large_record_jump_does_not_rotate() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let before = HeaderInfo {
            scope: Scope::IpfixDomain(42),
            sequence: 1024,
            export_seconds: 100,
            uptime_ms: None,
        };
        let delayed = HeaderInfo {
            sequence: 32,
            ..before
        };
        let next = HeaderInfo {
            sequence: 1124,
            ..before
        };
        assert_eq!(
            peers
                .packet_key(peer, before, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, before, now);
        assert_eq!(
            peers
                .packet_key(peer, delayed, now, &ctx, print_flow)
                .unwrap(),
            Admission::RestartCandidate
        );
        assert_eq!(
            peers.packet_key(peer, next, now, &ctx, print_flow).unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, next, now);
        assert_eq!(peers.rotations, 0);
    }

    #[test]
    fn uptime_reset_detects_restart_when_wall_clock_moves_backwards() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let before = v9_header(42, 2000, 1_000_000, 1000);
        let first = v9_header(42, 0, 1000, 900);
        let second = v9_header(42, 1, 2000, 901);
        assert_eq!(sequence_decision(before, first), SequenceDecision::Restart);
        assert_eq!(
            peers
                .packet_key(peer, before, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, before, now);
        assert_eq!(
            peers
                .packet_key(peer, first, now, &ctx, print_flow)
                .unwrap(),
            Admission::RestartCandidate
        );
        assert_eq!(
            peers
                .packet_key(peer, second, now, &ctx, print_flow)
                .unwrap(),
            Admission::Quiet
        );
        assert_eq!(peers.peers[&peer].keys[&before.scope], 2);
        ctx.stop_aging();
    }

    #[test]
    fn domains_keep_independent_sequence_history() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        let first = v9_header(1, 2000, 100_000, 100);
        let second = v9_header(2, 2, 100_000, 100);
        assert_eq!(
            peers
                .packet_key(peer, first, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(1)
        );
        peers.record(peer, first, now);
        assert_eq!(
            peers
                .packet_key(peer, second, now, &ctx, print_flow)
                .unwrap(),
            Admission::Accept(2)
        );
        peers.record(peer, second, now);
        assert_eq!(peers.rotations, 0);
    }

    #[test]
    fn scopes_per_peer_are_bounded() {
        let ctx = FlowContext::new();
        let mut peers = PeerTable::new(1, Duration::from_secs(1800));
        let peer: SocketAddr = "10.0.0.1:2055".parse().unwrap();
        let now = Instant::now();
        for domain in 0..MAX_SCOPES_PER_PEER {
            let header = v9_header(domain as u32, 1, 1000, 100);
            assert_eq!(
                peers
                    .packet_key(peer, header, now, &ctx, print_flow)
                    .unwrap(),
                Admission::Accept(domain as ExporterKey + 1)
            );
            peers.record(peer, header, now);
        }
        assert_eq!(
            peers
                .packet_key(
                    peer,
                    v9_header(MAX_SCOPES_PER_PEER as u32, 1, 1000, 100),
                    now,
                    &ctx,
                    print_flow
                )
                .unwrap(),
            Admission::ScopeLimit
        );
        assert_eq!(peers.peers[&peer].scopes.len(), MAX_SCOPES_PER_PEER);
    }

    #[test]
    fn explicit_allowlist_replaces_loopback_default() {
        let defaults = Options::default();
        assert!(defaults.allows_exporter("127.0.0.2".parse().unwrap()));
        assert!(defaults.allows_exporter("::1".parse().unwrap()));
        assert!(!defaults.allows_exporter("192.0.2.1".parse().unwrap()));
        let opts = parse_args_from(
            [
                "udp_listener",
                "--allow-exporter",
                "192.0.2.1",
                "--allow-exporter",
                "192.0.2.2",
            ]
            .into_iter()
            .map(str::to_string),
        )
        .unwrap()
        .unwrap();
        assert!(!opts
            .trusted_exporters
            .contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(opts
            .trusted_exporters
            .contains(&"192.0.2.1".parse().unwrap()));
        assert!(opts
            .trusted_exporters
            .contains(&"192.0.2.2".parse().unwrap()));
        assert!(opts
            .trusted_exporters
            .contains(&normalized_ip("::ffff:192.0.2.1".parse().unwrap())));
        assert!(!opts.allows_exporter("127.0.0.2".parse().unwrap()));
    }

    #[test]
    fn parses_protocol_header_fields_for_restart_detection() {
        let header = v9_header(42, 2000, 1000, 1_700_000_000);
        let parsed = header_info(&template_packet(header)).unwrap();
        assert_eq!(parsed.scope, header.scope);
        assert_eq!(parsed.sequence, header.sequence);
        assert_eq!(parsed.uptime_ms, header.uptime_ms);
    }

    #[test]
    fn invalid_ipfix_lengths_are_rejected_before_peer_admission() {
        let header = HeaderInfo {
            scope: Scope::IpfixDomain(42),
            sequence: 0,
            export_seconds: 100,
            uptime_ms: None,
        };
        let mut packet = ipfix_packet(header, None);
        packet[2..4].copy_from_slice(&15u16.to_be_bytes());
        assert!(header_info(&packet).is_none());
        packet[2..4].copy_from_slice(&17u16.to_be_bytes());
        assert!(header_info(&packet).is_none());
        let mut malformed_set = ipfix_packet(header, Some((2, &[0, 0, 0, 0])));
        malformed_set[18..20].copy_from_slice(&9u16.to_be_bytes());
        assert!(header_info(&malformed_set).is_none());
    }
}
