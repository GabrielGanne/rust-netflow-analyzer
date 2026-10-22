# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Expire templates 30 minutes after their last definition, reclaiming capacity through lookup, admission, and background aging.
- Bound the UDP listener peer table, admit configured exporter IPs, retire idle peers, and rotate keys after detected restarts.
- Keep UDP listener keys per endpoint and protocol scope so one domain's restart preserves the others.
- Presence bits for the 5-tuple and flow timestamps (`NETFLOW_ANALYZER_PRESENT_SRC_IP` … `_END_TIME`), so an absent field is no longer indistinguishable from zero.
- Decode-only C contexts: `netflow_analyzer_create` accepts a null flow callback and then starts no aging thread.
- 128-bit exporter keys (`ExporterKey = u128`) with C entry points taking a 16-byte key (`*_from_addr_at`, `netflow_analyzer_purge_exporter_addr`) and `exporter_key_hi` on emitted records.
- Scale NetFlow v5 counters by the header sampling interval.
- Decode `ipDiffServCodePoint` (IE 195) and `flowStart/EndDeltaMicroseconds` (IE 158/159).
- `make install` with a `netflow-analyzer.pc` pkg-config file, and a `REUSE.toml` declaring copyright and license.

### Fixed
- IE 98 is `postIpDiffServCodePoint` (a 6-bit code point), not `postIpClassOfService` (IE 55, a ToS byte); it was wrongly shifted right by 2.
- Ignore sampling rates scoped finer than the observation domain (per interface, line card, …) that carry no `flowSamplerId`/`selectorId`, instead of applying them domain-wide.

### Changed
- C ABI version bumped to 3 (`NetflowAnalyzerFlowRecord::exporter_key_hi` takes the first reserved slot).
- Documented that `flows_output`, `flows_dropped` and `active_flows` are flow-cache counters, always `0` on the decode-only path.

## [0.1.0] - 2026-09-28

### Added
- Zero-copy NetFlow v5, NetFlow v9 (RFC 3954), and IPFIX (RFC 7011) decoding engine.
- Fused decode + aggregate ingestion pipeline (`process_packet`, `process_packet_from`, `process_packet_at`, `process_packet_from_at`).
- Stateless decode-only pipeline with per-record callbacks (`decode_packet`, `decode_packet_scoped`).
- Internally sharded, concurrent flow state cache with additive flow stitching.
- Background flow aging worker with idle eviction, active timeout rollover, and emission callbacks.
- Exporter identity isolation (`ExporterKey`, `Scope`) preventing template collisions, clock skew contamination, and flow aliasing across independent transport sessions.
- Exporter clock skew tracking and optional fallback rebasing.
- Packet sampling ratio decoding and normalization from NetFlow v9 and IPFIX options records.
- Transport session reset primitive (`purge_exporter`) to drain resident flows and reclaim template, clock, and sampling capacity without leaking state.
- Size-bounded caches with hard caps (`max_flows`, `max_templates`) and conservative pre-allocation limits against hostile input.
- Strongly typed error enum (`PacketError`) with `Display` and `std::error::Error` implementations.
- C ABI bindings (`netflow_analyzer_ffi`) producing static and dynamic libraries with C11/C++11 headers (`include/netflow-analyzer.h`), ABI versioning, and layout validation.
- Reference OS-socket UDP listener example (`core/examples/udp_listener.rs`).
- C integration example with ABI smoke tests (`examples/c_integration`).
- Crate-level and item-level documentation covering all public APIs with runnable doctests.
