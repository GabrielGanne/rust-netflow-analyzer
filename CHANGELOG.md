# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Expire templates 30 minutes after their last definition, reclaiming capacity through lookup, admission, and background aging.
- Bound the UDP listener peer table, admit configured exporter IPs, retire idle peers, and rotate keys after detected restarts.

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
