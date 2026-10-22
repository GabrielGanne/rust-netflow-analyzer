# Flow aggregation semantics

This note records which aggregation behaviours the engine performs, and which
common NetFlow/IPFIX aggregation modes it deliberately does **not** perform, for
the first public release. It exists so consumers know exactly what an emitted
`FlowRecord` represents and do not assume higher-level processing that is not
there.

## The aggregation model

The engine keeps one aggregate per **flow key** and folds each decoded data
record into the aggregate that shares its key. The key is
`(exporter_key, Scope, identity)`, where `identity` is the exporter-assigned
`flowId` when present and the classic 5-tuple (src/dst address, src/dst port,
protocol) otherwise. Exporter and `Scope` scoping is described in
[`exporter-identity.md`](exporter-identity.md); flows from different exporters,
protocol versions, or observation domains are never merged.

The flow cache is bounded by `max_flows`. A record whose key is **already
resident** is always folded in, but a record with a **new** key is admitted only
while the cache is below that cap; once it is full, new-key records are dropped
and counted in `flows_dropped` rather than evicting an existing flow.

For each key the engine maintains:

- **Counters:** `bytes` and `packets` are summed across contributing records,
  saturating at `u64::MAX` — this is additive **flow stitching**. Each record is
  first scaled by its sampler's rate before being summed, so counters are
  estimated real traffic (see the sampling note below).
- **Times:** the earliest observed start and the latest observed end, in both
  exporter-derived and effective (clock-corrected) forms.
- **Descriptive metadata:** the optional fields tracked by the `present`
  bitmask — ingress/egress interface, source/destination MAC, ICMP type/code,
  TCP flags, DSCP, VLAN, IP version — plus `flowId`. These are taken from the
  first record that carries each field and filled in from later records that add
  a field not yet seen. The five-tuple fields (addresses, ports, protocol) are
  **not** carried forward this way: they are the flow's identity (or set from the
  first record, for a `flowId`-keyed flow) and are not merged from later records.

Sampling normalization applies to rates learned from **NetFlow v9 / IPFIX
options records** (`samplingInterval`, `samplerRandomInterval`, or the
`samplingPacketInterval` / `samplingPacketSpace` pair) and to the **NetFlow v5**
header `sampling_interval`, which applies to every record in that packet. A
v9 / IPFIX flow is matched to its
sampler by the `flowSamplerId` / `selectorId` it carries, or the domain-wide
sampler when it carries neither. Scaling is applied per record at decode time
and is **never retroactive** — a rate learned or changed later does not rescale
counters already folded into an aggregate. It is best-effort:

- If a domain's untagged rate becomes ambiguous (conflicting advertisements), it
  stops scaling **subsequent** records for that sampler (factor 1) rather than
  mis-scaling them; records already folded keep the rate that was applied then,
  so a rolled-up total can mix scaled and unscaled contributions.
- A rate scoped finer than the observation domain (per interface, line card, …)
  that carries no `flowSamplerId` / `selectorId` cannot be matched to a flow and
  is ignored rather than applied domain-wide.
- `selectionSequenceId` (IE 301) is **not** interpreted, so a flow that tags its
  sampler only that way is treated as the domain sampler: scaled by a domain-wide
  rate if one is configured (which may not be its true rate), and unscaled
  otherwise.

See [`exporter-identity.md`](exporter-identity.md) for the full sampling model
and its documented limits.

### When a record is emitted

An aggregate leaves the cache through these paths. Over the C API every emission
goes to the single callback registered at `netflow_analyzer_create`; a direct
Rust caller instead supplies its own closure to each of `start_aging`, `flush`,
and `purge_exporter`:

- **Idle timeout:** a flow with no new records for `idle_timeout` is evicted and
  emitted once.
- **Active-timeout rollover (periodic intermediate dumps):** a flow that has
  lived for `active_timeout` is emitted as an interim snapshot and its counters
  are reset in place, so a long-lived flow is reported periodically rather than
  only at the end.
- **Flush:** `flush` / `netflow_analyzer_flush` drains and emits the flows it
  finds by snapshotting the cache's keys and removing each in turn. It is not
  synchronized against concurrent ingestion, so under concurrency it is
  best-effort: any key ingested — or re-inserted by a re-entrant callback —
  outside that snapshot can remain cached, and a snapshotted key updated before
  its removal is emitted with that update. A flush is only exhaustive when
  ingestion and callback re-entry are quiesced first, which is what a clean
  shutdown must do.
- **Per-key purge:** `purge_exporter` snapshots and emits one exporter's flows,
  then drops its templates, clock, and sampling state. It is **not** atomic
  against ingestion for that exporter: the caller must fence concurrent and
  callback-re-entrant same-key ingestion, or a flow inserted after the snapshot
  can be left behind with its supporting state removed. See
  [`exporter-identity.md`](exporter-identity.md) for the full contract.

Idle eviction and active rollover run on the **background aging worker**, which
is not automatic for every entry point: the C API's `netflow_analyzer_create`
starts it, but a direct Rust caller of `FlowContext::new` / `with_config` must
call `start_aging` (or `try_start_aging`) itself — otherwise only `flush` and
`purge_exporter` ever emit. `process_packet` alone never triggers timeouts.

Options data records are **not** flows: they are decoded for their exporter
metadata (for example sampling configuration) and counted separately, never
aggregated or emitted as flows.

## Out of scope for the first release

The following modes are **not** performed. Records are still decoded and
aggregated by the model above; the engine simply does not do the extra
correlation, and downstream consumers must apply it themselves if they need it.

- **Flow dedup** (`flow-dedup`). There is no mode that takes the maximum of
  `packets`/`bytes` across records instead of summing them; the engine always
  sums. It also does not detect the *same* flow reported by multiple observation
  points: two observations that happen to share `(exporter_key, Scope, identity)`
  are **summed into one aggregate** (which double-counts a genuine duplicate and
  loses the individual observations), and observations that differ in exporter,
  scope, or identity stay as separate aggregates. There is no interface/
  observation-point component in the key to tell duplicates apart.
- **Bidirectional (biflow) aggregation** (`bidir-aggregation`). Separately
  exported forward and reverse uniflows are kept as two independent flows and
  never combined into a biflow. A single IPFIX **biflow** record that carries
  reverse information elements is not fully decoded: the reverse-direction
  fields are ignored, so that direction is discarded rather than emitted, and
  downstream cannot reconstruct it from this output.
- **Empty-record dropping.** Records with zero `packets`/`bytes`, or otherwise
  "empty" flows, are aggregated and emitted like any other; the engine applies
  no content-based filtering or suppression.

These are documented limitations, not defects. If a future release adds any of
them it will be a deliberate, versioned change.
