# Exporter / session identity model

This note records the identity model the engine uses to keep the state of
unrelated exporters separate. It is a prerequisite for a stable public API and
is implemented incrementally by the follow-up work described at the end.

## Problem

NetFlow v9 and IPFIX scope template ids, `flowId`s, and (implicitly) exporter
clocks to an *observation domain*. An observation domain is only unique *within
a single exporter/transport session*. Two independent exporters routinely use
the same domain id — most commonly `0` — so scoping engine state by observation
domain alone is not sufficient:

- **Templates** with the same id from different exporters overwrite each other,
  so data records are decoded against the wrong layout.
- **Exporter clocks** (export-time vs. receipt-time skew, uptime rebasing) from
  different senders are mixed into one `ClockState`.
- **Flows** — five-tuples and `flowId`s — from different exporters are folded
  into the same cache entry, silently aggregating unrelated traffic.

## Decision

The caller identifies the exporter/transport session with an **explicit,
opaque `u64` key** supplied on every ingest call. The engine keys all
per-exporter state on the pair `(exporter_key, Scope)`, where `Scope` is the
protocol-tagged scope defined below (**not** a bare `observation_domain_id`
`u32`, which is undefined for v5 and collides across v9/IPFIX):

- template cache,
- exporter clock tracker,
- flow cache keys (both the five-tuple and `flowId` variants),
- any options-derived, per-domain state added later — notably the sampling
  interval extracted from options records (the pending sampling-normalization
  work). It scales flow counters, so exporters sharing domain `0` must not share
  a sampling factor; scope and purge it by `(exporter_key, Scope)`
  like everything else. Note that a single domain can export several options
  records with **different scopes** (per interface or per sampler), each with its
  own interval, so the sampling state must additionally be keyed by the decoded
  option scope / sampler identity and each flow associated with the matching
  scope — a single per-domain value would let the last record overwrite the rest
  and apply the wrong multiplier.

A single `FlowContext` can therefore safely serve many exporters at once.

**NetFlow v5 has no observation domain**, so the pair above would collapse to
`(exporter_key, 0)` for every v5 packet. A single v5 device can export from
multiple switching engines over one transport endpoint, distinguished only by the
header's `engine_type`/`engine_id`, and those engines number their flows
independently. The v5 "domain" component of the key must therefore be derived
from the `(engine_type, engine_id)` tuple (not the hard-coded `0`), and that
distinction must be surfaced on emitted records so v5 flows from different engines
are neither merged nor mis-attributed. Callers that cannot supply distinct keys
per engine must at least rely on this engine-derived scope.

More generally, the domain integer alone is not a safe namespace across
protocol versions under one `exporter_key`. A v5 engine value can equal a real
observation domain, and — because NetFlow v9 `source_id`s and IPFIX observation
domain ids are **independent namespaces with independent template and flow-id
spaces** — an equal v9 and IPFIX value would alias each other too, letting one
stream overwrite the other's templates or merge its flows. The scope must
therefore carry a **protocol/version discriminator**, not a bare `u32` — for
example an enum tag

```text
Scope = V9Domain(u32) | IpfixDomain(u32) | V5Engine(u8 /*type*/, u8 /*id*/)
```

The same tagged `Scope` (or explicit protocol + domain/engine fields) must be
used for internal keying **and** surfaced on emitted identity, so no two versions
collide and every emitted record is attributable to the exact protocol and
domain/engine it came from.

### Why an opaque `u64`

- **Transport-agnostic.** The core never assumes UDP, sockets, or `std::net`
  types. A caller reading from UDP, a pcap file, or a kernel ring buffer maps
  its own notion of "session" onto the key. The key must be **allocated**, not
  merely derived: keep a table that assigns a unique, never-reused session id to
  each live session and rotates it when a session ends or restarts (see the
  caller contract below). A raw hash of the peer address and port is **not**
  acceptable — it collides between distinct concurrent peers and, worse, hands a
  restarted exporter the same key as its previous session, re-creating exactly
  the state collisions this design prevents.
- **C-ABI friendly.** A `u64` crosses the FFI boundary without new structs or
  lifetime rules, which matters for the published C header.
- **Cheap to hash and compare** as part of the cache keys.

### Caller contract

- The key must be **stable for the lifetime of a transport session** and
  **distinct between concurrent exporters**. Reusing one key for two different
  exporters re-introduces exactly the collisions described above.
- A key **must not be reused for a new session until the previous session's
  cached state has been purged.** A recycled key would otherwise let a new
  session inherit stale template layouts, clock baselines, or flow counters. The
  explicit per-key purge (`FlowContext::purge_exporter` /
  `netflow_analyzer_purge_exporter`) now provides that teardown: it emits and
  drains the key's flows, then drops its templates and clock state (step 4
  below). Time-based template expiry is still pending, so absent a purge or an
  external restart signal a key should be treated as **allocated for the
  lifetime of the process** (or scoped to a value, such as a monotonically
  increasing session id, that is never reused). A **new** transport
  session — for example an exporter that restarts or reconnects — must be given a
  fresh, never-before-used key, or the previous key's state must be purged first.
  A restarted exporter may reuse template ids and `flowId`s with entirely
  different meanings, so retaining its old key would decode or aggregate new
  records against stale state. Keeping the same key is safe **only** when the
  transport session never actually ended (a continuously connected peer).
  Crucially, once a key has been **emitted as identity** — handed to a
  `decode_packet_from*` sink or stored on emitted flows — an in-engine purge
  cannot retract it from downstream consumers. Purge reclaims *local* cache
  capacity; it does **not** make a key safe to re-emit. An external aggregator
  keyed on `(exporter_key, Scope, flowId/tuple)` would silently merge the old and
  new sessions. Session ids that are emitted as identity must therefore be
  **globally non-reusable** for the life of any downstream consumer, unless the
  emitted identity also carries a **generation** and there is an agreed
  downstream reset contract keyed on it.
- Key `0` is reserved as the **"single implicit exporter"** value used by the
  backward-compatible convenience entry points (see below). Callers that handle
  more than one exporter must supply real keys and must not send unrelated
  exporters under key `0`.

### Emitted-record identity

Scoping the caches by `(exporter_key, observation_domain_id)` keeps two
exporters' identical five-tuples in **separate** cache entries, but the emission
path must also let the consumer tell them apart. Today `FlowRecord` (and its
C-ABI mirror `NetflowAnalyzerFlowRecord`) carries neither the exporter key nor
the observation domain, and `NetflowAnalyzerFlowCallback` receives only the
record plus context-wide `user_data`. Emitting two same-tuple flows from
different exporters would therefore be indistinguishable downstream.

So the implementation must **carry the exporter key and the tagged `Scope` on
the emitted record**: add the exporter key and the protocol-tagged scope (from
the previous section — `V9Domain`/`IpfixDomain`/`V5Engine`, not a bare domain
`u32`) to `FlowRecord`, populate them when a flow is admitted, surface them in
the aging/flush emission and the FFI callback path, and regenerate the C header.
Emitting only `(exporter_key, observation_domain_id)` is insufficient: it cannot
distinguish v5 engines (which have no domain) or equal v9/IPFIX values, so
consumers could not attribute records that the cache deliberately kept separate.
The decode-only path, which already reports a domain `u32` to its sink, must
likewise carry the exporter key and the tagged scope.

Extending the emitted record is a **layout- and ABI-affecting change** for the
C-facing type. Adding fields to the core `FlowRecord` is source-compatible for
external Rust callers — it already has crate-private fields (`first_observed`,
`last_observed`), so downstream code can neither construct it nor match it
exhaustively. The `#[repr(C)]` `NetflowAnalyzerFlowRecord` is the real concern:
it is fully public and constructible, so adding fields both breaks Rust callers
that build or exhaustively destructure it *and* changes its size and offsets for
every compiled C consumer. It must therefore be coordinated with the
ABI-stability work (the size/version field or reserved-space mechanism for the
public C structs) and land **before** the first published ABI. Mark the public
`NetflowAnalyzerFlowRecord` `#[non_exhaustive]` so later additions do not repeat
the Rust-side break. Because the crate is still pre-`0.1` and unreleased,
finalizing the record layout now is the right time to absorb this change once.

### API shape

The **ingest entry points** are added additively, by introducing new symbols
rather than changing the signatures of any existing ones. This keeps the entry
points backward compatible for both Rust source and the published C ABI. (The
emitted-record layout change described above is the separate, ABI-affecting part
of this work and is not covered by this compatibility statement.)

- Add new key-aware entry points that thread the key end to end, e.g.
  `process_packet_from(exporter_key, bytes)`,
  `process_packet_from_at(exporter_key, bytes, receipt_time_ns)`, and the
  matching `decode_packet_from[_at]` decode-only variants.
- The decode-only sink must also become **scope-aware**. The existing sink is
  `FnMut(u32, &FlowFields)`, which can only carry a bare domain and therefore
  cannot convey the exporter key, the protocol tag, or a v5 engine — so the new
  `decode_packet_from*` variants take a scope-aware sink, for example
  `FnMut(exporter_key, &Scope, &FlowFields)` (or a small `RecordIdentity` struct).
  Emitting only the domain `u32` here would defeat the attribution invariant for
  external aggregators handling multiple v5 engines or equal v9/IPFIX values.
- The existing `process_packet` / `decode_packet` methods keep their current
  signatures and become single-exporter convenience wrappers that pass key `0`,
  so current callers and offline/one-source tools keep working unchanged. The
  legacy `decode_packet[_at]` sink (`FnMut(u32, &FlowFields)`) is explicitly a
  **lossy legacy adapter**: it reports the bare domain (and `0` for v5) and
  cannot distinguish tagged scopes; multi-scope consumers must use the
  scope-aware `decode_packet_from*` sink instead.
- The FFI surface follows the same rule: add **new** `*_from[_at]` C functions
  that take the key, and leave the existing `netflow_analyzer_process_packet[_at]`
  / `netflow_analyzer_decode_packet[_at]` functions in place as key-`0`
  wrappers. Do **not** add a parameter to an existing exported function — that
  would break source compilation and the calling convention of already-linked
  binaries. Regenerate the C header afterwards.

### Alternative considered

Requiring **one `FlowContext` per exporter** was rejected as the primary model.
It needs no core API change, but forces one aging thread and one set of cache
caps *per exporter*, which does not scale to many low-volume exporters and
pushes session bookkeeping into every caller. Running one context per exporter
remains possible for callers that want hard isolation, but it is not the model
the API is designed around.

## Bounding hostile input

The exporter key adds a dimension to every cache key, so a hostile source that
forges many distinct keys could grow state. Inside the engine this is bounded by
the existing size caps on the template, clock, and flow caches, and is covered
further by the resource-limit and deployment-hardening work tracked separately.

The **caller's** endpoint-to-session-key table is a separate concern that the
engine caps do not bound. A UDP listener that allocates a fresh key per peer will
grow that table without limit under spoofed source addresses or genuinely
high-cardinality traffic, and — until the per-key purge exists — cannot safely
evict entries. Any caller that allocates keys must therefore give that table its
own **hard cap, an admission policy** (for example a trusted-exporter allow-list
or rate limit), **and an expiry tied to the per-key purge**, so a flood of
distinct or spoofed peers cannot exhaust memory. This ties into the deployment
hardening guidance for the public UDP listener.

## Follow-up implementation

The steps below have ordering constraints: some must land together, and some are
prerequisites for others. Do not expose the keyed public API to callers until a
step's stated prerequisites are also in place.

1. Scope the template cache and clock tracker by `(exporter_key, Scope)`, using
   the protocol-tagged `Scope` (`V9Domain`/`IpfixDomain`/`V5Engine`) rather than
   a bare domain `u32`. This is **not purely internal**: `TemplateCache`,
   `ClockTracker`, and their bare-`u32` methods are reachable through the public
   `FlowContext` fields, so changing their signatures is a breaking Rust API
   change. Either add new scoped methods and keep the existing ones as explicit
   legacy adapters (bare `u32` ⇒ a fixed scope), or privatize those caches and
   treat it as a deliberate breaking change coordinated with the pre-`0.1` API
   review.
2. **Land together — do not split:** scope the flow-cache keys by
   `(exporter_key, Scope)` *and* carry the exporter key and the tagged `Scope`
   on emitted `FlowRecord`s, through the FFI flow callback, and on the
   decode-only sink. This likewise touches public API — `FlowCache`,
   `FlowFields::key_in_domain`, and the `FlowKey` enum fields — so apply the same
   legacy-adapter-or-breaking-change discipline as step 1. If flow scoping
   shipped without emitted identity, two exporters (or two protocol scopes) with
   the same tuple would be stored separately but emitted indistinguishably,
   violating the attribution rule above. Equivalently, keep the keyed public
   entry points unexposed until both halves are done.
3. Thread the key through the FFI surface and regenerate the C header. Gate this
   on step 2 so the moment callers can supply a key, the output already carries
   it.
4. **Prerequisite for step 5:** add transport-session reset/expiry semantics
   (template lifetime/expiry and an explicit per-key purge) so a key can be
   safely retired and its template, clock, flow, and options-derived (sampling)
   state removed. Without it there is no removal path from
   `TemplateCache`/`ClockTracker`, so key rotation would leak bounded slots
   permanently. The purge must **emit and drain that key's cached flows through
   the normal emission path first**, then remove its templates and clock state,
   so traffic accumulated since the last aging sweep is not lost. Note that purge
   only reclaims *local* capacity and makes it safe to reuse a key **internally**;
   it does **not** authorize re-emitting a key that was already emitted as
   identity (see the caller contract) — that still requires a fresh session id or
   an emitted generation with a downstream reset contract.

   *Status: the explicit per-key purge is implemented as
   `FlowContext::purge_exporter` (and the `netflow_analyzer_purge_exporter` FFI
   symbol). It emits and drains the key's flows first, then drops its templates
   and clock state, and reclaims the freed slots in every cache. It does not
   stop the aging worker, so a strict rotation boundary (step 5) must still
   serialize purge with that worker. Time-based template lifetime/expiry — the
   other half of this step — is not yet implemented; options-derived sampling
   state does not exist yet and will be purged here once it does.*
5. Update the reference UDP listener to key state per exporter *session*, keying
   on step 4's purge. A key derived only from the peer address and port is
   **not** sufficient: a UDP exporter that restarts keeps the same address and
   port but begins a new session, so the listener must detect a new exporter
   generation and **purge that key's state (step 4) before allocating a fresh
   key**. Restart detection must not fire on benign events: NetFlow/IPFIX
   sequence numbers wrap and packets arrive out of order, and NetFlow v9
   `sys_uptime` wraps roughly every 49.7 days, so a bare backwards step in those
   counters is not a restart. Restart history must also be kept **per tagged
   `Scope`**, not per endpoint: one endpoint can export several IPFIX observation
   domains whose sequence numbers advance independently, so interleaving (e.g.
   sequence 100 from one domain then 2 from another) is normal and must not read
   as a regression. Use wrap- and reordering-aware, per-scope detection (or an
   explicit external generation signal from the caller) before treating a
   regression as a new session. Rotating keys without the purge from step 4
   would fill `max_templates`/`max_domains` over time and stop later sessions
   from decoding, so step 4 must land first.

   Rotation also needs a **generation barrier**, because UDP delivers no clean
   session boundary: after the endpoint is remapped to the fresh key, late
   datagrams from the old generation can still arrive, and worker calls started
   under the old key may still be in flight. Detection, purge, and rekey must be
   **atomic with respect to packet dispatch for that endpoint**: the endpoint's
   mapping advances to the new key only after in-flight old-key work has
   quiesced, and no packet is processed under a key that is being purged.
   Quiescing packet *dispatch* is not sufficient on its own: the background aging
   worker (`FlowContext::start_aging`) runs on its own thread and keeps mutating
   old-key flows even while the receive loop is idle, so a sweep could emit and
   reset an entry that purge is about to emit again with zeroed counters. Purge
   must therefore also serialize with (or briefly stop) the aging worker for the
   affected key. The single-threaded reference listener still has a concurrency
   window here because its aging thread is independent — it detects, purges, and
   rekeys inline between `recv` calls, but must coordinate with the aging worker;
   a multi-threaded host must additionally quiesce or fence the endpoint's packet
   workers before rotating.

   Even with that barrier, a datagram cannot be attributed to a generation from
   the UDP stream alone, so a **straggler from the retired generation is not
   automatically harmless**: if it carries a template set it can reinstall the
   old layout under the new key, and if it carries data records after the
   successor has installed the same template id it can be decoded against the new
   layout and pollute the successor's flows. Missing templates therefore do *not*
   provide isolation. The rotation design must actively reject or quarantine
   retired-generation packets — for example by dropping datagrams on the endpoint
   for a short quiescence window after a detected restart, or by requiring the
   successor to be keyed only once traffic has clearly settled — and even then
   the boundary is best-effort. In the common case the residual risk stays within
   the same endpoint's successor session, but the model only isolates peers the
   caller can actually distinguish: if the endpoint is reassigned to a different
   physical exporter (NAT/DHCP churn) or an attacker spoofs the retired
   endpoint's address and port, old-generation packets are mapped to the
   successor's fresh key and *can* contaminate what is genuinely a different
   exporter. Endpoint-derived keys therefore provide no security boundary against
   spoofing or address reuse.
   Strict, loss-free session boundaries require **generation evidence bound to
   each datagram** — a transport or session layer that ties every packet to a
   generation (so a delayed old packet is recognized and rejected), or a
   generation tag the caller can derive per datagram. An out-of-band restart
   *notification* on its own is not enough: a datagram delayed past the
   notification still carries no generation identifier, so the caller maps it to
   the successor key and the contamination above remains possible. Absent
   per-datagram evidence, treat every restart-detection scheme described here as
   **best-effort**, and prefer an authenticated, session-bound transport for
   high-assurance deployments.

   *Status: the reference `udp_listener` example now maps each source endpoint
   to a distinct, monotonically increasing, never-reused exporter key and feeds
   packets through `process_packet_from`, so distinct senders no longer share
   engine state. The rest of this step is still pending: the endpoint→key table
   is unbounded (no hard cap or admission policy), and there is no restart
   detection, per-key purge-and-rekey, or aging-worker generation barrier yet.*
