// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Exporter / session identity primitives.
//!
//! See `docs/exporter-identity.md` for the full model. In short, engine state
//! is keyed by the pair `(ExporterKey, Scope)` so that unrelated exporters, and
//! the independent domain namespaces of different protocol versions, never
//! collide.

/// Opaque, caller-supplied identifier for one exporter / transport session.
///
/// The engine never interprets this value; callers map their own notion of a
/// session (for example an allocated per-peer id) onto it. A single
/// [`crate::FlowContext`] can serve many exporters by giving each a distinct
/// key. See `docs/exporter-identity.md` for the caller contract (uniqueness and
/// non-reuse rules).
pub type ExporterKey = u64;

/// Reserved key used by the single-exporter convenience entry points
/// (`process_packet` / `decode_packet`). Callers handling more than one exporter
/// must supply their own distinct keys and must not mix unrelated exporters
/// under this value.
pub const SINGLE_EXPORTER: ExporterKey = 0;

/// Protocol-tagged observation scope.
///
/// NetFlow v9 `source_id`s, IPFIX observation domain ids, and NetFlow v5
/// switching engines all number their templates and flows independently, and a
/// bare integer would let them alias one another (v5 has no domain at all, and
/// an equal v9/IPFIX value would collide). Tagging the scope by protocol keeps
/// those namespaces separate within one exporter key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// NetFlow v9 observation domain (`source_id`).
    V9Domain(u32),
    /// IPFIX observation domain id.
    IpfixDomain(u32),
    /// NetFlow v5 switching engine, which has no observation domain.
    V5Engine { engine_type: u8, engine_id: u8 },
}
