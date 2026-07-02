//! Shared helpers for the integration test suite.
//!
//! Each protocol has its own test file (`netflow_v5.rs`, `netflow_v9.rs`,
//! `ipfix.rs`) plus cross-cutting engine tests (`engine.rs`). They all pull in
//! this module via `mod common;`. Because every test file is compiled as a
//! separate crate, not all helpers are used by every binary, so dead-code
//! warnings are silenced here rather than per item.
#![allow(dead_code)]

/// Minimal big-endian writer used to assemble synthetic packets.
pub struct Builder {
    pub buf: Vec<u8>,
}

impl Builder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Appends `value` as a big-endian integer of `width` bytes.
    pub fn put(&mut self, value: u64, width: usize) -> &mut Self {
        for i in 0..width {
            self.buf.push((value >> (8 * (width - 1 - i))) as u8);
        }
        self
    }
}

impl Default for Builder {
    fn default() -> Self {
        Self::new()
    }
}

/// A NetFlow v9 packet with a 7-field template (id 256) and one data record.
pub fn sample_v9_packet() -> Vec<u8> {
    let mut b = Builder::new();

    // Header.
    b.put(9, 2) // version
        .put(2, 2) // count
        .put(1000, 4) // sys uptime
        .put(1_700_000_000, 4) // unix seconds
        .put(1, 4) // sequence
        .put(42, 4); // source id

    // Template FlowSet.
    b.put(0, 2) // flowset id (template)
        .put(36, 2) // length
        .put(256, 2) // template id
        .put(7, 2) // field count
        .put(1, 2)
        .put(4, 2) // IN_BYTES
        .put(2, 2)
        .put(4, 2) // IN_PKTS
        .put(8, 2)
        .put(4, 2) // IPV4_SRC
        .put(12, 2)
        .put(4, 2) // IPV4_DST
        .put(7, 2)
        .put(2, 2) // SRC_PORT
        .put(11, 2)
        .put(2, 2) // DST_PORT
        .put(4, 2)
        .put(1, 2); // PROTOCOL

    // Data FlowSet.
    b.put(256, 2) // flowset id = template id
        .put(25, 2) // length = 4 + 21
        .put(1500, 4) // bytes
        .put(10, 4) // packets
        .put(0xC0A8_010A, 4) // 192.168.1.10
        .put(0x0A00_0005, 4) // 10.0.0.5
        .put(12345, 2) // src port
        .put(443, 2) // dst port
        .put(6, 1); // proto = TCP

    b.buf
}

/// An IPFIX packet (version 10) with a Template Set (id 2) and a data set.
pub fn sample_ipfix_packet() -> Vec<u8> {
    let mut b = Builder::new();

    // IPFIX header (16 bytes).
    b.put(10, 2) // version
        .put(0, 2) // total length (ignored by the parser)
        .put(1_700_000_000, 4) // export time
        .put(5, 4) // sequence
        .put(7, 4); // observation domain id

    // Template Set (set id 2): one template (id 300) with 3 fields.
    b.put(2, 2) // set id = IPFIX template
        .put(20, 2) // set length = 4 + 4 + 3*4
        .put(300, 2) // template id
        .put(3, 2) // field count
        .put(8, 2)
        .put(4, 2) // IPV4_SRC
        .put(12, 2)
        .put(4, 2) // IPV4_DST
        .put(4, 2)
        .put(1, 2); // PROTOCOL

    // Data Set (set id 300): one 9-byte record.
    b.put(300, 2) // set id = template id
        .put(13, 2) // set length = 4 + 9
        .put(0xC0A8_0001, 4) // 192.168.0.1
        .put(0x08080808, 4) // 8.8.8.8
        .put(17, 1); // proto = UDP

    b.buf
}

/// (src_ip, dst_ip, packets, octets, src_port, dst_port, proto) for one v5 flow.
pub type V5Flow = ([u8; 4], [u8; 4], u32, u32, u16, u16, u8);

/// A NetFlow v5 datagram: 24-byte header followed by `records.len()` 48-byte
/// fixed records.
pub fn sample_v5_packet(records: &[V5Flow]) -> Vec<u8> {
    let mut b = Builder::new();
    // Header (24 bytes).
    b.put(5, 2) // version
        .put(records.len() as u64, 2) // count
        .put(1000, 4) // sys uptime
        .put(1_700_000_000, 4) // unix seconds
        .put(0, 4) // unix nanos
        .put(1, 4) // flow sequence
        .put(0, 1) // engine type
        .put(0, 1) // engine id
        .put(0, 2); // sampling interval

    for &(src, dst, pkts, octets, sport, dport, proto) in records {
        let mut rec = [0u8; 48];
        rec[0..4].copy_from_slice(&src);
        rec[4..8].copy_from_slice(&dst);
        rec[16..20].copy_from_slice(&pkts.to_be_bytes());
        rec[20..24].copy_from_slice(&octets.to_be_bytes());
        rec[32..34].copy_from_slice(&sport.to_be_bytes());
        rec[34..36].copy_from_slice(&dport.to_be_bytes());
        rec[38] = proto;
        b.buf.extend_from_slice(&rec);
    }

    b.buf
}
