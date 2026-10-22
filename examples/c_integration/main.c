/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

/*
 * Reference C test-bench for the netflow_analyzer library.
 *
 * Builds a synthetic NetFlow v9 datagram (one template + one data record) and
 * exercises the C API end to end:
 *   - fused decode + aggregation, flushed back through the flow callback;
 *   - capture replay with explicit timestamps and manual aging;
 *   - a decode-only context with a per-record callback;
 *   - null and empty inputs.
 * Every emitted record's fields are checked. Build with the local Makefile.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "netflow-analyzer.h"

#define EXPORT_SECONDS 1700000000ULL
#define NS_PER_SECOND 1000000000ULL
#define EXPORT_TIME_NS (EXPORT_SECONDS * NS_PER_SECOND)

static unsigned failures = 0;

#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, \
                    #cond);                                                \
            failures++;                                                    \
        }                                                                  \
    } while (0)

/* Append a big-endian value of `width` bytes to buf[*off]. */
static void put_be(uint8_t *buf, size_t *off, uint64_t value, size_t width) {
    for (size_t i = 0; i < width; i++) {
        buf[*off + i] = (uint8_t)(value >> (8 * (width - 1 - i)));
    }
    *off += width;
}

/* Collects the records delivered to a callback. */
typedef struct {
    unsigned count;
    uint32_t domain;
    NetflowAnalyzerFlowRecord last;
} Collector;

/* Callback invoked by the library for every emitted flow. */
static void on_flow(const NetflowAnalyzerFlowRecord *rec, void *user_data) {
    Collector *c = (Collector *)user_data;
    c->count++;
    c->last = *rec;

    /* IPv4-mapped addresses keep the four octets in the trailing bytes. */
    printf("[flow] %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u proto=%u bytes=%llu packets=%llu\n",
           rec->src_ip[12], rec->src_ip[13], rec->src_ip[14], rec->src_ip[15], rec->src_port,
           rec->dst_ip[12], rec->dst_ip[13], rec->dst_ip[14], rec->dst_ip[15], rec->dst_port,
           rec->proto,
           (unsigned long long)rec->bytes,
           (unsigned long long)rec->packets);
}

/* Callback invoked once per decoded record on the decode-only path. */
static void on_record(uint32_t observation_domain_id, const NetflowAnalyzerFlowRecord *rec,
                      void *user_data) {
    Collector *c = (Collector *)user_data;
    c->count++;
    c->domain = observation_domain_id;
    c->last = *rec;
}

/* Builds a NetFlow v9 packet: header + template FlowSet + data FlowSet. */
static size_t build_v9_packet(uint8_t *buf) {
    size_t off = 0;

    /* --- v9 header (20 bytes) --- */
    put_be(buf, &off, 9, 2);              /* version */
    put_be(buf, &off, 2, 2);              /* count (records) */
    put_be(buf, &off, 1000, 4);           /* sys uptime ms */
    put_be(buf, &off, EXPORT_SECONDS, 4); /* unix seconds */
    put_be(buf, &off, 1, 4);              /* sequence number */
    put_be(buf, &off, 42, 4);             /* source id (observation domain) */

    /* --- template FlowSet (id 0) --- */
    /* 7 fields: IN_BYTES, IN_PKTS, IPV4_SRC, IPV4_DST, SRC_PORT, DST_PORT, PROTO */
    put_be(buf, &off, 0, 2);          /* flowset id = 0 (template) */
    put_be(buf, &off, 36, 2);         /* flowset length = 4 + 4 + 7*4 */
    put_be(buf, &off, 256, 2);        /* template id */
    put_be(buf, &off, 7, 2);          /* field count */
    put_be(buf, &off, 1, 2);  put_be(buf, &off, 4, 2);  /* IN_BYTES (4) */
    put_be(buf, &off, 2, 2);  put_be(buf, &off, 4, 2);  /* IN_PKTS (4) */
    put_be(buf, &off, 8, 2);  put_be(buf, &off, 4, 2);  /* IPV4_SRC_ADDR (4) */
    put_be(buf, &off, 12, 2); put_be(buf, &off, 4, 2);  /* IPV4_DST_ADDR (4) */
    put_be(buf, &off, 7, 2);  put_be(buf, &off, 2, 2);  /* L4_SRC_PORT (2) */
    put_be(buf, &off, 11, 2); put_be(buf, &off, 2, 2);  /* L4_DST_PORT (2) */
    put_be(buf, &off, 4, 2);  put_be(buf, &off, 1, 2);  /* PROTOCOL (1) */

    /* --- data FlowSet (id 256) --- */
    /* record length = 4+4+4+4+2+2+1 = 21 bytes */
    put_be(buf, &off, 256, 2);        /* flowset id = template id */
    put_be(buf, &off, 25, 2);         /* flowset length = 4 + 21 */
    put_be(buf, &off, 1500, 4);       /* IN_BYTES */
    put_be(buf, &off, 10, 4);         /* IN_PKTS */
    put_be(buf, &off, 0xC0A8010A, 4); /* 192.168.1.10 */
    put_be(buf, &off, 0x0A000005, 4); /* 10.0.0.5 */
    put_be(buf, &off, 12345, 2);      /* src port */
    put_be(buf, &off, 443, 2);        /* dst port */
    put_be(buf, &off, 6, 1);          /* protocol = TCP */

    return off;
}

/* Asserts the fields of the single flow carried by build_v9_packet(). */
static void check_sample_flow(const NetflowAnalyzerFlowRecord *rec) {
    /* IPv4 octets occupy the trailing four bytes; the leading twelve are zero. */
    static const uint8_t src[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 168, 1, 10};
    static const uint8_t dst[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 5};
    const uint32_t tuple = NETFLOW_ANALYZER_PRESENT_SRC_IP | NETFLOW_ANALYZER_PRESENT_DST_IP |
                           NETFLOW_ANALYZER_PRESENT_PROTO | NETFLOW_ANALYZER_PRESENT_SRC_PORT |
                           NETFLOW_ANALYZER_PRESENT_DST_PORT;

    CHECK(memcmp(rec->src_ip, src, sizeof src) == 0);
    CHECK(memcmp(rec->dst_ip, dst, sizeof dst) == 0);
    CHECK(rec->src_port == 12345);
    CHECK(rec->dst_port == 443);
    CHECK(rec->proto == 6);
    CHECK(rec->bytes == 1500);
    CHECK(rec->packets == 10);
    CHECK(rec->scope_protocol == NETFLOW_ANALYZER_SCOPE_V9);
    CHECK(rec->observation_domain == 42);
    CHECK(rec->exporter_key == 0 && rec->exporter_key_hi == 0);
    CHECK((rec->present & tuple) == tuple);
    /* The template exports no flow times, so both fall back to export time. */
    CHECK((rec->present & NETFLOW_ANALYZER_PRESENT_START_TIME) == 0);
    CHECK((rec->present & NETFLOW_ANALYZER_PRESENT_END_TIME) == 0);
    CHECK(rec->start_time_ns == EXPORT_TIME_NS);
    CHECK(rec->end_time_ns == EXPORT_TIME_NS);
}

static void print_stats(const NetflowAnalyzerStats *stats) {
    printf("[stats] parsed=%llu parse_errors=%llu templates=%llu records=%llu output=%llu dropped=%llu active=%llu opt_templates=%llu opt_records=%llu\n",
           (unsigned long long)stats->pkts_parsed,
           (unsigned long long)stats->pkts_parse_error,
           (unsigned long long)stats->templates_received,
           (unsigned long long)stats->data_records_processed,
           (unsigned long long)stats->flows_output,
           (unsigned long long)stats->flows_dropped,
           (unsigned long long)stats->active_flows,
           (unsigned long long)stats->options_templates_received,
           (unsigned long long)stats->options_records_processed);
}

/* Fused decode + aggregation with library defaults, flushed on demand. */
static void fused_path(const uint8_t *packet, uint32_t len) {
    Collector flows = {0};
    NetflowAnalyzerContext *ctx = netflow_analyzer_create(NULL, on_flow, &flows);
    CHECK(ctx != NULL);
    if (ctx == NULL) {
        return;
    }

    int records = netflow_analyzer_process_packet(ctx, packet, len);
    printf("processed packet -> %d data record(s)\n", records);
    CHECK(records == 1);

    /* Flush emits the cached flow synchronously through on_flow. */
    netflow_analyzer_flush(ctx);
    CHECK(flows.count == 1);
    check_sample_flow(&flows.last);

    NetflowAnalyzerStats stats = netflow_analyzer_get_stats(ctx);
    print_stats(&stats);
    CHECK(stats.pkts_parsed == 1 && stats.pkts_parse_error == 0);
    CHECK(stats.templates_received == 1 && stats.data_records_processed == 1);
    CHECK(stats.flows_output == 1 && stats.active_flows == 0);

    netflow_analyzer_destroy(ctx);
}

/* Capture replay: explicit receipt timestamps with manual aging, so the
 * historical timestamps are never compared against the wall clock. */
static void replay_with_manual_aging(const uint8_t *packet, uint32_t len) {
    NetflowAnalyzerConfig config;
    memset(&config, 0, sizeof config);
    config.idle_timeout_secs = 30;
    config.manual_aging = 1;

    Collector flows = {0};
    NetflowAnalyzerContext *ctx = netflow_analyzer_create(&config, on_flow, &flows);
    CHECK(ctx != NULL);
    if (ctx == NULL) {
        return;
    }

    const uint64_t receipt = EXPORT_TIME_NS + 2 * NS_PER_SECOND;
    CHECK(netflow_analyzer_process_packet_at(ctx, packet, len, receipt) == 1);
    CHECK(netflow_analyzer_age_at(ctx, receipt + 29 * NS_PER_SECOND) == 0);
    CHECK(flows.count == 0);
    CHECK(netflow_analyzer_age_at(ctx, receipt + 30 * NS_PER_SECOND) == 1);
    CHECK(flows.count == 1);
    check_sample_flow(&flows.last);
    CHECK(netflow_analyzer_get_stats(ctx).active_flows == 0);

    netflow_analyzer_destroy(ctx);
}

/* A null flow callback creates a decode-only context. */
static void decode_only(const uint8_t *packet, uint32_t len) {
    NetflowAnalyzerContext *ctx = netflow_analyzer_create(NULL, NULL, NULL);
    CHECK(ctx != NULL);
    if (ctx == NULL) {
        return;
    }

    Collector decoded = {0};
    CHECK(netflow_analyzer_decode_packet_at(ctx, packet, len, EXPORT_TIME_NS, on_record,
                                            &decoded) == 1);
    CHECK(decoded.count == 1);
    CHECK(decoded.domain == 42);
    check_sample_flow(&decoded.last);

    /* Fused ingestion needs a flow callback; aging has nothing to emit. */
    CHECK(netflow_analyzer_process_packet(ctx, packet, len) == -1);
    CHECK(netflow_analyzer_age_at(ctx, UINT64_MAX) == 0);
    netflow_analyzer_flush(ctx);

    NetflowAnalyzerStats stats = netflow_analyzer_get_stats(ctx);
    CHECK(stats.data_records_processed == 1);
    CHECK(stats.active_flows == 0 && stats.flows_output == 0);

    netflow_analyzer_destroy(ctx);
}

/* Null and empty arguments are rejected with error codes, never a crash. */
static void null_and_empty_inputs(const uint8_t *packet, uint32_t len) {
    Collector unused = {0};

    CHECK(netflow_analyzer_process_packet(NULL, packet, len) == -1);
    CHECK(netflow_analyzer_process_packet_at(NULL, packet, len, EXPORT_TIME_NS) == -1);
    CHECK(netflow_analyzer_decode_packet(NULL, packet, len, on_record, &unused) == -1);
    CHECK(netflow_analyzer_age_at(NULL, 0) == -1);
    CHECK(netflow_analyzer_purge_exporter(NULL, 0) == -1);
    NetflowAnalyzerStats stats = netflow_analyzer_get_stats(NULL);
    CHECK(stats.pkts_parsed == 0 && stats.active_flows == 0);
    netflow_analyzer_flush(NULL);
    netflow_analyzer_destroy(NULL);

    Collector flows = {0};
    NetflowAnalyzerContext *ctx = netflow_analyzer_create(NULL, on_flow, &flows);
    CHECK(ctx != NULL);
    if (ctx == NULL) {
        return;
    }
    CHECK(netflow_analyzer_process_packet(ctx, NULL, len) == -1);
    CHECK(netflow_analyzer_decode_packet(ctx, NULL, len, on_record, &unused) == -1);
    CHECK(netflow_analyzer_decode_packet(ctx, packet, len, NULL, NULL) == -1);
    /* An empty datagram is malformed, not an argument error. */
    CHECK(netflow_analyzer_process_packet(ctx, packet, 0) == -2);
    CHECK(netflow_analyzer_decode_packet(ctx, packet, 0, on_record, &unused) == -2);
    CHECK(unused.count == 0 && flows.count == 0);
    CHECK(netflow_analyzer_get_stats(ctx).pkts_parse_error == 2);
    netflow_analyzer_destroy(ctx);
}

int main(void) {
    CHECK(netflow_analyzer_abi_version() == NETFLOW_ANALYZER_ABI_VERSION);

    uint8_t packet[256];
    uint32_t len = (uint32_t)build_v9_packet(packet);

    fused_path(packet, len);
    replay_with_manual_aging(packet, len);
    decode_only(packet, len);
    null_and_empty_inputs(packet, len);

    if (failures != 0) {
        fprintf(stderr, "%u check(s) failed\n", failures);
        return 1;
    }
    printf("OK\n");
    return 0;
}
