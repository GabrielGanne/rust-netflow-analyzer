/*
 * Reference C test-bench for the netflow_analyzer library.
 *
 * Builds a synthetic NetFlow v9 datagram (one template + one data record),
 * feeds it through the engine, flushes the cached flow back through our
 * callback, and prints the resulting telemetry. Build with the local Makefile.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "netflow-analyzer.h"

/* Append a big-endian value of `width` bytes to buf[*off]. */
static void put_be(uint8_t *buf, size_t *off, uint64_t value, size_t width) {
    for (size_t i = 0; i < width; i++) {
        buf[*off + i] = (uint8_t)(value >> (8 * (width - 1 - i)));
    }
    *off += width;
}

/* Callback invoked by the library for every emitted flow. */
static void on_flow(const FlowRecordFFI *rec, void *user_data) {
    unsigned *count = (unsigned *)user_data;
    (*count)++;

    /* IPv4-mapped addresses keep the four octets in the trailing bytes. */
    printf("[flow] %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u proto=%u bytes=%llu packets=%llu\n",
           rec->src_ip[12], rec->src_ip[13], rec->src_ip[14], rec->src_ip[15], rec->src_port,
           rec->dst_ip[12], rec->dst_ip[13], rec->dst_ip[14], rec->dst_ip[15], rec->dst_port,
           rec->proto,
           (unsigned long long)rec->bytes,
           (unsigned long long)rec->packets);
}

/* Builds a NetFlow v9 packet: header + template FlowSet + data FlowSet. */
static size_t build_v9_packet(uint8_t *buf) {
    size_t off = 0;

    /* --- v9 header (20 bytes) --- */
    put_be(buf, &off, 9, 2);          /* version */
    put_be(buf, &off, 2, 2);          /* count (records) */
    put_be(buf, &off, 1000, 4);       /* sys uptime ms */
    put_be(buf, &off, 1700000000, 4); /* unix seconds */
    put_be(buf, &off, 1, 4);          /* sequence number */
    put_be(buf, &off, 42, 4);         /* source id (observation domain) */

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

int main(void) {
    unsigned emitted = 0;

    /* NULL config -> library defaults. */
    AnalyzerContext *ctx = netflow_analyzer_create(NULL, on_flow, &emitted);
    if (ctx == NULL) {
        fprintf(stderr, "failed to create analyzer context\n");
        return 1;
    }

    uint8_t packet[256];
    size_t len = build_v9_packet(packet);

    int records = netflow_analyzer_process_packet(ctx, packet, (uint32_t)len);
    printf("processed packet -> %d data record(s)\n", records);

    /* Flush emits the cached flow synchronously through on_flow. */
    netflow_analyzer_flush(ctx);

    LibraryStatsFFI stats = netflow_analyzer_get_stats(ctx);
    printf("[stats] parsed=%llu parse_errors=%llu templates=%llu records=%llu output=%llu dropped=%llu active=%llu\n",
           (unsigned long long)stats.pkts_parsed,
           (unsigned long long)stats.pkts_parse_error,
           (unsigned long long)stats.templates_received,
           (unsigned long long)stats.data_records_processed,
           (unsigned long long)stats.flows_output,
           (unsigned long long)stats.flows_dropped,
           (unsigned long long)stats.active_flows);

    netflow_analyzer_destroy(ctx);

    if (records != 1 || emitted != 1) {
        fprintf(stderr, "unexpected result: records=%d emitted=%u\n", records, emitted);
        return 1;
    }

    printf("OK\n");
    return 0;
}
