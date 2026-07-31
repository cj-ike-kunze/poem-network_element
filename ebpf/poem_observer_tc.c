#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Apache-2.0";

#define MARKER_VERSION 0xc2115e23
#define REPORT_VERSION 0x2516f3b9

struct flow_key_v4 {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct flow_state {
    __u8 started;
    __u8 have_last_counter;
    __u8 last_counter_bit;
    __u8 pad;
    __u32 packets_since_last_marker;
    __u32 marker_seq;
    __u32 report_seq;
    __u64 agg_upstream_loss;
    __u64 agg_sender_loss;
};

struct observer_stats {
    __u64 udp_seen;
    __u64 marker_seen;
    __u64 report_seen;
    __u64 report_rewritten;
};

struct poem_event {
    __u8 ev_type; /* 1=marker, 2=report */
    __u8 reserved0;
    __u16 reserved1;
    __u32 src_ip;
    __u32 dst_ip;
    __u32 seq;
    __u16 count;
    __u8 loss;
    __u8 upstream;
    __u8 prev_val;
    __u8 new_val;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct flow_key_v4);
    __type(value, struct flow_state);
} flow_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct observer_stats);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 8192);
    __type(value, struct poem_event);
} poem_events SEC(".maps");

static __always_inline void stat_inc(__u64 *field)
{
    if (field) {
        (*field)++;
    }
}

static __always_inline int parse_ipv4_udp(void *data, void *data_end,
                                           struct flow_key_v4 *key,
                                           __u8 **udp_payload,
                                           __u32 *udp_payload_len)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return -1;
    }
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        return -1;
    }

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return -1;
    }
    if (ip->version != 4 || ip->protocol != IPPROTO_UDP) {
        return -1;
    }

    __u32 ihl_bytes = (__u32)ip->ihl * 4;
    if (ihl_bytes < sizeof(*ip)) {
        return -1;
    }
    struct udphdr *udp = (void *)ip + ihl_bytes;
    if ((void *)(udp + 1) > data_end) {
        return -1;
    }

    __u8 *payload = (void *)(udp + 1);
    if ((void *)(payload + 1) > data_end) {
        return -1;
    }

    key->src_ip = ip->saddr;
    key->dst_ip = ip->daddr;
    key->src_port = udp->source;
    key->dst_port = udp->dest;
    *udp_payload = payload;
    *udp_payload_len = (__u32)((unsigned long)data_end - (unsigned long)payload);
    return 0;
}

static __always_inline __u8 compute_upstream_ratio(__u64 upstream_loss, __u64 sender_loss)
{
    __u64 ratio = (upstream_loss * 62 + sender_loss / 2) / sender_loss;
    if (ratio > 62) {
        ratio = 62;
    }
    return (__u8)ratio;
}

static __always_inline __u8 upstream_ratio_or_unset(const struct flow_state *flow)
{
    if (!flow || flow->agg_sender_loss == 0) {
        return 63;
    }
    return compute_upstream_ratio(flow->agg_upstream_loss, flow->agg_sender_loss);
}

static __always_inline void emit_marker_event(__u32 src_ip, __u32 dst_ip,
                                              __u32 seq, __u16 count,
                                              __u8 loss, __u8 upstream)
{
    struct poem_event ev = {};
    ev.ev_type = 1;
    ev.src_ip = src_ip;
    ev.dst_ip = dst_ip;
    ev.seq = seq;
    ev.count = count;
    ev.loss = loss;
    ev.upstream = upstream;
    bpf_map_push_elem(&poem_events, &ev, 0);
}

static __always_inline void emit_report_event(__u32 src_ip, __u32 dst_ip,
                                              __u32 seq, __u8 upstream,
                                              __u8 prev_val, __u8 new_val)
{
    struct poem_event ev = {};
    ev.ev_type = 2;
    ev.src_ip = src_ip;
    ev.dst_ip = dst_ip;
    ev.seq = seq;
    ev.upstream = upstream;
    ev.prev_val = prev_val;
    ev.new_val = new_val;
    bpf_map_push_elem(&poem_events, &ev, 0);
}

SEC("tc")
int poem_observer_tc(struct __sk_buff *skb)
{
    void *data = (void *)(unsigned long)skb->data;
    void *data_end = (void *)(unsigned long)skb->data_end;

    struct flow_key_v4 key = {};
    __u8 *payload = NULL;
    __u32 payload_len = 0;
    if (parse_ipv4_udp(data, data_end, &key, &payload, &payload_len) < 0) {
        return TC_ACT_OK;
    }

    if ((void *)(payload + 5) > data_end) {
        return TC_ACT_OK;
    }

    __u32 idx = 0;
    struct observer_stats *st = bpf_map_lookup_elem(&stats, &idx);
    if (st) {
        stat_inc(&st->udp_seen);
    }

    struct flow_state *flow = bpf_map_lookup_elem(&flow_states, &key);
    if (flow && flow->started) {
        flow->packets_since_last_marker++;
    }

    __u8 first = payload[0];
    if ((first & 0x80) == 0) {
        return TC_ACT_OK;
    }

    __u32 version = ((__u32)payload[1] << 24) |
                    ((__u32)payload[2] << 16) |
                    ((__u32)payload[3] << 8) |
                    (__u32)payload[4];

    if (version == MARKER_VERSION) {
        if (st) {
            stat_inc(&st->marker_seen);
        }

        __u8 counter_bit = (first >> 5) & 0x01;
        __u8 sender_loss = first & 0x1f;

        if (!flow) {
            struct flow_state init = {};
            init.started = 1;
            init.have_last_counter = 1;
            init.last_counter_bit = counter_bit;
            init.packets_since_last_marker = 0;
            init.marker_seq = 1;
            bpf_map_update_elem(&flow_states, &key, &init, BPF_ANY);
            emit_marker_event(key.src_ip, key.dst_ip, init.marker_seq, 0, 0, 63);
            return TC_ACT_OK;
        }

        if (!flow->started) {
            flow->started = 1;
            flow->have_last_counter = 1;
            flow->last_counter_bit = counter_bit;
            flow->packets_since_last_marker = 0;
            flow->marker_seq++;
            emit_marker_event(key.src_ip, key.dst_ip, flow->marker_seq, 0, 0,
                              upstream_ratio_or_unset(flow));
            return TC_ACT_OK;
        }

        __u32 expected = 64;
        if (flow->have_last_counter && counter_bit == flow->last_counter_bit) {
            expected = 128;
        }

        __u32 observed = flow->packets_since_last_marker;
        __u32 upstream_interval_loss = 0;
        if (observed < expected) {
            upstream_interval_loss = expected - observed;
            flow->agg_upstream_loss += (__u64)upstream_interval_loss;
        }
        flow->agg_sender_loss += (__u64)sender_loss;
        flow->marker_seq++;
        emit_marker_event(key.src_ip, key.dst_ip, flow->marker_seq,
                  (__u16)observed, (__u8)upstream_interval_loss,
                  upstream_ratio_or_unset(flow));
        flow->have_last_counter = 1;
        flow->last_counter_bit = counter_bit;
        flow->packets_since_last_marker = 0;
        return TC_ACT_OK;
    }

    if (version != REPORT_VERSION) {
        return TC_ACT_OK;
    }

    if (st) {
        stat_inc(&st->report_seen);
    }

    __u8 before = first & 0x3f;
    __u32 report_seq = 0;
    if (flow) {
        flow->report_seq++;
        report_seq = flow->report_seq;
    }

    if (!flow || flow->agg_sender_loss == 0) {
        emit_report_event(key.src_ip, key.dst_ip, report_seq, 63, before, before);
        return TC_ACT_OK;
    }

    __u8 after = compute_upstream_ratio(flow->agg_upstream_loss, flow->agg_sender_loss);
    emit_report_event(key.src_ip, key.dst_ip, report_seq, after, before, after);
    if (before == after) {
        return TC_ACT_OK;
    }

    __u8 rewritten = (first & 0xc0) | after;
    int ret = bpf_skb_store_bytes(skb,
                                  (int)((unsigned long)payload - (unsigned long)data),
                                  &rewritten,
                                  sizeof(rewritten),
                                  0);
    if (ret == 0 && st) {
        stat_inc(&st->report_rewritten);
    }
    return TC_ACT_OK;
}
