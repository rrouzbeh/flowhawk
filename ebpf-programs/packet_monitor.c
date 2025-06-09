#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_FLOWS 1000000
#define RING_BUFFER_SIZE 1048576

// Packet event structure sent to userspace
struct packet_event {
    __u64 timestamp;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u32 packet_size;
    __u32 flags;
    __u32 pid;
    char  comm[16];
};

// Flow key for tracking connections
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
};

// Flow metrics stored in BPF map
struct flow_metrics {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen;
    __u64 last_seen;
    __u32 flags;
    __u32 tcp_state;
};

// Security event for threat detection
struct security_event {
    __u64 timestamp;
    __u32 event_type;
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u32 severity;
    __u32 pid;
    char  comm[16];
    __u32 metadata[4]; // Additional threat-specific data
};

// Event types for security events
#define EVENT_PORT_SCAN     1
#define EVENT_DDOS_ATTACK   2
#define EVENT_SUSPICIOUS    3
#define EVENT_BOTNET        4

// TCP flags
#define TCP_SYN  0x02
#define TCP_ACK  0x10
#define TCP_RST  0x04
#define TCP_FIN  0x01

// BPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} packet_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} security_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_metrics);
} flow_table SEC(".maps");

// Statistics map
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

// Configuration map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} config SEC(".maps");

// Port scan detection map (src_ip -> connection count)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 100000);
    __type(key, __u32);
    __type(value, __u32);
} port_scan_tracker SEC(".maps");

// DDoS detection map (per-second packet counters)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);
    __type(value, __u64);
} ddos_tracker SEC(".maps");

// Statistics indices
#define STAT_PACKETS_RECEIVED 0
#define STAT_PACKETS_DROPPED  1
#define STAT_BYTES_RECEIVED   2
#define STAT_FLOWS_ACTIVE     3
#define STAT_THREATS_DETECTED 4

// Configuration indices
#define CONFIG_SAMPLING_RATE    0
#define CONFIG_PORT_SCAN_THRESH 1
#define CONFIG_DDOS_PPS_THRESH  2
#define CONFIG_ENABLE_THREATS   3

static __always_inline void update_stats(__u32 index, __u64 value) {
    __u64 *stat = bpf_map_lookup_elem(&stats, &index);
    if (stat) {
        __sync_fetch_and_add(stat, value);
    }
}

static __always_inline __u32 get_config(__u32 index, __u32 default_val) {
    __u32 *config_val = bpf_map_lookup_elem(&config, &index);
    return config_val ? *config_val : default_val;
}

static __always_inline int parse_ip_packet(void *data, void *data_end, 
                                          struct packet_event *event) {
    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end)
        return -1;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;
    
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;
    
    event->src_ip = ip->saddr;
    event->dst_ip = ip->daddr;
    event->protocol = ip->protocol;
    event->packet_size = bpf_ntohs(ip->tot_len);
    
    void *l4_header = (void *)ip + (ip->ihl * 4);
    
    switch (ip->protocol) {
    case IPPROTO_TCP: {
        struct tcphdr *tcp = l4_header;
        if ((void *)(tcp + 1) > data_end)
            return -1;
        
        event->src_port = bpf_ntohs(tcp->source);
        event->dst_port = bpf_ntohs(tcp->dest);
        event->flags = (tcp->syn << 1) | (tcp->ack << 4) | 
                      (tcp->rst << 2) | tcp->fin;
        break;
    }
    case IPPROTO_UDP: {
        struct udphdr *udp = l4_header;
        if ((void *)(udp + 1) > data_end)
            return -1;
        
        event->src_port = bpf_ntohs(udp->source);
        event->dst_port = bpf_ntohs(udp->dest);
        event->flags = 0;
        break;
    }
    case IPPROTO_ICMP:
        event->src_port = 0;
        event->dst_port = 0;
        event->flags = 0;
        break;
    default:
        return -1;
    }
    
    return 0;
}

static __always_inline void update_flow_metrics(struct packet_event *event) {
    struct flow_key key = {
        .src_ip = event->src_ip,
        .dst_ip = event->dst_ip,
        .src_port = event->src_port,
        .dst_port = event->dst_port,
        .protocol = event->protocol,
    };
    
    struct flow_metrics *metrics = bpf_map_lookup_elem(&flow_table, &key);
    if (!metrics) {
        struct flow_metrics new_metrics = {
            .packets = 1,
            .bytes = event->packet_size,
            .first_seen = event->timestamp,
            .last_seen = event->timestamp,
            .flags = event->flags,
        };
        bpf_map_update_elem(&flow_table, &key, &new_metrics, BPF_ANY);
    } else {
        __sync_fetch_and_add(&metrics->packets, 1);
        __sync_fetch_and_add(&metrics->bytes, event->packet_size);
        metrics->last_seen = event->timestamp;
        metrics->flags |= event->flags;
    }
}

static __always_inline void detect_port_scan(struct packet_event *event) {
    // Only check TCP SYN packets for port scanning
    if (event->protocol != IPPROTO_TCP || !(event->flags & TCP_SYN))
        return;
    
    __u32 threshold = get_config(CONFIG_PORT_SCAN_THRESH, 100);
    __u32 *count = bpf_map_lookup_elem(&port_scan_tracker, &event->src_ip);
    
    if (!count) {
        __u32 new_count = 1;
        bpf_map_update_elem(&port_scan_tracker, &event->src_ip, &new_count, BPF_ANY);
    } else {
        __u32 new_count = *count + 1;
        bpf_map_update_elem(&port_scan_tracker, &event->src_ip, &new_count, BPF_ANY);
        
        if (new_count > threshold) {
            // Generate security event
            struct security_event *sec_event = 
                bpf_ringbuf_reserve(&security_events, sizeof(*sec_event), 0);
            if (sec_event) {
                sec_event->timestamp = event->timestamp;
                sec_event->event_type = EVENT_PORT_SCAN;
                sec_event->src_ip = event->src_ip;
                sec_event->dst_ip = event->dst_ip;
                sec_event->src_port = event->src_port;
                sec_event->dst_port = event->dst_port;
                sec_event->protocol = event->protocol;
                sec_event->severity = 2; // Medium severity
                sec_event->pid = event->pid;
                __builtin_memcpy(sec_event->comm, event->comm, 16);
                sec_event->metadata[0] = new_count; // Connection count
                
                bpf_ringbuf_submit(sec_event, 0);
                update_stats(STAT_THREATS_DETECTED, 1);
            }
        }
    }
}

static __always_inline void detect_ddos(struct packet_event *event) {
    __u32 threshold = get_config(CONFIG_DDOS_PPS_THRESH, 100000);
    __u64 current_sec = event->timestamp / 1000000000; // Convert to seconds
    
    __u64 *pps_count = bpf_map_lookup_elem(&ddos_tracker, (__u32*)&current_sec);
    if (!pps_count) {
        __u64 new_count = 1;
        bpf_map_update_elem(&ddos_tracker, (__u32*)&current_sec, &new_count, BPF_ANY);
    } else {
        __u64 new_count = *pps_count + 1;
        bpf_map_update_elem(&ddos_tracker, (__u32*)&current_sec, &new_count, BPF_ANY);
        
        if (new_count > threshold) {
            // Generate DDoS security event
            struct security_event *sec_event = 
                bpf_ringbuf_reserve(&security_events, sizeof(*sec_event), 0);
            if (sec_event) {
                sec_event->timestamp = event->timestamp;
                sec_event->event_type = EVENT_DDOS_ATTACK;
                sec_event->src_ip = event->src_ip;
                sec_event->dst_ip = event->dst_ip;
                sec_event->src_port = event->src_port;
                sec_event->dst_port = event->dst_port;
                sec_event->protocol = event->protocol;
                sec_event->severity = 3; // High severity
                sec_event->pid = event->pid;
                __builtin_memcpy(sec_event->comm, event->comm, 16);
                sec_event->metadata[0] = (__u32)new_count; // PPS count
                
                bpf_ringbuf_submit(sec_event, 0);
                update_stats(STAT_THREATS_DETECTED, 1);
            }
        }
    }
}

SEC("xdp")
int xdp_packet_monitor(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Basic packet length check
    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;
    
    // Sample packets based on configuration
    __u32 sampling_rate = get_config(CONFIG_SAMPLING_RATE, 1000);
    if (bpf_get_prandom_u32() % sampling_rate != 0)
        return XDP_PASS;
    
    // Reserve space in ring buffer
    struct packet_event *event = 
        bpf_ringbuf_reserve(&packet_events, sizeof(*event), 0);
    if (!event)
        return XDP_PASS;
    
    // Initialize event
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Parse packet
    if (parse_ip_packet(data, data_end, event) < 0) {
        bpf_ringbuf_discard(event, 0);
        return XDP_PASS;
    }
    
    // Update statistics
    update_stats(STAT_PACKETS_RECEIVED, 1);
    update_stats(STAT_BYTES_RECEIVED, event->packet_size);
    
    // Update flow metrics
    update_flow_metrics(event);
    
    // Threat detection (if enabled)
    if (get_config(CONFIG_ENABLE_THREATS, 1)) {
        detect_port_scan(event);
        detect_ddos(event);
    }
    
    // Submit event to userspace
    bpf_ringbuf_submit(event, 0);
    
    return XDP_PASS;
}

SEC("tc")
int tc_packet_monitor(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    
    // Basic packet length check
    if (data + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;
    
    // Sample packets based on configuration
    __u32 sampling_rate = get_config(CONFIG_SAMPLING_RATE, 1000);
    if (bpf_get_prandom_u32() % sampling_rate != 0)
        return TC_ACT_OK;
    
    // Reserve space in ring buffer
    struct packet_event *event = 
        bpf_ringbuf_reserve(&packet_events, sizeof(*event), 0);
    if (!event)
        return TC_ACT_OK;
    
    // Initialize event
    event->timestamp = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    
    // Parse packet
    if (parse_ip_packet(data, data_end, event) < 0) {
        bpf_ringbuf_discard(event, 0);
        return TC_ACT_OK;
    }
    
    // Update statistics
    update_stats(STAT_PACKETS_RECEIVED, 1);
    update_stats(STAT_BYTES_RECEIVED, event->packet_size);
    
    // Update flow metrics
    update_flow_metrics(event);
    
    // Submit event to userspace
    bpf_ringbuf_submit(event, 0);
    
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";