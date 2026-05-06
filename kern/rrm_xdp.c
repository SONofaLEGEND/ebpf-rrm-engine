#include "rrm_maps.h"

SEC("xdp")
int count_packets(struct xdp_md *ctx) {
    __u32 key = 0;
    __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
    
    if (count) {
        __sync_fetch_and_add(count, 1);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
