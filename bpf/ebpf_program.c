#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

struct bpf_map_def SEC("maps") port_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u16),
    .max_entries = 1,
};

SEC("xdp")
int xdp_drop_tcp(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u32 key = 0;
    __u16 *port;

    if (data + sizeof(*eth) > data_end) {
        bpf_printk("Packet too small\n");
        return XDP_PASS;
    }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        bpf_printk("Not an IP packet\n");
        return XDP_PASS;
    }

    ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) {
        bpf_printk("IP header too small\n");
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_TCP) {
        bpf_printk("Not a TCP packet\n");
        return XDP_PASS;
    }

    tcp = (void *)ip + ip->ihl * 4;
    if ((void *)tcp + sizeof(*tcp) > data_end) {
        bpf_printk("TCP header too small\n");
        return XDP_PASS;
    }

    port = bpf_map_lookup_elem(&port_map, &key);
    if (port && tcp->dest == __constant_htons(*port)) {
        bpf_printk("Dropping packet to port %d\n", *port);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
