// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * CSF 2.0 - Core Shield Firewall
 * csf_xdp.bpf.c - OPTIONAL XDP fast-drop program.
 *
 * Drops packets from source addresses present in the csf deny maps, in the XDP
 * hook (NIC driver, before the network stack). This is a fast path for severe,
 * high-rate attackers only; normal blocking stays in nftables. The maps are
 * populated from userspace by CSF2::XDP (bpftool map update).
 *
 * Build (on the target host, not shipped precompiled):
 *   clang -O2 -g -target bpf -c csf_xdp.bpf.c -o csf_xdp.bpf.o
 * Load/attach: see load-xdp.sh
 *
 * Copyright (C) 2026 CSF - Core Shield Firewall. GNU GPL v3.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* IPv4 deny map: key = __be32 src address, value = u8 present flag. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, __u32);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} deny4 SEC(".maps");

/* IPv6 deny map: key = 16-byte src address, value = u8 present flag. */
struct in6_key { __u8 addr[16]; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000000);
    __type(key, struct in6_key);
    __type(value, __u8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} deny6 SEC(".maps");

SEC("xdp")
int csf_xdp_drop(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto = bpf_ntohs(eth->h_proto);

    if (proto == ETH_P_IP) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        __u32 src = ip->saddr;
        __u8 *hit = bpf_map_lookup_elem(&deny4, &src);
        if (hit)
            return XDP_DROP;
    } else if (proto == ETH_P_IPV6) {
        struct ipv6hdr *ip6 = (void *)(eth + 1);
        if ((void *)(ip6 + 1) > data_end)
            return XDP_PASS;
        struct in6_key k;
        __builtin_memcpy(k.addr, &ip6->saddr, 16);
        __u8 *hit = bpf_map_lookup_elem(&deny6, &k);
        if (hit)
            return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
