#include <asm/byteorder.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/bits.h>
#include <linux/stddef.h>
#include <linux/icmp.h>
#include <sys/socket.h>

#include "bpf_helpers.h"

#define trace_printk(fmt, ...) do { \
	char _fmt[] = fmt; \
	bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__); \
	} while (0)

#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define MY_UDP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))



SEC("sched_cls/ingress_classifier")
int ingress_classifier(struct __sk_buff *skb)
{
	return -1;
}

SEC("sched_act/ingress_action")
int ingress_action(struct __sk_buff *skb)
{
	int ret;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    //  check that the packet has enough data,
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
        return TC_ACT_UNSPEC;

    // re-use the Kernel's struct definitions
    struct ethhdr  *eth  = data;
    struct iphdr   *ip   = (data + sizeof(struct ethhdr));
    struct udphdr *udp = (data + sizeof(struct ethhdr) + sizeof(struct iphdr));

    struct bpf_fib_lookup fib_params;

    // only IP packets are allowed
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    // grab original destination addr
    __u32 src_ip = ip->saddr;
    __u32 dst_ip = ip->daddr;
    __u32 target = TARGET_ADDR;

    // transform __be16
    __u16 udp_dest = (udp->dest >> 8) | (udp->dest << 8);

    // we handle only UDP
    if (ip->protocol != IPPROTO_UDP){
        trace_printk("not udp: %l | %l\n", ip->protocol);
        return TC_ACT_OK;
    }

    trace_printk("target: %lu\n", target);

    // handle only specific udp port
    if (udp_dest != UDP_DEST_PORT){
        return TC_ACT_UNSPEC;
    }

    __builtin_memset(&fib_params, 0, sizeof(fib_params));

    fib_params.family       = AF_INET;
    fib_params.tos          = ip->tos;
    fib_params.l4_protocol  = ip->protocol;
    fib_params.sport        = 0;
    fib_params.dport        = 0;
    fib_params.tot_len      = bpf_ntohs(ip->tot_len);
    fib_params.ipv4_src     = src_ip;
    fib_params.ipv4_dst     = target;
    fib_params.ifindex      = skb->ingress_ifindex;

    ret = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
    switch (ret){
        case BPF_FIB_LKUP_RET_SUCCESS:
            trace_printk("fib lookup successful: addr= %ld, dmac= %lx, smac= %lx\n", target, fib_params.dmac, fib_params.smac);
            break;
        case BPF_FIB_LKUP_RET_BLACKHOLE:
            trace_printk("fib lookup failed: dest is blackholed\n");
            return TC_ACT_OK;
        case BPF_FIB_LKUP_RET_UNREACHABLE:
            trace_printk("fib lookup failed: dest is unreachable\n");
            return TC_ACT_OK;
        case BPF_FIB_LKUP_RET_PROHIBIT:
            trace_printk("fib lookup failed: dest is prohibited\n");
            return TC_ACT_OK;
        case BPF_FIB_LKUP_RET_NOT_FWDED:
            trace_printk("fib lookup failed: packet is not forwarded\n");
            return TC_ACT_OK;
        case BPF_FIB_LKUP_RET_UNSUPP_LWT:
            trace_printk("fib lookup failed: fwd reqires encapsulation\n");
            return TC_ACT_OK;
        case BPF_FIB_LKUP_RET_NO_NEIGH:
            // todo: the re-written packet should go up the stack
            trace_printk("fib lookup failed: no neighbor\n");
            return TC_ACT_OK;
        case BPF_FIB_LKUP_RET_FRAG_NEEDED:
            trace_printk("fib lookup failed: fragmentation needed for dest\n");
            return TC_ACT_OK;
        default:
            trace_printk("fib lookup failed: unspecified return code: %d \n", ret);
            return TC_ACT_OK;
    }

    // set smac/dmac addr
    bpf_skb_store_bytes(skb, 0, &fib_params.dmac, sizeof(fib_params.dmac), 0);
    bpf_skb_store_bytes(skb, ETH_ALEN, &fib_params.smac, sizeof(fib_params.smac), 0);

    // recalc checksum
    bpf_l4_csum_replace(skb, MY_UDP_CSUM_OFF, dst_ip, target, sizeof(target));
    bpf_l4_csum_replace(skb, MY_UDP_CSUM_OFF, src_ip, dst_ip, sizeof(dst_ip));
	bpf_l3_csum_replace(skb, IP_CSUM_OFF, dst_ip, target, sizeof(target));
	bpf_l3_csum_replace(skb, IP_CSUM_OFF, src_ip, dst_ip, sizeof(dst_ip));

    // set src/dst addr
    bpf_skb_store_bytes(skb, IP_SRC_OFF, &dst_ip, sizeof(dst_ip), 0);
    bpf_skb_store_bytes(skb, IP_DST_OFF, &target, sizeof(target), 0);

    // clone packet, put it on interface found in fib
    ret = bpf_clone_redirect(skb, fib_params.ifindex, 0);
    if (ret == 0) {
        trace_printk("clone redirect succeeded\n");
    } else {
        trace_printk("clone redirect failed: %d \n", ret);
    }

    return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
