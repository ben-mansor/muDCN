//
// μDCN - XDP-based NDN Packet Parser
// 
// This implements the fast path for NDN packets processing using XDP
// to achieve line-rate performance even at 100Gbps.
//

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define NDN_ETHERTYPE 0x8624  // NDN ethertype for direct Ethernet framing
#define NDN_UDP_PORT 6363     // Standard NDN UDP port

// NDN packet types
#define NDN_INTEREST 0x05
#define NDN_DATA     0x06
#define NDN_NACK     0x03

// NDN TLV types
#define NDN_TLV_NAME        0x07
#define NDN_TLV_NAME_COMPONENT 0x08
#define NDN_TLV_INTEREST_LIFETIME 0x0A
#define NDN_TLV_CONTENT    0x15

// Maps for packet statistics and content store
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 4);
} packet_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, 64); // Simplified NDN name hash (real impl would be more complex)
    __uint(value_size, 64); // Content value (limited for simplicity)
    __uint(max_entries, 1024);
} content_store SEC(".maps");

struct ndn_tlv_hdr {
    __u8 type;
    __u8 length;
} __attribute__((packed));

struct ndn_packet {
    struct ndn_tlv_hdr hdr;
    __u8 data[0];
} __attribute__((packed));

// Parses NDN Name from a packet
static __always_inline int parse_ndn_name(struct xdp_md *ctx, struct ndn_packet *pkt, __u8 *name_hash) {
    void *data_end = (void *)(long)ctx->data_end;
    __u32 offset = sizeof(struct ndn_tlv_hdr);
    
    // Simplified name parsing (real implementation would be more complete)
    // Just a skeleton to show the approach
    if ((void *)pkt + offset > data_end)
        return -1;
    
    struct ndn_tlv_hdr *name_tlv = (struct ndn_tlv_hdr *)((void *)pkt + offset);
    
    if ((void *)name_tlv + sizeof(*name_tlv) > data_end)
        return -1;
    
    if (name_tlv->type != NDN_TLV_NAME)
        return -1;
    
    // Simple hash calculation (placeholder)
    // In a real implementation, we would compute a proper hash of the name
    *name_hash = name_tlv->length & 0xFF;
    
    return 0;
}

// Process NDN Interest packet
static __always_inline int process_interest(struct xdp_md *ctx, struct ndn_packet *pkt) {
    __u8 name_hash = 0;
    __u32 key = NDN_INTEREST;
    __u64 *counter;
    
    // Update interest counter
    counter = bpf_map_lookup_elem(&packet_stats, &key);
    if (counter)
        (*counter)++;
    
    // Parse name and check content store
    if (parse_ndn_name(ctx, pkt, &name_hash) < 0)
        return XDP_PASS;  // If parsing fails, let the packet pass
    
    // Look up in content store - simplified approach
    __u64 *content = bpf_map_lookup_elem(&content_store, &name_hash);
    if (content) {
        // Content found in store - in a real implementation we would
        // construct a Data packet and send it back
        // For now, we just drop as if we handled it
        return XDP_DROP;
    }
    
    // No cached content, pass to userspace for processing
    return XDP_PASS;
}

// Process NDN Data packet
static __always_inline int process_data(struct xdp_md *ctx, struct ndn_packet *pkt) {
    __u8 name_hash = 0;
    __u32 key = NDN_DATA;
    __u64 *counter;
    
    // Update data counter
    counter = bpf_map_lookup_elem(&packet_stats, &key);
    if (counter)
        (*counter)++;
    
    // Parse name and store in content store - simplified
    if (parse_ndn_name(ctx, pkt, &name_hash) < 0)
        return XDP_PASS;
    
    // In a real implementation, we would extract the content and store it
    // For now, just a placeholder
    __u64 content = 0xDEADBEEF; // Dummy content
    bpf_map_update_elem(&content_store, &name_hash, &content, BPF_ANY);
    
    return XDP_PASS;
}

SEC("xdp")
int ndn_xdp_parser(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    
    // Ensure we can read the Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    // Check for NDN direct Ethernet framing
    if (bpf_ntohs(eth->h_proto) == NDN_ETHERTYPE) {
        struct ndn_packet *ndn = (struct ndn_packet *)(eth + 1);
        if ((void *)ndn + sizeof(*ndn) > data_end)
            return XDP_PASS;
        
        // Process based on NDN packet type
        if (ndn->hdr.type == NDN_INTEREST)
            return process_interest(ctx, ndn);
        else if (ndn->hdr.type == NDN_DATA)
            return process_data(ctx, ndn);
    }
    
    // Check for NDN over UDP/IP
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)ip + sizeof(*ip) > data_end)
            return XDP_PASS;
        
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)((void *)ip + (ip->ihl * 4));
            if ((void *)udp + sizeof(*udp) > data_end)
                return XDP_PASS;
            
            if (bpf_ntohs(udp->dest) == NDN_UDP_PORT) {
                struct ndn_packet *ndn = (struct ndn_packet *)(udp + 1);
                if ((void *)ndn + sizeof(*ndn) > data_end)
                    return XDP_PASS;
                
                // Process based on NDN packet type
                if (ndn->hdr.type == NDN_INTEREST)
                    return process_interest(ctx, ndn);
                else if (ndn->hdr.type == NDN_DATA)
                    return process_data(ctx, ndn);
            }
        }
    }
    
    // Not NDN or parsing failed, just pass to normal network stack
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
