/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// NDN TLV types
#define TLV_INTEREST 0x05
#define TLV_DATA 0x06
#define TLV_NACK 0x03
#define TLV_NAME 0x07
#define TLV_COMPONENT 0x08
#define TLV_NONCE 0x0A

// NDN parameters
#define MAX_NAME_LEN 256
#define NDN_DEFAULT_PORT 6363

// Name structure for map keys
struct ndn_name {
    char name[MAX_NAME_LEN];
    uint16_t len;
};

// Statistics tracking structure
struct ndn_stats {
    __u64 interests_received;
    __u64 interests_forwarded;
    __u64 interests_dropped;
    __u64 data_received;
    __u64 data_forwarded;
    __u64 cache_hits;
    __u64 cache_misses;
};

// Map definitions
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ndn_name);
    __type(value, __u64);  // Timestamp
} name_cache SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 32);
    __type(key, __u32);    // Source ifindex
    __type(value, __u32);  // Destination ifindex
} redirect_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);    // Always 0
    __type(value, struct ndn_stats);
} stats_map SEC(".maps");

// Helper function to parse TLV type
static __always_inline __u8 parse_tlv_type(const void *data, __u16 *offset, void *data_end) {
    if ((void *)((__u8 *)data + *offset + 1) > data_end)
        return 0;
    
    __u8 type = *((__u8 *)data + *offset);
    (*offset)++;
    return type;
}

// Helper function to parse TLV length
static __always_inline __u16 parse_tlv_length(const void *data, __u16 *offset, void *data_end) {
    if ((void *)((__u8 *)data + *offset + 1) > data_end)
        return 0;
    
    __u8 first_byte = *((__u8 *)data + *offset);
    (*offset)++;
    
    // Short form (< 253)
    if (first_byte < 253)
        return first_byte;
    
    // Medium length (2 bytes) - ensure we can read 2 more bytes
    if (first_byte == 253) {
        if ((void *)((__u8 *)data + *offset + 2) > data_end)
            return 0;
        
        __u16 length = *((__u16 *)((__u8 *)data + *offset));
        (*offset) += 2;
        return bpf_ntohs(length);
    }
    
    // Long length not supported
    return 0;
}

// Helper function to update stats
static __always_inline void update_stats(__u32 key, __u32 stat_type) {
    struct ndn_stats *stats;
    
    stats = bpf_map_lookup_elem(&stats_map, &key);
    if (!stats)
        return;
    
    switch (stat_type) {
        case 0: // interests received
            stats->interests_received++;
            break;
        case 1: // interests forwarded
            stats->interests_forwarded++;
            break;
        case 2: // interests dropped
            stats->interests_dropped++;
            break;
        case 3: // data received
            stats->data_received++;
            break;
        case 4: // data forwarded
            stats->data_forwarded++;
            break;
        case 5: // cache hit
            stats->cache_hits++;
            break;
        case 6: // cache miss
            stats->cache_misses++;
            break;
    }
}

// Parse NDN name from TLV buffer
static __always_inline int parse_ndn_name(struct ndn_name *name, const void *data, 
                                          __u16 *offset, __u16 name_length, void *data_end) {
    // Initialize name
    __builtin_memset(name->name, 0, MAX_NAME_LEN);
    name->len = 0;
    
    __u16 remaining = name_length;
    __u16 name_end = *offset + name_length;
    
    // Make sure we don't read past data_end
    if ((void *)((__u8 *)data + name_end) > data_end)
        return -1;
    
    // Parse each name component
    while (remaining > 0 && name->len < MAX_NAME_LEN - 1 && *offset < name_end) {
        // First byte is component type (should be 8 for regular components)
        __u8 comp_type = parse_tlv_type(data, offset, data_end);
        if (comp_type != TLV_COMPONENT) {
            // Skip unknown component types
            __u16 comp_len = parse_tlv_length(data, offset, data_end);
            if (comp_len == 0 || (*offset) + comp_len > name_end)
                return -1;
                
            *offset += comp_len;
            remaining -= (comp_len + 2); // type + length + value
            continue;
        }
        
        // Get component length
        __u16 comp_len = parse_tlv_length(data, offset, data_end);
        if (comp_len == 0) {
            // Empty component
            remaining -= 2; // type + length
            continue;
        }
        
        // Make sure we don't read past data_end
        if ((void *)((__u8 *)data + *offset + comp_len) > data_end)
            return -1;
        
        // Add / separator between components
        if (name->len > 0)
            name->name[name->len++] = '/';
        
        // Copy component value to name buffer
        __u16 copy_len = comp_len;
        if (name->len + comp_len >= MAX_NAME_LEN)
            copy_len = MAX_NAME_LEN - name->len - 1;
        
        // Use memcpy with explicit bound checking for verifier
        #pragma unroll
        for (int i = 0; i < MAX_NAME_LEN; i++) {
            if (i >= copy_len)
                break;
            if (*offset + i >= name_end)
                break;
            
            name->name[name->len + i] = *((__u8 *)data + *offset + i);
        }
        name->len += copy_len;
        
        // Update offsets
        *offset += comp_len;
        remaining -= (comp_len + 2); // type + length + value
    }
    
    return 0;
}

SEC("xdp")
int ndn_xdp_func(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct udphdr *udp;
    __u16 offset, pkt_offset;
    __u32 key = 0;
    __u32 ifindex = ctx->ingress_ifindex;
    
    // Verify Ethernet header
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    // Check if it's an IP packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    // Verify IP header
    ip = (void *)eth + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;
    
    // Check if it's a UDP packet
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    // Verify UDP header
    udp = (void *)ip + (ip->ihl * 4);
    if ((void *)udp + sizeof(*udp) > data_end)
        return XDP_PASS;
    
    // Check if it's to/from NDN port
    if (udp->dest != bpf_htons(NDN_DEFAULT_PORT) && udp->source != bpf_htons(NDN_DEFAULT_PORT))
        return XDP_PASS;
    
    // Calculate the UDP data offset
    pkt_offset = (void *)udp - data + sizeof(*udp);
    
    // Ensure we have at least 2 bytes for TLV type and length
    if (pkt_offset + 2 > (data_end - data))
        return XDP_PASS;
    
    // Parse NDN packet type
    offset = 0;
    __u8 tlv_type = parse_tlv_type(data + pkt_offset, &offset, data_end);
    
    // Handle Interest packets
    if (tlv_type == TLV_INTEREST) {
        // Update stats for received interest
        update_stats(key, 0);
        
        // Parse interest length
        __u16 interest_len = parse_tlv_length(data + pkt_offset, &offset, data_end);
        if (interest_len == 0)
            return XDP_PASS;
        
        // Ensure the packet is complete
        if (pkt_offset + offset + interest_len > (data_end - data))
            return XDP_PASS;
        
        // Find and parse Name TLV
        __u16 end_offset = offset + interest_len;
        while (offset < end_offset) {
            __u8 field_type = parse_tlv_type(data + pkt_offset, &offset, data_end);
            
            if (field_type == TLV_NAME) {
                __u16 name_len = parse_tlv_length(data + pkt_offset, &offset, data_end);
                if (name_len == 0)
                    break;
                
                // Parse the NDN name
                struct ndn_name name;
                if (parse_ndn_name(&name, data + pkt_offset, &offset, name_len, data_end) < 0)
                    break;
                
                // If name is empty, continue processing
                if (name.len == 0)
                    break;
                
                // Check if name is already in cache
                __u64 *timestamp = bpf_map_lookup_elem(&name_cache, &name);
                if (timestamp) {
                    // Cache hit - drop duplicate interest
                    update_stats(key, 5);  // Update cache hit stats
                    update_stats(key, 2);  // Update dropped interest stats
                    return XDP_DROP;
                } else {
                    // Cache miss - add to cache
                    update_stats(key, 6);  // Update cache miss stats
                    
                    // Add to cache with current ktime
                    __u64 now = bpf_ktime_get_ns();
                    bpf_map_update_elem(&name_cache, &name, &now, BPF_ANY);
                    
                    // Check if we should redirect to another interface
                    __u32 *target_if = bpf_map_lookup_elem(&redirect_map, &ifindex);
                    
                    if (target_if && *target_if > 0) {
                        // Redirect to target interface
                        update_stats(key, 1); // Update forwarded interest stats
                        return bpf_redirect(*target_if, 0);
                    }
                    
                    // No redirect configured, pass up to userspace
                    update_stats(key, 1); // Update forwarded interest stats
                    return XDP_PASS;
                }
            }
            
            // Skip this TLV field
            __u16 field_len = parse_tlv_length(data + pkt_offset, &offset, data_end);
            if (field_len == 0)
                break;
                
            offset += field_len;
        }
    } 
    // Handle Data packets
    else if (tlv_type == TLV_DATA) {
        // Update stats for received data
        update_stats(key, 3);
        
        // Forward all DATA packets (no caching or filtering of data packets)
        update_stats(key, 4);
    }
    
    // Default: pass to userspace
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
