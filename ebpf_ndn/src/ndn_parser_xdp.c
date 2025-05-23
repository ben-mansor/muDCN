// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdint.h>

#include "../include/ndn_maps.h"
#include "../include/ndn_parser.h"

char LICENSE[] SEC("license") = "GPL";

// Helper function to parse NDN name from interest packet
static __always_inline int parse_ndn_name(struct ndn_name *name, 
                                         const void *data, 
                                         uint16_t *offset, 
                                         uint16_t name_length) {
    // Initialize name
    __builtin_memset(name->name, 0, MAX_NAME_LEN);
    name->len = 0;
    
    uint16_t remaining = name_length;
    uint16_t name_offset = 0;
    
    // Parse each name component
    while (remaining > 0 && name->len < MAX_NAME_LEN - 1) {
        // First byte is component type (should be 8 for regular components)
        uint8_t comp_type = parse_tlv_type(data, offset);
        if (comp_type != TLV_COMPONENT) {
            // Skip unknown component types
            uint16_t comp_len = parse_tlv_length(data, offset);
            *offset += comp_len;
            remaining -= (comp_len + 2); // type + length + value
            continue;
        }
        
        // Get component length
        uint16_t comp_len = parse_tlv_length(data, offset);
        if (comp_len == 0) {
            // Empty component
            remaining -= 2; // type + length
            continue;
        }
        
        // Add / separator between components
        if (name->len > 0) {
            name->name[name->len++] = '/';
        }
        
        // Copy component value to name buffer
        uint16_t copy_len = comp_len;
        if (name->len + comp_len >= MAX_NAME_LEN) {
            // Truncate if too long
            copy_len = MAX_NAME_LEN - name->len - 1;
        }
        
        __builtin_memcpy(&name->name[name->len], (char *)data + *offset, copy_len);
        name->len += copy_len;
        
        // Update offsets
        *offset += comp_len;
        remaining -= (comp_len + 2); // type + length + value
    }
    
    return 0;
}

// Helper function to update statistics
static __always_inline void update_stats(int key, void *map, int stat_type) {
    struct ndn_stats *stats;
    
    stats = bpf_map_lookup_elem(map, &key);
    if (!stats)
        return;
    
    switch (stat_type) {
        case 0: // interest received
            stats->interests_received++;
            break;
        case 1: // interest forwarded
            stats->interests_forwarded++;
            break;
        case 2: // data received
            stats->data_received++;
            break;
        case 3: // data forwarded
            stats->data_forwarded++;
            break;
        case 4: // cache hit
            stats->cache_hits++;
            break;
        case 5: // cache miss
            stats->cache_misses++;
            break;
    }
    
    bpf_map_update_elem(map, &key, stats, BPF_ANY);
}

SEC("xdp")
int ndn_parser_xdp_func(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Basic bounds check for Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
        
    // Only handle IPv4 packets
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;
        
    // Basic bounds check for IP header
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
        
    // Only handle UDP packets
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
        
    // Basic bounds check for UDP header
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
        
    // Check if this is likely an NDN packet (default port is 6363)
    if (udp->dest != __constant_htons(6363))
        return XDP_PASS;
        
    // Get the start of NDN TLV packet
    uint16_t offset = sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
    void *ndn_start = data + offset;
    
    // Ensure packet is big enough for NDN TLV type + length
    if (ndn_start + 2 > data_end)
        return XDP_PASS;
        
    // Parse NDN packet type
    uint16_t pkt_offset = 0;
    uint8_t tlv_type = parse_tlv_type(ndn_start, &pkt_offset);
    
    // Only process Interest packets for now
    if (tlv_type != TLV_INTEREST)
        return XDP_PASS;
        
    // Update interest received stat
    int key = 0;
    update_stats(key, &stats_map, 0);
    
    // Parse interest packet length
    uint16_t interest_len = parse_tlv_length(ndn_start, &pkt_offset);
    
    // Ensure packet is complete
    if (ndn_start + pkt_offset + interest_len > data_end)
        return XDP_PASS;
    
    // Find and parse the Name TLV
    while (pkt_offset < interest_len) {
        uint8_t field_type = parse_tlv_type(ndn_start, &pkt_offset);
        
        if (field_type == TLV_NAME) {
            uint16_t name_len = parse_tlv_length(ndn_start, &pkt_offset);
            
            // Parse the NDN name
            struct ndn_name name_key;
            parse_ndn_name(&name_key, ndn_start, &pkt_offset, name_len);
            
            // Check if name is in cache
            int *cache_entry = bpf_map_lookup_elem(&name_cache, &name_key);
            
            if (cache_entry) {
                // Cache hit - we've seen this interest before
                update_stats(key, &stats_map, 4); // Cache hit
                
                // Drop packet (avoid duplicate interests)
                return XDP_DROP;
            } else {
                // Cache miss - new interest
                update_stats(key, &stats_map, 5); // Cache miss
                
                // Add to cache
                int value = 1; // Just a placeholder value
                bpf_map_update_elem(&name_cache, &name_key, &value, BPF_ANY);
                
                // Check if we should redirect to another interface
                uint32_t ifindex = ctx->ingress_ifindex;
                uint32_t *target_if = bpf_map_lookup_elem(&redirect_map, &ifindex);
                
                if (target_if && *target_if != 0) {
                    // Redirect to target interface
                    update_stats(key, &stats_map, 1); // Interest forwarded
                    return bpf_redirect(*target_if, 0);
                }
            }
            
            // We've processed the name, no need to continue parsing
            break;
        }
        
        // Skip over this TLV field
        uint16_t field_len = parse_tlv_length(ndn_start, &pkt_offset);
        pkt_offset += field_len;
    }
    
    // Pass packet up to the userspace NDN daemon for further processing
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
