// 
// μDCN - Enhanced XDP NDN Processor Functions
// Part 2: Packet processing logic
//

// Process Interest packet with enhanced caching and zero-copy
static __always_inline int process_interest_v2(struct xdp_md *ctx, void *data, 
                                           __u32 pkt_offset, struct xdp_config_v2 *cfg) {
    void *data_end = (void *)(long)ctx->data_end;
    __u64 name_hash;
    __u32 name_size;
    __u64 start_time = get_timestamp_ns();
    __u8 action = DECISION_PASS;  // Default action
    
    // Get Interest Name and compute hash
    if (fast_hash_ndn_name(ctx, data, pkt_offset, &name_hash, &name_size) < 0) {
        update_metric(METRIC_ERRORS);
        return XDP_PASS;  // Let userspace handle malformed packets
    }
    
    update_metric(METRIC_INTERESTS_RECV);
    
    // Check if we have this content in our store
    if (cfg->cs_enabled) {
        struct cs_entry_v2 *entry = bpf_map_lookup_elem(&content_store_v2, &name_hash);
        
        if (entry && !content_expired(entry)) {
            // We have valid content in our store
            update_metric(METRIC_CACHE_HITS);
            
            // Create Data packet from the cache, but only if it's small enough
            if (entry->content_size <= cfg->cs_max_size) {
                // For now, we'll let userspace send the Data
                // In a more advanced implementation, we could craft and TX the response directly
                
                action = DECISION_SERVE;
                send_event(EVENT_CACHE_HIT, name_hash, entry->content_size, action, start_time);
                return XDP_PASS;  // Signal userspace to serve from cache
            }
        } else {
            update_metric(METRIC_CACHE_MISSES);
        }
    }
    
    // Check for duplicate Interests using nonce if available
    if (cfg->pit_enabled) {
        // Parse Interest to find nonce
        // This is a simplified version - we'd need more complex TLV parsing
        // to extract the nonce reliably, which is beyond the BPF verifier limits
        
        // For simplicity in this prototype, we'll use name_hash + a random value as substitute
        // In a real implementation, we'd extract the actual nonce
        __u32 pseudo_nonce = (__u32)(name_hash & 0xFFFFFFFF);
        
        // Check if we've seen this nonce recently
        __u64 *last_seen = bpf_map_lookup_elem(&nonce_cache, &pseudo_nonce);
        if (last_seen) {
            __u64 current_time = get_timestamp_ns();
            // If we've seen this nonce in the last second, it's likely a duplicate
            if (current_time - *last_seen < 1000000000ULL) {
                update_metric(METRIC_DROPS);
                action = DECISION_DROP;
                send_event(EVENT_DUPLICATE_INTEREST, name_hash, ctx->data_end - ctx->data, 
                          action, start_time);
                return XDP_DROP;
            }
        }
        
        // Update nonce cache
        __u64 current_time = get_timestamp_ns();
        bpf_map_update_elem(&nonce_cache, &pseudo_nonce, &current_time, BPF_ANY);
        
        // Create or update PIT entry
        struct pit_entry_v2 pit_entry = {
            .name_hash = name_hash,
            .arrival_time = current_time,
            .lifetime_ms = 4000, // Default 4 seconds lifetime
            .ingress_ifindex = ctx->ingress_ifindex,
            .nonce = pseudo_nonce,
            .hop_count = 0
        };
        
        bpf_map_update_elem(&pit_v2, &name_hash, &pit_entry, BPF_ANY);
    }
    
    // Determine if we should handle in userspace or make a direct forwarding decision
    // This implements a probabilistic fallback to userspace to avoid overwhelming it
    if (bpf_get_prandom_u32() % 100 < cfg->userspace_fallback_threshold) {
        // Let userspace handle some percentage of the traffic
        action = DECISION_PASS;
        send_event(EVENT_USERSPACE_FALLBACK, name_hash, ctx->data_end - ctx->data, 
                  action, start_time);
        return XDP_PASS;
    }
    
    // In a full implementation, we'd check the FIB here and potentially redirect
    // For now, we'll just pass to userspace
    send_event(EVENT_INTEREST_PROCESSED, name_hash, ctx->data_end - ctx->data, 
              action, start_time);
    
    return XDP_PASS;
}

// Process Data packet with optimized content store
static __always_inline int process_data_v2(struct xdp_md *ctx, void *data, 
                                       __u32 pkt_offset, struct xdp_config_v2 *cfg) {
    void *data_end = (void *)(long)ctx->data_end;
    __u64 name_hash;
    __u32 name_size;
    __u64 start_time = get_timestamp_ns();
    __u8 action = DECISION_PASS;  // Default action
    
    // Get Data Name and compute hash
    if (fast_hash_ndn_name(ctx, data, pkt_offset, &name_hash, &name_size) < 0) {
        update_metric(METRIC_ERRORS);
        return XDP_PASS;  // Let userspace handle malformed packets
    }
    
    update_metric(METRIC_DATA_RECV);
    
    // Check if we have a PIT entry for this Data
    if (cfg->pit_enabled) {
        struct pit_entry_v2 *pit_entry = bpf_map_lookup_elem(&pit_v2, &name_hash);
        
        if (!pit_entry) {
            // No PIT entry, this is unsolicited Data
            update_metric(METRIC_DROPS);
            action = DECISION_DROP;
            send_event(EVENT_UNSOLICITED_DATA, name_hash, ctx->data_end - ctx->data, 
                      action, start_time);
            return XDP_DROP;
        }
        
        // Store content in CS if enabled
        if (cfg->cs_enabled) {
            // Skip over the name to find metadata and content
            __u32 curr_offset = pkt_offset + name_size;
            __u32 content_offset = 0;
            __u32 content_size = 0;
            
            // In a real implementation, we'd parse the TLV structure to find the content
            // This is simplified for the prototype
            
            // Use a fixed size for this prototype
            content_size = 1024;  // Placeholder
            content_offset = curr_offset + 8;  // Placeholder
            
            // Check if content is small enough to store
            __u32 packet_size = ctx->data_end - ctx->data;
            if (content_size <= cfg->cs_max_size && 
                content_offset + content_size <= packet_size) {
                
                // Create content store entry
                struct cs_entry_v2 *new_entry;
                struct cs_entry_v2 tmp_entry;
                
                // Initialize the temporary entry
                tmp_entry.name_hash = name_hash;
                tmp_entry.insertion_time = get_timestamp_sec();
                tmp_entry.expiry_time = cfg->default_ttl;
                tmp_entry.content_size = content_size;
                tmp_entry.content_type = 0;  // Default content type
                tmp_entry.flags = 0;
                
                // Copy content data from packet to entry
                __u8 *content_ptr = data + content_offset;
                
                // We can't use a variable length as an array index in the kernel
                // So we'll hard code the maximum - the verifier will then check this
                if (content_size > CS_MAX_CONTENT_SIZE)
                    content_size = CS_MAX_CONTENT_SIZE;
                
                // Create properly sized content store entry
                int ret = bpf_map_update_elem(&content_store_v2, &name_hash, &tmp_entry, BPF_ANY);
                if (ret == 0) {
                    // Get the inserted entry so we can update the content
                    new_entry = bpf_map_lookup_elem(&content_store_v2, &name_hash);
                    if (new_entry) {
                        // Copy the content data safely
                        // Use bpf_probe_read to safely copy from the packet data
                        // This is a workaround for the eBPF verifier limitations
                        ret = bpf_probe_read(new_entry->content, content_size, content_ptr);
                        if (ret == 0) {
                            update_metric(METRIC_CACHE_INSERTS);
                            action = DECISION_PASS;
                            send_event(EVENT_CONTENT_CACHED, name_hash, content_size, 
                                      action, start_time);
                        }
                    }
                }
            }
            
            // Delete PIT entry for satisfied Interest
            bpf_map_delete_elem(&pit_v2, &name_hash);
        }
    }
    
    // Forward the Data packet using PIT information
    // In a real implementation, we'd check the PIT entry's ingress interface
    // and forward accordingly
    send_event(EVENT_DATA_PROCESSED, name_hash, ctx->data_end - ctx->data, 
              action, start_time);
    
    return XDP_PASS;
}

SEC("xdp")
int ndn_xdp_parser_v2(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_config_v2 *cfg;
    __u64 start_time = get_timestamp_ns();
    
    // Get configuration - initialize if not already done
    cfg = get_config_v2();
    if (!cfg) {
        init_config_v2();
        cfg = get_config_v2();
        if (!cfg)
            return XDP_PASS; // Can't proceed without config
    }
    
    // Ensure we can read the Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    // Check for NDN direct Ethernet framing
    if (bpf_ntohs(eth->h_proto) == NDN_ETHERTYPE) {
        // Skip Ethernet header
        __u32 offset = sizeof(struct ethhdr);
        
        // Parse NDN packet type
        __u32 type;
        if (fast_parse_tlv_type(data, data_end, &offset, &type) < 0)
            return XDP_PASS;
        
        // Process based on NDN packet type
        if (type == NDN_INTEREST)
            return process_interest_v2(ctx, data, offset, cfg);
        else if (type == NDN_DATA)
            return process_data_v2(ctx, data, offset, cfg);
        else if (type == NDN_NACK) {
            update_metric(METRIC_NACKS_RECV);
            // NACK handling would go here
            return XDP_PASS;
        }
    }
    
    // Check for NDN over UDP/IP
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP) {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)ip + sizeof(*ip) > data_end)
            return XDP_PASS;
        
        // Check for UDP traffic
        if (ip->protocol == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr *)((void *)ip + (ip->ihl * 4));
            if ((void *)udp + sizeof(*udp) > data_end)
                return XDP_PASS;
            
            if (bpf_ntohs(udp->dest) == NDN_UDP_PORT) {
                // Skip UDP header
                __u32 offset = sizeof(struct ethhdr) + (ip->ihl * 4) + sizeof(struct udphdr);
                
                // Parse NDN packet type
                __u32 type;
                if (fast_parse_tlv_type(data, data_end, &offset, &type) < 0)
                    return XDP_PASS;
                
                // Process based on NDN packet type
                if (type == NDN_INTEREST)
                    return process_interest_v2(ctx, data, offset, cfg);
                else if (type == NDN_DATA)
                    return process_data_v2(ctx, data, offset, cfg);
                else if (type == NDN_NACK) {
                    update_metric(METRIC_NACKS_RECV);
                    return XDP_PASS;
                }
            }
        }
    }
    
    // Not NDN or parsing failed, just pass to normal network stack
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
