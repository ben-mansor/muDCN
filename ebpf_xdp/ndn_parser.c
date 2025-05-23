//
// μDCN - XDP-based NDN Packet Parser
// 
// This implements the fast path for NDN packets processing using XDP
// to achieve line-rate performance even at 100Gbps. The program parses
// NDN packets, implements a high-performance content store, and handles
// packet forwarding and redirection.
//

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "ndn_tlv.h"  // Include the NDN TLV definitions

// Network constants
#define NDN_ETHERTYPE 0x8624  // NDN ethertype for direct Ethernet framing
#define NDN_UDP_PORT 6363     // Standard NDN UDP port
#define NDN_TCP_PORT 6363     // Standard NDN TCP port
#define NDN_WEBSOCKET_PORT 9696 // WebSocket transport port

// Content store settings
#define CS_MAX_ENTRIES 10240  // Max entries in content store
#define CS_MAX_CONTENT_SIZE 2048 // Max size of cached content
#define CS_DEFAULT_TTL 300    // Default TTL in seconds for cached items

// Map for per-CPU packet metrics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, METRIC_MAX);
} metrics SEC(".maps");

// Content store - maps name hash to content data
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));    // 64-bit name hash
    __uint(value_size, sizeof(struct cs_entry) + CS_MAX_CONTENT_SIZE); 
    __uint(max_entries, CS_MAX_ENTRIES);
} content_store SEC(".maps");

// FIB (Forwarding Information Base) - Maps name prefixes to outgoing interfaces
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u64));    // 64-bit prefix hash
    __uint(value_size, sizeof(__u32));  // Interface index
    __uint(max_entries, 1024);          // Maximum number of routes
} fib SEC(".maps");

// PIT (Pending Interest Table) - Maps name hash to incoming interfaces
struct pit_entry {
    __u64 expiry;            // Expiration time
    __u32 ingress_ifindex;   // Interface where Interest arrived
    __u32 nonce;             // Nonce for loop detection
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));     // 64-bit name hash
    __uint(value_size, sizeof(struct pit_entry));
    __uint(max_entries, 2048);           // Maximum pending interests
} pit SEC(".maps");

// Configuration map for XDP program behavior
struct xdp_config {
    __u8 hash_algorithm;     // Which hash algorithm to use
    __u8 cs_enabled;         // Whether content store is enabled
    __u8 pit_enabled;        // Whether PIT is enabled
    __u8 metrics_enabled;    // Whether metrics collection is enabled
    __u16 default_ttl;       // Default TTL for cached content
    __u16 cs_max_size;       // Max size of cached content
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct xdp_config));
    __uint(max_entries, 1);
} config SEC(".maps");

// Parse TLV length field with variable-length encoding support
static __always_inline int parse_tlv_length(void *data, void *data_end, __u32 *offset, __u64 *length) {
    __u8 *ptr = (__u8 *)data + *offset;
    if (ptr + 1 > data_end)
        return -1;
    
    __u8 first_byte = *ptr;
    *offset += 1;
    
    // Handle different length encodings
    if (first_byte < NDN_TLV_LEN_1BYTE_VAL) {
        // Short form - length is in the first byte
        *length = first_byte;
        return 0;
    } else if (first_byte == NDN_TLV_LEN_1BYTE_VAL) {
        // 1-byte length field follows
        if (ptr + 2 > data_end)
            return -1;
        *length = *(ptr + 1);
        *offset += 1;
        return 0;
    } else if (first_byte == NDN_TLV_LEN_2BYTE_VAL) {
        // 2-byte length field follows
        if (ptr + 3 > data_end)
            return -1;
        *length = (__u16)ptr[1] << 8 | ptr[2];
        *offset += 2;
        return 0;
    } else if (first_byte == NDN_TLV_LEN_4BYTE_VAL) {
        // 4-byte length field follows
        if (ptr + 5 > data_end)
            return -1;
        *length = (__u32)ptr[1] << 24 | (__u32)ptr[2] << 16 | (__u32)ptr[3] << 8 | ptr[4];
        *offset += 4;
        return 0;
    }
    
    // Invalid length encoding
    return -1;
}

// Jenkins hash function for NDN names
static __always_inline __u64 jenkins_hash(const void *data, __u32 size, void *data_end) {
    const __u8 *key = data;
    __u32 i = 0;
    __u64 hash = 0;
    
    #pragma unroll
    for (i = 0; i < 64 && i < size && &key[i] < data_end; i++) {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    
    return hash;
}

// Murmur hash function for NDN names - simplified version
static __always_inline __u64 murmur_hash(const void *data, __u32 size, void *data_end) {
    const __u64 seed = 0x5bd1e995;
    const __u64 m = 0x5bd1e995;
    __u64 hash = seed ^ size;
    const __u8 *key = data;
    __u32 i = 0;
    
    #pragma unroll
    for (i = 0; i < 64 && i < size && &key[i] + 8 <= data_end; i += 8) {
        __u64 k = *(__u64 *)&key[i];
        k *= m;
        k ^= k >> 24;
        k *= m;
        
        hash *= m;
        hash ^= k;
    }
    
    // Handle remaining bytes
    if (i < size && i < 64) {
        hash ^= key[i];
        hash *= m;
    }
    
    hash ^= hash >> 13;
    hash *= m;
    hash ^= hash >> 15;
    
    return hash;
}

// Compute hash for NDN name - supports different hash functions
static __always_inline __u64 compute_name_hash(struct xdp_md *ctx, const void *name_data, 
                                             __u32 name_size, __u8 hash_algo) {
    void *data_end = (void *)(long)ctx->data_end;
    
    // Check bounds
    if ((void *)name_data + name_size > data_end) {
        // If out of bounds, use a simple hash
        return (__u64)name_size;
    }
    
    // Choose hash algorithm based on configuration
    switch (hash_algo) {
        case HASH_ALGO_JENKINS:
            return jenkins_hash(name_data, name_size, data_end);
        case HASH_ALGO_MURMUR:
            return murmur_hash(name_data, name_size, data_end);
        case HASH_ALGO_XXHASH:
            // XXHash not implemented yet, fall back to Jenkins
            return jenkins_hash(name_data, name_size, data_end);
        case HASH_ALGO_SIMPLE:
        default:
            // Simple XOR-based hash
            const __u8 *bytes = name_data;
            __u64 hash = 0;
            __u32 i;
            
            #pragma unroll
            for (i = 0; i < 64 && i < name_size && &bytes[i] < data_end; i++) {
                hash = ((hash << 5) + hash) ^ bytes[i];
            }
            
            return hash;
    }
}

// Parse NDN Name and compute its hash
static __always_inline int parse_ndn_name(struct xdp_md *ctx, struct ndn_packet *pkt, 
                                        __u64 *name_hash, __u8 hash_algo) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 offset = sizeof(struct ndn_tlv_hdr);
    __u64 tlv_length = 0;
    
    // Ensure we can read the packet header
    if ((void *)pkt + offset > data_end)
        return -1;
    
    // Find the Name TLV
    struct ndn_tlv_hdr *tlv = (struct ndn_tlv_hdr *)((void *)pkt + offset);
    if ((void *)tlv + sizeof(*tlv) > data_end)
        return -1;
    
    // Check if this is a Name TLV
    if (tlv->type != NDN_TLV_NAME)
        return -1;
    
    // Parse TLV length
    offset += sizeof(struct ndn_tlv_hdr);
    if (parse_tlv_length((void *)pkt, data_end, &offset, &tlv_length) < 0)
        return -1;
    
    // Compute hash of the name
    void *name_data = (void *)pkt + offset;
    if (name_data + tlv_length > data_end)
        return -1;
    
    *name_hash = compute_name_hash(ctx, name_data, tlv_length, hash_algo);
    return 0;
}

// Increment a metric counter
static __always_inline void update_metric(int metric_idx) {
    __u64 *counter;
    
    counter = bpf_map_lookup_elem(&metrics, &metric_idx);
    if (counter)
        (*counter)++;
}

// Get current timestamp in seconds
static __always_inline __u64 get_timestamp() {
    return bpf_ktime_get_ns() / 1000000000; // Convert ns to seconds
}

// Check if a content item has expired
static __always_inline bool content_expired(struct cs_entry *entry) {
    __u64 now = get_timestamp();
    return (now > entry->expiry);
}

// Process NDN Interest packet
static __always_inline int process_interest(struct xdp_md *ctx, struct ndn_packet *pkt, 
                                           struct xdp_config *cfg) {
    __u64 name_hash = 0;
    __u32 ifindex = ctx->ingress_ifindex;
    
    // Update interest counter
    update_metric(METRIC_INTERESTS_RECV);
    
    // Parse name and check content store
    if (parse_ndn_name(ctx, pkt, &name_hash, cfg->hash_algorithm) < 0) {
        update_metric(METRIC_ERRORS);
        return XDP_PASS;  // If parsing fails, let the packet pass
    }
    
    // First, check if Content Store is enabled
    if (cfg->cs_enabled) {
        // Look up in content store
        struct cs_entry *entry = bpf_map_lookup_elem(&content_store, &name_hash);
        if (entry && !content_expired(entry)) {
            // Content found in store - in a real production implementation, we would
            // construct a Data packet and send it back directly from the XDP program
            // Since that's complex, we'll mark it for userspace handling
            update_metric(METRIC_CACHE_HITS);
            
            // For now, we just pass to userspace with a flag or redirect
            // In a full implementation, we would handle this differently
            return XDP_PASS;
        } else {
            update_metric(METRIC_CACHE_MISSES);
        }
    }
    
    // If PIT is enabled, update PIT with this interest 
    if (cfg->pit_enabled) {
        struct pit_entry pit_value = {
            .expiry = get_timestamp() + 10, // Default 10s lifetime
            .ingress_ifindex = ifindex,
            .nonce = 0  // We should extract the nonce from the interest
        };
        
        // Add to PIT (Pending Interest Table)
        bpf_map_update_elem(&pit, &name_hash, &pit_value, BPF_ANY);
    }
    
    // Check FIB for forwarding
    __u32 *fib_entry = bpf_map_lookup_elem(&fib, &name_hash);
    if (fib_entry && *fib_entry != 0 && *fib_entry != ifindex) {
        // Interest can be forwarded according to FIB
        // In real implementation, we would redirect here
        update_metric(METRIC_REDIRECTS);
        return bpf_redirect(*fib_entry, 0);
    }
    
    // No route or need for complex handling, pass to userspace
    return XDP_PASS;
}

// Extract and store content from a Data packet
static __always_inline int extract_content(struct xdp_md *ctx, struct ndn_packet *pkt,
                                         __u64 name_hash, struct xdp_config *cfg) {
    void *data_end = (void *)(long)ctx->data_end;
    __u32 offset = sizeof(struct ndn_tlv_hdr);
    __u64 content_size = 0;
    void *content_ptr = NULL;
    
    // Skip the name TLV
    struct ndn_tlv_hdr *name_tlv = (struct ndn_tlv_hdr *)((void *)pkt + offset);
    if ((void *)name_tlv + sizeof(*name_tlv) > data_end)
        return -1;
    
    // Skip past the name
    offset += sizeof(struct ndn_tlv_hdr);
    __u64 name_len = 0;
    if (parse_tlv_length((void *)pkt, data_end, &offset, &name_len) < 0)
        return -1;
    
    offset += name_len;
    
    // Find content TLV (simplified - real implementation would parse MetaInfo, etc.)
    while (offset < ctx->data_end - ctx->data) {
        struct ndn_tlv_hdr *tlv = (struct ndn_tlv_hdr *)((void *)pkt + offset);
        if ((void *)tlv + sizeof(*tlv) > data_end)
            return -1;
        
        if (tlv->type == NDN_TLV_CONTENT) {
            offset += sizeof(struct ndn_tlv_hdr);
            if (parse_tlv_length((void *)pkt, data_end, &offset, &content_size) < 0)
                return -1;
            
            // Ensure content isn't too large to store
            if (content_size > cfg->cs_max_size)
                return -1;
            
            content_ptr = (void *)pkt + offset;
            break;
        }
        
        // Skip this TLV
        offset += sizeof(struct ndn_tlv_hdr);
        __u64 tlv_len = 0;
        if (parse_tlv_length((void *)pkt, data_end, &offset, &tlv_len) < 0)
            return -1;
        
        offset += tlv_len;
    }
    
    // No content found
    if (!content_ptr)
        return -1;
    
    // Store in content store if we found content and it's not too large
    if (content_ptr && content_size > 0 && content_size <= cfg->cs_max_size) {
        // Create cache entry
        struct cs_entry *entry;
        __u64 now = get_timestamp();
        
        // Allocate memory for the cache entry (stack-based in XDP)
        struct {
            struct cs_entry hdr;
            __u8 data[CS_MAX_CONTENT_SIZE];
        } entry_buffer;
        
        // Initialize the entry
        entry_buffer.hdr.timestamp = now;
        entry_buffer.hdr.expiry = now + cfg->default_ttl;
        entry_buffer.hdr.content_len = content_size;
        entry_buffer.hdr.signature_len = 0; // Not storing signature for now
        
        // Copy the content data - with bounds checking
        if (content_ptr + content_size <= data_end) {
            __u32 i;
            const __u8 *src = content_ptr;
            
            #pragma unroll
            for (i = 0; i < CS_MAX_CONTENT_SIZE && i < content_size; i++) {
                entry_buffer.data[i] = src[i];
            }
            
            // Update the content store
            bpf_map_update_elem(&content_store, &name_hash, &entry_buffer, BPF_ANY);
            return 0;
        }
    }
    
    return -1;
}

// Process NDN Data packet
static __always_inline int process_data(struct xdp_md *ctx, struct ndn_packet *pkt,
                                      struct xdp_config *cfg) {
    __u64 name_hash = 0;
    __u32 ifindex = ctx->ingress_ifindex;
    
    // Update data packet counter
    update_metric(METRIC_DATA_RECV);
    
    // Parse name from the Data packet
    if (parse_ndn_name(ctx, pkt, &name_hash, cfg->hash_algorithm) < 0) {
        update_metric(METRIC_ERRORS);
        return XDP_PASS;
    }
    
    // Store in content store if enabled
    if (cfg->cs_enabled) {
        if (extract_content(ctx, pkt, name_hash, cfg) == 0) {
            // Content successfully stored
        }
    }
    
    // Check PIT if enabled
    if (cfg->pit_enabled) {
        struct pit_entry *pit_entry = bpf_map_lookup_elem(&pit, &name_hash);
        if (pit_entry) {
            // Data packet matches a pending interest
            // In a full implementation, we would forward to the incoming interface
            if (pit_entry->ingress_ifindex != ifindex) {
                update_metric(METRIC_REDIRECTS);
                // Redirect Data packet to the interface where the Interest came from
                return bpf_redirect(pit_entry->ingress_ifindex, 0);
            }
            
            // Remove the PIT entry as it's been satisfied
            bpf_map_delete_elem(&pit, &name_hash);
        }
    }
    
    // Pass to normal network stack
    return XDP_PASS;
}

// Initialize default configuration for the XDP program
static __always_inline void init_config() {
    // Default configuration - can be updated by userspace control program
    struct xdp_config cfg = {
        .hash_algorithm = HASH_ALGO_JENKINS,
        .cs_enabled = 1,        // Content store enabled by default
        .pit_enabled = 1,       // PIT enabled by default
        .metrics_enabled = 1,   // Metrics collection enabled by default
        .default_ttl = CS_DEFAULT_TTL,
        .cs_max_size = CS_MAX_CONTENT_SIZE
    };
    
    __u32 key = 0;
    bpf_map_update_elem(&config, &key, &cfg, BPF_ANY);
    
    // Initialize metrics counters to zero
    __u64 zero = 0;
    for (int i = 0; i < METRIC_MAX; i++) {
        bpf_map_update_elem(&metrics, &i, &zero, BPF_ANY);
    }
}

// Get the current configuration
static __always_inline struct xdp_config *get_config() {
    __u32 key = 0;
    return bpf_map_lookup_elem(&config, &key);
}

SEC("xdp")
int ndn_xdp_parser(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct xdp_config *cfg;
    
    // Get configuration - initialize if not already done
    cfg = get_config();
    if (!cfg) {
        init_config();
        cfg = get_config();
        if (!cfg)
            return XDP_PASS; // Can't proceed without config
    }
    
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
            return process_interest(ctx, ndn, cfg);
        else if (ndn->hdr.type == NDN_DATA)
            return process_data(ctx, ndn, cfg);
        else if (ndn->hdr.type == NDN_NACK) {
            update_metric(METRIC_NACKS_RECV);
            // In a full implementation, we would properly handle NACK packets
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
                struct ndn_packet *ndn = (struct ndn_packet *)(udp + 1);
                if ((void *)ndn + sizeof(*ndn) > data_end)
                    return XDP_PASS;
                
                // Process based on NDN packet type
                if (ndn->hdr.type == NDN_INTEREST)
                    return process_interest(ctx, ndn, cfg);
                else if (ndn->hdr.type == NDN_DATA)
                    return process_data(ctx, ndn, cfg);
                else if (ndn->hdr.type == NDN_NACK) {
                    update_metric(METRIC_NACKS_RECV);
                    return XDP_PASS;
                }
            }
        }
        
        // Check for TCP traffic
        else if (ip->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
            if ((void *)tcp + sizeof(*tcp) > data_end)
                return XDP_PASS;
            
            if (bpf_ntohs(tcp->dest) == NDN_TCP_PORT || 
                bpf_ntohs(tcp->dest) == NDN_WEBSOCKET_PORT) {
                // TCP packets are more complex to handle in XDP
                // We'll let the userspace handle these
                return XDP_PASS;
            }
        }
    }
    
    // Not NDN or parsing failed, just pass to normal network stack
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
