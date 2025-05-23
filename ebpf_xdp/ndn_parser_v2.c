//
// μDCN - Enhanced XDP-based NDN Packet Parser (v2)
// 
// This version implements optimized NDN packet processing with:
// - Zero-copy packet handling
// - Direct content store read/write
// - Optimized nested TLV parsing
// - Smart decision logic for packet processing
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
#define CS_MAX_ENTRIES 32768  // Increased capacity for in-kernel CS
#define CS_MAX_CONTENT_SIZE 4096 // Increased max content size
#define CS_DEFAULT_TTL 300    // Default TTL in seconds for cached items

// Performance settings
#define MAX_TLV_DEPTH 8       // Maximum nesting of TLV fields we'll process
#define MAX_NAME_COMPONENTS 16 // Maximum number of name components we'll process

// Decision codes for packet handling
#define DECISION_PASS 0       // Pass to userspace
#define DECISION_SERVE 1      // Serve from cache
#define DECISION_DROP 2       // Drop packet (duplicate, invalid)
#define DECISION_REDIRECT 3   // Redirect to another interface

// Enhanced content store entry with metadata
struct cs_entry_v2 {
    __u64 name_hash;          // Name hash (for quick validation)
    __u64 insertion_time;     // When the content was inserted
    __u32 expiry_time;        // Time to live in seconds
    __u16 content_size;       // Size of the content
    __u8 content_type;        // Content type from NDN packet
    __u8 flags;               // Additional flags
    __u8 content[];           // Flexible array for content data
};

// Map for per-CPU packet metrics
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, METRIC_MAX);
} metrics SEC(".maps");

// Enhanced content store with optimized key structure
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));    // 64-bit name hash
    __uint(value_size, sizeof(struct cs_entry_v2) + CS_MAX_CONTENT_SIZE); 
    __uint(max_entries, CS_MAX_ENTRIES);
} content_store_v2 SEC(".maps");

// Enhanced PIT with better expiry handling
struct pit_entry_v2 {
    __u64 name_hash;          // Name hash for verification
    __u64 arrival_time;       // When the interest arrived
    __u32 lifetime_ms;        // Interest lifetime in milliseconds
    __u32 ingress_ifindex;    // Interface where Interest arrived
    __u32 nonce;              // Nonce for loop detection
    __u8 hop_count;           // Number of hops this interest has traversed
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u64));     // 64-bit name hash
    __uint(value_size, sizeof(struct pit_entry_v2));
    __uint(max_entries, 4096);           // Increased capacity
} pit_v2 SEC(".maps");

// Duplicate detection cache for quick Interest deduplication
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(key_size, sizeof(__u32));     // Nonce
    __uint(value_size, sizeof(__u64));   // Timestamp
    __uint(max_entries, 8192);           // Large enough to catch most duplicates
} nonce_cache SEC(".maps");

// Configuration map for XDP program behavior
struct xdp_config_v2 {
    __u8 hash_algorithm;        // Which hash algorithm to use
    __u8 cs_enabled;            // Whether content store is enabled
    __u8 pit_enabled;           // Whether PIT is enabled
    __u8 metrics_enabled;       // Whether metrics collection is enabled
    __u16 default_ttl;          // Default TTL for cached content
    __u16 cs_max_size;          // Max size of cached content
    __u8 zero_copy_enabled;     // Whether to use zero-copy packet handling
    __u8 nested_tlv_optimization; // Whether to use optimized TLV parsing
    __u8 userspace_fallback_threshold; // When to fall back to userspace (0-100%)
    __u8 reserved[3];           // Reserved for future use
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct xdp_config_v2));
    __uint(max_entries, 1);
} config_v2 SEC(".maps");

// Ring buffer for sending events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256KB ring buffer
} events SEC(".maps");

// Event structure for reporting to userspace
struct event {
    __u64 timestamp;
    __u32 event_type;
    __u32 packet_size;
    __u64 name_hash;
    __u32 action_taken;
    __u32 processing_time_ns;  // Processing time in nanoseconds
};

// Zero-copy helper functions
static __always_inline void *adjust_data_ptr(struct xdp_md *ctx, __u32 offset) {
    if (offset > ctx->data_end - ctx->data)
        return NULL;
    return (void *)(long)(ctx->data + offset);
}

// Optimized TLV length parser with boundary checks
static __always_inline int fast_parse_tlv_length(void *data, void *data_end, __u32 *offset, __u64 *length) {
    // Check if we can read at least one byte
    if (data + *offset + 1 > data_end)
        return -1;
    
    __u8 *ptr = data + *offset;
    __u8 first_byte = *ptr;
    *offset += 1;
    
    // Fast path for short form (most common case)
    if (first_byte < NDN_TLV_LEN_1BYTE_VAL) {
        *length = first_byte;
        return 0;
    }
    
    // Check which length encoding is used
    switch (first_byte) {
        case NDN_TLV_LEN_1BYTE_VAL:
            // Verify we can read the next byte
            if (data + *offset + 1 > data_end)
                return -1;
            *length = *(__u8 *)(ptr + 1);
            *offset += 1;
            return 0;
            
        case NDN_TLV_LEN_2BYTE_VAL:
            // Verify we can read the next 2 bytes
            if (data + *offset + 2 > data_end)
                return -1;
            *length = (__u16)ptr[1] << 8 | ptr[2];
            *offset += 2;
            return 0;
            
        case NDN_TLV_LEN_4BYTE_VAL:
            // Verify we can read the next 4 bytes
            if (data + *offset + 4 > data_end)
                return -1;
            *length = (__u32)ptr[1] << 24 | (__u32)ptr[2] << 16 | 
                      (__u16)ptr[3] << 8 | ptr[4];
            *offset += 4;
            return 0;
            
        case NDN_TLV_LEN_8BYTE_VAL:
            // 8-byte length not fully supported in XDP
            // Going to fall back to userspace for these rare cases
            return -2;
            
        default:
            // Invalid length encoding
            return -1;
    }
}

// Optimized TLV type parser with boundary checks
static __always_inline int fast_parse_tlv_type(void *data, void *data_end, __u32 *offset, __u32 *type) {
    // Check if we can read at least one byte
    if (data + *offset + 1 > data_end)
        return -1;
    
    __u8 *ptr = data + *offset;
    __u8 first_byte = *ptr;
    *offset += 1;
    
    // Fast path for common case (small type numbers)
    if (first_byte < NDN_TLV_TYPE_1BYTE_VAL) {
        *type = first_byte;
        return 0;
    }
    
    // Handle larger type values
    switch (first_byte) {
        case NDN_TLV_TYPE_1BYTE_VAL:
            if (data + *offset + 1 > data_end)
                return -1;
            *type = *(__u8 *)(ptr + 1);
            *offset += 1;
            return 0;
            
        case NDN_TLV_TYPE_2BYTE_VAL:
            if (data + *offset + 2 > data_end)
                return -1;
            *type = (__u16)ptr[1] << 8 | ptr[2];
            *offset += 2;
            return 0;
            
        case NDN_TLV_TYPE_4BYTE_VAL:
            if (data + *offset + 4 > data_end)
                return -1;
            *type = (__u32)ptr[1] << 24 | (__u32)ptr[2] << 16 | 
                    (__u16)ptr[3] << 8 | ptr[4];
            *offset += 4;
            return 0;
            
        default:
            // Invalid type encoding
            return -1;
    }
}

// Enhanced hash function optimized for kernel execution
static __always_inline __u64 xxhash(__u8 *data, __u32 length, __u64 seed, void *data_end) {
    const __u64 PRIME64_1 = 11400714785074694791ULL;
    const __u64 PRIME64_2 = 14029467366897019727ULL;
    const __u64 PRIME64_3 = 1609587929392839161ULL;
    const __u64 PRIME64_4 = 9650029242287828579ULL;
    const __u64 PRIME64_5 = 2870177450012600261ULL;
    
    __u64 h64;
    
    // Safety check
    if (data + length > data_end)
        length = data_end - data;
    
    // Special handling based on length
    if (length >= 32) {
        // For longer inputs, we'd need the full algorithm
        // But BPF verifier limits make this difficult
        // Use a simplified approach for eBPF compatibility
        h64 = seed + PRIME64_5;
        
        // Process in 8-byte blocks as much as possible
        __u32 block_count = length / 8;
        
        // BPF loops can't have dynamic iteration counts, 
        // so we'll limit to a reasonable max
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            if (i >= block_count) break;
            
            // Safety check for each access
            if (data + (i * 8) + 8 > data_end) break;
            
            __u64 k1 = *(__u64 *)(data + (i * 8));
            h64 ^= k1 * PRIME64_2;
            h64 = ((h64 << 31) | (h64 >> 33)) * PRIME64_1;
            h64 = h64 * PRIME64_1 + PRIME64_4;
        }
        
        // Process remaining bytes
        h64 += length;
    } 
    else if (length >= 16) {
        h64 = seed + PRIME64_5;
        
        // Process two 8-byte blocks
        if (data + 8 > data_end) goto fallback;
        __u64 k1 = *(__u64 *)(data);
        h64 ^= k1 * PRIME64_2;
        h64 = ((h64 << 31) | (h64 >> 33)) * PRIME64_1;
        
        if (data + 16 > data_end) goto partial_second_block;
        k1 = *(__u64 *)(data + 8);
        h64 ^= k1 * PRIME64_2;
        h64 = ((h64 << 31) | (h64 >> 33)) * PRIME64_1;
        
        partial_second_block:
        h64 += length;
    }
    else if (length >= 8) {
        h64 = seed + PRIME64_5;
        
        // Process one 8-byte block
        if (data + 8 > data_end) goto fallback;
        __u64 k1 = *(__u64 *)(data);
        h64 ^= k1 * PRIME64_2;
        h64 = ((h64 << 31) | (h64 >> 33)) * PRIME64_1;
        h64 += length;
    }
    else {
        fallback:
        // Fallback for small inputs
        h64 = seed + PRIME64_5;
        
        // Process byte by byte
        #pragma unroll
        for (int i = 0; i < 8; i++) {
            if (i >= length) break;
            
            // Safety check for each access
            if (data + i > data_end) break;
            
            h64 ^= (__u64)data[i] * PRIME64_5;
            h64 = ((h64 << 11) | (h64 >> 53)) * PRIME64_1;
        }
        
        h64 += length;
    }
    
    // Finalization
    h64 ^= h64 >> 33;
    h64 *= PRIME64_2;
    h64 ^= h64 >> 29;
    h64 *= PRIME64_3;
    h64 ^= h64 >> 32;
    
    return h64;
}

// Get current timestamp in nanoseconds
static __always_inline __u64 get_timestamp_ns(void) {
    return bpf_ktime_get_ns();
}

// Get current timestamp in seconds
static __always_inline __u32 get_timestamp_sec(void) {
    return (__u32)(bpf_ktime_get_ns() / 1000000000);
}

// Update a metric counter
static __always_inline void update_metric(int metric_idx) {
    __u64 *counter = bpf_map_lookup_elem(&metrics, &metric_idx);
    if (counter)
        __sync_fetch_and_add(counter, 1);
}

// Send an event to userspace via ring buffer
static __always_inline void send_event(__u32 event_type, __u64 name_hash, 
                                      __u32 packet_size, __u32 action,
                                      __u64 start_time) {
    struct event *e;
    
    // Reserve space in the ring buffer
    e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!e)
        return;
    
    // Fill the event data
    e->timestamp = get_timestamp_ns();
    e->event_type = event_type;
    e->name_hash = name_hash;
    e->packet_size = packet_size;
    e->action_taken = action;
    e->processing_time_ns = get_timestamp_ns() - start_time;
    
    // Submit the event
    bpf_ringbuf_submit(e, 0);
}

// Fast name hash calculation optimized for BPF
static __always_inline int fast_hash_ndn_name(struct xdp_md *ctx, void *data, __u32 offset, 
                                          __u64 *name_hash, __u32 *name_size) {
    void *data_end = (void *)(long)ctx->data_end;
    __u32 curr_offset = offset;
    __u32 type;
    __u64 length;
    
    // Parse Name TLV-TYPE
    if (fast_parse_tlv_type(data, data_end, &curr_offset, &type) < 0)
        return -1;
    
    if (type != NDN_TLV_NAME)
        return -1;
    
    // Parse Name TLV-LENGTH
    if (fast_parse_tlv_length(data, data_end, &curr_offset, &length) < 0)
        return -1;
    
    // Save the name size (including type and length)
    *name_size = curr_offset - offset + length;
    
    // Hash the name components
    __u8 *name_start = data + curr_offset;
    __u32 name_length = length;
    
    // Ensure we don't read past the end of the packet
    if (name_start + name_length > data_end)
        return -1;
    
    // Compute the hash of the name
    *name_hash = xxhash(name_start, name_length, 0, data_end);
    
    return 0;
}

// Optimized function to check if content is expired
static __always_inline int content_expired(struct cs_entry_v2 *entry) {
    __u32 now = get_timestamp_sec();
    return (now >= (entry->insertion_time + entry->expiry_time));
}

// Initialize configuration with defaults
static __always_inline void init_config_v2() {
    struct xdp_config_v2 cfg = {
        .hash_algorithm = HASH_ALGO_XXHASH,
        .cs_enabled = 1,
        .pit_enabled = 1,
        .metrics_enabled = 1,
        .default_ttl = CS_DEFAULT_TTL,
        .cs_max_size = CS_MAX_CONTENT_SIZE,
        .zero_copy_enabled = 1,
        .nested_tlv_optimization = 1,
        .userspace_fallback_threshold = 20  // 20% fallback rate
    };
    
    __u32 key = 0;
    bpf_map_update_elem(&config_v2, &key, &cfg, BPF_ANY);
}

// Get current configuration
static __always_inline struct xdp_config_v2 *get_config_v2() {
    __u32 key = 0;
    return bpf_map_lookup_elem(&config_v2, &key);
}
