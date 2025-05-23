#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/time.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <inttypes.h>

// NDN TLV types
#define TLV_INTEREST 0x05
#define TLV_DATA 0x06
#define TLV_NACK 0x03
#define TLV_NAME 0x07
#define TLV_COMPONENT 0x08
#define TLV_NONCE 0x0A

// NDN parameters
#define MAX_NAME_LEN 256
#define MAX_CACHE_ENTRIES 1024
#define NDN_DEFAULT_PORT 6363

// Forward declarations
struct ndn_name {
    char name[MAX_NAME_LEN];
    uint16_t len;
};

// Simplified LRU cache for NDN names
struct ndn_cache_entry {
    struct ndn_name name;
    uint64_t timestamp;
    int valid;
};

// Global variables
static struct ndn_cache_entry name_cache[MAX_CACHE_ENTRIES];
static int cache_next_idx = 0;
static int cache_size = 0;
static volatile int keep_running = 1;
static uint64_t stats_interests_received = 0;
static uint64_t stats_interests_forwarded = 0;
static uint64_t stats_data_received = 0;
static uint64_t stats_data_forwarded = 0;
static uint64_t stats_cache_hits = 0;
static uint64_t stats_cache_misses = 0;

// Get current timestamp in milliseconds
static uint64_t get_timestamp_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((uint64_t)(tv.tv_sec) * 1000) + (tv.tv_usec / 1000);
}

// Signal handler for graceful termination
static void signal_handler(int sig) {
    keep_running = 0;
}

// Helper function to parse TLV type
static uint8_t parse_tlv_type(const void *data, uint16_t *offset) {
    uint8_t type = *(uint8_t *)((char *)data + *offset);
    (*offset)++;
    return type;
}

// Helper function to parse TLV length
static uint16_t parse_tlv_length(const void *data, uint16_t *offset) {
    uint8_t first_byte = *(uint8_t *)((char *)data + *offset);
    (*offset)++;
    
    /* Check if this is a short form (< 253) */
    if (first_byte < 253) {
        return first_byte;
    }
    
    /* Medium length (2 bytes) */
    if (first_byte == 253) {
        uint16_t length = *(uint16_t *)((char *)data + *offset);
        (*offset) += 2;
        return (length >> 8) | ((length & 0xff) << 8); // Convert from network to host byte order
    }
    
    /* Long length not supported in this implementation */
    return 0;
}

// Parse NDN name from TLV buffer
static int parse_ndn_name(struct ndn_name *name, const void *data, uint16_t *offset, uint16_t name_length) {
    // Initialize name
    memset(name->name, 0, MAX_NAME_LEN);
    name->len = 0;
    
    uint16_t remaining = name_length;
    
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
        
        memcpy(&name->name[name->len], (char *)data + *offset, copy_len);
        name->len += copy_len;
        
        // Update offsets
        *offset += comp_len;
        remaining -= (comp_len + 2); // type + length + value
    }
    
    return 0;
}

// Add an entry to the name cache
static void cache_add(struct ndn_name *name) {
    if (cache_size < MAX_CACHE_ENTRIES) {
        // Cache is not full, add to next slot
        name_cache[cache_next_idx].valid = 1;
        strncpy(name_cache[cache_next_idx].name.name, name->name, MAX_NAME_LEN - 1);
        name_cache[cache_next_idx].name.len = name->len;
        name_cache[cache_next_idx].timestamp = get_timestamp_ms();
        
        cache_next_idx = (cache_next_idx + 1) % MAX_CACHE_ENTRIES;
        cache_size++;
    } else {
        // Cache is full, replace oldest entry
        int oldest_idx = 0;
        uint64_t oldest_time = UINT64_MAX;
        
        for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
            if (name_cache[i].valid && name_cache[i].timestamp < oldest_time) {
                oldest_time = name_cache[i].timestamp;
                oldest_idx = i;
            }
        }
        
        // Replace oldest entry
        strncpy(name_cache[oldest_idx].name.name, name->name, MAX_NAME_LEN - 1);
        name_cache[oldest_idx].name.len = name->len;
        name_cache[oldest_idx].timestamp = get_timestamp_ms();
    }
}

// Check if a name is in the cache
static int cache_check(struct ndn_name *name) {
    for (int i = 0; i < MAX_CACHE_ENTRIES; i++) {
        if (name_cache[i].valid && 
            name_cache[i].name.len == name->len && 
            strncmp(name_cache[i].name.name, name->name, name->len) == 0) {
            // Update timestamp for this entry (for LRU)
            name_cache[i].timestamp = get_timestamp_ms();
            return 1; // Found in cache
        }
    }
    return 0; // Not found in cache
}

// Process an NDN packet - the core of what the XDP program would do
static int process_ndn_packet(const uint8_t *packet, uint32_t len, int *should_forward) {
    // Default: forward the packet
    *should_forward = 1;
    
    uint16_t offset = 0;
    
    // Check if packet is long enough for a TLV type and length
    if (len < 2) {
        return -1;
    }
    
    // Parse packet type
    uint8_t tlv_type = parse_tlv_type(packet, &offset);
    
    // For this simulation, we only handle Interest packets
    if (tlv_type == TLV_INTEREST) {
        stats_interests_received++;
        
        // Parse interest length
        uint16_t interest_len = parse_tlv_length(packet, &offset);
        
        // Ensure packet is complete
        if (offset + interest_len > len) {
            return -1;
        }
        
        // Find and parse Name TLV
        uint16_t end_of_interest = offset + interest_len;
        while (offset < end_of_interest) {
            uint8_t field_type = parse_tlv_type(packet, &offset);
            
            if (field_type == TLV_NAME) {
                uint16_t name_len = parse_tlv_length(packet, &offset);
                
                // Parse the NDN name
                struct ndn_name name;
                parse_ndn_name(&name, packet, &offset, name_len);
                
                printf("Received NDN Interest: %s\n", name.name);
                
                // Check if name is already in cache
                if (cache_check(&name)) {
                    stats_cache_hits++;
                    printf("Cache HIT for %s - dropping duplicate interest\n", name.name);
                    *should_forward = 0; // Don't forward (simulating XDP_DROP)
                    return 0;
                } else {
                    stats_cache_misses++;
                    printf("Cache MISS for %s - adding to cache and forwarding\n", name.name);
                    // Add to cache
                    cache_add(&name);
                    stats_interests_forwarded++;
                    return 0;
                }
            }
            
            // Skip this TLV field
            uint16_t field_len = parse_tlv_length(packet, &offset);
            offset += field_len;
        }
    } else if (tlv_type == TLV_DATA) {
        // For Data packets, just count them
        stats_data_received++;
        stats_data_forwarded++;
        return 0;
    }
    
    return 0;
}

// Packet handler for libpcap
static void packet_handler(uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *bytes) {
    // Check if the packet is large enough to be an Ethernet frame
    if (h->len < sizeof(struct ethhdr)) {
        return;
    }
    
    // Cast the packet to an Ethernet header
    const struct ethhdr *eth = (struct ethhdr *)bytes;
    
    // Check if it's an IP packet
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return;
    }
    
    // Check if packet is large enough to contain an IP header
    if (h->len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
        return;
    }
    
    // Cast to an IP header
    const struct iphdr *ip = (struct iphdr *)(bytes + sizeof(struct ethhdr));
    
    // Check if it's a UDP packet
    if (ip->protocol != IPPROTO_UDP) {
        return;
    }
    
    // Check if packet is large enough to contain a UDP header
    if (h->len < sizeof(struct ethhdr) + (ip->ihl * 4) + sizeof(struct udphdr)) {
        return;
    }
    
    // Cast to a UDP header
    const struct udphdr *udp = (struct udphdr *)(bytes + sizeof(struct ethhdr) + (ip->ihl * 4));
    
    // Check if it's to/from NDN port
    if (ntohs(udp->dest) != NDN_DEFAULT_PORT && ntohs(udp->source) != NDN_DEFAULT_PORT) {
        return;
    }
    
    // Calculate the UDP data offset and length
    uint32_t udp_data_offset = sizeof(struct ethhdr) + (ip->ihl * 4) + sizeof(struct udphdr);
    uint32_t udp_data_len = h->len - udp_data_offset;
    
    // Check if we have any UDP payload
    if (udp_data_len == 0) {
        return;
    }
    
    // Call our NDN packet processor - simulating the XDP functionality
    int should_forward;
    process_ndn_packet(bytes + udp_data_offset, udp_data_len, &should_forward);
    
    // In real XDP, we would return XDP_PASS or XDP_DROP here. In this simulation,
    // we're just logging the decision.
    if (should_forward) {
        printf("Action: FORWARD packet\n");
    } else {
        printf("Action: DROP packet\n");
    }
    
    printf("\n");
}

// Print usage information
static void print_usage(const char *progname) {
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("Options:\n");
    printf("  -i INTERFACE   Specify the network interface to capture\n");
    printf("  -f FILTER      Specify a pcap filter (default: udp port %d)\n", NDN_DEFAULT_PORT);
    printf("  -h             Print this help message\n");
}

// Print statistics
static void print_stats() {
    printf("\nNDN XDP Simulation Statistics:\n");
    printf("-------------------------------\n");
    printf("  Interests received:     %" PRIu64 "\n", stats_interests_received);
    printf("  Interests forwarded:    %" PRIu64 "\n", stats_interests_forwarded);
    printf("  Data packets received:  %" PRIu64 "\n", stats_data_received);
    printf("  Data packets forwarded: %" PRIu64 "\n", stats_data_forwarded);
    printf("  Name cache hits:        %" PRIu64 "\n", stats_cache_hits);
    printf("  Name cache misses:      %" PRIu64 "\n", stats_cache_misses);
    printf("  Name cache size:        %d/%d\n", cache_size, MAX_CACHE_ENTRIES);
}

int main(int argc, char **argv) {
    char *interface = NULL;
    char *filter = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    int opt;
    
    // Parse command-line options
    while ((opt = getopt(argc, argv, "i:f:h")) != -1) {
        switch (opt) {
        case 'i':
            interface = optarg;
            break;
        case 'f':
            filter = optarg;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Check if interface was provided
    if (!interface) {
        fprintf(stderr, "Error: Network interface must be specified.\n");
        print_usage(argv[0]);
        return 1;
    }
    
    // Set up filter if not provided
    if (!filter) {
        char default_filter[64];
        snprintf(default_filter, sizeof(default_filter), "udp port %d", NDN_DEFAULT_PORT);
        filter = default_filter;
    }
    
    // Initialize the name cache
    memset(name_cache, 0, sizeof(name_cache));
    
    // Set up signal handler for graceful termination
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("NDN XDP Simulation\n");
    printf("-----------------\n");
    printf("Interface: %s\n", interface);
    printf("Filter: %s\n", filter);
    printf("Press Ctrl+C to stop and view statistics.\n\n");
    
    // Open the network interface for packet capture
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error: Couldn't open interface %s: %s\n", interface, errbuf);
        return 2;
    }
    
    // Compile and set the filter
    if (pcap_compile(handle, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Error: Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Error: Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return 2;
    }
    
    // Start packet capture
    while (keep_running) {
        // Process one packet
        if (pcap_dispatch(handle, 1, packet_handler, NULL) < 0) {
            break;
        }
        
        // Small sleep to prevent CPU hogging
        usleep(10000); // 10ms
    }
    
    // Print statistics before exiting
    print_stats();
    
    // Clean up
    pcap_close(handle);
    
    return 0;
}
