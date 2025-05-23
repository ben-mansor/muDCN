#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>

// NDN TLV types
#define TLV_INTEREST 0x05
#define TLV_NAME 0x07
#define TLV_COMPONENT 0x08
#define TLV_NONCE 0x0A
#define TLV_INTEREST_LIFETIME 0x0C

// NDN default UDP port
#define NDN_DEFAULT_PORT 6363

// Max packet size
#define MAX_PACKET_SIZE 1500
#define MAX_NAME_LEN 256

// UDP packet structure
struct packet {
    struct ethhdr eth;
    struct iphdr ip;
    struct udphdr udp;
    uint8_t ndn_data[MAX_PACKET_SIZE - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr)];
    uint32_t ndn_data_len;
};

// Helper function to calculate IP checksum
static uint16_t ip_checksum(void *vdata, size_t length) {
    uint16_t *data = vdata;
    uint32_t sum = 0;
    
    // Sum all 16-bit words
    while (length > 1) {
        sum += *data++;
        length -= 2;
    }
    
    // If there's an odd byte left, add it
    if (length == 1) {
        sum += *(uint8_t *)data;
    }
    
    // Fold 32-bit sum to 16 bits
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    return ~sum;
}

// Create an NDN Interest packet with the given name
static uint32_t create_ndn_interest(uint8_t *buffer, uint32_t buffer_size, const char *name_uri) {
    if (!buffer || buffer_size < 64 || !name_uri) {
        return 0;
    }

    uint32_t offset = 0;
    uint8_t *ptr = buffer;

    // Interest TLV type
    ptr[offset++] = TLV_INTEREST;
    
    // Reserve space for Interest length (will be filled in later)
    uint32_t interest_length_pos = offset;
    offset++;
    
    // Name TLV
    ptr[offset++] = TLV_NAME;
    
    // Reserve space for Name length (will be filled in later)
    uint32_t name_length_pos = offset;
    offset++;
    
    uint32_t name_start = offset;
    
    // Parse and encode each component from URI (e.g., "/foo/bar")
    const char *p = name_uri;
    if (*p == '/') p++; // Skip initial slash
    
    while (*p) {
        const char *component_start = p;
        
        // Find the end of this component
        while (*p && *p != '/') p++;
        
        uint32_t component_len = p - component_start;
        if (component_len > 0) {
            // Add component type
            ptr[offset++] = TLV_COMPONENT;
            // Add component length
            ptr[offset++] = component_len;
            // Add component value
            memcpy(ptr + offset, component_start, component_len);
            offset += component_len;
        }
        
        // Skip the slash
        if (*p == '/') p++;
    }
    
    // Fill in Name TLV length
    uint32_t name_length = offset - name_start;
    ptr[name_length_pos] = name_length;
    
    // Add Nonce TLV
    ptr[offset++] = TLV_NONCE;
    ptr[offset++] = 4; // Length (4 bytes)
    
    // Generate a random nonce
    uint32_t nonce = rand();
    memcpy(ptr + offset, &nonce, sizeof(nonce));
    offset += sizeof(nonce);
    
    // Add Interest Lifetime TLV
    ptr[offset++] = TLV_INTEREST_LIFETIME;
    ptr[offset++] = 2; // Length (2 bytes)
    
    // Set lifetime to 4 seconds (4000 ms)
    uint16_t lifetime = htons(4000);
    memcpy(ptr + offset, &lifetime, sizeof(lifetime));
    offset += sizeof(lifetime);
    
    // Fill in Interest TLV length
    uint32_t interest_length = offset - interest_length_pos - 1;
    ptr[interest_length_pos] = interest_length;
    
    return offset; // Return total packet size
}

// Send a UDP packet containing an NDN Interest
static int send_ndn_interest(const char *dest_ip, uint16_t dest_port, const char *name_uri) {
    struct packet pkt;
    struct sockaddr_in dest_addr;
    int sockfd, ret;
    
    // Create raw socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }
    
    // Clear the packet struct
    memset(&pkt, 0, sizeof(pkt));
    
    // Create the NDN Interest
    pkt.ndn_data_len = create_ndn_interest(pkt.ndn_data, sizeof(pkt.ndn_data), name_uri);
    if (pkt.ndn_data_len == 0) {
        fprintf(stderr, "Failed to create NDN Interest\n");
        close(sockfd);
        return -1;
    }
    
    // Set up the destination address
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(dest_port);
    if (inet_pton(AF_INET, dest_ip, &dest_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sockfd);
        return -1;
    }
    
    // Send the packet
    ret = sendto(sockfd, pkt.ndn_data, pkt.ndn_data_len, 0,
                 (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (ret < 0) {
        perror("sendto");
        close(sockfd);
        return -1;
    }
    
    printf("Sent NDN Interest: %s (%d bytes)\n", name_uri, ret);
    
    close(sockfd);
    return 0;
}

// Print usage information
static void print_usage(const char *progname) {
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("Options:\n");
    printf("  -d DEST_IP    Destination IP address (default: 127.0.0.1)\n");
    printf("  -p PORT       Destination port (default: %d)\n", NDN_DEFAULT_PORT);
    printf("  -n NAME       NDN name to request (default: /test/data)\n");
    printf("  -c COUNT      Number of packets to send (default: 1)\n");
    printf("  -i INTERVAL   Interval between packets in ms (default: 1000)\n");
    printf("  -r            Send same request repeatedly (default: false)\n");
    printf("  -h            Print this help message\n");
}

int main(int argc, char **argv) {
    char *dest_ip = "127.0.0.1";
    uint16_t dest_port = NDN_DEFAULT_PORT;
    char *name = "/test/data";
    int count = 1;
    int interval_ms = 1000;
    int repeat = 0;
    int opt;
    
    // Initialize random number generator
    srand(time(NULL));
    
    // Parse command-line options
    while ((opt = getopt(argc, argv, "d:p:n:c:i:rh")) != -1) {
        switch (opt) {
        case 'd':
            dest_ip = optarg;
            break;
        case 'p':
            dest_port = (uint16_t)atoi(optarg);
            break;
        case 'n':
            name = optarg;
            break;
        case 'c':
            count = atoi(optarg);
            break;
        case 'i':
            interval_ms = atoi(optarg);
            break;
        case 'r':
            repeat = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }
    
    printf("NDN Interest Generator\n");
    printf("---------------------\n");
    printf("Destination: %s:%d\n", dest_ip, dest_port);
    printf("Name: %s\n", name);
    printf("Count: %d\n", count);
    printf("Interval: %d ms\n", interval_ms);
    printf("Repeat mode: %s\n\n", repeat ? "on" : "off");
    
    // Send packets
    for (int i = 0; i < count; i++) {
        char current_name[MAX_NAME_LEN];
        
        if (repeat) {
            // Use the same name for all packets
            snprintf(current_name, sizeof(current_name), "%s", name);
        } else {
            // Append a unique identifier to the name
            snprintf(current_name, sizeof(current_name), "%s/%d", name, i + 1);
        }
        
        if (send_ndn_interest(dest_ip, dest_port, current_name) < 0) {
            fprintf(stderr, "Failed to send packet %d\n", i + 1);
        }
        
        // Wait for the specified interval
        if (i < count - 1 && interval_ms > 0) {
            usleep(interval_ms * 1000);
        }
    }
    
    return 0;
}
