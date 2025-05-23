#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <time.h>
#include <inttypes.h>

#include "../include/ndn_parser.h"

// Structure for packet generation
struct packet_info {
    struct ethhdr eth;
    struct iphdr ip;
    struct udphdr udp;
    uint8_t ndn_data[512]; // NDN TLV data buffer
    uint32_t ndn_data_len;
};

static volatile int running = 1;

// Signal handler for Ctrl+C
static void handle_sigint(int sig) {
    running = 0;
    printf("\nExiting test program...\n");
}

// Helper function to create an NDN Interest packet
static uint32_t create_ndn_interest(
    uint8_t *buffer,
    uint32_t buffer_size,
    const char *name_uri)
{
    if (!buffer || buffer_size < 64 || !name_uri) {
        return 0;
    }

    uint32_t offset = 0;
    uint8_t *ptr = buffer;

    // Interest TLV type
    ptr[offset++] = TLV_INTEREST;
    
    // We'll set the length later
    uint32_t length_pos = offset;
    offset++; // Reserve space for length
    
    // Name TLV
    ptr[offset++] = TLV_NAME;
    
    // Count name components
    uint32_t name_len_pos = offset;
    offset++; // Reserve space for name length
    
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
    
    // Set name TLV length
    uint32_t name_length = offset - name_start;
    ptr[name_len_pos] = name_length;
    
    // Add Nonce TLV
    ptr[offset++] = TLV_NONCE;
    ptr[offset++] = 4; // Length
    
    // Generate a random nonce
    uint32_t nonce = rand();
    memcpy(ptr + offset, &nonce, sizeof(nonce));
    offset += sizeof(nonce);
    
    // Set Interest TLV length
    uint32_t interest_length = offset - length_pos - 1;
    ptr[length_pos] = interest_length;
    
    return offset; // Return total packet size
}

// Send a test NDN packet
static int send_test_packet(
    pcap_t *handle,
    const char *name_uri,
    const uint8_t *src_mac,
    const uint8_t *dst_mac,
    const char *src_ip,
    const char *dst_ip,
    uint16_t src_port,
    uint16_t dst_port)
{
    struct packet_info packet;
    memset(&packet, 0, sizeof(packet));
    
    // Ethernet header
    memcpy(packet.eth.h_dest, dst_mac, ETH_ALEN);
    memcpy(packet.eth.h_source, src_mac, ETH_ALEN);
    packet.eth.h_proto = htons(ETH_P_IP);
    
    // IP header
    packet.ip.version = 4;
    packet.ip.ihl = 5; // 5 * 4 = 20 bytes
    packet.ip.tos = 0;
    packet.ip.tot_len = 0; // Fill in later
    packet.ip.id = htons(rand() & 0xFFFF);
    packet.ip.frag_off = 0;
    packet.ip.ttl = 64;
    packet.ip.protocol = IPPROTO_UDP;
    packet.ip.check = 0; // Fill in later
    packet.ip.saddr = inet_addr(src_ip);
    packet.ip.daddr = inet_addr(dst_ip);
    
    // UDP header
    packet.udp.source = htons(src_port);
    packet.udp.dest = htons(dst_port);
    packet.udp.len = 0; // Fill in later
    packet.udp.check = 0; // Optional for IPv4
    
    // Create NDN Interest packet
    packet.ndn_data_len = create_ndn_interest(
        packet.ndn_data, sizeof(packet.ndn_data), name_uri);
    
    if (packet.ndn_data_len == 0) {
        fprintf(stderr, "Failed to create NDN interest\n");
        return -1;
    }
    
    // Calculate header lengths
    uint32_t udp_len = sizeof(packet.udp) + packet.ndn_data_len;
    packet.udp.len = htons(udp_len);
    
    uint32_t ip_len = sizeof(packet.ip) + udp_len;
    packet.ip.tot_len = htons(ip_len);
    
    // Calculate IP checksum
    // (For a real implementation, a proper checksum function would be used)
    packet.ip.check = 0;
    
    // Prepare final packet buffer
    uint32_t pkt_size = sizeof(packet.eth) + ip_len;
    uint8_t *pkt_buffer = malloc(pkt_size);
    if (!pkt_buffer) {
        fprintf(stderr, "Failed to allocate packet buffer\n");
        return -1;
    }
    
    // Copy headers to packet buffer
    uint32_t offset = 0;
    memcpy(pkt_buffer + offset, &packet.eth, sizeof(packet.eth));
    offset += sizeof(packet.eth);
    
    memcpy(pkt_buffer + offset, &packet.ip, sizeof(packet.ip));
    offset += sizeof(packet.ip);
    
    memcpy(pkt_buffer + offset, &packet.udp, sizeof(packet.udp));
    offset += sizeof(packet.udp);
    
    memcpy(pkt_buffer + offset, packet.ndn_data, packet.ndn_data_len);
    
    // Send the packet
    if (pcap_sendpacket(handle, pkt_buffer, pkt_size) != 0) {
        fprintf(stderr, "Failed to send packet: %s\n", pcap_geterr(handle));
        free(pkt_buffer);
        return -1;
    }
    
    printf("Sent NDN Interest packet with name: %s\n", name_uri);
    free(pkt_buffer);
    return 0;
}

// Print usage information
static void print_usage(const char *prog_name) {
    printf("Usage: %s [-i interface] [-c count] [-r rate]\n", prog_name);
    printf("  -i interface  Interface to send packets on (default: eth0)\n");
    printf("  -c count      Number of packets to send (default: 10)\n");
    printf("  -r rate       Packets per second (default: 1)\n");
}

int main(int argc, char **argv) {
    char *interface = "eth0";
    int packet_count = 10;
    float rate = 1.0;
    
    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "i:c:r:")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'c':
                packet_count = atoi(optarg);
                break;
            case 'r':
                rate = atof(optarg);
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Initialize random number generator
    srand(time(NULL));
    
    // Open pcap device for sending packets
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Failed to open interface %s: %s\n", interface, errbuf);
        return 1;
    }
    
    // Set up signal handler for clean exit
    signal(SIGINT, handle_sigint);
    
    // Set up packet parameters
    uint8_t src_mac[ETH_ALEN] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    uint8_t dst_mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    char src_ip[] = "192.168.1.10";
    char dst_ip[] = "192.168.1.20";
    uint16_t src_port = 6363;
    uint16_t dst_port = 6363;
    
    // NDN name templates for testing
    const char *name_templates[] = {
        "/test/data1",
        "/test/data2",
        "/ndn/interest/example",
        "/example/video/segment1",
        "/example/video/segment2"
    };
    int num_templates = sizeof(name_templates) / sizeof(name_templates[0]);
    
    // Calculate delay between packets
    long delay_us = rate > 0 ? (long)(1000000.0 / rate) : 1000000;
    
    printf("Starting NDN packet test on interface %s\n", interface);
    printf("Sending %d packets at %.2f packets/second\n", packet_count, rate);
    printf("Press Ctrl+C to stop\n\n");
    
    int packets_sent = 0;
    while (running && packets_sent < packet_count) {
        // Select a random name from templates
        const char *name = name_templates[rand() % num_templates];
        
        // Send test packet
        if (send_test_packet(handle, name, src_mac, dst_mac, 
                             src_ip, dst_ip, src_port, dst_port) == 0) {
            packets_sent++;
        }
        
        // Sleep between packets
        usleep(delay_us);
    }
    
    printf("\nTest completed: sent %d packets\n", packets_sent);
    
    // Clean up
    pcap_close(handle);
    return 0;
}
