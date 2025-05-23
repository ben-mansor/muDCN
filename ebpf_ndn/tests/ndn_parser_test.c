#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

// Simplified NDN TLV definitions for testing
#define TLV_INTEREST 0x05
#define TLV_DATA 0x06
#define TLV_NAME 0x07
#define TLV_COMPONENT 0x08
#define TLV_NONCE 0x0A
#define TLV_INTEREST_LIFETIME 0x0C
#define TLV_SELECTORS 0x09

// Simplified NDN name structure for testing
#define MAX_NAME_LEN 256
struct ndn_name {
    char name[MAX_NAME_LEN];
    uint16_t len;
};

// TLV parser functions from our XDP program
static uint8_t parse_tlv_type(const void *data, uint16_t *offset) {
    uint8_t type = *(uint8_t *)((char *)data + *offset);
    (*offset)++;
    return type;
}

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
        return (length >> 8) | ((length & 0xff) << 8); /* Convert from network to host byte order */
    }
    
    /* Long length not supported in this implementation */
    return 0;
}

// Function to parse NDN name (simplified from the XDP version)
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

// Function to create a test NDN Interest packet
static uint32_t create_ndn_interest(uint8_t *buffer, uint32_t buffer_size, const char *name_uri) {
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

// Main test function
int main() {
    printf("NDN TLV Parser Test\n");
    printf("====================\n\n");
    
    // Initialize random seed
    srand(42); // Fixed seed for reproducible results
    
    // Test cases - array of NDN names to test
    const char *test_cases[] = {
        "/ndn/test/data1",
        "/example/video/segment1",
        "/test/with/many/components/data",
        "/a/very/long/name/that/might/be/truncated/if/it/exceeds/buffer/size",
        "/special/chars/!@#$%^&*()"
    };
    int num_tests = sizeof(test_cases) / sizeof(test_cases[0]);
    
    // Buffer for NDN packets
    uint8_t packet_buffer[1024];
    
    // Run tests
    for (int i = 0; i < num_tests; i++) {
        printf("Test Case %d: %s\n", i + 1, test_cases[i]);
        
        // Create an NDN Interest packet with the test name
        uint32_t packet_size = create_ndn_interest(packet_buffer, sizeof(packet_buffer), test_cases[i]);
        
        if (packet_size == 0) {
            printf("  Error: Failed to create NDN Interest packet\n\n");
            continue;
        }
        
        printf("  Created packet of size %d bytes\n", packet_size);
        
        // Parse the packet to extract the name
        uint16_t offset = 0;
        
        // Check packet type
        uint8_t pkt_type = parse_tlv_type(packet_buffer, &offset);
        if (pkt_type != TLV_INTEREST) {
            printf("  Error: Not an Interest packet (type = %d)\n\n", pkt_type);
            continue;
        }
        
        // Get interest length
        uint16_t interest_len = parse_tlv_length(packet_buffer, &offset);
        printf("  Interest TLV length: %d\n", interest_len);
        
        // Find the Name TLV
        uint8_t name_tlv_found = 0;
        while (offset < packet_size) {
            uint8_t tlv_type = parse_tlv_type(packet_buffer, &offset);
            
            if (tlv_type == TLV_NAME) {
                name_tlv_found = 1;
                uint16_t name_len = parse_tlv_length(packet_buffer, &offset);
                printf("  Name TLV length: %d\n", name_len);
                
                // Parse name components
                struct ndn_name parsed_name;
                parse_ndn_name(&parsed_name, packet_buffer, &offset, name_len);
                
                // Print the parsed name
                printf("  Parsed name: %s\n", parsed_name.name);
                
                // Verify
                if (strcmp(parsed_name.name, test_cases[i] + 1) == 0) { // Skip leading / in test cases
                    printf("  TEST PASSED: Name correctly parsed!\n");
                } else {
                    printf("  TEST FAILED: Name incorrectly parsed\n");
                    printf("    Expected: %s\n", test_cases[i] + 1);
                    printf("    Got: %s\n", parsed_name.name);
                }
                
                break;
            } else {
                // Skip over other TLV fields
                uint16_t field_len = parse_tlv_length(packet_buffer, &offset);
                offset += field_len;
            }
        }
        
        if (!name_tlv_found) {
            printf("  Error: Name TLV not found in packet\n");
        }
        
        printf("\n");
    }
    
    return 0;
}
