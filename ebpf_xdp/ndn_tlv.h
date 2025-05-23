//
// μDCN - NDN TLV Definitions
//
// This file contains definitions for NDN TLV packet format to be used
// by the XDP packet parser and other components.
//

#ifndef NDN_TLV_H
#define NDN_TLV_H

// NDN packet types
#define NDN_INTEREST 0x05
#define NDN_DATA     0x06
#define NDN_NACK     0x03

// NDN TLV types - Common
#define NDN_TLV_NAME                0x07
#define NDN_TLV_NAME_COMPONENT      0x08
#define NDN_TLV_IMPLIED_SHA256_DIGEST_COMPONENT 0x01
#define NDN_TLV_PARAMETERS_SHA256_DIGEST_COMPONENT 0x02

// Interest packet specific TLV types
#define NDN_TLV_SELECTORS           0x09
#define NDN_TLV_NONCE               0x0A
#define NDN_TLV_INTEREST_LIFETIME   0x0C
#define NDN_TLV_FORWARDING_HINT     0x1E
#define NDN_TLV_CAN_BE_PREFIX       0x21
#define NDN_TLV_MUST_BE_FRESH       0x12
#define NDN_TLV_HOP_LIMIT           0x22

// Data packet specific TLV types
#define NDN_TLV_METAINFO            0x14
#define NDN_TLV_CONTENT             0x15
#define NDN_TLV_SIGNATURE_INFO      0x16
#define NDN_TLV_SIGNATURE_VALUE     0x17

// MetaInfo TLV types
#define NDN_TLV_CONTENT_TYPE        0x18
#define NDN_TLV_FRESHNESS_PERIOD    0x19
#define NDN_TLV_FINAL_BLOCK_ID      0x1A

// Content types
#define NDN_CONTENT_TYPE_BLOB       0x00
#define NDN_CONTENT_TYPE_LINK       0x01
#define NDN_CONTENT_TYPE_KEY        0x02
#define NDN_CONTENT_TYPE_NACK       0x03

// NDN TLV header with variable-length encoding support
struct ndn_tlv_hdr {
    __u8 type;    // TLV Type
    __u8 length;  // TLV Length (can be extended)
} __attribute__((packed));

// Extended length formats
#define NDN_TLV_LEN_1BYTE_VAL       0xFD  // 2-byte length follows
#define NDN_TLV_LEN_2BYTE_VAL       0xFE  // 4-byte length follows
#define NDN_TLV_LEN_4BYTE_VAL       0xFF  // 8-byte length follows

// NDN packet basic structure
struct ndn_packet {
    struct ndn_tlv_hdr hdr;
    __u8 data[0];
} __attribute__((packed));

// NDN Content Store entry
struct cs_entry {
    __u64 timestamp;     // Creation timestamp
    __u64 expiry;        // Expiration time
    __u16 content_len;   // Length of content
    __u16 signature_len; // Length of signature
    __u8 data[0];        // Variable length data
} __attribute__((packed));

// Hash function types for NDN names
#define HASH_ALGO_SIMPLE     0  // Simple XOR-based hash (for testing)
#define HASH_ALGO_JENKINS    1  // Jenkins hash
#define HASH_ALGO_MURMUR     2  // MurmurHash3
#define HASH_ALGO_XXHASH     3  // xxHash

// NDN metrics counter indexes
#define METRIC_INTERESTS_RECV    0
#define METRIC_DATA_RECV         1
#define METRIC_NACKS_RECV        2
#define METRIC_CACHE_HITS        3
#define METRIC_CACHE_MISSES      4
#define METRIC_REDIRECTS         5
#define METRIC_DROPS             6
#define METRIC_ERRORS            7
#define METRIC_MAX               8  // Total number of metrics

#endif /* NDN_TLV_H */
