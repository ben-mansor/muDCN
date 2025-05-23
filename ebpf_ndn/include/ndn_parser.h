/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NDN_PARSER_H
#define __NDN_PARSER_H

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <stdint.h>

/*
 * NDN packet format (TLV encoding)
 * Each TLV has:
 * - Type (1 byte for small types)
 * - Length (1 byte for small lengths)
 * - Value (variable length)
 */

/* NDN TLV types (common) */
#define TLV_INTEREST 0x05
#define TLV_DATA 0x06
#define TLV_NACK 0x03
#define TLV_NAME 0x07
#define TLV_COMPONENT 0x08
#define TLV_NONCE 0x0A
#define TLV_INTEREST_LIFETIME 0x0C
#define TLV_SELECTORS 0x09
#define TLV_CONTENT 0x15

/* NDN header parsing helper functions */
static __always_inline uint8_t parse_tlv_type(const void *data, uint16_t *offset)
{
    uint8_t type = *(uint8_t *)((char *)data + *offset);
    (*offset)++;
    return type;
}

static __always_inline uint8_t parse_tlv_length_small(const void *data, uint16_t *offset)
{
    uint8_t length = *(uint8_t *)((char *)data + *offset);
    (*offset)++;
    return length;
}

static __always_inline uint16_t parse_tlv_length(const void *data, uint16_t *offset)
{
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
        return __builtin_bswap16(length); /* Convert from network to host byte order */
    }
    
    /* Long length not supported in this implementation */
    return 0;
}

/* Struct to hold parsed NDN Interest packet information */
struct ndn_interest_info {
    char name[256];       /* Name (URI format) */
    uint16_t name_len;    /* Name length */
    uint32_t nonce;       /* Nonce value */
    uint16_t lifetime;    /* Interest lifetime in ms */
};

#endif /* __NDN_PARSER_H */
