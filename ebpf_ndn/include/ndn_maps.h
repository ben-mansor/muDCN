/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __NDN_MAPS_H
#define __NDN_MAPS_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <stdint.h>

/* NDN packet types */
#define NDN_INTEREST 5
#define NDN_DATA 6
#define NDN_NACK 7

/* NDN TLV types */
#define TLV_INTEREST 0x05
#define TLV_NAME 0x07
#define TLV_SELECTORS 0x09
#define TLV_NONCE 0x0A

/* Maximum length for NDN name components */
#define MAX_NAME_LEN 256

/* NDN name component structure */
struct ndn_name {
    char name[MAX_NAME_LEN];
    uint16_t len;
};

/* Forward declaration for the name cache map */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1024);
    __type(key, struct ndn_name);
    __type(value, int);
} name_cache SEC(".maps");

/* Forward declaration for the redirect map for interest forwarding */
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(max_entries, 32);
    __type(key, uint32_t);
    __type(value, uint32_t);
} redirect_map SEC(".maps");

/* Forward declaration for the interface info map */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 32);
    __type(key, uint32_t);
    __type(value, uint32_t); /* Stores MTU and other interface info */
} interface_info SEC(".maps");

/* Forward declaration for stats map */
struct ndn_stats {
    uint64_t interests_received;
    uint64_t interests_forwarded;
    uint64_t data_received;
    uint64_t data_forwarded;
    uint64_t cache_hits;
    uint64_t cache_misses;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct ndn_stats);
} stats_map SEC(".maps");

#endif /* __NDN_MAPS_H */
