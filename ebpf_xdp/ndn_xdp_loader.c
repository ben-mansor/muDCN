//
// μDCN - XDP Program Loader
//
// This program loads the NDN XDP parser program, attaches it to an 
// interface, and provides a userspace API to interact with its maps.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>

// Include auto-generated skeleton from the ndn_parser.c
#include "ndn_parser.skel.h"

static volatile int keep_running = 1;

static void int_exit(int sig) {
    keep_running = 0;
}

void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "Options:\n"
        "  -i IFNAME    Interface to attach XDP program to\n"
        "  -S           Use skb-mode (default: driver mode)\n"
        "  -h           Display this help and exit\n",
        prog);
}

int main(int argc, char **argv) {
    struct ndn_parser_bpf *skel;
    int err, i, opt, stats_fd;
    char *ifname = NULL;
    int ifindex;
    int xdp_flags = XDP_FLAGS_DRV_MODE;
    __u32 key;
    __u64 value[4] = {0}; // Array for all CPUs
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:Sh")) != -1) {
        switch (opt) {
        case 'i':
            ifname = optarg;
            break;
        case 'S':
            xdp_flags = XDP_FLAGS_SKB_MODE;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return opt != 'h';
        }
    }
    
    if (!ifname) {
        fprintf(stderr, "Error: Required option -i missing\n");
        print_usage(argv[0]);
        return 1;
    }
    
    // Get interface index from name
    ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Error: Interface '%s' not found: %s\n", 
                ifname, strerror(errno));
        return 1;
    }
    
    // Initialize signal handling
    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);
    
    // Load and verify BPF application
    skel = ndn_parser_bpf__open();
    if (!skel) {
        fprintf(stderr, "Error: Failed to open and load BPF skeleton\n");
        return 1;
    }
    
    // Load BPF program
    err = ndn_parser_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to load BPF program: %s\n", strerror(errno));
        goto cleanup;
    }
    
    // Attach XDP program to interface
    err = bpf_set_link_xdp_fd(ifindex, bpf_program__fd(skel->progs.ndn_xdp_parser), xdp_flags);
    if (err) {
        fprintf(stderr, "Error: Failed to attach XDP program to interface '%s': %s\n",
                ifname, strerror(-err));
        goto cleanup;
    }
    
    // Get file descriptor for packet_stats map
    stats_fd = bpf_map__fd(skel->maps.packet_stats);
    if (stats_fd < 0) {
        fprintf(stderr, "Error: Failed to get file descriptor for stats map\n");
        goto cleanup;
    }
    
    printf("Successfully attached XDP program to %s (ifindex %d)\n", ifname, ifindex);
    printf("Press Ctrl+C to exit and detach program\n");
    
    // Main loop: periodically print statistics
    while (keep_running) {
        // Print statistics for Interest packets
        key = 5; // NDN_INTEREST
        if (bpf_map_lookup_elem(stats_fd, &key, value) == 0) {
            __u64 sum = 0;
            for (i = 0; i < 4; i++) // Sum up per-CPU values
                sum += value[i];
            printf("Interests processed: %llu\n", sum);
        }
        
        // Print statistics for Data packets
        key = 6; // NDN_DATA
        if (bpf_map_lookup_elem(stats_fd, &key, value) == 0) {
            __u64 sum = 0;
            for (i = 0; i < 4; i++) // Sum up per-CPU values
                sum += value[i];
            printf("Data packets processed: %llu\n", sum);
        }
        
        sleep(1);
    }
    
    // Detach XDP program and cleanup
    bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
    printf("\nDetached XDP program from %s\n", ifname);
    
cleanup:
    ndn_parser_bpf__destroy(skel);
    return err != 0;
}
