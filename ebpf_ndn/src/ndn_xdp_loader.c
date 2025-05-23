#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/resource.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <getopt.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <time.h>

// Same as in ndn_xdp.c
struct ndn_stats {
    uint64_t interests_received;
    uint64_t interests_forwarded;
    uint64_t interests_dropped;
    uint64_t data_received;
    uint64_t data_forwarded;
    uint64_t cache_hits;
    uint64_t cache_misses;
};

struct ndn_name {
    char name[256];
    uint16_t len;
};

static int xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static int ifindex;
static int verbose = 0;
static volatile int keep_running = 1;
static char ifname[IF_NAMESIZE];
static int name_cache_fd;
static int stats_map_fd;
static int redirect_map_fd;

static void int_exit(int sig) {
    keep_running = 0;
}

// Increase rlimit for locked memory
static void bump_rlimit(void) {
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    
    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Warning: failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
    }
}

// Print statistics from the stats map
static void print_stats(void) {
    struct ndn_stats stats;
    uint32_t key = 0;
    
    if (bpf_map_lookup_elem(stats_map_fd, &key, &stats)) {
        fprintf(stderr, "Error: failed to read statistics\n");
        return;
    }
    
    printf("\nNDN XDP Statistics:\n");
    printf("  Interests received:  %llu\n", stats.interests_received);
    printf("  Interests forwarded: %llu\n", stats.interests_forwarded);
    printf("  Interests dropped:   %llu\n", stats.interests_dropped);
    printf("  Data received:       %llu\n", stats.data_received);
    printf("  Data forwarded:      %llu\n", stats.data_forwarded);
    printf("  Cache hits:          %llu\n", stats.cache_hits);
    printf("  Cache misses:        %llu\n", stats.cache_misses);
}

// Print cache entries (top 10)
static void print_cache_entries(void) {
    struct ndn_name key, next_key;
    uint64_t value;
    int count = 0;
    
    printf("\nNDN Name Cache (recent entries):\n");
    
    // Zero out the key for initial lookup
    memset(&key, 0, sizeof(key));
    
    // Loop through all cache entries
    while (bpf_map_get_next_key(name_cache_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(name_cache_fd, &next_key, &value) == 0) {
            printf("  %s (timestamp: %llu)\n", next_key.name, value);
            count++;
        }
        
        // Store this key for the next iteration
        memcpy(&key, &next_key, sizeof(key));
        
        // Only show 10 entries
        if (count >= 10) {
            printf("  ... (and more)\n");
            break;
        }
    }
    
    if (count == 0) {
        printf("  <empty>\n");
    }
}

// Configure interface redirection
static int setup_redirect(uint32_t from_ifindex, uint32_t to_ifindex) {
    if (bpf_map_update_elem(redirect_map_fd, &from_ifindex, &to_ifindex, BPF_ANY)) {
        fprintf(stderr, "Error: failed to update redirect map: %s\n", strerror(errno));
        return -1;
    }
    
    printf("Configured forwarding from interface %d to interface %d\n",
           from_ifindex, to_ifindex);
    return 0;
}

// Initialize stats map
static void init_stats_map(void) {
    struct ndn_stats stats = {0};
    uint32_t key = 0;
    
    bpf_map_update_elem(stats_map_fd, &key, &stats, BPF_ANY);
}

// Usage information
static void usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n", prog);
    printf("Options:\n");
    printf("  -i INTERFACE    Network interface to attach XDP program\n");
    printf("  -r INTERFACE    Redirect traffic to this interface (optional)\n");
    printf("  -s              Use skb mode instead of native XDP\n");
    printf("  -d              Use driver/native XDP mode (default)\n");
    printf("  -H              Use hardware offload XDP mode\n");
    printf("  -v              Verbose output\n");
    printf("  -h              Show this help\n");
    printf("\nExample:\n");
    printf("  %s -i eth0 -r eth1    # Attach to eth0, redirect to eth1\n", prog);
}

int main(int argc, char **argv) {
    struct bpf_prog_load_attr prog_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
    };
    struct bpf_object *obj;
    struct bpf_program *prog;
    int prog_fd, opt, err;
    char *redirect_iface = NULL;
    uint32_t redirect_ifindex = 0;
    
    // Parse command line options
    while ((opt = getopt(argc, argv, "i:r:sHdhv")) != -1) {
        switch (opt) {
            case 'i': // Interface to attach XDP program
                strncpy(ifname, optarg, IF_NAMESIZE);
                ifindex = if_nametoindex(ifname);
                if (!ifindex) {
                    fprintf(stderr, "Error: interface '%s' not found\n", ifname);
                    return EXIT_FAILURE;
                }
                break;
                
            case 'r': // Redirect interface
                redirect_iface = optarg;
                redirect_ifindex = if_nametoindex(redirect_iface);
                if (!redirect_ifindex) {
                    fprintf(stderr, "Error: redirect interface '%s' not found\n", redirect_iface);
                    return EXIT_FAILURE;
                }
                break;
                
            case 's': // SKB mode
                xdp_flags = XDP_FLAGS_SKB_MODE;
                break;
                
            case 'd': // Driver/native mode (default)
                xdp_flags = XDP_FLAGS_DRV_MODE;
                break;
                
            case 'H': // Hardware offload mode
                xdp_flags = XDP_FLAGS_HW_MODE;
                break;
                
            case 'v': // Verbose
                verbose = 1;
                break;
                
            case 'h': // Help
                usage(argv[0]);
                return EXIT_SUCCESS;
                
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }
    
    if (!ifindex) {
        fprintf(stderr, "Error: interface must be specified with -i\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    // Increase resource limits for locked memory
    bump_rlimit();
    
    // Set up signal handler
    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);
    
    // Load BPF program
    prog_load_attr.file = "ndn_xdp.o";
    
    err = bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd);
    if (err) {
        fprintf(stderr, "Error: failed to load BPF program: %s\n", strerror(-err));
        return EXIT_FAILURE;
    }
    
    // Find the XDP program
    prog = bpf_object__find_program_by_name(obj, "ndn_xdp_func");
    if (!prog) {
        fprintf(stderr, "Error: failed to find XDP program in BPF object\n");
        return EXIT_FAILURE;
    }
    
    // Get program file descriptor
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Error: failed to get XDP program file descriptor\n");
        return EXIT_FAILURE;
    }
    
    // Get map file descriptors
    name_cache_fd = bpf_object__find_map_fd_by_name(obj, "name_cache");
    stats_map_fd = bpf_object__find_map_fd_by_name(obj, "stats_map");
    redirect_map_fd = bpf_object__find_map_fd_by_name(obj, "redirect_map");
    
    if (name_cache_fd < 0 || stats_map_fd < 0 || redirect_map_fd < 0) {
        fprintf(stderr, "Error: failed to find BPF maps\n");
        return EXIT_FAILURE;
    }
    
    // Initialize the stats map
    init_stats_map();
    
    // Set up redirection if specified
    if (redirect_ifindex) {
        if (setup_redirect(ifindex, redirect_ifindex) < 0) {
            return EXIT_FAILURE;
        }
    }
    
    // Attach the program to the interface
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
    if (err) {
        fprintf(stderr, "Error: failed to attach XDP program to %s: %s\n",
                ifname, strerror(-err));
        return EXIT_FAILURE;
    }
    
    printf("Successfully attached XDP program to %s (ifindex %d)\n", ifname, ifindex);
    printf("XDP mode: %s\n", 
           xdp_flags & XDP_FLAGS_SKB_MODE ? "SKB/generic" : 
           xdp_flags & XDP_FLAGS_HW_MODE ? "hardware offload" : 
           "driver/native");
    
    if (redirect_ifindex) {
        printf("Redirecting packets to %s (ifindex %d)\n", redirect_iface, redirect_ifindex);
    }
    
    printf("\nPress Ctrl+C to stop and view statistics\n");
    
    // Main loop - just wait for Ctrl+C and print stats periodically
    while (keep_running) {
        sleep(2);
        if (verbose) {
            print_stats();
            print_cache_entries();
        }
    }
    
    // Print final statistics
    printf("\nFinal statistics:\n");
    print_stats();
    print_cache_entries();
    
    // Detach the program from the interface
    bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
    printf("\nDetached XDP program from %s\n", ifname);
    
    return EXIT_SUCCESS;
}
