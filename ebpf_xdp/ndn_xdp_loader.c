//
// μDCN - XDP Program Loader
//
// This program loads the NDN XDP parser program, attaches it to an 
// interface, and provides a userspace API to interact with its maps.
// It supports advanced features like content store management, metrics
// collection, and forwarding configuration.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>

// NDN TLV definitions
#include "ndn_tlv.h"

// Include auto-generated skeleton from the ndn_parser.c
#include "ndn_parser.skel.h"

// Program state and configuration
static volatile int keep_running = 1;
static struct xdp_config program_config = {
    .hash_algorithm = HASH_ALGO_JENKINS,
    .cs_enabled = 1,
    .pit_enabled = 1,
    .metrics_enabled = 1,
    .default_ttl = 300,  // 5 minutes default TTL
    .cs_max_size = 2048  // 2KB max content size
};

// Structure for metrics monitoring
struct metrics_data {
    __u64 interests_recv;
    __u64 data_recv;
    __u64 nacks_recv;
    __u64 cache_hits;
    __u64 cache_misses;
    __u64 redirects;
    __u64 drops;
    __u64 errors;
};

// Signal handler for graceful shutdown
static void int_exit(int sig) {
    keep_running = 0;
}

// Print usage information
void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "Options:\n"
        "  -i IFNAME       Interface to attach XDP program to\n"
        "  -S              Use skb-mode (default: driver mode)\n"
        "  -c CAPACITY     Content store capacity (default: 10240)\n"
        "  -t TTL          Content store TTL in seconds (default: 300)\n"
        "  -a ALGORITHM    Name hash algorithm (0=simple, 1=jenkins, 2=murmur)\n"
        "  -d              Disable content store\n"
        "  -p              Disable PIT\n"
        "  -m              Disable metrics collection\n"
        "  -r INTERVAL     Reporting interval in seconds (default: 1)\n"
        "  -o OUTPUT       Output file for metrics (default: stdout)\n"
        "  -h              Display this help and exit\n",
        prog);
}

// Update XDP program configuration
int update_config(int config_fd) {
    __u32 key = 0;
    return bpf_map_update_elem(config_fd, &key, &program_config, BPF_ANY);
}

// Initialize FIB with default routes
int init_fib(int fib_fd, int ifindex) {
    // Default catch-all route - just an example
    __u64 default_prefix = 0xFFFFFFFFFFFFFFFF;
    __u32 output_if = ifindex;
    
    return bpf_map_update_elem(fib_fd, &default_prefix, &output_if, BPF_ANY);
}

// Collect metrics from the XDP program
int collect_metrics(int metrics_fd, struct metrics_data *data) {
    __u32 key;
    __u64 values[4] = {0}; // 4 CPUs max for this example
    __u64 sum;
    
    // Collect each metric
    for (key = 0; key < METRIC_MAX; key++) {
        if (bpf_map_lookup_elem(metrics_fd, &key, values) != 0) {
            fprintf(stderr, "Error looking up metric %d\n", key);
            continue;
        }
        
        // Sum up per-CPU values
        sum = 0;
        for (int i = 0; i < 4; i++) {
            sum += values[i];
        }
        
        // Store in the appropriate metric field
        switch (key) {
            case METRIC_INTERESTS_RECV: data->interests_recv = sum; break;
            case METRIC_DATA_RECV: data->data_recv = sum; break;
            case METRIC_NACKS_RECV: data->nacks_recv = sum; break;
            case METRIC_CACHE_HITS: data->cache_hits = sum; break;
            case METRIC_CACHE_MISSES: data->cache_misses = sum; break;
            case METRIC_REDIRECTS: data->redirects = sum; break;
            case METRIC_DROPS: data->drops = sum; break;
            case METRIC_ERRORS: data->errors = sum; break;
        }
    }
    
    return 0;
}

// Print metrics to output stream
void print_metrics(FILE *out, struct metrics_data *data) {
    time_t now = time(NULL);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    fprintf(out, "[%s] μDCN Metrics Report:\n", timestamp);
    fprintf(out, "  Interests Received: %llu\n", data->interests_recv);
    fprintf(out, "  Data Packets Received: %llu\n", data->data_recv);
    fprintf(out, "  NACK Packets Received: %llu\n", data->nacks_recv);
    fprintf(out, "  Cache Hits: %llu\n", data->cache_hits);
    fprintf(out, "  Cache Misses: %llu\n", data->cache_misses);
    fprintf(out, "  Packet Redirections: %llu\n", data->redirects);
    fprintf(out, "  Packets Dropped: %llu\n", data->drops);
    fprintf(out, "  Errors: %llu\n", data->errors);
    
    // Calculate hit rate if there were any cache lookups
    if (data->cache_hits + data->cache_misses > 0) {
        double hit_rate = (double)data->cache_hits / (data->cache_hits + data->cache_misses) * 100.0;
        fprintf(out, "  Cache Hit Rate: %.2f%%\n", hit_rate);
    }
    
    fprintf(out, "\n");
    fflush(out);
}

int main(int argc, char **argv) {
    struct ndn_parser_bpf *skel;
    int err, i, opt;
    char *ifname = NULL;
    char *output_file = NULL;
    int ifindex;
    int xdp_flags = XDP_FLAGS_DRV_MODE;
    int metrics_interval = 1; // Default reporting interval (seconds)
    FILE *metrics_output = stdout;
    int cs_capacity = 10240; // Default content store capacity
    
    // Map file descriptors
    int metrics_fd, config_fd, cs_fd, fib_fd, pit_fd;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:Sc:t:a:dpmr:o:h")) != -1) {
        switch (opt) {
        case 'i':
            ifname = optarg;
            break;
        case 'S':
            xdp_flags = XDP_FLAGS_SKB_MODE;
            break;
        case 'c':
            cs_capacity = atoi(optarg);
            break;
        case 't':
            program_config.default_ttl = atoi(optarg);
            break;
        case 'a':
            program_config.hash_algorithm = atoi(optarg);
            break;
        case 'd':
            program_config.cs_enabled = 0;
            break;
        case 'p':
            program_config.pit_enabled = 0;
            break;
        case 'm':
            program_config.metrics_enabled = 0;
            break;
        case 'r':
            metrics_interval = atoi(optarg);
            break;
        case 'o':
            output_file = optarg;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Validate command line arguments
    if (!ifname) {
        fprintf(stderr, "Error: Required option -i missing\n");
        print_usage(argv[0]);
        return 1;
    }
    
    // Validate configuration values
    if (program_config.hash_algorithm > HASH_ALGO_XXHASH) {
        fprintf(stderr, "Error: Invalid hash algorithm. Using default (Jenkins)\n");
        program_config.hash_algorithm = HASH_ALGO_JENKINS;
    }
    
    if (program_config.default_ttl < 1) {
        fprintf(stderr, "Error: TTL must be positive. Using default (300)\n");
        program_config.default_ttl = 300;
    }
    
    if (cs_capacity < 1) {
        fprintf(stderr, "Error: Content store capacity must be positive. Using default (10240)\n");
        cs_capacity = 10240;
    }
    
    // Open metrics output file if specified
    if (output_file) {
        metrics_output = fopen(output_file, "a");
        if (!metrics_output) {
            fprintf(stderr, "Error: Could not open output file '%s': %s\n", 
                    output_file, strerror(errno));
            metrics_output = stdout;
        }
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
    
    // Increase RLIMIT_MEMLOCK to allow BPF verifier to do more work
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Warning: Failed to increase RLIMIT_MEMLOCK limit! %s\n", strerror(errno));
    }
    
    // Load and verify BPF application
    skel = ndn_parser_bpf__open();
    if (!skel) {
        fprintf(stderr, "Error: Failed to open and load BPF skeleton\n");
        return 1;
    }
    
    // Customize map sizes based on command line options
    bpf_map__set_max_entries(skel->maps.content_store, cs_capacity);
    
    // Load BPF program
    err = ndn_parser_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to load BPF program: %s\n", strerror(errno));
        goto cleanup;
    }
    
    // Get file descriptors for maps
    metrics_fd = bpf_map__fd(skel->maps.metrics);
    config_fd = bpf_map__fd(skel->maps.config);
    cs_fd = bpf_map__fd(skel->maps.content_store);
    fib_fd = bpf_map__fd(skel->maps.fib);
    pit_fd = bpf_map__fd(skel->maps.pit);
    
    if (metrics_fd < 0 || config_fd < 0 || cs_fd < 0 || fib_fd < 0 || pit_fd < 0) {
        fprintf(stderr, "Error: Failed to get file descriptors for maps\n");
        goto cleanup;
    }
    
    // Update configuration
    if (update_config(config_fd) != 0) {
        fprintf(stderr, "Warning: Failed to update configuration\n");
    }
    
    // Initialize FIB with default routes
    if (init_fib(fib_fd, ifindex) != 0) {
        fprintf(stderr, "Warning: Failed to initialize FIB\n");
    }
    
    // Attach XDP program to interface
    err = bpf_set_link_xdp_fd(ifindex, bpf_program__fd(skel->progs.ndn_xdp_parser), xdp_flags);
    if (err) {
        fprintf(stderr, "Error: Failed to attach XDP program to interface '%s': %s\n",
                ifname, strerror(-err));
        goto cleanup;
    }
    
    printf("Successfully attached XDP program to %s (ifindex %d)\n", ifname, ifindex);
    printf("μDCN XDP Program Configuration:\n");
    printf("  Content Store: %s (capacity %d, TTL %d sec)\n", 
           program_config.cs_enabled ? "Enabled" : "Disabled",
           cs_capacity, program_config.default_ttl);
    printf("  PIT: %s\n", program_config.pit_enabled ? "Enabled" : "Disabled");
    printf("  Metrics: %s\n", program_config.metrics_enabled ? "Enabled" : "Disabled");
    printf("  Hash Algorithm: %d\n", program_config.hash_algorithm);
    printf("Press Ctrl+C to exit and detach program\n\n");
    
    // Main loop: periodically collect and print metrics
    struct metrics_data metrics = {0};
    while (keep_running) {
        if (program_config.metrics_enabled) {
            // Collect metrics
            if (collect_metrics(metrics_fd, &metrics) == 0) {
                // Print metrics report
                print_metrics(metrics_output, &metrics);
            }
        }
        
        sleep(metrics_interval);
    }
    
    // Detach XDP program and cleanup
    bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
    printf("\nDetached XDP program from %s\n", ifname);
    
    // Cleanup resources
    cleanup:
    ndn_parser_bpf__destroy(skel);
    
    // Close metrics output file if it's not stdout
    if (metrics_output != stdout && metrics_output != NULL) {
        fclose(metrics_output);
    }
    
    return err != 0;
}
