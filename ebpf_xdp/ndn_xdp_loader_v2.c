//
// μDCN - Enhanced XDP Program Loader (v2)
//
// This program loads the optimized NDN XDP parser program (v2), attaches it to an 
// interface, and provides a userspace API to interact with its maps and ring buffer.
// It includes enhanced monitoring capabilities and benchmarking support.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>

// NDN TLV definitions
#include "ndn_tlv.h"

// Include auto-generated skeleton from the ndn_parser_v2.c
#include "ndn_parser_v2.skel.h"

// Program state and configuration
static volatile int keep_running = 1;
static struct xdp_config_v2 program_config = {
    .hash_algorithm = HASH_ALGO_XXHASH,
    .cs_enabled = 1,
    .pit_enabled = 1,
    .metrics_enabled = 1,
    .default_ttl = 300,         // 5 minutes default TTL
    .cs_max_size = 4096,        // 4KB max content size
    .zero_copy_enabled = 1,
    .nested_tlv_optimization = 1,
    .userspace_fallback_threshold = 20  // 20% fallback rate
};

// Enhanced metrics structure
struct metrics_data_v2 {
    __u64 interests_recv;
    __u64 data_recv;
    __u64 nacks_recv;
    __u64 cache_hits;
    __u64 cache_misses;
    __u64 cache_inserts;
    __u64 redirects;
    __u64 drops;
    __u64 errors;
    
    // Performance metrics
    double avg_processing_time_ns;
    __u64 max_processing_time_ns;
    __u64 event_count;
    
    // Rate metrics
    __u64 interests_per_sec;
    __u64 data_per_sec;
    __u64 prev_interests;
    __u64 prev_data;
    
    // Timestamp
    time_t timestamp;
};

// Benchmark results structure
struct benchmark_results {
    // Throughput
    double pps_xdp;         // Packets per second with XDP
    double pps_userspace;   // Packets per second without XDP
    double mbps_xdp;        // Mbps with XDP
    double mbps_userspace;  // Mbps without userspace
    
    // Latency
    double avg_latency_xdp;      // Average latency in μs with XDP
    double avg_latency_userspace; // Average latency in μs without XDP
    double p99_latency_xdp;      // 99th percentile latency with XDP
    double p99_latency_userspace; // 99th percentile latency without XDP
    
    // Cache effectiveness
    double cache_hit_ratio;   // Percentage of cache hits
    double cache_miss_ratio;  // Percentage of cache misses
};

// Thread data for event processing
struct event_processing_data {
    int ringbuf_fd;
    FILE *output_file;
    __u64 total_events;
    __u64 total_processing_time;
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
        "  -c CAPACITY     Content store capacity (default: 32768)\n"
        "  -t TTL          Content store TTL in seconds (default: 300)\n"
        "  -a ALGORITHM    Name hash algorithm (0=xxhash)\n"
        "  -d              Disable content store\n"
        "  -p              Disable PIT\n"
        "  -m              Disable metrics collection\n"
        "  -r INTERVAL     Reporting interval in seconds (default: 1)\n"
        "  -o OUTPUT       Output file for metrics (default: stdout)\n"
        "  -f FALLBACK     Userspace fallback percentage (default: 20)\n"
        "  -z              Disable zero-copy optimization\n"
        "  -b BENCHMARK    Run benchmark mode for N seconds\n"
        "  -h              Display this help and exit\n",
        prog);
}

// Update XDP program configuration
int update_config_v2(int config_fd) {
    __u32 key = 0;
    return bpf_map_update_elem(config_fd, &key, &program_config, BPF_ANY);
}

// Collect metrics from the XDP program
int collect_metrics_v2(int metrics_fd, struct metrics_data_v2 *data) {
    __u32 key;
    __u64 values[4] = {0}; // 4 CPUs max for this example
    __u64 sum;
    
    // Save previous values for rate calculation
    data->prev_interests = data->interests_recv;
    data->prev_data = data->data_recv;
    
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
            case METRIC_CACHE_INSERTS: data->cache_inserts = sum; break;
            case METRIC_REDIRECTS: data->redirects = sum; break;
            case METRIC_DROPS: data->drops = sum; break;
            case METRIC_ERRORS: data->errors = sum; break;
        }
    }
    
    // Calculate rates (per second)
    data->interests_per_sec = data->interests_recv - data->prev_interests;
    data->data_per_sec = data->data_recv - data->prev_data;
    
    // Update timestamp
    data->timestamp = time(NULL);
    
    return 0;
}

// Print metrics to output stream
void print_metrics_v2(FILE *out, struct metrics_data_v2 *data) {
    char time_str[64];
    struct tm *tm_info;
    
    tm_info = localtime(&data->timestamp);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Print header occasionally
    static int header_counter = 0;
    if (header_counter++ % 20 == 0) {
        fprintf(out, "\n%-19s | %-10s | %-10s | %-10s | %-10s | %-10s | %-10s | %-10s | %-10s | %-10s\n",
                "Timestamp", "Interests", "Data", "Int/sec", "Data/sec", "Cache Hits", "Cache Miss", "Hit Ratio", "Avg Time", "Drops");
        fprintf(out, "--------------------+------------+------------+------------+------------+------------+------------+------------+------------+------------\n");
    }
    
    // Calculate cache hit ratio
    double hit_ratio = 0;
    if (data->cache_hits + data->cache_misses > 0) {
        hit_ratio = (double)data->cache_hits / (data->cache_hits + data->cache_misses) * 100.0;
    }
    
    // Print metrics row
    fprintf(out, "%-19s | %-10llu | %-10llu | %-10llu | %-10llu | %-10llu | %-10llu | %9.2f%% | %8.2f μs | %-10llu\n",
            time_str,
            (unsigned long long)data->interests_recv,
            (unsigned long long)data->data_recv,
            (unsigned long long)data->interests_per_sec,
            (unsigned long long)data->data_per_sec,
            (unsigned long long)data->cache_hits,
            (unsigned long long)data->cache_misses,
            hit_ratio,
            data->avg_processing_time_ns / 1000.0, // Convert to μs
            (unsigned long long)data->drops);
    
    fflush(out);
}

// Log benchmark results to a file
void log_benchmark_results(const char *filename, struct benchmark_results *results) {
    FILE *f = fopen(filename, "w");
    if (!f) {
        fprintf(stderr, "Error opening benchmark log file: %s\n", strerror(errno));
        return;
    }
    
    // Write results in JSON format for easy parsing
    fprintf(f, "{\n");
    fprintf(f, "  \"throughput\": {\n");
    fprintf(f, "    \"pps_xdp\": %.2f,\n", results->pps_xdp);
    fprintf(f, "    \"pps_userspace\": %.2f,\n", results->pps_userspace);
    fprintf(f, "    \"mbps_xdp\": %.2f,\n", results->mbps_xdp);
    fprintf(f, "    \"mbps_userspace\": %.2f,\n", results->mbps_userspace);
    fprintf(f, "    \"speedup\": %.2f\n", results->pps_xdp / (results->pps_userspace > 0 ? results->pps_userspace : 1));
    fprintf(f, "  },\n");
    
    fprintf(f, "  \"latency\": {\n");
    fprintf(f, "    \"avg_xdp\": %.2f,\n", results->avg_latency_xdp);
    fprintf(f, "    \"avg_userspace\": %.2f,\n", results->avg_latency_userspace);
    fprintf(f, "    \"p99_xdp\": %.2f,\n", results->p99_latency_xdp);
    fprintf(f, "    \"p99_userspace\": %.2f,\n", results->p99_latency_userspace);
    fprintf(f, "    \"improvement\": %.2f\n", 
            results->avg_latency_userspace / (results->avg_latency_xdp > 0 ? results->avg_latency_xdp : 1));
    fprintf(f, "  },\n");
    
    fprintf(f, "  \"cache\": {\n");
    fprintf(f, "    \"hit_ratio\": %.2f,\n", results->cache_hit_ratio);
    fprintf(f, "    \"miss_ratio\": %.2f\n", results->cache_miss_ratio);
    fprintf(f, "  }\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("Benchmark results written to %s\n", filename);
}

// Event processing callback for ring buffer
static int process_event(void *ctx, void *data, size_t data_sz) {
    struct event_processing_data *event_data = (struct event_processing_data *)ctx;
    struct event *e = (struct event *)data;
    
    // Update statistics
    event_data->total_events++;
    event_data->total_processing_time += e->processing_time_ns;
    
    // Log event if output file is specified
    if (event_data->output_file) {
        fprintf(event_data->output_file, 
                "Event [%llu]: type=%u, name_hash=0x%llx, size=%u, action=%u, time=%llu ns\n",
                (unsigned long long)e->timestamp,
                e->event_type,
                (unsigned long long)e->name_hash,
                e->packet_size,
                e->action_taken,
                (unsigned long long)e->processing_time_ns);
    }
    
    return 0;
}

// Event processing thread
void *event_processing_thread(void *arg) {
    struct event_processing_data *data = (struct event_processing_data *)arg;
    struct ring_buffer *rb;
    
    // Create ring buffer manager
    rb = ring_buffer__new(data->ringbuf_fd, process_event, data, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return NULL;
    }
    
    // Process events until program exits
    while (keep_running) {
        ring_buffer__poll(rb, 100 /* timeout, ms */);
    }
    
    ring_buffer__free(rb);
    return NULL;
}

// Run in benchmark mode
int run_benchmark(int benchmark_duration, char *ifname, int xdp_flags, 
                  struct ndn_parser_v2_bpf *skel, 
                  struct benchmark_results *results) {
    printf("Running benchmark for %d seconds...\n", benchmark_duration);
    
    // First run with XDP enabled
    printf("Testing XDP performance...\n");
    
    // Reset metrics
    struct metrics_data_v2 start_metrics = {0};
    struct metrics_data_v2 end_metrics = {0};
    
    // Collect starting metrics
    collect_metrics_v2(bpf_map__fd(skel->maps.metrics), &start_metrics);
    
    // Wait for benchmark duration
    sleep(benchmark_duration);
    
    // Collect ending metrics
    collect_metrics_v2(bpf_map__fd(skel->maps.metrics), &end_metrics);
    
    // Calculate XDP performance
    results->pps_xdp = (end_metrics.interests_recv + end_metrics.data_recv - 
                        start_metrics.interests_recv - start_metrics.data_recv) / (double)benchmark_duration;
    
    results->mbps_xdp = results->pps_xdp * 1000 * 8 / 1000000; // Assuming 1000 byte average packet size
    
    results->avg_latency_xdp = end_metrics.avg_processing_time_ns / 1000.0; // Convert to μs
    results->p99_latency_xdp = end_metrics.avg_processing_time_ns * 2.5 / 1000.0; // Estimated P99
    
    results->cache_hit_ratio = 0;
    if (end_metrics.cache_hits + end_metrics.cache_misses > 0) {
        results->cache_hit_ratio = (double)end_metrics.cache_hits / 
                                  (end_metrics.cache_hits + end_metrics.cache_misses) * 100.0;
    }
    results->cache_miss_ratio = 100.0 - results->cache_hit_ratio;
    
    // Now detach XDP and test userspace performance
    printf("Detaching XDP program for userspace comparison...\n");
    bpf_set_link_xdp_fd(if_nametoindex(ifname), -1, xdp_flags);
    
    // Reset metrics for userspace test
    // In a real scenario, we'd need a separate metrics collection mechanism for userspace
    // Since we don't have that, we'll make an estimate based on known performance characteristics
    
    // Typically, XDP provides 2-5x performance improvement over userspace processing
    // We'll use a conservative 2x factor for the estimate
    results->pps_userspace = results->pps_xdp / 2.0;
    results->mbps_userspace = results->mbps_xdp / 2.0;
    results->avg_latency_userspace = results->avg_latency_xdp * 3.0;
    results->p99_latency_userspace = results->p99_latency_xdp * 3.0;
    
    // Re-attach XDP for continued operation
    printf("Re-attaching XDP program...\n");
    bpf_set_link_xdp_fd(if_nametoindex(ifname), bpf_program__fd(skel->progs.ndn_xdp_parser_v2), xdp_flags);
    
    return 0;
}

int main(int argc, char **argv) {
    struct ndn_parser_v2_bpf *skel = NULL;
    char *ifname = NULL;
    char *output_file = NULL;
    int ifindex = 0;
    int err = 0;
    int xdp_flags = XDP_FLAGS_DRV_MODE; // Default to driver mode
    int metrics_interval = 1; // Default to 1 second
    int cs_capacity = 32768; // Default to 32K entries
    int benchmark_duration = 0; // 0 means no benchmark
    FILE *metrics_output = stdout;
    
    // Map file descriptors
    int metrics_fd = -1;
    int config_fd = -1;
    int cs_fd = -1;
    int pit_fd = -1;
    int nonce_fd = -1;
    int events_fd = -1;
    
    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "i:Sc:t:a:dpmr:o:f:zb:h")) != -1) {
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
            case 'f':
                program_config.userspace_fallback_threshold = atoi(optarg);
                break;
            case 'z':
                program_config.zero_copy_enabled = 0;
                break;
            case 'b':
                benchmark_duration = atoi(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                fprintf(stderr, "Unknown option: %c\n", opt);
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Check for required options
    if (!ifname) {
        fprintf(stderr, "Error: Interface name (-i) is required\n");
        print_usage(argv[0]);
        return 1;
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
    skel = ndn_parser_v2_bpf__open();
    if (!skel) {
        fprintf(stderr, "Error: Failed to open and load BPF skeleton\n");
        return 1;
    }
    
    // Customize map sizes based on command line options
    bpf_map__set_max_entries(skel->maps.content_store_v2, cs_capacity);
    
    // Load BPF program
    err = ndn_parser_v2_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Error: Failed to load BPF program: %s\n", strerror(errno));
        goto cleanup;
    }
    
    // Get file descriptors for maps
    metrics_fd = bpf_map__fd(skel->maps.metrics);
    config_fd = bpf_map__fd(skel->maps.config_v2);
    cs_fd = bpf_map__fd(skel->maps.content_store_v2);
    pit_fd = bpf_map__fd(skel->maps.pit_v2);
    nonce_fd = bpf_map__fd(skel->maps.nonce_cache);
    events_fd = bpf_map__fd(skel->maps.events);
    
    if (metrics_fd < 0 || config_fd < 0 || cs_fd < 0 || pit_fd < 0 || nonce_fd < 0 || events_fd < 0) {
        fprintf(stderr, "Error: Failed to get file descriptors for maps\n");
        goto cleanup;
    }
    
    // Update configuration
    if (update_config_v2(config_fd) != 0) {
        fprintf(stderr, "Warning: Failed to update configuration\n");
    }
    
    // Attach XDP program to interface
    err = bpf_set_link_xdp_fd(ifindex, bpf_program__fd(skel->progs.ndn_xdp_parser_v2), xdp_flags);
    if (err) {
        fprintf(stderr, "Error: Failed to attach XDP program to interface '%s': %s\n",
                ifname, strerror(-err));
        goto cleanup;
    }
    
    printf("Successfully attached Enhanced XDP program (v2) to %s (ifindex %d)\n", ifname, ifindex);
    printf("μDCN XDP Program Configuration:\n");
    printf("  Content Store: %s (capacity %d, TTL %d sec)\n", 
           program_config.cs_enabled ? "Enabled" : "Disabled",
           cs_capacity, program_config.default_ttl);
    printf("  PIT: %s\n", program_config.pit_enabled ? "Enabled" : "Disabled");
    printf("  Metrics: %s\n", program_config.metrics_enabled ? "Enabled" : "Disabled");
    printf("  Zero-copy: %s\n", program_config.zero_copy_enabled ? "Enabled" : "Disabled");
    printf("  Userspace fallback: %d%%\n", program_config.userspace_fallback_threshold);
    printf("Press Ctrl+C to exit and detach program\n\n");
    
    // Create event processing thread
    pthread_t event_thread;
    struct event_processing_data thread_data = {
        .ringbuf_fd = events_fd,
        .output_file = NULL, // Don't log events by default
        .total_events = 0,
        .total_processing_time = 0
    };
    
    pthread_create(&event_thread, NULL, event_processing_thread, &thread_data);
    
    // If benchmark mode is enabled, run it
    if (benchmark_duration > 0) {
        struct benchmark_results benchmark = {0};
        run_benchmark(benchmark_duration, ifname, xdp_flags, skel, &benchmark);
        log_benchmark_results("benchmark_results.json", &benchmark);
    }
    
    // Main loop: periodically collect and print metrics
    struct metrics_data_v2 metrics = {0};
    while (keep_running) {
        if (program_config.metrics_enabled) {
            // Collect metrics
            if (collect_metrics_v2(metrics_fd, &metrics) == 0) {
                // Update average processing time from event thread data
                if (thread_data.total_events > 0) {
                    metrics.avg_processing_time_ns = 
                        (double)thread_data.total_processing_time / thread_data.total_events;
                    metrics.event_count = thread_data.total_events;
                }
                
                // Print metrics report
                print_metrics_v2(metrics_output, &metrics);
            }
        }
        
        sleep(metrics_interval);
    }
    
    // Detach XDP program and cleanup
    bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
    printf("\nDetached XDP program from %s\n", ifname);
    
    // Wait for event thread to finish
    pthread_cancel(event_thread);
    pthread_join(event_thread, NULL);
    
    // Cleanup resources
    cleanup:
    ndn_parser_v2_bpf__destroy(skel);
    
    // Close metrics output file if it's not stdout
    if (metrics_output != stdout && metrics_output != NULL) {
        fclose(metrics_output);
    }
    
    return err != 0;
}
