/**
 * @file main.c
 * @brief Main application entry point for EthUDP
 * 
 * This is the main application file that handles initialization,
 * argument parsing, and coordination of all EthUDP modules.
 */

#include "ethudp_common.h"
#include "ethudp_config.h"
#include "ethudp_network.h"
#include "ethudp_utils.h"
#include "ethudp_dynamic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/wait.h>
#include <pcap.h>

// Global variables (defined in ethudp_common.h)
int daemon_proc = 0;
volatile int debug = 0;
int mode = -1;
int mtu = 0;
int udp_frg_seq = 0;
int master_slave = 0;
int read_only = 0, write_only = 0;
int fixmss = 0;
int nopromisc = 0;
int loopback_check = 0;
int packet_len = 1500;
char name[MAXLEN];
char run_cmd[MAXLEN];
char dev_name[IFNAMSIZ];
char syslog_name[MAXLEN];
int run_seconds = 0;

int32_t ifindex;

char mypassword[MAXLEN];
int enc_algorithm;
unsigned char enc_key[MAXLEN];
#ifdef ENABLE_OPENSSL
unsigned char enc_iv[EVP_MAX_IV_LENGTH];
#endif
int enc_key_len = 0;

int fdudp[2], fdraw;
int nat[2];
pcap_t *pcap_handle;

int lz4 = 0;
volatile long long udp_total = 0;
volatile long long compress_overhead = 0;
volatile long long compress_save = 0;
volatile long long encrypt_overhead = 0;

int vlan_map = 0;
int my_vlan[4096];
int remote_vlan[4096];

volatile struct sockaddr_storage local_addr[2];
volatile struct sockaddr_storage cmd_remote_addr[2];
volatile struct sockaddr_storage remote_addr[2];
volatile unsigned long myticket, last_pong[2];
volatile unsigned long ping_send[2], ping_recv[2], pong_send[2], pong_recv[2];
volatile unsigned long raw_send_pkt, raw_send_byte, raw_recv_pkt, raw_recv_byte;
volatile unsigned long udp_send_pkt[2], udp_send_byte[2], udp_recv_pkt[2], udp_recv_byte[2];
volatile unsigned long udp_send_err[2], raw_send_err;
volatile int master_status = STATUS_BAD;
volatile int slave_status = STATUS_BAD;
volatile int current_remote = MASTER;
volatile int got_signal = 1;

// Global configuration and worker pool
ethudp_config_t global_config = {
    .mode = -1,
    .debug = 0,
    .master_slave = 0,
    
    .udp_workers = DEFAULT_UDP_WORKERS,
    .raw_workers = DEFAULT_RAW_WORKERS,
    .batch_size = DEFAULT_BATCH_SIZE,
    .queue_size = DEFAULT_QUEUE_SIZE,
    
    .enable_so_reuseport = ENABLE_SO_REUSEPORT,
    .enable_cpu_affinity = ENABLE_CPU_AFFINITY,
    .cpu_affinity = 0,
    .enable_numa_optimization = ENABLE_NUMA_OPT,
    .enable_batch_processing = ENABLE_BATCH_PROCESSING,
    .enable_dynamic_scaling = 1,
    
    .packet_buffer_count = DEFAULT_BUFFER_COUNT,
    .packet_buffer_size = MAX_PACKET_SIZE,
    .socket_rcvbuf_size = 16 * 1024 * 1024,
    .socket_sndbuf_size = 16 * 1024 * 1024,
    
    .encryption_enabled = 0,
    .compression_enabled = 0,
    
    .keepalive_interval = 10,
    .worker_timeout = 30,
    .stats_interval = 5
};

struct worker_pool global_worker_pool;
dynamic_system_t* global_dynamic_system = NULL;

// Forward declarations
void print_worker_statistics(void) {
    printf("\n=== EthUDP Worker Statistics Report ===\n");
    
    // Get current time for uptime calculation
    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC, &current_time);
    
    // Pool overview
    printf("Worker Pool Overview:\n");
    printf("  Status: %s\n", global_worker_pool.running ? "Running" : "Stopped");
    printf("  UDP Workers: %d active\n", global_worker_pool.udp_worker_count);
    printf("  RAW Workers: %d active\n", global_worker_pool.raw_worker_count);
    printf("  Total Workers: %d\n", global_worker_pool.udp_worker_count + global_worker_pool.raw_worker_count);
    
    // Pool-wide statistics
    printf("\nPool-wide Statistics:\n");
    printf("  Total Packets Processed: %lld\n", global_worker_pool.total_packets_processed);
    printf("  Total Bytes Processed: %lld (%.2f MB)\n", 
           global_worker_pool.total_bytes_processed,
           (double)global_worker_pool.total_bytes_processed / (1024.0 * 1024.0));
    printf("  Total Errors: %lld\n", global_worker_pool.total_errors);
    
    // Configuration
    printf("\nConfiguration:\n");
    printf("  Batch Size: %d\n", global_worker_pool.batch_size);
    printf("  Queue Size: %d\n", global_worker_pool.queue_size);
    printf("  CPU Affinity: %s\n", global_worker_pool.enable_cpu_affinity ? "Enabled" : "Disabled");
    printf("  SO_REUSEPORT: %s\n", global_worker_pool.enable_so_reuseport ? "Enabled" : "Disabled");
    printf("  NUMA Optimization: %s\n", global_worker_pool.enable_numa_opt ? "Enabled" : "Disabled");
    printf("  Batch Processing: %s\n", global_worker_pool.enable_batch_processing ? "Enabled" : "Disabled");
    
    // UDP Workers detailed statistics
    if (global_worker_pool.udp_workers && global_worker_pool.udp_worker_count > 0) {
        printf("\nUDP Workers (UDP→RAW) Details:\n");
        printf("  ID | Thread ID    | CPU | Packets    | Bytes      | Errors | Queue | Uptime   | PPS    | Throughput\n");
        printf("  ---|--------------|-----|------------|------------|--------|-------|----------|--------|----------\n");
        
        for (int i = 0; i < global_worker_pool.udp_worker_count; i++) {
            worker_context_t *worker = &global_worker_pool.udp_workers[i];
            
            // Calculate uptime
            double uptime_seconds = (current_time.tv_sec - worker->start_time.tv_sec) +
                                  (current_time.tv_nsec - worker->start_time.tv_nsec) / 1e9;
            
            // Calculate rates
            double pps = (uptime_seconds > 0) ? (double)worker->packets_processed / uptime_seconds : 0.0;
            double throughput_mbps = (uptime_seconds > 0) ? 
                                   ((double)worker->bytes_processed * 8.0) / (uptime_seconds * 1024.0 * 1024.0) : 0.0;
            
            // Format uptime
            int hours = (int)(uptime_seconds / 3600);
            int minutes = (int)((uptime_seconds - hours * 3600) / 60);
            int seconds = (int)(uptime_seconds - hours * 3600 - minutes * 60);
            
            printf("  %2d | %12lu | %3d | %10lld | %10lld | %6lld | %5u | %02d:%02d:%02d | %6.1f | %8.2f Mbps\n",
                   worker->worker_id,
                   (unsigned long)worker->thread_id,
                   worker->cpu_affinity,
                   worker->packets_processed,
                   worker->bytes_processed,
                   worker->errors,
                   worker->current_queue_depth,
                   hours, minutes, seconds,
                   pps,
                   throughput_mbps);
        }
    }
    
    // RAW Workers detailed statistics
    if (global_worker_pool.raw_workers && global_worker_pool.raw_worker_count > 0) {
        printf("\nRAW Workers (RAW→UDP) Details:\n");
        printf("  ID | Thread ID    | CPU | Packets    | Bytes      | Errors | Queue | Uptime   | PPS    | Throughput\n");
        printf("  ---|--------------|-----|------------|------------|--------|-------|----------|--------|----------\n");
        
        for (int i = 0; i < global_worker_pool.raw_worker_count; i++) {
            worker_context_t *worker = &global_worker_pool.raw_workers[i];
            
            // Calculate uptime
            double uptime_seconds = (current_time.tv_sec - worker->start_time.tv_sec) +
                                  (current_time.tv_nsec - worker->start_time.tv_nsec) / 1e9;
            
            // Calculate rates
            double pps = (uptime_seconds > 0) ? (double)worker->packets_processed / uptime_seconds : 0.0;
            double throughput_mbps = (uptime_seconds > 0) ? 
                                   ((double)worker->bytes_processed * 8.0) / (uptime_seconds * 1024.0 * 1024.0) : 0.0;
            
            // Format uptime
            int hours = (int)(uptime_seconds / 3600);
            int minutes = (int)((uptime_seconds - hours * 3600) / 60);
            int seconds = (int)(uptime_seconds - hours * 3600 - minutes * 60);
            
            printf("  %2d | %12lu | %3d | %10lld | %10lld | %6lld | %5u | %02d:%02d:%02d | %6.1f | %8.2f Mbps\n",
                   worker->worker_id,
                   (unsigned long)worker->thread_id,
                   worker->cpu_affinity,
                   worker->packets_processed,
                   worker->bytes_processed,
                   worker->errors,
                   worker->current_queue_depth,
                   hours, minutes, seconds,
                   pps,
                   throughput_mbps);
        }
    }
    
    // Performance summary
    printf("\nPerformance Summary:\n");
    long long total_packets = 0, total_bytes = 0, total_errors = 0;
    double total_uptime = 0.0;
    int active_workers = 0;
    
    // Sum UDP workers
    for (int i = 0; i < global_worker_pool.udp_worker_count; i++) {
        worker_context_t *worker = &global_worker_pool.udp_workers[i];
        if (worker->running) {
            total_packets += worker->packets_processed;
            total_bytes += worker->bytes_processed;
            total_errors += worker->errors;
            
            double uptime = (current_time.tv_sec - worker->start_time.tv_sec) +
                          (current_time.tv_nsec - worker->start_time.tv_nsec) / 1e9;
            if (uptime > total_uptime) total_uptime = uptime;
            active_workers++;
        }
    }
    
    // Sum RAW workers
    for (int i = 0; i < global_worker_pool.raw_worker_count; i++) {
        worker_context_t *worker = &global_worker_pool.raw_workers[i];
        if (worker->running) {
            total_packets += worker->packets_processed;
            total_bytes += worker->bytes_processed;
            total_errors += worker->errors;
            
            double uptime = (current_time.tv_sec - worker->start_time.tv_sec) +
                          (current_time.tv_nsec - worker->start_time.tv_nsec) / 1e9;
            if (uptime > total_uptime) total_uptime = uptime;
            active_workers++;
        }
    }
    
    // Calculate aggregate statistics
    double aggregate_pps = (total_uptime > 0) ? (double)total_packets / total_uptime : 0.0;
    double aggregate_throughput = (total_uptime > 0) ? 
                                ((double)total_bytes * 8.0) / (total_uptime * 1024.0 * 1024.0) : 0.0;
    double error_rate = (total_packets > 0) ? ((double)total_errors / (double)total_packets) * 100.0 : 0.0;
    
    printf("  Active Workers: %d\n", active_workers);
    printf("  Aggregate PPS: %.1f packets/sec\n", aggregate_pps);
    printf("  Aggregate Throughput: %.2f Mbps\n", aggregate_throughput);
    printf("  Error Rate: %.4f%% (%lld errors / %lld packets)\n", error_rate, total_errors, total_packets);
    printf("  Average Bytes per Packet: %.1f bytes\n", 
           (total_packets > 0) ? (double)total_bytes / (double)total_packets : 0.0);
    
    printf("\n=== End of Statistics Report ===\n\n");
}

void reset_worker_statistics(void) {
    printf("Resetting worker statistics...\n");
    
    struct timespec reset_time;
    clock_gettime(CLOCK_MONOTONIC, &reset_time);
    
    // Reset pool-wide statistics (thread-safe atomic operations)
    __sync_lock_test_and_set(&global_worker_pool.total_packets_processed, 0);
    __sync_lock_test_and_set(&global_worker_pool.total_bytes_processed, 0);
    __sync_lock_test_and_set(&global_worker_pool.total_errors, 0);
    
    int total_workers_reset = 0;
    
    // Reset UDP workers statistics
    if (global_worker_pool.udp_workers) {
        for (int i = 0; i < global_worker_pool.udp_worker_count; i++) {
            worker_context_t *worker = &global_worker_pool.udp_workers[i];
            
            // Thread-safe reset of volatile counters using atomic operations
            __sync_lock_test_and_set(&worker->packets_processed, 0);
            __sync_lock_test_and_set(&worker->bytes_processed, 0);
            __sync_lock_test_and_set(&worker->errors, 0);
            __sync_lock_test_and_set(&worker->queue_full_drops, 0);
            __sync_lock_test_and_set(&worker->total_latency_us, 0);
            __sync_lock_test_and_set(&worker->current_queue_depth, 0);
            
            // Reset timing information (these are not accessed concurrently during reset)
            worker->start_time = reset_time;
            worker->last_stats_time = reset_time;
            
            total_workers_reset++;
            
            Debug("Reset statistics for UDP worker %d (thread_id=%lu)", 
                  worker->worker_id, (unsigned long)worker->thread_id);
        }
    }
    
    // Reset RAW workers statistics
    if (global_worker_pool.raw_workers) {
        for (int i = 0; i < global_worker_pool.raw_worker_count; i++) {
            worker_context_t *worker = &global_worker_pool.raw_workers[i];
            
            // Thread-safe reset of volatile counters using atomic operations
            __sync_lock_test_and_set(&worker->packets_processed, 0);
            __sync_lock_test_and_set(&worker->bytes_processed, 0);
            __sync_lock_test_and_set(&worker->errors, 0);
            __sync_lock_test_and_set(&worker->queue_full_drops, 0);
            __sync_lock_test_and_set(&worker->total_latency_us, 0);
            __sync_lock_test_and_set(&worker->current_queue_depth, 0);
            
            // Reset timing information
            worker->start_time = reset_time;
            worker->last_stats_time = reset_time;
            
            total_workers_reset++;
            
            Debug("Reset statistics for RAW worker %d (thread_id=%lu)", 
                  worker->worker_id, (unsigned long)worker->thread_id);
        }
    }
    
    // Reset shared queue statistics if available
    // Lock the queue mutex to safely reset queue statistics
    if (pthread_mutex_lock(&global_worker_pool.raw_queue.mutex) == 0) {
        // Reset queue-specific counters
        global_worker_pool.raw_queue.head = NULL;
        global_worker_pool.raw_queue.tail = NULL;
        global_worker_pool.raw_queue.enqueue_count = 0;
        global_worker_pool.raw_queue.dequeue_count = 0;
        global_worker_pool.raw_queue.current_size = 0;
        
        pthread_mutex_unlock(&global_worker_pool.raw_queue.mutex);
        Debug("Reset shared RAW queue statistics");
    } else {
        err_msg("Failed to lock RAW queue mutex for statistics reset");
    }
    
    // Log the reset operation
    printf("Worker statistics reset completed:\n");
    printf("  Total workers reset: %d\n", total_workers_reset);
    printf("  UDP workers reset: %d\n", global_worker_pool.udp_worker_count);
    printf("  RAW workers reset: %d\n", global_worker_pool.raw_worker_count);
    printf("  Reset timestamp: %ld.%09ld\n", reset_time.tv_sec, reset_time.tv_nsec);
    
    // Optional: Force a statistics report after reset to show clean state
    if (debug) {
        printf("\nPost-reset statistics verification:\n");
        print_worker_statistics();
    }
    
    Debug("reset_worker_statistics completed successfully - all counters zeroed");
}
void* process_udp_to_raw_worker(void *arg);
void* process_raw_to_udp_worker(void *arg);
void* worker_stats_reporter(void *arg);
void* process_udp_to_raw_master(void *arg);
void* process_udp_to_raw_slave(void *arg);
void* send_keepalive_to_udp(void *arg);
void process_raw_to_udp(void);
int start_worker_threads(void) {
    printf("Starting worker threads...\n");
    
    // Initialize worker pool structure
    memset(&global_worker_pool, 0, sizeof(global_worker_pool));
    
    // Set initial worker counts from configuration
    int udp_workers = (global_config.udp_workers > 0) ? global_config.udp_workers : DEFAULT_UDP_WORKERS;
    int raw_workers = (global_config.raw_workers > 0) ? global_config.raw_workers : DEFAULT_RAW_WORKERS;
    
    // Validate worker counts
    if (udp_workers > MAX_WORKERS) udp_workers = MAX_WORKERS;
    if (raw_workers > MAX_WORKERS) raw_workers = MAX_WORKERS;
    if (udp_workers < MIN_WORKERS) udp_workers = MIN_WORKERS;
    if (raw_workers < MIN_WORKERS) raw_workers = MIN_WORKERS;
    
    Debug("Initializing worker pool: %d UDP workers, %d RAW workers", udp_workers, raw_workers);
    
    // Allocate memory for worker arrays
    global_worker_pool.udp_workers = calloc(MAX_WORKERS, sizeof(worker_context_t));
    global_worker_pool.raw_workers = calloc(MAX_WORKERS, sizeof(worker_context_t));
    
    if (!global_worker_pool.udp_workers || !global_worker_pool.raw_workers) {
        err_msg("Failed to allocate memory for worker pools");
        if (global_worker_pool.udp_workers) free(global_worker_pool.udp_workers);
        if (global_worker_pool.raw_workers) free(global_worker_pool.raw_workers);
        return -1;
    }
    
    // Initialize worker pool configuration
    global_worker_pool.udp_worker_count = 0;
    global_worker_pool.raw_worker_count = 0;
    global_worker_pool.running = 1;
    global_worker_pool.batch_size = (global_config.batch_size > 0) ? global_config.batch_size : DEFAULT_BATCH_SIZE;
    global_worker_pool.queue_size = DEFAULT_QUEUE_SIZE;
    global_worker_pool.enable_cpu_affinity = global_config.cpu_affinity;
    global_worker_pool.enable_so_reuseport = ENABLE_SO_REUSEPORT;
    global_worker_pool.enable_numa_opt = ENABLE_NUMA_OPT;
    global_worker_pool.enable_batch_processing = ENABLE_BATCH_PROCESSING;
    
    // Initialize shared raw queue for RAW→UDP communication
    memset(&global_worker_pool.raw_queue, 0, sizeof(lockfree_queue_t));
    global_worker_pool.raw_queue.capacity = global_worker_pool.queue_size;
    if (pthread_mutex_init(&global_worker_pool.raw_queue.mutex, NULL) != 0) {
        err_msg("Failed to initialize raw queue mutex");
        free(global_worker_pool.udp_workers);
        free(global_worker_pool.raw_workers);
        return -1;
    }
    if (pthread_cond_init(&global_worker_pool.raw_queue.cond, NULL) != 0) {
        err_msg("Failed to initialize raw queue condition variable");
        pthread_mutex_destroy(&global_worker_pool.raw_queue.mutex);
        free(global_worker_pool.udp_workers);
        free(global_worker_pool.raw_workers);
        return -1;
    }
    
    // Create UDP workers
    for (int i = 0; i < udp_workers; i++) {
        worker_context_t *ctx = &global_worker_pool.udp_workers[i];
        memset(ctx, 0, sizeof(worker_context_t));
        
        ctx->worker_id = i;
        ctx->worker_type = WORKER_TYPE_UDP_TO_RAW;
        ctx->socket_index = MASTER;  // Default to master socket
        ctx->running = 1;
        ctx->should_stop = 0;
        
        // Set CPU affinity if enabled
        if (global_worker_pool.enable_cpu_affinity) {
            ctx->cpu_affinity = i % sysconf(_SC_NPROCESSORS_ONLN);
        } else {
            ctx->cpu_affinity = -1;  // No specific affinity
        }
        
        // Initialize worker statistics
        clock_gettime(CLOCK_MONOTONIC, &ctx->start_time);
        ctx->last_stats_time = ctx->start_time;
        
        // Create worker thread
        if (pthread_create(&ctx->thread_id, NULL, process_udp_to_raw_worker, ctx) != 0) {
            err_msg("Failed to create UDP worker thread %d", i);
            // Cleanup already created workers
            for (int j = 0; j < i; j++) {
                global_worker_pool.udp_workers[j].should_stop = 1;
                pthread_join(global_worker_pool.udp_workers[j].thread_id, NULL);
            }
            pthread_mutex_destroy(&global_worker_pool.raw_queue.mutex);
            pthread_cond_destroy(&global_worker_pool.raw_queue.cond);
            free(global_worker_pool.udp_workers);
            free(global_worker_pool.raw_workers);
            return -1;
        }
        
        global_worker_pool.udp_worker_count++;
        Debug("Created UDP worker %d (thread_id=%lu, cpu_affinity=%d)", 
              i, (unsigned long)ctx->thread_id, ctx->cpu_affinity);
    }
    
    // Create RAW workers
    for (int i = 0; i < raw_workers; i++) {
        worker_context_t *ctx = &global_worker_pool.raw_workers[i];
        memset(ctx, 0, sizeof(worker_context_t));
        
        ctx->worker_id = i;
        ctx->worker_type = WORKER_TYPE_RAW_TO_UDP;
        ctx->running = 1;
        ctx->should_stop = 0;
        
        // Set CPU affinity if enabled (offset by UDP worker count)
        if (global_worker_pool.enable_cpu_affinity) {
            ctx->cpu_affinity = (udp_workers + i) % sysconf(_SC_NPROCESSORS_ONLN);
        } else {
            ctx->cpu_affinity = -1;  // No specific affinity
        }
        
        // Initialize worker statistics
        clock_gettime(CLOCK_MONOTONIC, &ctx->start_time);
        ctx->last_stats_time = ctx->start_time;
        
        // Create worker thread
        if (pthread_create(&ctx->thread_id, NULL, process_raw_to_udp_worker, ctx) != 0) {
            err_msg("Failed to create RAW worker thread %d", i);
            // Cleanup already created workers
            for (int j = 0; j < global_worker_pool.udp_worker_count; j++) {
                global_worker_pool.udp_workers[j].should_stop = 1;
                pthread_join(global_worker_pool.udp_workers[j].thread_id, NULL);
            }
            for (int j = 0; j < i; j++) {
                global_worker_pool.raw_workers[j].should_stop = 1;
                pthread_join(global_worker_pool.raw_workers[j].thread_id, NULL);
            }
            pthread_mutex_destroy(&global_worker_pool.raw_queue.mutex);
            pthread_cond_destroy(&global_worker_pool.raw_queue.cond);
            free(global_worker_pool.udp_workers);
            free(global_worker_pool.raw_workers);
            return -1;
        }
        
        global_worker_pool.raw_worker_count++;
        Debug("Created RAW worker %d (thread_id=%lu, cpu_affinity=%d)", 
              i, (unsigned long)ctx->thread_id, ctx->cpu_affinity);
    }
    
    // Create statistics reporting thread
    if (pthread_create(&global_worker_pool.stats_thread, NULL, worker_stats_reporter, NULL) != 0) {
        err_msg("Failed to create statistics thread");
        // Continue without stats thread - not critical
    } else {
        Debug("Created statistics reporting thread");
    }
    
    printf("Worker threads started successfully: %d UDP workers, %d RAW workers\n", 
           global_worker_pool.udp_worker_count, global_worker_pool.raw_worker_count);
    
    return 0;
}

int stop_worker_threads(void) {
    printf("Stopping worker threads...\n");
    
    if (!global_worker_pool.running) {
        Debug("Worker pool is not running, nothing to stop");
        return 0;
    }
    
    // Signal all workers to stop
    global_worker_pool.running = 0;
    
    // Stop UDP workers
    if (global_worker_pool.udp_workers) {
        Debug("Stopping %d UDP workers...", global_worker_pool.udp_worker_count);
        for (int i = 0; i < global_worker_pool.udp_worker_count; i++) {
            worker_context_t *ctx = &global_worker_pool.udp_workers[i];
            if (ctx->running) {
                ctx->should_stop = 1;
                ctx->running = 0;
                
                // Send signal to wake up worker if it's waiting
                if (ctx->thread_id != 0) {
                    pthread_kill(ctx->thread_id, SIGUSR1);
                }
            }
        }
        
        // Wait for UDP workers to finish
        for (int i = 0; i < global_worker_pool.udp_worker_count; i++) {
            worker_context_t *ctx = &global_worker_pool.udp_workers[i];
            if (ctx->thread_id != 0) {
                void *thread_result;
                int join_result = pthread_join(ctx->thread_id, &thread_result);
                if (join_result == 0) {
                    Debug("UDP worker %d stopped successfully", i);
                } else {
                    err_msg("Failed to join UDP worker thread %d: %s", i, strerror(join_result));
                }
                ctx->thread_id = 0;
            }
        }
        
        // Free UDP worker memory
        free(global_worker_pool.udp_workers);
        global_worker_pool.udp_workers = NULL;
        global_worker_pool.udp_worker_count = 0;
    }
    
    // Stop RAW workers
    if (global_worker_pool.raw_workers) {
        Debug("Stopping %d RAW workers...", global_worker_pool.raw_worker_count);
        for (int i = 0; i < global_worker_pool.raw_worker_count; i++) {
            worker_context_t *ctx = &global_worker_pool.raw_workers[i];
            if (ctx->running) {
                ctx->should_stop = 1;
                ctx->running = 0;
                
                // Send signal to wake up worker if it's waiting
                if (ctx->thread_id != 0) {
                    pthread_kill(ctx->thread_id, SIGUSR1);
                }
            }
        }
        
        // Signal the raw queue condition to wake up waiting workers
        pthread_mutex_lock(&global_worker_pool.raw_queue.mutex);
        pthread_cond_broadcast(&global_worker_pool.raw_queue.cond);
        pthread_mutex_unlock(&global_worker_pool.raw_queue.mutex);
        
        // Wait for RAW workers to finish
        for (int i = 0; i < global_worker_pool.raw_worker_count; i++) {
            worker_context_t *ctx = &global_worker_pool.raw_workers[i];
            if (ctx->thread_id != 0) {
                void *thread_result;
                int join_result = pthread_join(ctx->thread_id, &thread_result);
                if (join_result == 0) {
                    Debug("RAW worker %d stopped successfully", i);
                } else {
                    err_msg("Failed to join RAW worker thread %d: %s", i, strerror(join_result));
                }
                ctx->thread_id = 0;
            }
        }
        
        // Free RAW worker memory
        free(global_worker_pool.raw_workers);
        global_worker_pool.raw_workers = NULL;
        global_worker_pool.raw_worker_count = 0;
    }
    
    // Stop statistics thread
    if (global_worker_pool.stats_thread != 0) {
        Debug("Stopping statistics thread...");
        pthread_kill(global_worker_pool.stats_thread, SIGUSR1);
        void *thread_result;
        int join_result = pthread_join(global_worker_pool.stats_thread, &thread_result);
        if (join_result == 0) {
            Debug("Statistics thread stopped successfully");
        } else {
            err_msg("Failed to join statistics thread: %s", strerror(join_result));
        }
        global_worker_pool.stats_thread = 0;
    }
    
    // Cleanup shared resources
    pthread_mutex_destroy(&global_worker_pool.raw_queue.mutex);
    pthread_cond_destroy(&global_worker_pool.raw_queue.cond);
    
    // Reset worker pool structure
    memset(&global_worker_pool, 0, sizeof(global_worker_pool));
    
    printf("Worker threads stopped successfully\n");
    return 0;
}
void read_vlan_map_file(const char *filename);

// Signal handlers
void sig_handler_hup(int signo)
{
    got_signal = 1;
    // Print worker statistics if using optimized system
    if (global_worker_pool.running) {
        print_worker_statistics();
    }
}

void sig_handler_usr1(int signo)
{
    udp_total = compress_overhead = compress_save = encrypt_overhead = 0;
    raw_send_pkt = raw_send_byte = raw_recv_pkt = raw_recv_byte = 0;
    udp_send_pkt[0] = udp_send_byte[0] = udp_recv_pkt[0] = udp_recv_byte[0] = 0;
    udp_send_pkt[1] = udp_send_byte[1] = udp_recv_pkt[1] = udp_recv_byte[1] = 0;
    
    // Reset worker statistics if using optimized system
    if (global_worker_pool.running) {
        reset_worker_statistics();
    }
}

// Benchmark function
#define BENCHCNT 300000

void do_benchmark(void)
{
#ifdef ENABLE_OPENSSL
    u_int8_t buf[MAX_PACKET_SIZE];
    u_int8_t nbuf[MAX_PACKET_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned long int pkt_cnt;
    unsigned long int pkt_len = 0, pkt_len_send = 0;
    int len;
    struct timeval start_tm, end_tm;
    gettimeofday(&start_tm, NULL);
    fprintf(stderr, "benchmarking for %d packets, %d size...\n", BENCHCNT, packet_len);
    fprintf(stderr, "enc_algorithm = %s\n",
        enc_algorithm == XOR ? "xor" : enc_algorithm == AES_128 ? "aes-128" : enc_algorithm == AES_192 ? "aes-192" : enc_algorithm ==
        AES_256 ? "aes-256" : "none");
    fprintf(stderr, "      enc_key = %s\n", enc_key);
    fprintf(stderr, "      key_len = %d\n", enc_key_len);
    fprintf(stderr, "          lz4 = %d\n", lz4);
    pkt_cnt = BENCHCNT;
    memset(buf, 'a', packet_len);

    while (1) {
        len = packet_len;
        pkt_len += len;
        len = do_encrypt(buf, len, nbuf);
        pkt_len_send += len;
        pkt_cnt--;
        if (pkt_cnt == 0)
            break;
    }
    gettimeofday(&end_tm, NULL);
    float tspan = ((end_tm.tv_sec - start_tm.tv_sec) * 1000000L + end_tm.tv_usec) - start_tm.tv_usec;
    tspan = tspan / 1000000L;
    fprintf(stderr, "%0.3f seconds\n", tspan);
    fprintf(stderr, "PPS: %.0f PKT/S, %lu(%lu) Byte, %.0f(%.0f) Byte/S\n", (float)BENCHCNT / tspan, pkt_len, pkt_len_send, 1.0 * pkt_len / tspan,
        1.0 * pkt_len_send / tspan);
    fprintf(stderr, "UDP BPS: %.0f(%.0f) BPS\n", 8.0 * pkt_len / tspan, 8.0 * pkt_len_send / tspan);
#endif
    exit(0);
}

// Initialize application
int initialize_application(void)
{
    // Initialize global variables
    memset(name, 0, MAXLEN);
    memset(run_cmd, 0, MAXLEN);
    memset(dev_name, 0, IFNAMSIZ);
    memset(mypassword, 0, MAXLEN);
    memset(enc_key, 0, MAXLEN);
    
    // Initialize VLAN mapping
    for (int i = 0; i < 4096; i++) {
        my_vlan[i] = i;
        remote_vlan[i] = i;
    }
    
    // Initialize network addresses
    memset((void*)local_addr, 0, sizeof(local_addr));
    memset((void*)cmd_remote_addr, 0, sizeof(cmd_remote_addr));
    memset((void*)remote_addr, 0, sizeof(remote_addr));
    
    // Initialize statistics
    myticket = 0;
    last_pong[0] = last_pong[1] = 0;
    ping_send[0] = ping_send[1] = 0;
    ping_recv[0] = ping_recv[1] = 0;
    pong_send[0] = pong_send[1] = 0;
    pong_recv[0] = pong_recv[1] = 0;
    raw_send_pkt = raw_send_byte = raw_recv_pkt = raw_recv_byte = 0;
    udp_send_pkt[0] = udp_send_byte[0] = udp_recv_pkt[0] = udp_recv_byte[0] = 0;
    udp_send_pkt[1] = udp_send_byte[1] = udp_recv_pkt[1] = udp_recv_byte[1] = 0;
    udp_send_err[0] = udp_send_err[1] = 0;
    raw_send_err = 0;
    
    // Initialize worker pool
    memset(&global_worker_pool, 0, sizeof(global_worker_pool));
    
    return 0;
}

// Setup network connections based on mode
int setup_network_connections(int argc, char *argv[], int arg_start)
{
    int i = arg_start;
    
    if (mode == MODEE) {    // eth bridge mode
        fdudp[MASTER] = ethudp_udp_xconnect(argv[i], argv[i + 1], argv[i + 2], argv[i + 3], MASTER);
        if (master_slave)
            fdudp[SLAVE] = ethudp_udp_xconnect(argv[i + 5], argv[i + 6], argv[i + 7], argv[i + 8], SLAVE);
        fdraw = ethudp_open_rawsocket(argv[i + 4], &ifindex);
    } else if (mode == MODEI) {    // interface mode
        char *actualname = NULL;
        char buf[MAXLEN];
        fdudp[MASTER] = ethudp_udp_xconnect(argv[i], argv[i + 1], argv[i + 2], argv[i + 3], MASTER);
        if (master_slave)
            fdudp[SLAVE] = ethudp_udp_xconnect(argv[i + 6], argv[i + 7], argv[i + 8], argv[i + 9], SLAVE);
        fdraw = ethudp_open_tun("tap", &actualname);
        if (dev_name[0])
            snprintf(buf, MAXLEN, "%s link set %s name %s; %s addr add %s/%s dev %s; %s link set %s up",
                 IPCMD, actualname, dev_name, IPCMD, argv[i + 4], argv[i + 5], dev_name, IPCMD, dev_name);
        else
            snprintf(buf, MAXLEN, "%s addr add %s/%s dev %s; %s link set %s up", IPCMD, argv[i + 4], argv[i + 5], actualname, IPCMD, actualname);
        if (debug)
            printf(" run cmd: %s\n", buf);
        if (system(buf) != 0)
            printf(" run cmd: %s returned not 0\n", buf);
        if (debug) {
            snprintf(buf, MAXLEN, "%s addr", IPCMD);
            if (system(buf) != 0)
                printf(" run cmd: %s returned not 0\n", buf);
        }
    } else if (mode == MODEB) {    // bridge mode
        char *actualname = NULL;
        char buf[MAXLEN];
        fdudp[MASTER] = ethudp_udp_xconnect(argv[i], argv[i + 1], argv[i + 2], argv[i + 3], MASTER);
        if (master_slave)
            fdudp[SLAVE] = ethudp_udp_xconnect(argv[i + 5], argv[i + 6], argv[i + 7], argv[i + 8], SLAVE);
        fdraw = ethudp_open_tun("tap", &actualname);
        if (dev_name[0])
            snprintf(buf, MAXLEN, "%s link set %s name %s; %s link set %s up; %s addif %s %s",
                 IPCMD, actualname, dev_name, IPCMD, dev_name, BRIDGECMD, argv[i + 4], dev_name);
        else
            snprintf(buf, MAXLEN, "%s link set %s up; %s addif %s %s", IPCMD, actualname, BRIDGECMD, argv[i + 4], actualname);
        if (debug)
            printf(" run cmd: %s\n", buf);
        if (system(buf) != 0)
            printf(" run cmd: %s returned not 0\n", buf);
        if (debug) {
            snprintf(buf, MAXLEN, "%s addr", IPCMD);
            if (system(buf) != 0)
                printf(" run cmd: %s returned not 0\n", buf);
            snprintf(buf, MAXLEN, "%s show", BRIDGECMD);
            if (system(buf) != 0)
                printf(" run cmd: %s returned not 0\n", buf);
        }
    } else if ((mode == MODET) || (mode == MODEU)) {    // tcpdump mode
        char errbuf[PCAP_ERRBUF_SIZE];
        read_only = 1;
        fdudp[MASTER] = ethudp_udp_xconnect(argv[i], argv[i + 1], argv[i + 2], argv[i + 3], MASTER);
        pcap_handle = pcap_open_live(argv[i + 4], MAX_PACKET_SIZE, 0, 1000, errbuf);
        if (argc - i == 6) {
            struct bpf_program pgm;
            if (pcap_compile(pcap_handle, &pgm, argv[i + 5], 1, PCAP_NETMASK_UNKNOWN) == -1) {
                err_msg("pcap_filter compile error\n");
                exit(0);
            }
            if (pcap_setfilter(pcap_handle, &pgm) == -1) {
                err_msg("pcap_setfilter error\n");
                exit(0);
            }
        }
    }
    
    return 0;
}

// Run the main application loop
int run_application(void)
{
    pthread_t tid;
    
    // Check if we should use the new optimized worker system
    if (global_config.udp_workers > 1 || global_config.raw_workers > 1 || 
        global_config.cpu_affinity || global_config.batch_size > 1 || 
        global_config.enable_dynamic_scaling) {
        
        // Use new optimized worker system
        Debug("Using optimized worker system with dynamic scaling: %s", 
              global_config.enable_dynamic_scaling ? "enabled" : "disabled");
        
        // Initialize dynamic thread management system
        if (global_config.enable_dynamic_scaling) {
            global_dynamic_system = malloc(sizeof(dynamic_system_t));
            if (ethudp_init_dynamic_system(global_dynamic_system) != 0) {
                err_sys("Failed to initialize dynamic system");
            }
            if (global_dynamic_system == NULL) {
                err_sys("Failed to initialize dynamic system");
            }
            Debug("Dynamic thread management system initialized");
        }
        
        // Start worker threads
        if (start_worker_threads() != 0) {
            err_sys("Failed to start worker threads");
        }
        
        // Start dynamic system if enabled
        if (global_config.enable_dynamic_scaling && global_dynamic_system) {
            if (ethudp_start_dynamic_system(global_dynamic_system) != 0) {
                err_sys("Failed to start dynamic system");
            }
            Debug("Dynamic scaling system started");
        }
        
        // Keep alive thread for non-tcpdump modes
        if ((mode != MODET) && (mode != MODEU)) {
            if (pthread_create(&tid, NULL, (void *)send_keepalive_to_udp, NULL) != 0)
                err_sys("pthread_create send_keepalive error");
        }
        
        // Main thread handles RAW socket reading for tcpdump modes
        if (mode == MODET || mode == MODEU) {
            process_raw_to_udp();
        } else {
            // For other modes, main thread can sleep or handle signals
            while (global_worker_pool.running) {
                sleep(1);
            }
        }
        
        // Cleanup
        if (global_config.enable_dynamic_scaling) {
            ethudp_stop_dynamic_system(global_dynamic_system);
            Debug("Dynamic thread management system stopped");
            free(global_dynamic_system);
            global_dynamic_system = NULL;
        }
        stop_worker_threads();
        
    } else {
        // Use original single-threaded system for compatibility
        Debug("Using original single-threaded system");
        
        // create a pthread to forward packets from master udp to raw
        if (pthread_create(&tid, NULL, (void *)process_udp_to_raw_master, NULL) != 0)
            err_sys("pthread_create udp_to_raw_master error");

        // create a pthread to forward packets from slave udp to raw
        if (master_slave)
            if (pthread_create(&tid, NULL, (void *)process_udp_to_raw_slave, NULL) != 0)
                err_sys("pthread_create udp_to_raw_slave error");

        if ((mode != MODET) && (mode != MODEU))
            if (pthread_create(&tid, NULL, (void *)send_keepalive_to_udp, NULL) != 0)
                err_sys("pthread_create send_keepalive error");

        //  forward packets from raw to udp
        process_raw_to_udp();
    }
    
    return 0;
}

// Main function
int main(int argc, char *argv[])
{
    
    // Initialize application
    if (initialize_application() != 0) {
        err_quit("Failed to initialize application");
    }
    
    // Parse command line arguments
    ethudp_config_t config;
    ethudp_config_init(&config);
    
    int arg_start = ethudp_config_parse_args(&config, argc, argv);
    if (arg_start < 0) {
        ethudp_config_usage();
        exit(1);
    }
    
    // Apply configuration to global variables
    debug = config.debug;
    mode = config.mode;
    master_slave = config.master_slave;
    read_only = config.read_only;
    write_only = config.write_only;
    nopromisc = config.nopromisc;
    loopback_check = config.loopback_check;
    fixmss = config.fixmss;
    mtu = config.mtu;
    lz4 = config.lz4;
    packet_len = config.packet_len;
    run_seconds = config.run_seconds;
    enc_algorithm = config.enc_algorithm;
    enc_key_len = config.enc_key_len;
    vlan_map = config.vlan_map;
    
    // Copy string fields
    strncpy(name, config.name, MAXLEN - 1);
    strncpy(run_cmd, config.run_cmd, MAXLEN - 1);
    strncpy(dev_name, config.dev_name, IFNAMSIZ - 1);
    strncpy(mypassword, config.password, MAXLEN - 1);
    memcpy(enc_key, config.enc_key, MAXLEN);
    
    // Copy global config
    global_config.mode = config.mode;
    global_config.debug = config.debug;
    global_config.master_slave = config.master_slave;
    global_config.udp_workers = config.udp_workers;
    global_config.raw_workers = config.raw_workers;
    global_config.cpu_affinity = config.cpu_affinity;
    global_config.batch_size = config.batch_size;
    global_config.enable_dynamic_scaling = config.enable_dynamic_scaling;
    
    // Validate configuration
    if (ethudp_config_validate(&config) != 0) {
        err_quit("Invalid configuration");
    }
    
    // Print configuration if debug mode
    if (debug) {
        ethudp_config_print(&config);
    }
    
    // Handle benchmark mode
    if (config.benchmark) {
        do_benchmark();
    }
    
    // Daemonize if not in debug mode
    if (debug == 0) {
        ethudp_daemon_init("EthUDP", LOG_DAEMON);
        while (1) {
            int pid;
            pid = fork();
            if (pid == 0)    // child do the job
                break;
            else if (pid == -1)    // error
                exit(0);
            else
                wait(NULL);    // parent wait for child
            sleep(2);    // wait 2 second, and rerun
        }
    }
    
    // Setup signal handlers
    signal(SIGHUP, sig_handler_hup);
    signal(SIGUSR1, sig_handler_usr1);
    
    // Setup network connections
    if (setup_network_connections(argc, argv, arg_start) != 0) {
        err_quit("Failed to setup network connections");
    }
    
    // Run user command if specified
    if (run_cmd[0]) {
        if (debug)
            printf(" run user cmd: %s\n", run_cmd);
        if (system(run_cmd) != 0)
            printf(" run cmd: %s returned not 0\n", run_cmd);
    }
    
    // Run main application
    return run_application();
}

// ============================================================================
// STUB IMPLEMENTATIONS FOR MISSING FUNCTIONS
// ============================================================================

void* process_udp_to_raw_master(void *arg)
{
    Debug("process_udp_to_raw_master thread started (master mode)");
    
    // Allocate packet buffers
    unsigned char recv_buf[MAX_PACKET_SIZE];
    unsigned char send_buf[MAX_PACKET_SIZE + 8]; // Extra space for headers
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // Statistics counters
    long long packets_processed = 0;
    long long bytes_processed = 0;
    long long errors = 0;
    
    // Main processing loop
    while (1) {
        // Receive UDP packet from master socket
        ssize_t recv_len = recvfrom(fdudp[MASTER], recv_buf, sizeof(recv_buf), 
                                   0, (struct sockaddr*)&client_addr, &client_len);
        
        if (recv_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No data available, yield CPU briefly
                usleep(1000); // 1 millisecond
                continue;
            } else {
                err_msg("process_udp_to_raw_master: recvfrom error: %s", strerror(errno));
                errors++;
                continue;
            }
        }
        
        if (recv_len == 0) {
            continue; // Empty packet
        }
        
        // Update statistics
        packets_processed++;
        bytes_processed += recv_len;
        
        // Process packet based on mode
        int processed_len = recv_len;
        
        // Apply loopback check if enabled
        if (loopback_check && do_loopback_check(recv_buf, recv_len)) {
            Debug("process_udp_to_raw_master: Packet failed loopback check, dropping");
            continue;
        }
        
        // Apply MSS fixing if enabled
        if (fixmss) {
            processed_len = fix_mss(recv_buf, recv_len);
            if (processed_len < 0) {
                err_msg("process_udp_to_raw_master: MSS fixing failed");
                errors++;
                continue;
            }
        }
        
        // Apply encryption if configured
        if (enc_algorithm != 0) {
            processed_len = do_encrypt(recv_buf, processed_len, send_buf);
            if (processed_len < 0) {
                err_msg("process_udp_to_raw_master: Encryption failed");
                errors++;
                continue;
            }
        } else {
            // No encryption, just copy
            memcpy(send_buf, recv_buf, processed_len);
        }
        
        // Add EthUDP header (8 bytes: "UDPFRG" + sequence)
        memmove(send_buf + 8, send_buf, processed_len);
        memcpy(send_buf, "UDPFRG", 6);
        uint16_t seq = htons((uint16_t)(packets_processed & 0xFFFF));
        memcpy(send_buf + 6, &seq, 2);
        processed_len += 8;
        
        // Send to RAW socket
        ssize_t sent_len = write(fdraw, send_buf, processed_len);
        if (sent_len < 0) {
            err_msg("process_udp_to_raw_master: write to RAW socket failed: %s", 
                    strerror(errno));
            errors++;
            continue;
        }
        
        if (sent_len != processed_len) {
            err_msg("process_udp_to_raw_master: Partial write to RAW socket (%zd/%d bytes)", 
                    sent_len, processed_len);
            errors++;
        }
        
        // Debug packet processing
        if (debug > 1) {
            Debug("process_udp_to_raw_master: Processed UDP→RAW packet: %zd→%d bytes, seq=%u", 
                  recv_len, processed_len, ntohs(seq));
        }
        
        // Periodic statistics reporting
        if (debug && (packets_processed % 1000 == 0)) {
            Debug("process_udp_to_raw_master: Processed %lld packets, %lld bytes, %lld errors", 
                  packets_processed, bytes_processed, errors);
        }
    }
    
    Debug("process_udp_to_raw_master thread stopped (processed %lld packets, %lld bytes, %lld errors)", 
          packets_processed, bytes_processed, errors);
    
    return NULL;
}

void* process_udp_to_raw_slave(void *arg)
{
    Debug("process_udp_to_raw_slave thread started");
    
    // Allocate packet buffers
    unsigned char recv_buf[MAX_PACKET_SIZE];
    unsigned char send_buf[MAX_PACKET_SIZE + 8]; // Extra space for headers
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // Statistics counters
    long long packets_processed = 0;
    long long bytes_processed = 0;
    long long errors = 0;
    
    // Main processing loop - slave mode
    while (1) {
        // Check if we should switch to master mode
        if (current_remote == MASTER && master_status == STATUS_OK) {
            // Master is active, slave should be in standby mode
            usleep(10000); // 10 milliseconds standby
            continue;
        }
        
        // Slave mode active - process packets from SLAVE socket
        ssize_t recv_len = recvfrom(fdudp[SLAVE], recv_buf, sizeof(recv_buf), 
                                   MSG_DONTWAIT, (struct sockaddr*)&client_addr, &client_len);
        
        if (recv_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No data available, check master status and yield CPU briefly
                if (master_status == STATUS_OK) {
                    // Master recovered, go back to standby
                    usleep(10000); // 10 milliseconds
                } else {
                    // Still in slave mode, brief yield
                    usleep(1000); // 1 millisecond
                }
                continue;
            } else {
                err_msg("process_udp_to_raw_slave: recvfrom error: %s", strerror(errno));
                errors++;
                continue;
            }
        }
        
        if (recv_len == 0) {
            continue; // Empty packet
        }
        
        // Update statistics
        packets_processed++;
        bytes_processed += recv_len;
        
        // Process packet based on mode
        int processed_len = recv_len;
        
        // Apply loopback check if enabled
        if (loopback_check && do_loopback_check(recv_buf, recv_len)) {
            Debug("process_udp_to_raw_slave: Packet failed loopback check, dropping");
            continue;
        }
        
        // Apply MSS fixing if enabled
        if (fixmss) {
            processed_len = fix_mss(recv_buf, recv_len);
            if (processed_len < 0) {
                err_msg("process_udp_to_raw_slave: MSS fixing failed");
                errors++;
                continue;
            }
        }
        
        // Apply encryption if configured
        if (enc_algorithm != 0) {
            processed_len = do_encrypt(recv_buf, processed_len, send_buf);
            if (processed_len < 0) {
                err_msg("process_udp_to_raw_slave: Encryption failed");
                errors++;
                continue;
            }
        } else {
            // No encryption, just copy
            memcpy(send_buf, recv_buf, processed_len);
        }
        
        // Add EthUDP header (8 bytes: "UDPFRG" + sequence) with slave marker
        memmove(send_buf + 8, send_buf, processed_len);
        memcpy(send_buf, "UDPSLV", 6); // Different header for slave packets
        uint16_t seq = htons((uint16_t)(packets_processed & 0xFFFF));
        memcpy(send_buf + 6, &seq, 2);
        processed_len += 8;
        
        // Send to RAW socket
        ssize_t sent_len = write(fdraw, send_buf, processed_len);
        if (sent_len < 0) {
            err_msg("process_udp_to_raw_slave: write to RAW socket failed: %s", 
                    strerror(errno));
            errors++;
            continue;
        }
        
        if (sent_len != processed_len) {
            err_msg("process_udp_to_raw_slave: Partial write to RAW socket (%zd/%d bytes)", 
                    sent_len, processed_len);
            errors++;
        }
        
        // Debug packet processing
        if (debug > 1) {
            Debug("process_udp_to_raw_slave: Processed UDP→RAW packet: %zd→%d bytes, seq=%u (SLAVE MODE)", 
                  recv_len, processed_len, ntohs(seq));
        }
        
        // Update slave status to indicate activity
        slave_status = STATUS_OK;
        
        // Periodic statistics reporting
        if (debug && (packets_processed % 1000 == 0)) {
            Debug("process_udp_to_raw_slave: Processed %lld packets, %lld bytes, %lld errors (SLAVE MODE)", 
                  packets_processed, bytes_processed, errors);
        }
    }
    
    Debug("process_udp_to_raw_slave thread stopped (processed %lld packets, %lld bytes, %lld errors)", 
          packets_processed, bytes_processed, errors);
    
    return NULL;
}

void* send_keepalive_to_udp(void *arg)
{
    Debug("send_keepalive_to_udp thread started");
    
    // Keepalive packet structure
    struct keepalive_packet {
        char magic[8];          // "ETHKPALV" magic string
        uint32_t timestamp;     // Current timestamp
        uint32_t sequence;      // Sequence number
        uint16_t mode;          // Current mode (master/slave)
        uint16_t status;        // Current status
        char padding[32];       // Padding to make packet larger for NAT
    } __attribute__((packed));
    
    struct keepalive_packet keepalive;
    uint32_t sequence = 0;
    
    // Statistics counters
    long long keepalives_sent = 0;
    long long keepalive_errors = 0;
    
    // Get keepalive interval from configuration (default 30 seconds)
    int keepalive_interval = (global_config.keepalive_interval > 0) ? 
                            global_config.keepalive_interval : DEFAULT_KEEPALIVE_INTERVAL;
    
    Debug("Keepalive interval set to %d seconds", keepalive_interval);
    
    // Main keepalive loop
    while (1) {
        // Sleep for the keepalive interval
        sleep(keepalive_interval);
        
        // Prepare keepalive packet
        memset(&keepalive, 0, sizeof(keepalive));
        memcpy(keepalive.magic, "ETHKPALV", 8);
        keepalive.timestamp = htonl((uint32_t)time(NULL));
        keepalive.sequence = htonl(sequence++);
        keepalive.mode = htons((uint16_t)current_remote);
        keepalive.status = htons((uint16_t)((current_remote == MASTER) ? master_status : slave_status));
        
        // Fill padding with pseudo-random data to avoid pattern detection
        for (int i = 0; i < sizeof(keepalive.padding); i++) {
            keepalive.padding[i] = (char)(sequence + i) ^ 0xAA;
        }
        
        // Send keepalive to both master and slave if configured
        for (int remote_idx = 0; remote_idx < 2; remote_idx++) {
            // Skip if remote address is not configured
            if (((struct sockaddr_in*)&remote_addr[remote_idx])->sin_addr.s_addr == 0) {
                continue;
            }
            
            // Send keepalive packet
            ssize_t sent_len = sendto(fdudp[remote_idx], &keepalive, sizeof(keepalive), 0,
                                     (struct sockaddr*)&remote_addr[remote_idx], 
                                     sizeof(struct sockaddr_in));
            
            if (sent_len < 0) {
                err_msg("send_keepalive_to_udp: Failed to send keepalive to remote %d: %s", 
                        remote_idx, strerror(errno));
                keepalive_errors++;
            } else if (sent_len != sizeof(keepalive)) {
                err_msg("send_keepalive_to_udp: Partial keepalive sent to remote %d (%zd/%zu bytes)", 
                        remote_idx, sent_len, sizeof(keepalive));
                keepalive_errors++;
            } else {
                keepalives_sent++;
                
                if (debug > 1) {
                    Debug("send_keepalive_to_udp: Sent keepalive to remote %d (seq=%u, mode=%s, status=%s)", 
                          remote_idx, ntohl(keepalive.sequence),
                          (current_remote == MASTER) ? "MASTER" : "SLAVE",
                          ((current_remote == MASTER) ? master_status : slave_status) == STATUS_OK ? "OK" : "BAD");
                }
            }
        }
        
        // Update ping statistics for compatibility
        if (keepalives_sent > 0) {
            ping_send[MASTER]++;
            ping_send[SLAVE]++;
        }
        
        // Periodic statistics reporting
        if (debug && (keepalives_sent % 10 == 0)) {
            Debug("send_keepalive_to_udp: Sent %lld keepalives, %lld errors", 
                  keepalives_sent, keepalive_errors);
        }
        
        // Check for thread termination signal
        if (got_signal) {
            Debug("send_keepalive_to_udp: Received termination signal");
            break;
        }
    }
    
    Debug("send_keepalive_to_udp thread stopped (sent %lld keepalives, %lld errors)", 
          keepalives_sent, keepalive_errors);
    
    return NULL;
}

void process_raw_to_udp(void)
{
    Debug("process_raw_to_udp started (main processing loop)");
    
    // Allocate packet buffers
    unsigned char recv_buf[MAX_PACKET_SIZE + 8]; // Extra space for headers
    unsigned char send_buf[MAX_PACKET_SIZE];
    struct sockaddr_in dest_addr;
    
    // Initialize destination address structure
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    
    // Statistics counters
    long long packets_processed = 0;
    long long bytes_processed = 0;
    long long errors = 0;
    
    // Main processing loop
    while (1) {
        // Receive RAW packet
        ssize_t recv_len = read(fdraw, recv_buf, sizeof(recv_buf));
        
        if (recv_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No data available, yield CPU briefly
                usleep(1000); // 1 millisecond
                continue;
            } else {
                err_msg("process_raw_to_udp: read from RAW socket error: %s", strerror(errno));
                errors++;
                continue;
            }
        }
        
        if (recv_len < 8) {
            // Packet too small to contain EthUDP header
            continue;
        }
        
        // Verify EthUDP header
        if (memcmp(recv_buf, "UDPFRG", 6) != 0) {
            Debug("process_raw_to_udp: Invalid EthUDP header, dropping packet");
            continue;
        }
        
        // Extract sequence number (for debugging/statistics)
        uint16_t seq = ntohs(*(uint16_t*)(recv_buf + 6));
        
        // Skip EthUDP header (8 bytes)
        unsigned char *payload = recv_buf + 8;
        int payload_len = recv_len - 8;
        
        // Update statistics
        packets_processed++;
        bytes_processed += payload_len;
        
        // Process packet based on mode
        int processed_len = payload_len;
        
        // Apply decryption if configured
        if (enc_algorithm != 0) {
            processed_len = do_encrypt(payload, payload_len, send_buf); // decrypt is same function
            if (processed_len < 0) {
                err_msg("process_raw_to_udp: Decryption failed");
                errors++;
                continue;
            }
        } else {
            // No decryption, just copy
            memcpy(send_buf, payload, processed_len);
        }
        
        // Apply MSS fixing if enabled (reverse operation)
        if (fixmss) {
            processed_len = fix_mss(send_buf, processed_len);
            if (processed_len < 0) {
                err_msg("process_raw_to_udp: MSS fixing failed");
                errors++;
                continue;
            }
        }
        
        // Extract destination from packet or use configured destination
        if (remote_addr[MASTER].ss_family == AF_INET) {
            struct sockaddr_in *remote_in = (struct sockaddr_in*)&remote_addr[MASTER];
            dest_addr.sin_addr.s_addr = remote_in->sin_addr.s_addr;
        } else {
            // Try to extract destination from IP header if available
            if (processed_len >= 20) { // Minimum IP header size
                struct iphdr *ip_hdr = (struct iphdr*)send_buf;
                if (ip_hdr->version == 4) {
                    dest_addr.sin_addr.s_addr = ip_hdr->daddr;
                } else {
                    err_msg("process_raw_to_udp: No destination IP configured and cannot extract from packet");
                    errors++;
                    continue;
                }
            } else {
                err_msg("process_raw_to_udp: Packet too small to extract destination");
                errors++;
                continue;
            }
        }
        
        // Set destination port
        if (remote_addr[MASTER].ss_family == AF_INET) {
            struct sockaddr_in *remote_in = (struct sockaddr_in*)&remote_addr[MASTER];
            dest_addr.sin_port = remote_in->sin_port;
        } else {
            // Try to extract port from UDP header if available
            if (processed_len >= 28) { // IP header (20) + UDP header (8)
                struct iphdr *ip_hdr = (struct iphdr*)send_buf;
                if (ip_hdr->protocol == IPPROTO_UDP) {
                    struct udphdr *udp_hdr = (struct udphdr*)(send_buf + (ip_hdr->ihl * 4));
                    dest_addr.sin_port = udp_hdr->dest;
                } else {
                    dest_addr.sin_port = htons(8080);  // Default UDP port
                }
            } else {
                dest_addr.sin_port = htons(8080);  // Default UDP port
            }
        }
        
        // Send to UDP socket (use first UDP socket for main processing)
        ssize_t sent_len = sendto(fdudp[MASTER], send_buf, processed_len, 0,
                                 (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        
        if (sent_len < 0) {
            err_msg("process_raw_to_udp: sendto UDP socket failed: %s", strerror(errno));
            errors++;
            continue;
        }
        
        if (sent_len != processed_len) {
            err_msg("process_raw_to_udp: Partial send to UDP socket (%zd/%d bytes)", 
                    sent_len, processed_len);
            errors++;
        }
        
        // Debug packet processing
        if (debug > 1) {
            char dest_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &dest_addr.sin_addr, dest_ip_str, INET_ADDRSTRLEN);
            Debug("process_raw_to_udp: Processed RAW→UDP packet: %zd→%d bytes, seq=%u, dest=%s:%d", 
                  recv_len, processed_len, seq, dest_ip_str, ntohs(dest_addr.sin_port));
        }
        
        // Periodic statistics reporting
        if (debug && (packets_processed % 1000 == 0)) {
            Debug("process_raw_to_udp: Processed %lld packets, %lld bytes, %lld errors", 
                  packets_processed, bytes_processed, errors);
        }
    }
    
    Debug("process_raw_to_udp stopped (processed %lld packets, %lld bytes, %lld errors)", 
          packets_processed, bytes_processed, errors);
}

void* worker_stats_reporter(void *arg)
{
    Debug("worker_stats_reporter thread started - enhanced statistics reporting");
    
    int report_counter = 0;
    struct timespec start_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    while (global_worker_pool.running) {
        sleep(DEFAULT_STATS_INTERVAL); // Report stats every 5 seconds (configurable)
        report_counter++;
        
        if (debug) {
            struct timespec current_time;
            clock_gettime(CLOCK_MONOTONIC, &current_time);
            double uptime = (current_time.tv_sec - start_time.tv_sec) +
                          (current_time.tv_nsec - start_time.tv_nsec) / 1e9;
            
            printf("\n=== Worker Statistics Report #%d (Uptime: %.1fs) ===\n", report_counter, uptime);
            
            // Basic pool status
            printf("Pool Status: %s | UDP Workers: %d | RAW Workers: %d\n", 
                   global_worker_pool.running ? "Running" : "Stopped",
                   global_worker_pool.udp_worker_count,
                   global_worker_pool.raw_worker_count);
            
            // Quick performance summary
            long long total_packets = 0, total_bytes = 0, total_errors = 0;
            
            // Sum UDP workers
            for (int i = 0; i < global_worker_pool.udp_worker_count; i++) {
                worker_context_t *worker = &global_worker_pool.udp_workers[i];
                total_packets += worker->packets_processed;
                total_bytes += worker->bytes_processed;
                total_errors += worker->errors;
            }
            
            // Sum RAW workers
            for (int i = 0; i < global_worker_pool.raw_worker_count; i++) {
                worker_context_t *worker = &global_worker_pool.raw_workers[i];
                total_packets += worker->packets_processed;
                total_bytes += worker->bytes_processed;
                total_errors += worker->errors;
            }
            
            // Calculate rates
            double pps = (uptime > 0) ? (double)total_packets / uptime : 0.0;
            double throughput_mbps = (uptime > 0) ? 
                                   ((double)total_bytes * 8.0) / (uptime * 1024.0 * 1024.0) : 0.0;
            double error_rate = (total_packets > 0) ? 
                              ((double)total_errors / (double)total_packets) * 100.0 : 0.0;
            
            printf("Performance: %.1f PPS | %.2f Mbps | %.4f%% errors | %lld total packets\n",
                   pps, throughput_mbps, error_rate, total_packets);
            
            // Every 6th report (30 seconds), show detailed statistics
            if (report_counter % 6 == 0) {
                printf("\n--- Detailed Statistics (every 30s) ---\n");
                print_worker_statistics();
            }
            
            printf("=== End Report #%d ===\n\n", report_counter);
        }
        
        // Check for thread termination signal
        if (!global_worker_pool.running) {
            Debug("worker_stats_reporter: Received termination signal");
            break;
        }
    }
    
    // Final statistics report
    if (debug) {
        printf("\n=== FINAL Worker Statistics Report ===\n");
        print_worker_statistics();
        printf("Total reports generated: %d\n", report_counter);
    }
    
    Debug("worker_stats_reporter thread stopped after %d reports", report_counter);
    return NULL;
}