/**
 * @file ethudp_dynamic.c
 * @brief Dynamic thread management and auto-scaling system for EthUDP
 * 
 * This module implements intelligent dynamic thread management with:
 * - Real-time system metrics collection
 * - Load pattern detection and prediction
 * - Adaptive auto-scaling of worker threads
 * - Performance monitoring and optimization
 * - Load balancing across workers
 */

#include "ethudp_common.h"
#include "ethudp_types.h"
#include "ethudp_utils.h"
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <string.h>
#include <math.h>

// External references
extern volatile int debug;
extern dynamic_system_t *global_dynamic_system;
extern worker_pool_t global_worker_pool;

// Forward declarations for worker functions
extern void* process_udp_to_raw_worker(void *arg);
extern void* process_raw_to_udp_worker(void *arg);

// ============================================================================
// SYSTEM METRICS COLLECTION
// ============================================================================

/**
 * Collect comprehensive system metrics for scaling decisions
 */
void ethudp_collect_dynamic_metrics(system_metrics_t *metrics) {
    if (!metrics) return;
    
    memset(metrics, 0, sizeof(system_metrics_t));
    
    // Get current timestamp
    metrics->timestamp = ethudp_get_current_time_ms();
    
    // Collect CPU usage
    metrics->cpu_usage_percent = ethudp_get_cpu_usage();
    
    // Collect memory usage
    metrics->memory_usage_percent = ethudp_get_memory_usage();
    
    // Calculate packets per second from worker statistics
    static uint64_t last_total_packets = 0;
    static uint64_t last_timestamp = 0;
    
    uint64_t total_packets = 0;
    uint64_t total_latency = 0;
    uint32_t total_queue_depth = 0;
    uint32_t active_workers = 0;
    
    // Aggregate UDP worker statistics
    for (int i = 0; i < global_worker_pool.udp_worker_count; i++) {
        worker_context_t *ctx = &global_worker_pool.udp_workers[i];
        if (ctx->running) {
            total_packets += ctx->packets_processed;
            total_latency += ctx->total_latency_us;
            total_queue_depth += ctx->current_queue_depth;
            active_workers++;
        }
    }
    
    // Aggregate RAW worker statistics
    for (int i = 0; i < global_worker_pool.raw_worker_count; i++) {
        worker_context_t *ctx = &global_worker_pool.raw_workers[i];
        if (ctx->running) {
            total_packets += ctx->packets_processed;
            total_latency += ctx->total_latency_us;
            total_queue_depth += ctx->current_queue_depth;
            active_workers++;
        }
    }
    
    // Calculate PPS
    if (last_timestamp > 0) {
        uint64_t time_diff = metrics->timestamp - last_timestamp;
        if (time_diff > 0) {
            metrics->packets_per_second = (double)(total_packets - last_total_packets) * 1000.0 / time_diff;
        }
    }
    
    // Calculate average latency
    if (total_packets > 0) {
        metrics->avg_latency_us = (double)total_latency / total_packets;
    }
    
    // Set queue depth
    metrics->queue_depth = total_queue_depth;
    
    // Update for next calculation
    last_total_packets = total_packets;
    last_timestamp = metrics->timestamp;
}

/**
 * Update metrics history with new sample
 */
void ethudp_update_metrics_history(metrics_history_t *history, const system_metrics_t *metrics) {
    if (!history || !metrics) return;
    
    // Shift existing samples
    if (history->count >= METRICS_HISTORY_SIZE) {
        memmove(&history->samples[0], &history->samples[1], 
                (METRICS_HISTORY_SIZE - 1) * sizeof(system_metrics_t));
        history->count = METRICS_HISTORY_SIZE - 1;
    }
    
    // Add new sample
    history->samples[history->count] = *metrics;
    history->count++;
    
    // Calculate running averages
    double pps_sum = 0.0, latency_sum = 0.0;
    uint64_t queue_sum = 0;
    
    for (int i = 0; i < history->count; i++) {
        pps_sum += history->samples[i].packets_per_second;
        latency_sum += history->samples[i].avg_latency_us;
        queue_sum += history->samples[i].queue_depth;
    }
    
    history->avg_pps = pps_sum / history->count;
    history->avg_latency = latency_sum / history->count;
    history->avg_queue_depth = (double)queue_sum / history->count;
}

// ============================================================================
// LOAD PATTERN DETECTION AND PREDICTION
// ============================================================================

/**
 * Detect load patterns and trends for predictive scaling
 */
void ethudp_detect_load_patterns(load_pattern_t *pattern, const metrics_history_t *history) {
    if (!pattern || !history || history->count < 10) return;
    
    // Detect trends by comparing recent vs older samples
    double recent_avg = 0.0, older_avg = 0.0;
    int recent_count = history->count / 3;
    int older_count = history->count - recent_count;
    
    for (int i = 0; i < recent_count; i++) {
        recent_avg += history->samples[i].packets_per_second;
    }
    for (int i = recent_count; i < history->count; i++) {
        older_avg += history->samples[i].packets_per_second;
    }
    
    recent_avg /= recent_count;
    older_avg /= older_count;
    
    // Determine trend
    if (recent_avg > older_avg * 1.2) {
        pattern->trend = TREND_INCREASING;
    } else if (recent_avg < older_avg * 0.8) {
        pattern->trend = TREND_DECREASING;
    } else {
        pattern->trend = TREND_STABLE;
    }
    
    // Predict load based on time of day patterns
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    int hour = tm_info->tm_hour;
    
    // Peak hours: 9-11 AM, 2-4 PM, 7-9 PM
    if ((hour >= 9 && hour <= 11) || (hour >= 14 && hour <= 16) || (hour >= 19 && hour <= 21)) {
        pattern->predicted_load = LOAD_HIGH;
    } else if (hour >= 22 || hour <= 6) {
        pattern->predicted_load = LOAD_LOW;
    } else {
        pattern->predicted_load = LOAD_MEDIUM;
    }
    
    pattern->confidence = 0.7; // Basic confidence level
    pattern->last_update = ethudp_get_current_time_ms();
}

// ============================================================================
// AUTO-SCALING DECISION ENGINE
// ============================================================================

/**
 * Make intelligent scaling decisions based on metrics and patterns
 */
scale_decision_t ethudp_make_scaling_decision(const dynamic_config_t *config, 
                                            const system_metrics_t *current_metrics,
                                            const metrics_history_t *history,
                                            const load_pattern_t *pattern) {
    if (!config || !current_metrics || !global_dynamic_system) {
        return SCALE_NONE;
    }
    
    // Check cooldown period
    uint64_t now = ethudp_get_current_time_ms();
    if (now - global_dynamic_system->last_scale_time < config->scale_cooldown_ms) {
        return SCALE_NONE;
    }
    
    // Scale up conditions
    if (current_metrics->cpu_usage_percent > config->cpu_threshold_high ||
        current_metrics->packets_per_second > config->pps_threshold_high ||
        current_metrics->avg_latency_us > config->latency_threshold_high ||
        current_metrics->queue_depth > config->queue_threshold_high) {
        
        // Verify trend supports scaling up
        if (pattern && (pattern->trend == TREND_INCREASING || pattern->predicted_load == LOAD_HIGH)) {
            return SCALE_UP;
        }
    }
    
    // Scale down conditions (more conservative)
    if (current_metrics->cpu_usage_percent < config->cpu_threshold_low &&
        current_metrics->packets_per_second < config->pps_threshold_low &&
        current_metrics->avg_latency_us < config->latency_threshold_low &&
        current_metrics->queue_depth < config->queue_threshold_low) {
        
        // Ensure we have enough history and trend supports scaling down
        if (history && history->count >= 20 && pattern && pattern->trend == TREND_DECREASING) {
            // Don't scale below minimum workers
            int total_workers = global_worker_pool.udp_worker_count + global_worker_pool.raw_worker_count;
            if (total_workers > config->min_workers) {
                return SCALE_DOWN;
            }
        }
    }
    
    return SCALE_NONE;
}

/**
 * Auto-tune thresholds based on historical performance data
 */
void ethudp_auto_tune_thresholds(dynamic_config_t *config, const metrics_history_t *history) {
    if (!config || !history || history->count < METRICS_HISTORY_SIZE) return;
    
    // Prepare arrays for percentile calculation
    double cpu_values[METRICS_HISTORY_SIZE];
    double pps_values[METRICS_HISTORY_SIZE];
    double latency_values[METRICS_HISTORY_SIZE];
    
    for (int i = 0; i < history->count; i++) {
        cpu_values[i] = history->samples[i].cpu_usage_percent;
        pps_values[i] = history->samples[i].packets_per_second;
        latency_values[i] = history->samples[i].avg_latency_us;
    }
    
    // Simple bubble sort for percentile calculation
    for (int i = 0; i < history->count - 1; i++) {
        for (int j = i + 1; j < history->count; j++) {
            if (cpu_values[i] > cpu_values[j]) {
                double temp = cpu_values[i];
                cpu_values[i] = cpu_values[j];
                cpu_values[j] = temp;
            }
            if (pps_values[i] > pps_values[j]) {
                double temp = pps_values[i];
                pps_values[i] = pps_values[j];
                pps_values[j] = temp;
            }
            if (latency_values[i] > latency_values[j]) {
                double temp = latency_values[i];
                latency_values[i] = latency_values[j];
                latency_values[j] = temp;
            }
        }
    }
    
    // Update thresholds based on 75th and 25th percentiles
    int p75_idx = (int)(history->count * 0.75);
    int p25_idx = (int)(history->count * 0.25);
    
    config->cpu_threshold_high = cpu_values[p75_idx] * 1.1;
    config->cpu_threshold_low = cpu_values[p25_idx] * 0.9;
    
    config->pps_threshold_high = pps_values[p75_idx] * 1.2;
    config->pps_threshold_low = pps_values[p25_idx] * 0.8;
    
    config->latency_threshold_high = latency_values[p75_idx] * 1.3;
    config->latency_threshold_low = latency_values[p25_idx] * 0.7;
    
    // Ensure reasonable bounds
    if (config->cpu_threshold_high > 95.0) config->cpu_threshold_high = 95.0;
    if (config->cpu_threshold_low < 10.0) config->cpu_threshold_low = 10.0;
    if (config->latency_threshold_low < 100.0) config->latency_threshold_low = 100.0;
}

/**
 * Log scaling events with structured information
 */
void ethudp_log_scaling_event(const char *event_type, const char *reason, 
                            int old_workers, int new_workers, 
                            const system_metrics_t *metrics) {
    if (!debug || !event_type || !reason || !metrics) return;
    
    char timestamp[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    ethudp_debug("SCALING_EVENT: {\"timestamp\":\"%s\", \"event\":\"%s\", \"reason\":\"%s\", "
          "\"workers_before\":%d, \"workers_after\":%d, \"cpu_usage\":%.2f, "
          "\"pps\":%.2f, \"latency_us\":%.2f, \"queue_depth\":%u}",
          timestamp, event_type, reason, old_workers, new_workers,
          metrics->cpu_usage_percent, metrics->packets_per_second, 
          metrics->avg_latency_us, metrics->queue_depth);
}

// ============================================================================
// WORKER MANAGEMENT
// ============================================================================

/**
 * Create a new UDP worker dynamically
 */
int ethudp_create_udp_worker(int worker_id) {
    if (worker_id >= MAX_WORKERS) return -1;
    
    worker_context_t *ctx = &global_worker_pool.udp_workers[worker_id];
    memset(ctx, 0, sizeof(worker_context_t));
    
    ctx->worker_id = worker_id;
    ctx->worker_type = WORKER_TYPE_UDP_TO_RAW;
    ctx->socket_index = MASTER;
    ctx->running = 1;
    
    // Initialize worker statistics
    clock_gettime(CLOCK_MONOTONIC, &ctx->start_time);
    
    if (pthread_create(&ctx->thread_id, NULL, process_udp_to_raw_worker, ctx) != 0) {
        ethudp_err_msg("Failed to create UDP worker %d", worker_id);
        return -1;
    }
    
    ethudp_debug("Created UDP worker %d", worker_id);
    return 0;
}

/**
 * Create a new RAW worker dynamically
 */
int ethudp_create_raw_worker(int worker_id) {
    if (worker_id >= MAX_WORKERS) return -1;
    
    worker_context_t *ctx = &global_worker_pool.raw_workers[worker_id];
    memset(ctx, 0, sizeof(worker_context_t));
    
    ctx->worker_id = worker_id;
    ctx->worker_type = WORKER_TYPE_RAW_TO_UDP;
    ctx->running = 1;
    
    // Initialize worker statistics
    clock_gettime(CLOCK_MONOTONIC, &ctx->start_time);
    
    if (pthread_create(&ctx->thread_id, NULL, process_raw_to_udp_worker, ctx) != 0) {
        ethudp_err_msg("Failed to create RAW worker %d", worker_id);
        return -1;
    }
    
    ethudp_debug("Created RAW worker %d", worker_id);
    return 0;
}

/**
 * Gracefully stop a UDP worker
 */
int ethudp_stop_udp_worker(int worker_id) {
    if (worker_id >= global_worker_pool.udp_worker_count) return -1;
    
    worker_context_t *ctx = &global_worker_pool.udp_workers[worker_id];
    if (!ctx->running) return 0;
    
    // Mark worker for graceful shutdown
    ctx->running = 0;
    ctx->should_stop = 1;
    
    // Wait for worker to finish current tasks
    pthread_join(ctx->thread_id, NULL);
    
    ethudp_debug("Stopped UDP worker %d", worker_id);
    return 0;
}

/**
 * Gracefully stop a RAW worker
 */
int ethudp_stop_raw_worker(int worker_id) {
    if (worker_id >= global_worker_pool.raw_worker_count) return -1;
    
    worker_context_t *ctx = &global_worker_pool.raw_workers[worker_id];
    if (!ctx->running) return 0;
    
    // Mark worker for graceful shutdown
    ctx->running = 0;
    ctx->should_stop = 1;
    
    // Signal the worker to wake up and check shutdown flag
    pthread_cond_broadcast(&global_worker_pool.raw_queue.cond);
    
    // Wait for worker to finish current tasks
    pthread_join(ctx->thread_id, NULL);
    
    ethudp_debug("Stopped RAW worker %d", worker_id);
    return 0;
}

/**
 * Find the least utilized UDP worker for scaling down
 */
int ethudp_find_least_utilized_udp_worker(void) {
    int least_utilized = -1;
    double min_utilization = 100.0;
    
    for (int i = 0; i < global_worker_pool.udp_worker_count; i++) {
        worker_context_t *ctx = &global_worker_pool.udp_workers[i];
        if (!ctx->running) continue;
        
        // Calculate utilization based on packets processed and CPU time
        double utilization = 0.0;
        if (ctx->packets_processed > 0) {
            struct timespec current_time;
            clock_gettime(CLOCK_MONOTONIC, &current_time);
            uint64_t runtime = (current_time.tv_sec - ctx->start_time.tv_sec) * 1000 + 
                              (current_time.tv_nsec - ctx->start_time.tv_nsec) / 1000000;
            if (runtime > 0) {
                utilization = (double)ctx->packets_processed / runtime * 1000.0;
            }
        }
        
        if (utilization < min_utilization) {
            min_utilization = utilization;
            least_utilized = i;
        }
    }
    
    return least_utilized;
}

/**
 * Find the least utilized RAW worker for scaling down
 */
int ethudp_find_least_utilized_raw_worker(void) {
    int least_utilized = -1;
    double min_utilization = 100.0;
    
    for (int i = 0; i < global_worker_pool.raw_worker_count; i++) {
        worker_context_t *ctx = &global_worker_pool.raw_workers[i];
        if (!ctx->running) continue;
        
        // Calculate utilization based on packets processed and CPU time
        double utilization = 0.0;
        if (ctx->packets_processed > 0) {
            struct timespec current_time;
            clock_gettime(CLOCK_MONOTONIC, &current_time);
            uint64_t runtime = (current_time.tv_sec - ctx->start_time.tv_sec) * 1000 + 
                              (current_time.tv_nsec - ctx->start_time.tv_nsec) / 1000000;
            if (runtime > 0) {
                utilization = (double)ctx->packets_processed / runtime * 1000.0;
            }
        }
        
        if (utilization < min_utilization) {
            min_utilization = utilization;
            least_utilized = i;
        }
    }
    
    return least_utilized;
}

/**
 * Scale up workers based on current load
 */
int ethudp_scale_up_workers(const system_metrics_t *metrics) {
    if (!metrics || !global_dynamic_system) return 0;
    
    int total_workers = global_worker_pool.udp_worker_count + global_worker_pool.raw_worker_count;
    
    if (total_workers >= global_dynamic_system->config.max_workers) {
        ethudp_debug("Cannot scale up: already at maximum workers (%d)", global_dynamic_system->config.max_workers);
        return 0;
    }
    
    // Determine which type of worker to add based on current load distribution
    double udp_load = 0.0, raw_load = 0.0;
    
    for (int i = 0; i < global_worker_pool.udp_worker_count; i++) {
        udp_load += (uint32_t)global_worker_pool.udp_workers[i].queue_full_drops;
    }
    for (int i = 0; i < global_worker_pool.raw_worker_count; i++) {
        raw_load += (uint32_t)global_worker_pool.raw_workers[i].queue_full_drops;
    }
    
    // Add worker to the more loaded type
    if (udp_load >= raw_load) {
        // Add UDP worker
        if (global_worker_pool.udp_worker_count < MAX_WORKERS) {
            if (ethudp_create_udp_worker(global_worker_pool.udp_worker_count) == 0) {
                global_worker_pool.udp_worker_count++;
                ethudp_log_scaling_event("SCALE_UP_UDP", "High UDP load", total_workers, total_workers + 1, metrics);
                return 1;
            }
        }
    } else {
        // Add RAW worker
        if (global_worker_pool.raw_worker_count < MAX_WORKERS) {
            if (ethudp_create_raw_worker(global_worker_pool.raw_worker_count) == 0) {
                global_worker_pool.raw_worker_count++;
                ethudp_log_scaling_event("SCALE_UP_RAW", "High RAW load", total_workers, total_workers + 1, metrics);
                return 1;
            }
        }
    }
    
    return 0;
}

/**
 * Scale down workers based on low load
 */
int ethudp_scale_down_workers(const system_metrics_t *metrics) {
    if (!metrics || !global_dynamic_system) return 0;
    
    int total_workers = global_worker_pool.udp_worker_count + global_worker_pool.raw_worker_count;
    
    if (total_workers <= global_dynamic_system->config.min_workers) {
        ethudp_debug("Cannot scale down: already at minimum workers (%d)", global_dynamic_system->config.min_workers);
        return 0;
    }
    
    // Determine which type of worker to remove based on utilization
    int udp_candidate = ethudp_find_least_utilized_udp_worker();
    int raw_candidate = ethudp_find_least_utilized_raw_worker();
    
    // Remove the least utilized worker
    if (udp_candidate >= 0 && raw_candidate >= 0) {
        // Compare utilization and remove the least utilized
        worker_context_t *udp_ctx = &global_worker_pool.udp_workers[udp_candidate];
        worker_context_t *raw_ctx = &global_worker_pool.raw_workers[raw_candidate];
        
        if (udp_ctx->packets_processed <= raw_ctx->packets_processed) {
            if (ethudp_stop_udp_worker(udp_candidate) == 0) {
                global_worker_pool.udp_worker_count--;
                ethudp_log_scaling_event("SCALE_DOWN_UDP", "Low UDP utilization", total_workers, total_workers - 1, metrics);
                return 1;
            }
        } else {
            if (ethudp_stop_raw_worker(raw_candidate) == 0) {
                global_worker_pool.raw_worker_count--;
                ethudp_log_scaling_event("SCALE_DOWN_RAW", "Low RAW utilization", total_workers, total_workers - 1, metrics);
                return 1;
            }
        }
    } else if (udp_candidate >= 0 && global_worker_pool.udp_worker_count > 1) {
        if (ethudp_stop_udp_worker(udp_candidate) == 0) {
            global_worker_pool.udp_worker_count--;
            ethudp_log_scaling_event("SCALE_DOWN_UDP", "Low UDP utilization", total_workers, total_workers - 1, metrics);
            return 1;
        }
    } else if (raw_candidate >= 0 && global_worker_pool.raw_worker_count > 1) {
        if (ethudp_stop_raw_worker(raw_candidate) == 0) {
            global_worker_pool.raw_worker_count--;
            ethudp_log_scaling_event("SCALE_DOWN_RAW", "Low RAW utilization", total_workers, total_workers - 1, metrics);
            return 1;
        }
    }
    
    return 0;
}

/**
 * Intelligent load balancer for optimal distribution
 */
void ethudp_balance_worker_load(void) {
    // Calculate load distribution across workers
    double udp_loads[MAX_WORKERS] = {0};
    double raw_loads[MAX_WORKERS] = {0};
    
    for (int i = 0; i < global_worker_pool.udp_worker_count; i++) {
        udp_loads[i] = (uint32_t)global_worker_pool.udp_workers[i].queue_full_drops;
    }
    for (int i = 0; i < global_worker_pool.raw_worker_count; i++) {
        raw_loads[i] = (uint32_t)global_worker_pool.raw_workers[i].queue_full_drops;
    }
    
    // Find imbalanced workers (simple threshold-based approach)
    double udp_avg = 0.0, raw_avg = 0.0;
    for (int i = 0; i < global_worker_pool.udp_worker_count; i++) {
        udp_avg += udp_loads[i];
    }
    for (int i = 0; i < global_worker_pool.raw_worker_count; i++) {
        raw_avg += raw_loads[i];
    }
    
    if (global_worker_pool.udp_worker_count > 0) udp_avg /= global_worker_pool.udp_worker_count;
    if (global_worker_pool.raw_worker_count > 0) raw_avg /= global_worker_pool.raw_worker_count;
    
    // Log load imbalance if significant
    for (int i = 0; i < global_worker_pool.udp_worker_count; i++) {
        if (udp_loads[i] > udp_avg * 2.0) {
            ethudp_debug("UDP worker %d overloaded: %.2f vs avg %.2f", i, udp_loads[i], udp_avg);
        }
    }
    for (int i = 0; i < global_worker_pool.raw_worker_count; i++) {
        if (raw_loads[i] > raw_avg * 2.0) {
            ethudp_debug("RAW worker %d overloaded: %.2f vs avg %.2f", i, raw_loads[i], raw_avg);
        }
    }
}

/**
 * Execute scaling decision with actual worker management
 */
void ethudp_execute_scaling_decision(scale_decision_t decision, const system_metrics_t *metrics) {
    if (!metrics || !global_dynamic_system) return;
    
    switch (decision) {
        case SCALE_UP:
            if (ethudp_scale_up_workers(metrics)) {
                global_dynamic_system->last_scale_time = ethudp_get_current_time_ms();
                ethudp_balance_worker_load();
            }
            break;
            
        case SCALE_DOWN:
            if (ethudp_scale_down_workers(metrics)) {
                global_dynamic_system->last_scale_time = ethudp_get_current_time_ms();
                ethudp_balance_worker_load();
            }
            break;
            
        case SCALE_NONE:
        default:
            // Perform load balancing even when not scaling
            ethudp_balance_worker_load();
            break;
    }
}

// ============================================================================
// DYNAMIC SYSTEM MANAGEMENT
// ============================================================================

/**
 * Main monitoring thread function
 */
void* ethudp_metrics_collector_thread(void *arg) {
    dynamic_system_t *system = (dynamic_system_t*)arg;
    if (!system) return NULL;
    
    system_metrics_t current_metrics;
    
    ethudp_debug("Dynamic metrics collector thread started");
    
    while (system->running) {
        // Collect current metrics
        ethudp_collect_dynamic_metrics(&current_metrics);
        
        // Update history
        ethudp_update_metrics_history(&system->metrics_history, &current_metrics);
        
        // Detect load patterns
        ethudp_detect_load_patterns(&system->load_pattern, &system->metrics_history);
        
        // Make scaling decision
        scale_decision_t decision = ethudp_make_scaling_decision(&system->config, 
                                                        &current_metrics, 
                                                        &system->metrics_history, 
                                                        &system->load_pattern);
        
        // Execute scaling decision
        ethudp_execute_scaling_decision(decision, &current_metrics);
        
        // Auto-tune thresholds periodically
        static int tune_counter = 0;
        if (++tune_counter >= 100) { // Every 10 seconds (100ms * 100)
            ethudp_auto_tune_thresholds(&system->config, &system->metrics_history);
            tune_counter = 0;
        }
        
        // Sleep for monitoring interval
        ethudp_sleep_ms(system->config.monitoring_interval_ms);
    }
    
    ethudp_debug("Dynamic metrics collector thread stopped");
    return NULL;
}

/**
 * Initialize dynamic system with default configuration
 */
int ethudp_init_dynamic_system(dynamic_system_t *system) {
    if (!system) return -1;
    
    memset(system, 0, sizeof(dynamic_system_t));
    
    // Initialize configuration with default values
    system->config.monitoring_interval_ms = 100;
    system->config.scale_cooldown_ms = 5000;
    system->config.cpu_threshold_high = 80.0;
    system->config.cpu_threshold_low = 20.0;
    system->config.pps_threshold_high = 10000.0;
    system->config.pps_threshold_low = 1000.0;
    system->config.latency_threshold_high = 5000.0;
    system->config.latency_threshold_low = 500.0;
    system->config.queue_threshold_high = 1000;
    system->config.queue_threshold_low = 10;
    system->config.min_workers = 2;
    system->config.max_workers = ethudp_get_cpu_count();
    system->config.enable_auto_tuning = 1;
    system->config.enable_pattern_prediction = 1;
    
    system->running = 0;
    system->last_scale_time = 0;
    
    ethudp_debug("Dynamic system initialized with max_workers=%d", system->config.max_workers);
    return 0;
}

/**
 * Start dynamic system monitoring
 */
int ethudp_start_dynamic_system(dynamic_system_t *system) {
    if (!system || system->running) return 0;
    
    system->running = 1;
    
    if (pthread_create(&system->monitor_thread, NULL, ethudp_metrics_collector_thread, system) != 0) {
        ethudp_err_msg("Failed to create metrics collector thread");
        system->running = 0;
        return -1;
    }
    
    ethudp_debug("Dynamic thread management system started");
    return 0;
}

/**
 * Stop dynamic system monitoring
 */
void ethudp_stop_dynamic_system(dynamic_system_t *system) {
    if (!system || !system->running) return;
    
    system->running = 0;
    
    if (system->monitor_thread) {
        pthread_join(system->monitor_thread, NULL);
        system->monitor_thread = 0;
    }
    
    ethudp_debug("Dynamic thread management system stopped");
}