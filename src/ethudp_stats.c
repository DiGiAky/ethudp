#include "../include/ethudp_common.h"
#include "../include/ethudp_types.h"
#include "../include/ethudp_stats.h"
#include "../include/ethudp_utils.h"
#include <math.h>

// Global statistics manager
ethudp_stats_manager_t *global_stats_manager = NULL;

// Window durations in milliseconds
static const uint64_t window_durations[STATS_WINDOW_MAX] = {
    1000,      // 1 second
    5000,      // 5 seconds
    30000,     // 30 seconds
    60000,     // 1 minute
    300000,    // 5 minutes
    900000,    // 15 minutes
    3600000    // 1 hour
};

/**
 * Initialize time series
 */
int ethudp_stats_timeseries_init(ethudp_stats_timeseries_t *ts, 
                                size_t capacity, uint64_t window_size_ms) {
    if (!ts || capacity == 0) {
        return -1;
    }
    
    memset(ts, 0, sizeof(ethudp_stats_timeseries_t));
    
    ts->points = calloc(capacity, sizeof(ethudp_stats_datapoint_t));
    if (!ts->points) {
        return -1;
    }
    
    ts->capacity = capacity;
    ts->window_size_ms = window_size_ms;
    
    if (pthread_mutex_init(&ts->buffer_mutex, NULL) != 0) {
        free(ts->points);
        return -1;
    }
    
    return 0;
}

/**
 * Cleanup time series
 */
void ethudp_stats_timeseries_cleanup(ethudp_stats_timeseries_t *ts) {
    if (!ts) {
        return;
    }
    
    if (ts->points) {
        free(ts->points);
        ts->points = NULL;
    }
    
    pthread_mutex_destroy(&ts->buffer_mutex);
    memset(ts, 0, sizeof(ethudp_stats_timeseries_t));
}

/**
 * Add data point to time series
 */
int ethudp_stats_timeseries_add(ethudp_stats_timeseries_t *ts, 
                               uint64_t timestamp, double value) {
    if (!ts || !ts->points) {
        return -1;
    }
    
    pthread_mutex_lock(&ts->buffer_mutex);
    
    // Add new point
    ts->points[ts->tail].timestamp = timestamp;
    ts->points[ts->tail].value = value;
    
    ts->tail = (ts->tail + 1) % ts->capacity;
    
    if (ts->count < ts->capacity) {
        ts->count++;
    } else {
        // Buffer is full, advance head
        ts->head = (ts->head + 1) % ts->capacity;
    }
    
    pthread_mutex_unlock(&ts->buffer_mutex);
    
    return 0;
}

/**
 * Cleanup old data points
 */
void ethudp_stats_timeseries_cleanup_old(ethudp_stats_timeseries_t *ts, uint64_t cutoff_time) {
    if (!ts || !ts->points) {
        return;
    }
    
    pthread_mutex_lock(&ts->buffer_mutex);
    
    while (ts->count > 0) {
        if (ts->points[ts->head].timestamp >= cutoff_time) {
            break;
        }
        
        ts->head = (ts->head + 1) % ts->capacity;
        ts->count--;
    }
    
    pthread_mutex_unlock(&ts->buffer_mutex);
}

/**
 * Calculate statistics summary
 */
void ethudp_stats_calculate_summary(const ethudp_stats_datapoint_t *points, size_t count,
                                   ethudp_stats_summary_t *summary) {
    if (!points || count == 0 || !summary) {
        memset(summary, 0, sizeof(ethudp_stats_summary_t));
        return;
    }
    
    memset(summary, 0, sizeof(ethudp_stats_summary_t));
    
    summary->min = INFINITY;
    summary->max = -INFINITY;
    
    // Calculate sum, min, max
    for (size_t i = 0; i < count; i++) {
        double value = points[i].value;
        summary->sum += value;
        
        if (value < summary->min) {
            summary->min = value;
        }
        
        if (value > summary->max) {
            summary->max = value;
        }
    }
    
    summary->count = count;
    summary->avg = summary->sum / count;
    
    // Calculate standard deviation
    summary->stddev = ethudp_stats_calculate_stddev(points, count, summary->avg);
    
    // Calculate percentiles
    summary->median = ethudp_stats_calculate_percentile(points, count, 50.0);
    summary->p95 = ethudp_stats_calculate_percentile(points, count, 95.0);
    summary->p99 = ethudp_stats_calculate_percentile(points, count, 99.0);
    
    // Calculate rate (simplified)
    if (count > 1) {
        uint64_t time_span = points[count-1].timestamp - points[0].timestamp;
        if (time_span > 0) {
            summary->rate_per_sec = (uint64_t)((summary->sum * 1000.0) / time_span);
        }
    }
}

/**
 * Calculate percentile
 */
double ethudp_stats_calculate_percentile(const ethudp_stats_datapoint_t *points, size_t count,
                                        double percentile) {
    if (!points || count == 0 || percentile < 0.0 || percentile > 100.0) {
        return 0.0;
    }
    
    // Create sorted array of values
    double *values = malloc(count * sizeof(double));
    if (!values) {
        return 0.0;
    }
    
    for (size_t i = 0; i < count; i++) {
        values[i] = points[i].value;
    }
    
    // Simple bubble sort (for small datasets)
    for (size_t i = 0; i < count - 1; i++) {
        for (size_t j = 0; j < count - i - 1; j++) {
            if (values[j] > values[j + 1]) {
                double temp = values[j];
                values[j] = values[j + 1];
                values[j + 1] = temp;
            }
        }
    }
    
    // Calculate percentile index
    double index = (percentile / 100.0) * (count - 1);
    size_t lower = (size_t)floor(index);
    size_t upper = (size_t)ceil(index);
    
    double result;
    if (lower == upper) {
        result = values[lower];
    } else {
        double weight = index - lower;
        result = values[lower] * (1.0 - weight) + values[upper] * weight;
    }
    
    free(values);
    return result;
}

/**
 * Calculate standard deviation
 */
double ethudp_stats_calculate_stddev(const ethudp_stats_datapoint_t *points, size_t count,
                                    double mean) {
    if (!points || count <= 1) {
        return 0.0;
    }
    
    double variance = 0.0;
    for (size_t i = 0; i < count; i++) {
        double diff = points[i].value - mean;
        variance += diff * diff;
    }
    
    variance /= (count - 1);
    return sqrt(variance);
}

/**
 * Calculate rate per second
 */
uint64_t ethudp_stats_calculate_rate(const ethudp_stats_datapoint_t *points, size_t count,
                                    uint64_t window_ms) {
    if (!points || count == 0 || window_ms == 0) {
        return 0;
    }
    
    double total = 0.0;
    for (size_t i = 0; i < count; i++) {
        total += points[i].value;
    }
    
    return (uint64_t)((total * 1000.0) / window_ms);
}

/**
 * Initialize statistics manager
 */
int ethudp_stats_manager_init(ethudp_stats_manager_t *manager, 
                             size_t max_workers, size_t max_connections,
                             uint64_t collection_interval_ms) {
    if (!manager || max_workers == 0 || max_connections == 0) {
        return -1;
    }
    
    memset(manager, 0, sizeof(ethudp_stats_manager_t));
    
    if (pthread_mutex_init(&manager->stats_mutex, NULL) != 0) {
        return -1;
    }
    
    // Allocate worker stats
    manager->worker_stats = calloc(max_workers, sizeof(ethudp_worker_stats_t));
    if (!manager->worker_stats) {
        pthread_mutex_destroy(&manager->stats_mutex);
        return -1;
    }
    
    // Allocate connection stats
    manager->connection_stats = calloc(max_connections, sizeof(ethudp_connection_stats_t));
    if (!manager->connection_stats) {
        free(manager->worker_stats);
        pthread_mutex_destroy(&manager->stats_mutex);
        return -1;
    }
    
    manager->worker_count = max_workers;
    manager->max_connections = max_connections;
    manager->collection_interval_ms = collection_interval_ms;
    manager->collection_enabled = 1;
    
    // Initialize time series for each window
    for (int i = 0; i < STATS_WINDOW_MAX; i++) {
        manager->timeseries[i] = calloc(1, sizeof(ethudp_stats_timeseries_t));
        if (!manager->timeseries[i]) {
            ethudp_stats_manager_cleanup(manager);
            return -1;
        }
        
        size_t capacity = (window_durations[i] / collection_interval_ms) + 1;
        if (ethudp_stats_timeseries_init(manager->timeseries[i], capacity, window_durations[i]) != 0) {
            ethudp_stats_manager_cleanup(manager);
            return -1;
        }
    }
    
    // Set global manager if not set
    if (!global_stats_manager) {
        global_stats_manager = manager;
    }
    
    return 0;
}

/**
 * Cleanup statistics manager
 */
void ethudp_stats_manager_cleanup(ethudp_stats_manager_t *manager) {
    if (!manager) {
        return;
    }
    
    // Stop collection thread
    ethudp_stats_manager_stop(manager);
    
    // Cleanup time series
    for (int i = 0; i < STATS_WINDOW_MAX; i++) {
        if (manager->timeseries[i]) {
            ethudp_stats_timeseries_cleanup(manager->timeseries[i]);
            free(manager->timeseries[i]);
            manager->timeseries[i] = NULL;
        }
    }
    
    // Free allocated memory
    if (manager->worker_stats) {
        free(manager->worker_stats);
        manager->worker_stats = NULL;
    }
    
    if (manager->connection_stats) {
        free(manager->connection_stats);
        manager->connection_stats = NULL;
    }
    
    pthread_mutex_destroy(&manager->stats_mutex);
    
    if (global_stats_manager == manager) {
        global_stats_manager = NULL;
    }
    
    memset(manager, 0, sizeof(ethudp_stats_manager_t));
}

/**
 * Statistics collection thread
 */
static void *stats_collection_thread(void *arg) {
    ethudp_stats_manager_t *manager = (ethudp_stats_manager_t *)arg;
    
    while (manager->collection_running) {
        ethudp_stats_collect_all(manager);
        
        // Sleep for collection interval
        ethudp_sleep_ms(manager->collection_interval_ms);
    }
    
    return NULL;
}

/**
 * Start statistics collection
 */
int ethudp_stats_manager_start(ethudp_stats_manager_t *manager) {
    if (!manager || manager->collection_running) {
        return -1;
    }
    
    manager->collection_running = 1;
    
    if (pthread_create(&manager->collection_thread, NULL, stats_collection_thread, manager) != 0) {
        manager->collection_running = 0;
        return -1;
    }
    
    return 0;
}

/**
 * Stop statistics collection
 */
void ethudp_stats_manager_stop(ethudp_stats_manager_t *manager) {
    if (!manager || !manager->collection_running) {
        return;
    }
    
    manager->collection_running = 0;
    
    if (manager->collection_thread) {
        pthread_join(manager->collection_thread, NULL);
        manager->collection_thread = 0;
    }
}

/**
 * Collect all statistics
 */
void ethudp_stats_collect_all(ethudp_stats_manager_t *manager) {
    if (!manager) {
        return;
    }
    
    uint64_t timestamp = ethudp_get_current_time_ms();
    
    pthread_mutex_lock(&manager->stats_mutex);
    
    // Collect performance metrics
    ethudp_stats_collect_performance(manager);
    
    // Collect worker statistics
    ethudp_stats_collect_workers(manager);
    
    // Collect connection statistics
    ethudp_stats_collect_connections(manager);
    
    // Update time series
    for (int i = 0; i < STATS_WINDOW_MAX; i++) {
        if (manager->timeseries[i]) {
            ethudp_stats_timeseries_add(manager->timeseries[i], timestamp, 
                                       manager->performance.packet_rate.avg);
            
            // Cleanup old data
            uint64_t cutoff = timestamp - window_durations[i];
            ethudp_stats_timeseries_cleanup_old(manager->timeseries[i], cutoff);
        }
    }
    
    // Call callback if set
    if (manager->stats_callback) {
        manager->stats_callback(&manager->performance, manager->callback_user_data);
    }
    
    pthread_mutex_unlock(&manager->stats_mutex);
}

/**
 * Collect performance statistics
 */
int ethudp_stats_collect_performance(ethudp_stats_manager_t *manager) {
    if (!manager) {
        return -1;
    }
    
    // This would collect from various system components
    // For now, using placeholder values
    manager->performance.uptime_seconds = ethudp_get_current_time_ms() / 1000;
    manager->performance.last_updated = ethudp_get_current_time_ms();
    
    // Initialize summary structures with default values
    memset(&manager->performance.packet_rate, 0, sizeof(ethudp_stats_summary_t));
    memset(&manager->performance.byte_rate, 0, sizeof(ethudp_stats_summary_t));
    memset(&manager->performance.processing_latency, 0, sizeof(ethudp_stats_summary_t));
    memset(&manager->performance.queue_depth, 0, sizeof(ethudp_stats_summary_t));
    memset(&manager->performance.cpu_usage, 0, sizeof(ethudp_stats_summary_t));
    memset(&manager->performance.memory_usage, 0, sizeof(ethudp_stats_summary_t));
    memset(&manager->performance.error_rate, 0, sizeof(ethudp_stats_summary_t));
    
    return 0;
}

/**
 * Collect worker statistics
 */
int ethudp_stats_collect_workers(ethudp_stats_manager_t *manager) {
    if (!manager || !manager->worker_stats) {
        return -1;
    }
    
    // This would collect from actual worker threads
    // For now, using placeholder values
    for (size_t i = 0; i < manager->worker_count; i++) {
        manager->worker_stats[i].worker_id = i;
        snprintf(manager->worker_stats[i].worker_type, sizeof(manager->worker_stats[i].worker_type), 
                "worker_%zu", i);
        manager->worker_stats[i].last_activity = ethudp_get_current_time_ms();
    }
    
    return 0;
}

/**
 * Collect connection statistics
 */
int ethudp_stats_collect_connections(ethudp_stats_manager_t *manager) {
    if (!manager || !manager->connection_stats) {
        return -1;
    }
    
    // This would collect from active connections
    // For now, using placeholder values
    for (size_t i = 0; i < manager->connection_count; i++) {
        manager->connection_stats[i].last_activity = ethudp_get_current_time_ms();
    }
    
    return 0;
}

/**
 * Update packet count
 */
void ethudp_stats_update_packet_count(ethudp_stats_manager_t *manager, uint64_t count) {
    if (!manager) {
        return;
    }
    
    pthread_mutex_lock(&manager->stats_mutex);
    manager->performance.packet_rate.sum += count;
    manager->performance.packet_rate.count++;
    pthread_mutex_unlock(&manager->stats_mutex);
}

/**
 * Update byte count
 */
void ethudp_stats_update_byte_count(ethudp_stats_manager_t *manager, uint64_t bytes) {
    if (!manager) {
        return;
    }
    
    pthread_mutex_lock(&manager->stats_mutex);
    manager->performance.byte_rate.sum += bytes;
    manager->performance.byte_rate.count++;
    pthread_mutex_unlock(&manager->stats_mutex);
}

/**
 * Update processing time
 */
void ethudp_stats_update_processing_time(ethudp_stats_manager_t *manager, double time_us) {
    if (!manager) {
        return;
    }
    
    pthread_mutex_lock(&manager->stats_mutex);
    manager->performance.processing_latency.sum += time_us;
    manager->performance.processing_latency.count++;
    
    if (time_us < manager->performance.processing_latency.min || 
        manager->performance.processing_latency.min == 0.0) {
        manager->performance.processing_latency.min = time_us;
    }
    
    if (time_us > manager->performance.processing_latency.max) {
        manager->performance.processing_latency.max = time_us;
    }
    
    manager->performance.processing_latency.avg = 
        manager->performance.processing_latency.sum / manager->performance.processing_latency.count;
    
    pthread_mutex_unlock(&manager->stats_mutex);
}

/**
 * Update error count
 */
void ethudp_stats_update_error_count(ethudp_stats_manager_t *manager, uint64_t errors) {
    if (!manager) {
        return;
    }
    
    pthread_mutex_lock(&manager->stats_mutex);
    manager->performance.error_rate.sum += errors;
    manager->performance.error_rate.count++;
    pthread_mutex_unlock(&manager->stats_mutex);
}

/**
 * Print performance statistics
 */
void ethudp_stats_print_performance(const ethudp_performance_stats_t *stats) {
    if (!stats) {
        return;
    }
    
    printf("Performance Statistics:\n");
    printf("  Uptime: %lu seconds\n", stats->uptime_seconds);
    printf("  Packet Rate: %.2f pps (avg), %.2f (min), %.2f (max)\n",
           stats->packet_rate.avg, stats->packet_rate.min, stats->packet_rate.max);
    printf("  Byte Rate: %.2f Bps (avg), %.2f (min), %.2f (max)\n",
           stats->byte_rate.avg, stats->byte_rate.min, stats->byte_rate.max);
    printf("  Processing Latency: %.2f us (avg), %.2f (min), %.2f (max)\n",
           stats->processing_latency.avg, stats->processing_latency.min, stats->processing_latency.max);
    printf("  CPU Usage: %.1f%% (avg)\n", stats->cpu_usage.avg);
    printf("  Memory Usage: %.1f%% (avg)\n", stats->memory_usage.avg);
    printf("  Error Rate: %.2f errors/sec (avg)\n", stats->error_rate.avg);
}

/**
 * Print summary
 */
void ethudp_stats_print_summary(const ethudp_stats_manager_t *manager) {
    if (!manager) {
        return;
    }
    
    printf("Statistics Summary:\n");
    ethudp_stats_print_performance(&manager->performance);
    
    printf("Active Workers: %zu\n", manager->worker_count);
    printf("Active Connections: %zu/%zu\n", manager->connection_count, manager->max_connections);
    printf("Collection Interval: %lu ms\n", manager->collection_interval_ms);
    printf("Collection Status: %s\n", manager->collection_running ? "Running" : "Stopped");
}

/**
 * Get window name
 */
const char *ethudp_stats_window_name(ethudp_stats_window_t window) {
    switch (window) {
        case STATS_WINDOW_1SEC: return "1sec";
        case STATS_WINDOW_5SEC: return "5sec";
        case STATS_WINDOW_30SEC: return "30sec";
        case STATS_WINDOW_1MIN: return "1min";
        case STATS_WINDOW_5MIN: return "5min";
        case STATS_WINDOW_15MIN: return "15min";
        case STATS_WINDOW_1HOUR: return "1hour";
        default: return "unknown";
    }
}

/**
 * Get format name
 */
const char *ethudp_stats_format_name(ethudp_stats_format_t format) {
    switch (format) {
        case STATS_FORMAT_JSON: return "json";
        case STATS_FORMAT_CSV: return "csv";
        case STATS_FORMAT_PROMETHEUS: return "prometheus";
        case STATS_FORMAT_INFLUXDB: return "influxdb";
        default: return "unknown";
    }
}

/**
 * Get window duration
 */
uint64_t ethudp_stats_window_duration_ms(ethudp_stats_window_t window) {
    if (window >= STATS_WINDOW_MAX) {
        return 0;
    }
    
    return window_durations[window];
}

/**
 * Set callback
 */
void ethudp_stats_manager_set_callback(ethudp_stats_manager_t *manager,
                                      void (*callback)(const ethudp_performance_stats_t *stats, void *user_data),
                                      void *user_data) {
    if (!manager) {
        return;
    }
    
    pthread_mutex_lock(&manager->stats_mutex);
    manager->stats_callback = callback;
    manager->callback_user_data = user_data;
    pthread_mutex_unlock(&manager->stats_mutex);
}