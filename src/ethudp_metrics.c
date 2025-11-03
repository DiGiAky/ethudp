#include "../include/ethudp_common.h"
#include "../include/ethudp_types.h"
#include "../include/ethudp_metrics.h"
#include "../include/ethudp_utils.h"
#include <math.h>

// Global metrics registry
ethudp_metrics_registry_t *global_metrics_registry = NULL;

// Default histogram buckets
static const double default_histogram_buckets[] = {
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, INFINITY
};
static const size_t default_histogram_bucket_count = sizeof(default_histogram_buckets) / sizeof(double);

/**
 * Initialize metrics registry
 */
int ethudp_metrics_registry_init(ethudp_metrics_registry_t *registry, uint64_t collection_interval_ms) {
    if (!registry) {
        return -1;
    }
    
    memset(registry, 0, sizeof(ethudp_metrics_registry_t));
    
    if (pthread_mutex_init(&registry->registry_mutex, NULL) != 0) {
        return -1;
    }
    
    registry->collection_interval_ms = collection_interval_ms;
    registry->last_collection_time = ethudp_get_current_time_ms();
    registry->initialized = 1;
    
    // Set global registry if not set
    if (!global_metrics_registry) {
        global_metrics_registry = registry;
    }
    
    return 0;
}

/**
 * Cleanup metrics registry
 */
void ethudp_metrics_registry_cleanup(ethudp_metrics_registry_t *registry) {
    if (!registry || !registry->initialized) {
        return;
    }
    
    pthread_mutex_lock(&registry->registry_mutex);
    
    // Cleanup all metrics
    for (int category = 0; category < METRIC_CATEGORY_MAX; category++) {
        ethudp_metric_t *metric = registry->metrics[category];
        while (metric) {
            ethudp_metric_t *next = metric->next;
            ethudp_metric_destroy(metric);
            metric = next;
        }
        registry->metrics[category] = NULL;
        registry->metric_counts[category] = 0;
    }
    
    registry->initialized = 0;
    
    pthread_mutex_unlock(&registry->registry_mutex);
    pthread_mutex_destroy(&registry->registry_mutex);
    
    if (global_metrics_registry == registry) {
        global_metrics_registry = NULL;
    }
    
    memset(registry, 0, sizeof(ethudp_metrics_registry_t));
}

/**
 * Register a metric
 */
int ethudp_metrics_registry_register(ethudp_metrics_registry_t *registry, ethudp_metric_t *metric) {
    if (!registry || !metric || !registry->initialized) {
        return -1;
    }
    
    if (metric->category >= METRIC_CATEGORY_MAX) {
        return -1;
    }
    
    pthread_mutex_lock(&registry->registry_mutex);
    
    // Check for duplicate names
    ethudp_metric_t *existing = registry->metrics[metric->category];
    while (existing) {
        if (strcmp(existing->name, metric->name) == 0) {
            pthread_mutex_unlock(&registry->registry_mutex);
            return -2; // Duplicate name
        }
        existing = existing->next;
    }
    
    // Add to linked list
    metric->next = registry->metrics[metric->category];
    registry->metrics[metric->category] = metric;
    registry->metric_counts[metric->category]++;
    
    pthread_mutex_unlock(&registry->registry_mutex);
    
    return 0;
}

/**
 * Find a metric by name and category
 */
ethudp_metric_t *ethudp_metrics_registry_find(ethudp_metrics_registry_t *registry, 
                                             const char *name, ethudp_metric_category_t category) {
    if (!registry || !name || !registry->initialized || category >= METRIC_CATEGORY_MAX) {
        return NULL;
    }
    
    pthread_mutex_lock(&registry->registry_mutex);
    
    ethudp_metric_t *metric = registry->metrics[category];
    while (metric) {
        if (strcmp(metric->name, name) == 0) {
            pthread_mutex_unlock(&registry->registry_mutex);
            return metric;
        }
        metric = metric->next;
    }
    
    pthread_mutex_unlock(&registry->registry_mutex);
    
    return NULL;
}

/**
 * Create a counter metric
 */
ethudp_metric_t *ethudp_metric_create_counter(const char *name, const char *description, 
                                             ethudp_metric_category_t category) {
    if (!name || !description || category >= METRIC_CATEGORY_MAX) {
        return NULL;
    }
    
    ethudp_metric_t *metric = calloc(1, sizeof(ethudp_metric_t));
    if (!metric) {
        return NULL;
    }
    
    strncpy(metric->name, name, sizeof(metric->name) - 1);
    strncpy(metric->description, description, sizeof(metric->description) - 1);
    metric->type = METRIC_TYPE_COUNTER;
    metric->category = category;
    metric->value.counter = 0;
    metric->last_updated = ethudp_get_current_time_ms();
    
    if (pthread_mutex_init(&metric->metric_mutex, NULL) != 0) {
        free(metric);
        return NULL;
    }
    
    return metric;
}

/**
 * Create a gauge metric
 */
ethudp_metric_t *ethudp_metric_create_gauge(const char *name, const char *description, 
                                           ethudp_metric_category_t category) {
    if (!name || !description || category >= METRIC_CATEGORY_MAX) {
        return NULL;
    }
    
    ethudp_metric_t *metric = calloc(1, sizeof(ethudp_metric_t));
    if (!metric) {
        return NULL;
    }
    
    strncpy(metric->name, name, sizeof(metric->name) - 1);
    strncpy(metric->description, description, sizeof(metric->description) - 1);
    metric->type = METRIC_TYPE_GAUGE;
    metric->category = category;
    metric->value.gauge = 0.0;
    metric->last_updated = ethudp_get_current_time_ms();
    
    if (pthread_mutex_init(&metric->metric_mutex, NULL) != 0) {
        free(metric);
        return NULL;
    }
    
    return metric;
}

/**
 * Create a histogram metric
 */
ethudp_metric_t *ethudp_metric_create_histogram(const char *name, const char *description, 
                                               ethudp_metric_category_t category,
                                               const double *buckets, size_t bucket_count) {
    if (!name || !description || category >= METRIC_CATEGORY_MAX) {
        return NULL;
    }
    
    ethudp_metric_t *metric = calloc(1, sizeof(ethudp_metric_t));
    if (!metric) {
        return NULL;
    }
    
    strncpy(metric->name, name, sizeof(metric->name) - 1);
    strncpy(metric->description, description, sizeof(metric->description) - 1);
    metric->type = METRIC_TYPE_HISTOGRAM;
    metric->category = category;
    
    // Use default buckets if none provided
    if (!buckets || bucket_count == 0) {
        buckets = default_histogram_buckets;
        bucket_count = default_histogram_bucket_count;
    }
    
    metric->value.histogram.buckets = calloc(bucket_count, sizeof(ethudp_histogram_bucket_t));
    if (!metric->value.histogram.buckets) {
        free(metric);
        return NULL;
    }
    
    for (size_t i = 0; i < bucket_count; i++) {
        metric->value.histogram.buckets[i].upper_bound = buckets[i];
        metric->value.histogram.buckets[i].count = 0;
    }
    
    metric->value.histogram.bucket_count = bucket_count;
    metric->value.histogram.total_count = 0;
    metric->value.histogram.sum = 0.0;
    metric->last_updated = ethudp_get_current_time_ms();
    
    if (pthread_mutex_init(&metric->metric_mutex, NULL) != 0) {
        free(metric->value.histogram.buckets);
        free(metric);
        return NULL;
    }
    
    return metric;
}

/**
 * Create a timer metric
 */
ethudp_metric_t *ethudp_metric_create_timer(const char *name, const char *description, 
                                           ethudp_metric_category_t category) {
    if (!name || !description || category >= METRIC_CATEGORY_MAX) {
        return NULL;
    }
    
    ethudp_metric_t *metric = calloc(1, sizeof(ethudp_metric_t));
    if (!metric) {
        return NULL;
    }
    
    strncpy(metric->name, name, sizeof(metric->name) - 1);
    strncpy(metric->description, description, sizeof(metric->description) - 1);
    metric->type = METRIC_TYPE_TIMER;
    metric->category = category;
    metric->value.timer.count = 0;
    metric->value.timer.total_time_us = 0.0;
    metric->value.timer.min_time_us = INFINITY;
    metric->value.timer.max_time_us = 0.0;
    metric->last_updated = ethudp_get_current_time_ms();
    
    if (pthread_mutex_init(&metric->metric_mutex, NULL) != 0) {
        free(metric);
        return NULL;
    }
    
    return metric;
}

/**
 * Destroy a metric
 */
void ethudp_metric_destroy(ethudp_metric_t *metric) {
    if (!metric) {
        return;
    }
    
    if (metric->type == METRIC_TYPE_HISTOGRAM && metric->value.histogram.buckets) {
        free(metric->value.histogram.buckets);
    }
    
    pthread_mutex_destroy(&metric->metric_mutex);
    free(metric);
}

/**
 * Increment counter
 */
int ethudp_metric_counter_inc(ethudp_metric_t *metric) {
    if (!metric || metric->type != METRIC_TYPE_COUNTER) {
        return -1;
    }
    
    pthread_mutex_lock(&metric->metric_mutex);
    metric->value.counter++;
    metric->last_updated = ethudp_get_current_time_ms();
    pthread_mutex_unlock(&metric->metric_mutex);
    
    return 0;
}

/**
 * Add to counter
 */
int ethudp_metric_counter_add(ethudp_metric_t *metric, uint64_t value) {
    if (!metric || metric->type != METRIC_TYPE_COUNTER) {
        return -1;
    }
    
    pthread_mutex_lock(&metric->metric_mutex);
    metric->value.counter += value;
    metric->last_updated = ethudp_get_current_time_ms();
    pthread_mutex_unlock(&metric->metric_mutex);
    
    return 0;
}

/**
 * Set gauge value
 */
int ethudp_metric_gauge_set(ethudp_metric_t *metric, double value) {
    if (!metric || metric->type != METRIC_TYPE_GAUGE) {
        return -1;
    }
    
    pthread_mutex_lock(&metric->metric_mutex);
    metric->value.gauge = value;
    metric->last_updated = ethudp_get_current_time_ms();
    pthread_mutex_unlock(&metric->metric_mutex);
    
    return 0;
}

/**
 * Increment gauge
 */
int ethudp_metric_gauge_inc(ethudp_metric_t *metric) {
    if (!metric || metric->type != METRIC_TYPE_GAUGE) {
        return -1;
    }
    
    pthread_mutex_lock(&metric->metric_mutex);
    metric->value.gauge += 1.0;
    metric->last_updated = ethudp_get_current_time_ms();
    pthread_mutex_unlock(&metric->metric_mutex);
    
    return 0;
}

/**
 * Decrement gauge
 */
int ethudp_metric_gauge_dec(ethudp_metric_t *metric) {
    if (!metric || metric->type != METRIC_TYPE_GAUGE) {
        return -1;
    }
    
    pthread_mutex_lock(&metric->metric_mutex);
    metric->value.gauge -= 1.0;
    metric->last_updated = ethudp_get_current_time_ms();
    pthread_mutex_unlock(&metric->metric_mutex);
    
    return 0;
}

/**
 * Add to gauge
 */
int ethudp_metric_gauge_add(ethudp_metric_t *metric, double value) {
    if (!metric || metric->type != METRIC_TYPE_GAUGE) {
        return -1;
    }
    
    pthread_mutex_lock(&metric->metric_mutex);
    metric->value.gauge += value;
    metric->last_updated = ethudp_get_current_time_ms();
    pthread_mutex_unlock(&metric->metric_mutex);
    
    return 0;
}

/**
 * Observe histogram value
 */
int ethudp_metric_histogram_observe(ethudp_metric_t *metric, double value) {
    if (!metric || metric->type != METRIC_TYPE_HISTOGRAM) {
        return -1;
    }
    
    pthread_mutex_lock(&metric->metric_mutex);
    
    // Find appropriate bucket
    for (size_t i = 0; i < metric->value.histogram.bucket_count; i++) {
        if (value <= metric->value.histogram.buckets[i].upper_bound) {
            metric->value.histogram.buckets[i].count++;
            break;
        }
    }
    
    metric->value.histogram.total_count++;
    metric->value.histogram.sum += value;
    metric->last_updated = ethudp_get_current_time_ms();
    
    pthread_mutex_unlock(&metric->metric_mutex);
    
    return 0;
}

/**
 * Observe timer value
 */
int ethudp_metric_timer_observe(ethudp_metric_t *metric, double time_us) {
    if (!metric || metric->type != METRIC_TYPE_TIMER) {
        return -1;
    }
    
    pthread_mutex_lock(&metric->metric_mutex);
    
    metric->value.timer.count++;
    metric->value.timer.total_time_us += time_us;
    
    if (time_us < metric->value.timer.min_time_us) {
        metric->value.timer.min_time_us = time_us;
    }
    
    if (time_us > metric->value.timer.max_time_us) {
        metric->value.timer.max_time_us = time_us;
    }
    
    metric->last_updated = ethudp_get_current_time_ms();
    
    pthread_mutex_unlock(&metric->metric_mutex);
    
    return 0;
}

/**
 * Get counter value
 */
uint64_t ethudp_metric_counter_get(const ethudp_metric_t *metric) {
    if (!metric || metric->type != METRIC_TYPE_COUNTER) {
        return 0;
    }
    
    return metric->value.counter;
}

/**
 * Get gauge value
 */
double ethudp_metric_gauge_get(const ethudp_metric_t *metric) {
    if (!metric || metric->type != METRIC_TYPE_GAUGE) {
        return 0.0;
    }
    
    return metric->value.gauge;
}

/**
 * Get histogram count
 */
uint64_t ethudp_metric_histogram_get_count(const ethudp_metric_t *metric) {
    if (!metric || metric->type != METRIC_TYPE_HISTOGRAM) {
        return 0;
    }
    
    return metric->value.histogram.total_count;
}

/**
 * Get histogram sum
 */
double ethudp_metric_histogram_get_sum(const ethudp_metric_t *metric) {
    if (!metric || metric->type != METRIC_TYPE_HISTOGRAM) {
        return 0.0;
    }
    
    return metric->value.histogram.sum;
}

/**
 * Get timer count
 */
uint64_t ethudp_metric_timer_get_count(const ethudp_metric_t *metric) {
    if (!metric || metric->type != METRIC_TYPE_TIMER) {
        return 0;
    }
    
    return metric->value.timer.count;
}

/**
 * Get timer average
 */
double ethudp_metric_timer_get_avg(const ethudp_metric_t *metric) {
    if (!metric || metric->type != METRIC_TYPE_TIMER || metric->value.timer.count == 0) {
        return 0.0;
    }
    
    return metric->value.timer.total_time_us / metric->value.timer.count;
}

/**
 * Get timer minimum
 */
double ethudp_metric_timer_get_min(const ethudp_metric_t *metric) {
    if (!metric || metric->type != METRIC_TYPE_TIMER) {
        return 0.0;
    }
    
    return metric->value.timer.min_time_us;
}

/**
 * Get timer maximum
 */
double ethudp_metric_timer_get_max(const ethudp_metric_t *metric) {
    if (!metric || metric->type != METRIC_TYPE_TIMER) {
        return 0.0;
    }
    
    return metric->value.timer.max_time_us;
}

/**
 * Collect performance metrics
 */
int ethudp_collect_performance_metrics(ethudp_performance_counters_t *counters) {
    if (!counters) {
        return -1;
    }
    
    memset(counters, 0, sizeof(ethudp_performance_counters_t));
    
    // This would typically collect from various system components
    // For now, we'll use placeholder values
    counters->packets_received = 0;
    counters->packets_sent = 0;
    counters->packets_dropped = 0;
    counters->packets_corrupted = 0;
    counters->bytes_received = 0;
    counters->bytes_sent = 0;
    counters->processing_errors = 0;
    counters->queue_overflows = 0;
    counters->avg_processing_time_us = 0.0;
    counters->avg_queue_wait_time_us = 0.0;
    counters->active_connections = 0;
    counters->peak_connections = 0;
    
    return 0;
}

/**
 * Collect system metrics
 */
int ethudp_collect_system_metrics(ethudp_system_metrics_t *metrics) {
    if (!metrics) {
        return -1;
    }
    
    memset(metrics, 0, sizeof(ethudp_system_metrics_t));
    
    metrics->cpu_usage_percent = ethudp_get_cpu_usage();
    metrics->memory_usage_percent = ethudp_get_memory_usage();
    
    // Additional system metrics would be collected here
    metrics->memory_used_bytes = 0;
    metrics->memory_available_bytes = 0;
    metrics->thread_count = 0;
    metrics->file_descriptor_count = 0;
    metrics->load_average_1m = 0.0;
    metrics->load_average_5m = 0.0;
    metrics->load_average_15m = 0.0;
    
    return 0;
}

/**
 * Collect network metrics
 */
int ethudp_collect_network_metrics(ethudp_network_metrics_t *metrics) {
    if (!metrics) {
        return -1;
    }
    
    memset(metrics, 0, sizeof(ethudp_network_metrics_t));
    
    // Network metrics would be collected from network interfaces
    metrics->udp_packets_in = 0;
    metrics->udp_packets_out = 0;
    metrics->raw_packets_in = 0;
    metrics->raw_packets_out = 0;
    metrics->fragmented_packets = 0;
    metrics->reassembled_packets = 0;
    metrics->checksum_errors = 0;
    metrics->timeout_errors = 0;
    metrics->avg_packet_size_bytes = 0.0;
    metrics->network_utilization_percent = 0.0;
    
    return 0;
}

/**
 * Collect error metrics
 */
int ethudp_collect_error_metrics(ethudp_error_metrics_t *metrics) {
    if (!metrics) {
        return -1;
    }
    
    memset(metrics, 0, sizeof(ethudp_error_metrics_t));
    
    // Error metrics would be collected from error counters
    metrics->socket_errors = 0;
    metrics->allocation_failures = 0;
    metrics->buffer_overruns = 0;
    metrics->protocol_errors = 0;
    metrics->encryption_errors = 0;
    metrics->compression_errors = 0;
    metrics->configuration_errors = 0;
    metrics->system_errors = 0;
    
    return 0;
}

/**
 * Collect all metrics
 */
int ethudp_collect_all_metrics(ethudp_metrics_snapshot_t *snapshot) {
    if (!snapshot) {
        return -1;
    }
    
    snapshot->timestamp = ethudp_get_current_time_ms();
    
    if (ethudp_collect_performance_metrics(&snapshot->performance) != 0 ||
        ethudp_collect_system_metrics(&snapshot->system) != 0 ||
        ethudp_collect_network_metrics(&snapshot->network) != 0 ||
        ethudp_collect_error_metrics(&snapshot->errors) != 0) {
        return -1;
    }
    
    return 0;
}

/**
 * Get metric type name
 */
const char *ethudp_metric_type_name(ethudp_metric_type_t type) {
    switch (type) {
        case METRIC_TYPE_COUNTER: return "counter";
        case METRIC_TYPE_GAUGE: return "gauge";
        case METRIC_TYPE_HISTOGRAM: return "histogram";
        case METRIC_TYPE_TIMER: return "timer";
        default: return "unknown";
    }
}

/**
 * Get metric category name
 */
const char *ethudp_metric_category_name(ethudp_metric_category_t category) {
    switch (category) {
        case METRIC_CATEGORY_NETWORK: return "network";
        case METRIC_CATEGORY_SYSTEM: return "system";
        case METRIC_CATEGORY_PERFORMANCE: return "performance";
        case METRIC_CATEGORY_ERROR: return "error";
        default: return "unknown";
    }
}

/**
 * Print metrics summary
 */
void ethudp_metrics_print_summary(const ethudp_metrics_snapshot_t *snapshot) {
    if (!snapshot) {
        return;
    }
    
    printf("Metrics Summary (timestamp: %lu):\n", snapshot->timestamp);
    
    printf("Performance:\n");
    printf("  Packets RX: %lu, TX: %lu, Dropped: %lu\n",
           snapshot->performance.packets_received,
           snapshot->performance.packets_sent,
           snapshot->performance.packets_dropped);
    printf("  Bytes RX: %lu, TX: %lu\n",
           snapshot->performance.bytes_received,
           snapshot->performance.bytes_sent);
    printf("  Avg Processing Time: %.2f us\n",
           snapshot->performance.avg_processing_time_us);
    
    printf("System:\n");
    printf("  CPU Usage: %.1f%%, Memory Usage: %.1f%%\n",
           snapshot->system.cpu_usage_percent,
           snapshot->system.memory_usage_percent);
    printf("  Thread Count: %u, FD Count: %u\n",
           snapshot->system.thread_count,
           snapshot->system.file_descriptor_count);
    
    printf("Network:\n");
    printf("  UDP In: %lu, Out: %lu\n",
           snapshot->network.udp_packets_in,
           snapshot->network.udp_packets_out);
    printf("  RAW In: %lu, Out: %lu\n",
           snapshot->network.raw_packets_in,
           snapshot->network.raw_packets_out);
    
    printf("Errors:\n");
    printf("  Socket: %lu, Allocation: %lu, Buffer: %lu\n",
           snapshot->errors.socket_errors,
           snapshot->errors.allocation_failures,
           snapshot->errors.buffer_overruns);
}