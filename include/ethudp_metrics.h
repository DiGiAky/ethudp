#ifndef ETHUDP_METRICS_H
#define ETHUDP_METRICS_H

#include "ethudp_common.h"
#include "ethudp_types.h"

// Metric types
typedef enum {
    METRIC_TYPE_COUNTER = 0,
    METRIC_TYPE_GAUGE,
    METRIC_TYPE_HISTOGRAM,
    METRIC_TYPE_TIMER,
    METRIC_TYPE_MAX
} ethudp_metric_type_t;

// Metric categories
typedef enum {
    METRIC_CATEGORY_NETWORK = 0,
    METRIC_CATEGORY_SYSTEM,
    METRIC_CATEGORY_PERFORMANCE,
    METRIC_CATEGORY_ERROR,
    METRIC_CATEGORY_MAX
} ethudp_metric_category_t;

// Histogram bucket structure
typedef struct {
    double upper_bound;
    uint64_t count;
} ethudp_histogram_bucket_t;

// Metric value union
typedef union {
    uint64_t counter;
    double gauge;
    struct {
        ethudp_histogram_bucket_t *buckets;
        size_t bucket_count;
        uint64_t total_count;
        double sum;
    } histogram;
    struct {
        uint64_t count;
        double total_time_us;
        double min_time_us;
        double max_time_us;
    } timer;
} ethudp_metric_value_t;

// Individual metric structure
typedef struct ethudp_metric {
    char name[64];
    char description[256];
    ethudp_metric_type_t type;
    ethudp_metric_category_t category;
    ethudp_metric_value_t value;
    uint64_t last_updated;
    pthread_mutex_t metric_mutex;
    struct ethudp_metric *next;
} ethudp_metric_t;

// Metrics registry
typedef struct {
    ethudp_metric_t *metrics[METRIC_CATEGORY_MAX];
    size_t metric_counts[METRIC_CATEGORY_MAX];
    pthread_mutex_t registry_mutex;
    int initialized;
    uint64_t collection_interval_ms;
    uint64_t last_collection_time;
} ethudp_metrics_registry_t;

// Performance counters
typedef struct {
    uint64_t packets_received;
    uint64_t packets_sent;
    uint64_t packets_dropped;
    uint64_t packets_corrupted;
    uint64_t bytes_received;
    uint64_t bytes_sent;
    uint64_t processing_errors;
    uint64_t queue_overflows;
    double avg_processing_time_us;
    double avg_queue_wait_time_us;
    uint32_t active_connections;
    uint32_t peak_connections;
} ethudp_performance_counters_t;

// System resource metrics
typedef struct {
    double cpu_usage_percent;
    double memory_usage_percent;
    uint64_t memory_used_bytes;
    uint64_t memory_available_bytes;
    uint32_t thread_count;
    uint32_t file_descriptor_count;
    double load_average_1m;
    double load_average_5m;
    double load_average_15m;
} ethudp_system_metrics_t;

// Network metrics
typedef struct {
    uint64_t udp_packets_in;
    uint64_t udp_packets_out;
    uint64_t raw_packets_in;
    uint64_t raw_packets_out;
    uint64_t fragmented_packets;
    uint64_t reassembled_packets;
    uint64_t checksum_errors;
    uint64_t timeout_errors;
    double avg_packet_size_bytes;
    double network_utilization_percent;
} ethudp_network_metrics_t;

// Error metrics
typedef struct {
    uint64_t socket_errors;
    uint64_t allocation_failures;
    uint64_t buffer_overruns;
    uint64_t protocol_errors;
    uint64_t encryption_errors;
    uint64_t compression_errors;
    uint64_t configuration_errors;
    uint64_t system_errors;
} ethudp_error_metrics_t;

// Comprehensive metrics snapshot
typedef struct {
    uint64_t timestamp;
    ethudp_performance_counters_t performance;
    ethudp_system_metrics_t system;
    ethudp_network_metrics_t network;
    ethudp_error_metrics_t errors;
} ethudp_metrics_snapshot_t;

// Metrics collection callback
typedef void (*ethudp_metrics_callback_t)(const ethudp_metrics_snapshot_t *snapshot, void *user_data);

// Registry functions
int ethudp_metrics_registry_init(ethudp_metrics_registry_t *registry, uint64_t collection_interval_ms);
void ethudp_metrics_registry_cleanup(ethudp_metrics_registry_t *registry);
int ethudp_metrics_registry_register(ethudp_metrics_registry_t *registry, ethudp_metric_t *metric);
ethudp_metric_t *ethudp_metrics_registry_find(ethudp_metrics_registry_t *registry, 
                                             const char *name, ethudp_metric_category_t category);
void ethudp_metrics_registry_collect(ethudp_metrics_registry_t *registry, 
                                    ethudp_metrics_snapshot_t *snapshot);
void ethudp_metrics_registry_print(const ethudp_metrics_registry_t *registry);

// Metric creation functions
ethudp_metric_t *ethudp_metric_create_counter(const char *name, const char *description, 
                                             ethudp_metric_category_t category);
ethudp_metric_t *ethudp_metric_create_gauge(const char *name, const char *description, 
                                           ethudp_metric_category_t category);
ethudp_metric_t *ethudp_metric_create_histogram(const char *name, const char *description, 
                                               ethudp_metric_category_t category,
                                               const double *buckets, size_t bucket_count);
ethudp_metric_t *ethudp_metric_create_timer(const char *name, const char *description, 
                                           ethudp_metric_category_t category);

// Metric manipulation functions
void ethudp_metric_destroy(ethudp_metric_t *metric);
int ethudp_metric_counter_inc(ethudp_metric_t *metric);
int ethudp_metric_counter_add(ethudp_metric_t *metric, uint64_t value);
int ethudp_metric_gauge_set(ethudp_metric_t *metric, double value);
int ethudp_metric_gauge_inc(ethudp_metric_t *metric);
int ethudp_metric_gauge_dec(ethudp_metric_t *metric);
int ethudp_metric_gauge_add(ethudp_metric_t *metric, double value);
int ethudp_metric_histogram_observe(ethudp_metric_t *metric, double value);
int ethudp_metric_timer_start(ethudp_metric_t *metric);
int ethudp_metric_timer_stop(ethudp_metric_t *metric);
int ethudp_metric_timer_observe(ethudp_metric_t *metric, double time_us);

// Metric value access functions
uint64_t ethudp_metric_counter_get(const ethudp_metric_t *metric);
double ethudp_metric_gauge_get(const ethudp_metric_t *metric);
uint64_t ethudp_metric_histogram_get_count(const ethudp_metric_t *metric);
double ethudp_metric_histogram_get_sum(const ethudp_metric_t *metric);
uint64_t ethudp_metric_timer_get_count(const ethudp_metric_t *metric);
double ethudp_metric_timer_get_avg(const ethudp_metric_t *metric);
double ethudp_metric_timer_get_min(const ethudp_metric_t *metric);
double ethudp_metric_timer_get_max(const ethudp_metric_t *metric);

// High-level metrics collection functions
int ethudp_collect_performance_metrics(ethudp_performance_counters_t *counters);
int ethudp_collect_system_metrics(ethudp_system_metrics_t *metrics);
int ethudp_collect_network_metrics(ethudp_network_metrics_t *metrics);
int ethudp_collect_error_metrics(ethudp_error_metrics_t *metrics);
int ethudp_collect_all_metrics(ethudp_metrics_snapshot_t *snapshot);

// Metrics export functions
int ethudp_metrics_export_json(const ethudp_metrics_snapshot_t *snapshot, char *buffer, size_t buffer_size);
int ethudp_metrics_export_prometheus(const ethudp_metrics_snapshot_t *snapshot, char *buffer, size_t buffer_size);
int ethudp_metrics_export_csv(const ethudp_metrics_snapshot_t *snapshot, char *buffer, size_t buffer_size);

// Metrics monitoring and alerting
typedef struct {
    char metric_name[64];
    ethudp_metric_category_t category;
    double threshold;
    int (*condition_func)(double value, double threshold);
    void (*alert_callback)(const char *metric_name, double value, double threshold, void *user_data);
    void *user_data;
} ethudp_metric_alert_t;

int ethudp_metrics_add_alert(ethudp_metrics_registry_t *registry, const ethudp_metric_alert_t *alert);
void ethudp_metrics_check_alerts(ethudp_metrics_registry_t *registry);

// Utility functions
const char *ethudp_metric_type_name(ethudp_metric_type_t type);
const char *ethudp_metric_category_name(ethudp_metric_category_t category);
void ethudp_metrics_reset_all(ethudp_metrics_registry_t *registry);
void ethudp_metrics_print_summary(const ethudp_metrics_snapshot_t *snapshot);

// Global metrics registry
extern ethudp_metrics_registry_t *global_metrics_registry;

// Convenience macros for common operations
#define ETHUDP_METRIC_INC(name, category) do { \
    ethudp_metric_t *m = ethudp_metrics_registry_find(global_metrics_registry, name, category); \
    if (m) ethudp_metric_counter_inc(m); \
} while(0)

#define ETHUDP_METRIC_ADD(name, category, value) do { \
    ethudp_metric_t *m = ethudp_metrics_registry_find(global_metrics_registry, name, category); \
    if (m) ethudp_metric_counter_add(m, value); \
} while(0)

#define ETHUDP_METRIC_SET(name, category, value) do { \
    ethudp_metric_t *m = ethudp_metrics_registry_find(global_metrics_registry, name, category); \
    if (m) ethudp_metric_gauge_set(m, value); \
} while(0)

#define ETHUDP_METRIC_OBSERVE(name, category, value) do { \
    ethudp_metric_t *m = ethudp_metrics_registry_find(global_metrics_registry, name, category); \
    if (m) { \
        if (m->type == METRIC_TYPE_HISTOGRAM) ethudp_metric_histogram_observe(m, value); \
        else if (m->type == METRIC_TYPE_TIMER) ethudp_metric_timer_observe(m, value); \
    } \
} while(0)

#endif // ETHUDP_METRICS_H