#ifndef ETHUDP_STATS_H
#define ETHUDP_STATS_H

#include "ethudp_common.h"
#include "ethudp_types.h"
#include "ethudp_metrics.h"

// Statistics time windows
typedef enum {
    STATS_WINDOW_1SEC = 0,
    STATS_WINDOW_5SEC,
    STATS_WINDOW_30SEC,
    STATS_WINDOW_1MIN,
    STATS_WINDOW_5MIN,
    STATS_WINDOW_15MIN,
    STATS_WINDOW_1HOUR,
    STATS_WINDOW_MAX
} ethudp_stats_window_t;

// Statistics aggregation types
typedef enum {
    STATS_AGG_SUM = 0,
    STATS_AGG_AVG,
    STATS_AGG_MIN,
    STATS_AGG_MAX,
    STATS_AGG_COUNT,
    STATS_AGG_RATE,
    STATS_AGG_PERCENTILE,
    STATS_AGG_MAX_TYPE
} ethudp_stats_aggregation_t;

// Time series data point
typedef struct {
    uint64_t timestamp;
    double value;
} ethudp_stats_datapoint_t;

// Time series buffer
typedef struct {
    ethudp_stats_datapoint_t *points;
    size_t capacity;
    size_t count;
    size_t head;
    size_t tail;
    uint64_t window_size_ms;
    pthread_mutex_t buffer_mutex;
} ethudp_stats_timeseries_t;

// Statistical summary
typedef struct {
    double sum;
    double avg;
    double min;
    double max;
    double stddev;
    double median;
    double p95;
    double p99;
    uint64_t count;
    uint64_t rate_per_sec;
} ethudp_stats_summary_t;

// Performance statistics
typedef struct {
    ethudp_stats_summary_t packet_rate;
    ethudp_stats_summary_t byte_rate;
    ethudp_stats_summary_t processing_latency;
    ethudp_stats_summary_t queue_depth;
    ethudp_stats_summary_t cpu_usage;
    ethudp_stats_summary_t memory_usage;
    ethudp_stats_summary_t error_rate;
    uint64_t uptime_seconds;
    uint64_t last_updated;
} ethudp_performance_stats_t;

// Worker statistics
typedef struct {
    uint32_t worker_id;
    char worker_type[32];
    uint64_t packets_processed;
    uint64_t bytes_processed;
    uint64_t errors_encountered;
    double avg_processing_time_us;
    double cpu_usage_percent;
    uint32_t queue_depth;
    uint64_t last_activity;
    int is_active;
} ethudp_worker_stats_t;

// Connection statistics
typedef struct {
    char remote_addr[64];
    uint16_t remote_port;
    uint64_t packets_sent;
    uint64_t packets_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t connection_time;
    uint64_t last_activity;
    double avg_rtt_ms;
    uint32_t packet_loss_count;
    int is_active;
} ethudp_connection_stats_t;

// Global statistics container
typedef struct {
    ethudp_performance_stats_t performance;
    ethudp_worker_stats_t *worker_stats;
    size_t worker_count;
    ethudp_connection_stats_t *connection_stats;
    size_t connection_count;
    size_t max_connections;
    
    // Time series data
    ethudp_stats_timeseries_t *timeseries[STATS_WINDOW_MAX];
    
    // Configuration
    int collection_enabled;
    uint64_t collection_interval_ms;
    uint64_t retention_period_ms;
    
    // Synchronization
    pthread_mutex_t stats_mutex;
    pthread_t collection_thread;
    int collection_running;
    
    // Callbacks
    void (*stats_callback)(const ethudp_performance_stats_t *stats, void *user_data);
    void *callback_user_data;
} ethudp_stats_manager_t;

// Statistics export formats
typedef enum {
    STATS_FORMAT_JSON = 0,
    STATS_FORMAT_CSV,
    STATS_FORMAT_PROMETHEUS,
    STATS_FORMAT_INFLUXDB,
    STATS_FORMAT_MAX
} ethudp_stats_format_t;

// Statistics manager functions
int ethudp_stats_manager_init(ethudp_stats_manager_t *manager, 
                             size_t max_workers, size_t max_connections,
                             uint64_t collection_interval_ms);
void ethudp_stats_manager_cleanup(ethudp_stats_manager_t *manager);
int ethudp_stats_manager_start(ethudp_stats_manager_t *manager);
void ethudp_stats_manager_stop(ethudp_stats_manager_t *manager);
void ethudp_stats_manager_set_callback(ethudp_stats_manager_t *manager,
                                      void (*callback)(const ethudp_performance_stats_t *stats, void *user_data),
                                      void *user_data);

// Time series functions
int ethudp_stats_timeseries_init(ethudp_stats_timeseries_t *ts, 
                                size_t capacity, uint64_t window_size_ms);
void ethudp_stats_timeseries_cleanup(ethudp_stats_timeseries_t *ts);
int ethudp_stats_timeseries_add(ethudp_stats_timeseries_t *ts, 
                               uint64_t timestamp, double value);
int ethudp_stats_timeseries_get_summary(const ethudp_stats_timeseries_t *ts,
                                       ethudp_stats_summary_t *summary,
                                       uint64_t start_time, uint64_t end_time);
void ethudp_stats_timeseries_cleanup_old(ethudp_stats_timeseries_t *ts, uint64_t cutoff_time);

// Statistics collection functions
int ethudp_stats_collect_performance(ethudp_stats_manager_t *manager);
int ethudp_stats_collect_workers(ethudp_stats_manager_t *manager);
int ethudp_stats_collect_connections(ethudp_stats_manager_t *manager);
void ethudp_stats_collect_all(ethudp_stats_manager_t *manager);

// Statistics update functions
void ethudp_stats_update_packet_count(ethudp_stats_manager_t *manager, uint64_t count);
void ethudp_stats_update_byte_count(ethudp_stats_manager_t *manager, uint64_t bytes);
void ethudp_stats_update_processing_time(ethudp_stats_manager_t *manager, double time_us);
void ethudp_stats_update_error_count(ethudp_stats_manager_t *manager, uint64_t errors);
void ethudp_stats_update_worker(ethudp_stats_manager_t *manager, uint32_t worker_id,
                               const ethudp_worker_stats_t *stats);
void ethudp_stats_update_connection(ethudp_stats_manager_t *manager, const char *remote_addr,
                                   uint16_t remote_port, const ethudp_connection_stats_t *stats);

// Statistics query functions
int ethudp_stats_get_performance(const ethudp_stats_manager_t *manager,
                                ethudp_performance_stats_t *stats);
int ethudp_stats_get_worker(const ethudp_stats_manager_t *manager, uint32_t worker_id,
                           ethudp_worker_stats_t *stats);
int ethudp_stats_get_connection(const ethudp_stats_manager_t *manager, const char *remote_addr,
                               uint16_t remote_port, ethudp_connection_stats_t *stats);
int ethudp_stats_get_summary(const ethudp_stats_manager_t *manager,
                            ethudp_stats_window_t window, ethudp_stats_summary_t *summary);

// Statistics calculation functions
void ethudp_stats_calculate_summary(const ethudp_stats_datapoint_t *points, size_t count,
                                   ethudp_stats_summary_t *summary);
double ethudp_stats_calculate_percentile(const ethudp_stats_datapoint_t *points, size_t count,
                                        double percentile);
double ethudp_stats_calculate_stddev(const ethudp_stats_datapoint_t *points, size_t count,
                                    double mean);
uint64_t ethudp_stats_calculate_rate(const ethudp_stats_datapoint_t *points, size_t count,
                                    uint64_t window_ms);

// Statistics export functions
int ethudp_stats_export(const ethudp_stats_manager_t *manager, ethudp_stats_format_t format,
                       char *buffer, size_t buffer_size);
int ethudp_stats_export_json(const ethudp_stats_manager_t *manager, char *buffer, size_t buffer_size);
int ethudp_stats_export_csv(const ethudp_stats_manager_t *manager, char *buffer, size_t buffer_size);
int ethudp_stats_export_prometheus(const ethudp_stats_manager_t *manager, char *buffer, size_t buffer_size);

// Statistics reporting functions
void ethudp_stats_print_performance(const ethudp_performance_stats_t *stats);
void ethudp_stats_print_workers(const ethudp_worker_stats_t *workers, size_t count);
void ethudp_stats_print_connections(const ethudp_connection_stats_t *connections, size_t count);
void ethudp_stats_print_summary(const ethudp_stats_manager_t *manager);
void ethudp_stats_print_timeseries(const ethudp_stats_timeseries_t *ts, const char *name);

// Statistics persistence functions
int ethudp_stats_save_to_file(const ethudp_stats_manager_t *manager, const char *filename,
                             ethudp_stats_format_t format);
int ethudp_stats_load_from_file(ethudp_stats_manager_t *manager, const char *filename,
                               ethudp_stats_format_t format);

// Utility functions
const char *ethudp_stats_window_name(ethudp_stats_window_t window);
const char *ethudp_stats_format_name(ethudp_stats_format_t format);
uint64_t ethudp_stats_window_duration_ms(ethudp_stats_window_t window);
int ethudp_stats_is_window_expired(uint64_t timestamp, ethudp_stats_window_t window);

// Global statistics manager
extern ethudp_stats_manager_t *global_stats_manager;

// Convenience macros for statistics updates
#define ETHUDP_STATS_INC_PACKETS(count) do { \
    if (global_stats_manager) ethudp_stats_update_packet_count(global_stats_manager, count); \
} while(0)

#define ETHUDP_STATS_INC_BYTES(bytes) do { \
    if (global_stats_manager) ethudp_stats_update_byte_count(global_stats_manager, bytes); \
} while(0)

#define ETHUDP_STATS_UPDATE_LATENCY(time_us) do { \
    if (global_stats_manager) ethudp_stats_update_processing_time(global_stats_manager, time_us); \
} while(0)

#define ETHUDP_STATS_INC_ERRORS(count) do { \
    if (global_stats_manager) ethudp_stats_update_error_count(global_stats_manager, count); \
} while(0)

#endif // ETHUDP_STATS_H