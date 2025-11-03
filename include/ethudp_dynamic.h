/* EthUDP Dynamic Thread Management
 * Dynamic scaling, load balancing, and performance optimization
 * by james@ustc.edu.cn 2009.04.02
 */

#ifndef ETHUDP_DYNAMIC_H
#define ETHUDP_DYNAMIC_H

#include "ethudp_common.h"
#include "ethudp_types.h"

// ============================================================================
// DYNAMIC SYSTEM MANAGEMENT
// ============================================================================

/**
 * Initialize dynamic system
 * @param system Dynamic system instance to initialize
 * @return 0 on success, -1 on error
 */
int ethudp_init_dynamic_system(dynamic_system_t *system);

/**
 * Start dynamic system
 * @param system Dynamic system instance
 * @return 0 on success, -1 on error
 */
int ethudp_start_dynamic_system(dynamic_system_t *system);

/**
 * Stop dynamic system
 * @param system Dynamic system instance
 * @return 0 on success, -1 on error
 */
int ethudp_stop_dynamic_system(dynamic_system_t *system);

/**
 * Cleanup dynamic system resources
 * @param system Dynamic system instance
 */
void ethudp_cleanup_dynamic_system(dynamic_system_t *system);

// ============================================================================
// METRICS COLLECTION
// ============================================================================

/**
 * Collect current system metrics
 * @param metrics System metrics structure to fill
 * @return 0 on success, -1 on error
 */
int collect_system_metrics(system_metrics_t *metrics);

/**
 * Update metrics history with new sample
 * @param history Metrics history structure
 * @param metrics New metrics sample
 * @return 0 on success, -1 on error
 */
int update_metrics_history(metrics_history_t *history, const system_metrics_t *metrics);

/**
 * Get metrics statistics from history
 * @param history Metrics history structure
 * @param avg_cpu Average CPU usage (output)
 * @param avg_pps Average packets per second (output)
 * @param avg_latency Average latency (output)
 * @param avg_queue_depth Average queue depth (output)
 * @return 0 on success, -1 on error
 */
int get_metrics_statistics(const metrics_history_t *history, double *avg_cpu,
                          double *avg_pps, double *avg_latency, double *avg_queue_depth);

/**
 * Metrics collector thread function
 * @param arg Dynamic system instance
 * @return NULL
 */
void* metrics_collector_thread(void *arg);

// ============================================================================
// LOAD PATTERN DETECTION
// ============================================================================

/**
 * Detect load patterns from metrics history
 * @param history Metrics history
 * @param pattern Load pattern structure to fill
 * @return 0 on success, -1 on error
 */
int detect_load_patterns(const metrics_history_t *history, load_pattern_t *pattern);

/**
 * Predict future load based on patterns
 * @param pattern Load pattern structure
 * @param current_time Current timestamp
 * @param prediction_horizon_ms Prediction horizon in milliseconds
 * @return Predicted load multiplier
 */
double predict_future_load(const load_pattern_t *pattern, uint64_t current_time,
                          uint32_t prediction_horizon_ms);

/**
 * Update load pattern with new data
 * @param pattern Load pattern structure
 * @param metrics Current metrics
 * @param timestamp Current timestamp
 * @return 0 on success, -1 on error
 */
int update_load_pattern(load_pattern_t *pattern, const system_metrics_t *metrics,
                       uint64_t timestamp);

// ============================================================================
// SCALING DECISIONS
// ============================================================================

/**
 * Make scaling decision based on current metrics
 * @param metrics Current system metrics
 * @param config Dynamic configuration
 * @param pattern Load pattern (optional)
 * @return Scaling decision (SCALE_UP, SCALE_DOWN, or SCALE_NONE)
 */
scale_decision_t make_scaling_decision(const system_metrics_t *metrics,
                                     const dynamic_config_t *config,
                                     const load_pattern_t *pattern);

/**
 * Execute scaling decision
 * @param system Dynamic system instance
 * @param decision Scaling decision
 * @param worker_pool Worker pool to scale
 * @return 0 on success, -1 on error
 */
int execute_scaling_decision(dynamic_system_t *system, scale_decision_t decision,
                           worker_pool_t *worker_pool);

/**
 * Log scaling event
 * @param decision Scaling decision
 * @param metrics Current metrics
 * @param reason Reason for scaling
 */
void log_scaling_event(scale_decision_t decision, const system_metrics_t *metrics,
                      const char *reason);

// ============================================================================
// WORKER SCALING
// ============================================================================

/**
 * Scale up workers
 * @param worker_pool Worker pool
 * @param worker_type Worker type (UDP or RAW)
 * @param count Number of workers to add
 * @return Number of workers actually added, -1 on error
 */
int scale_up_workers(worker_pool_t *worker_pool, int worker_type, int count);

/**
 * Scale down workers
 * @param worker_pool Worker pool
 * @param worker_type Worker type (UDP or RAW)
 * @param count Number of workers to remove
 * @return Number of workers actually removed, -1 on error
 */
int scale_down_workers(worker_pool_t *worker_pool, int worker_type, int count);

/**
 * Create new UDP worker
 * @param worker_pool Worker pool
 * @param worker_id Worker ID
 * @param config Worker configuration
 * @return Pointer to created worker, NULL on error
 */
worker_context_t* create_udp_worker(worker_pool_t *worker_pool, int worker_id,
                                   const ethudp_config_t *config);

/**
 * Create new RAW worker
 * @param worker_pool Worker pool
 * @param worker_id Worker ID
 * @param config Worker configuration
 * @return Pointer to created worker, NULL on error
 */
worker_context_t* create_raw_worker(worker_pool_t *worker_pool, int worker_id,
                                   const ethudp_config_t *config);

/**
 * Stop UDP worker
 * @param worker Worker context
 * @return 0 on success, -1 on error
 */
int stop_udp_worker(worker_context_t *worker);

/**
 * Stop RAW worker
 * @param worker Worker context
 * @return 0 on success, -1 on error
 */
int stop_raw_worker(worker_context_t *worker);

// ============================================================================
// LOAD BALANCING
// ============================================================================

/**
 * Balance worker load
 * @param worker_pool Worker pool
 * @param system Dynamic system instance
 * @return 0 on success, -1 on error
 */
int balance_worker_load(worker_pool_t *worker_pool, dynamic_system_t *system);

/**
 * Find least utilized UDP worker
 * @param worker_pool Worker pool
 * @return Pointer to least utilized worker, NULL if none available
 */
worker_context_t* find_least_utilized_udp_worker(const worker_pool_t *worker_pool);

/**
 * Find least utilized RAW worker
 * @param worker_pool Worker pool
 * @return Pointer to least utilized worker, NULL if none available
 */
worker_context_t* find_least_utilized_raw_worker(const worker_pool_t *worker_pool);

/**
 * Calculate worker utilization
 * @param worker Worker context
 * @return Utilization percentage (0.0-100.0)
 */
double calculate_worker_utilization(const worker_context_t *worker);

/**
 * Redistribute work among workers
 * @param worker_pool Worker pool
 * @param target_utilization Target utilization percentage
 * @return 0 on success, -1 on error
 */
int redistribute_worker_load(worker_pool_t *worker_pool, double target_utilization);

// ============================================================================
// ADAPTIVE THRESHOLDS
// ============================================================================

/**
 * Auto-tune scaling thresholds based on historical data
 * @param config Dynamic configuration to update
 * @param history Metrics history
 * @return 0 on success, -1 on error
 */
int auto_tune_thresholds(dynamic_config_t *config, const metrics_history_t *history);

/**
 * Update threshold based on performance feedback
 * @param threshold Threshold to update
 * @param current_value Current metric value
 * @param target_value Target metric value
 * @param learning_rate Learning rate (0.0-1.0)
 * @return Updated threshold value
 */
double update_adaptive_threshold(double threshold, double current_value,
                               double target_value, double learning_rate);

/**
 * Calculate optimal worker count
 * @param metrics Current system metrics
 * @param config Dynamic configuration
 * @return Optimal worker count
 */
int calculate_optimal_worker_count(const system_metrics_t *metrics,
                                 const dynamic_config_t *config);

// ============================================================================
// WORKER STATISTICS
// ============================================================================

/**
 * Collect worker statistics
 * @param worker Worker context
 * @param stats Worker statistics structure to fill
 * @return 0 on success, -1 on error
 */
int collect_worker_stats(const worker_context_t *worker, atomic_metrics_t *stats);

/**
 * Update worker performance metrics
 * @param worker Worker context
 * @param processing_time Processing time for last operation
 * @param packets_processed Number of packets processed
 * @param bytes_processed Number of bytes processed
 */
void update_worker_metrics(worker_context_t *worker, uint64_t processing_time,
                          uint64_t packets_processed, uint64_t bytes_processed);

/**
 * Worker statistics reporter thread
 * @param arg Worker pool instance
 * @return NULL
 */
void* worker_stats_reporter(void *arg);

/**
 * Get aggregated worker statistics
 * @param worker_pool Worker pool
 * @param total_packets Total packets processed (output)
 * @param total_bytes Total bytes processed (output)
 * @param avg_utilization Average utilization (output)
 * @return 0 on success, -1 on error
 */
int get_aggregated_worker_stats(const worker_pool_t *worker_pool,
                               uint64_t *total_packets, uint64_t *total_bytes,
                               double *avg_utilization);

// ============================================================================
// MEMORY MANAGEMENT
// ============================================================================

/**
 * Initialize dynamic memory manager
 * @param manager Memory manager instance
 * @param initial_pools Number of initial buffer pools
 * @return 0 on success, -1 on error
 */
int init_dynamic_memory_manager(dynamic_memory_manager_t *manager, uint32_t initial_pools);

/**
 * Cleanup dynamic memory manager
 * @param manager Memory manager instance
 */
void cleanup_dynamic_memory_manager(dynamic_memory_manager_t *manager);

/**
 * Adapt buffer pool sizes based on usage patterns
 * @param manager Memory manager instance
 * @param metrics Current system metrics
 * @return 0 on success, -1 on error
 */
int adapt_buffer_pool_sizes(dynamic_memory_manager_t *manager,
                           const system_metrics_t *metrics);

/**
 * Get optimal buffer size for current load
 * @param metrics Current system metrics
 * @param current_size Current buffer size
 * @return Optimal buffer size
 */
uint32_t get_optimal_buffer_size(const system_metrics_t *metrics, uint32_t current_size);

// ============================================================================
// CONFIGURATION MANAGEMENT
// ============================================================================

/**
 * Initialize RCU configuration system
 * @param rcu_config RCU configuration instance
 * @param initial_config Initial configuration
 * @return 0 on success, -1 on error
 */
int init_rcu_config(rcu_config_t *rcu_config, const dynamic_config_t *initial_config);

/**
 * Update configuration using RCU
 * @param rcu_config RCU configuration instance
 * @param new_config New configuration
 * @return 0 on success, -1 on error
 */
int update_rcu_config(rcu_config_t *rcu_config, const dynamic_config_t *new_config);

/**
 * Read current configuration (RCU-safe)
 * @param rcu_config RCU configuration instance
 * @return Pointer to current configuration
 */
const dynamic_config_t* read_rcu_config(const rcu_config_t *rcu_config);

/**
 * Cleanup RCU configuration system
 * @param rcu_config RCU configuration instance
 */
void cleanup_rcu_config(rcu_config_t *rcu_config);

// ============================================================================
// PERFORMANCE MONITORING
// ============================================================================

/**
 * Start performance monitoring
 * @param system Dynamic system instance
 * @return 0 on success, -1 on error
 */
int start_performance_monitoring(dynamic_system_t *system);

/**
 * Stop performance monitoring
 * @param system Dynamic system instance
 * @return 0 on success, -1 on error
 */
int stop_performance_monitoring(dynamic_system_t *system);

/**
 * Generate performance report
 * @param system Dynamic system instance
 * @param report_buffer Buffer to store report
 * @param buffer_size Size of report buffer
 * @return 0 on success, -1 on error
 */
int generate_performance_report(const dynamic_system_t *system, char *report_buffer,
                               size_t buffer_size);

/**
 * Export metrics to external monitoring system
 * @param metrics Current system metrics
 * @param endpoint Monitoring endpoint URL
 * @return 0 on success, -1 on error
 */
int export_metrics_to_monitoring(const system_metrics_t *metrics, const char *endpoint);

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Convert scaling decision to string
 * @param decision Scaling decision
 * @return String representation
 */
const char* scaling_decision_to_string(scale_decision_t decision);

/**
 * Convert load level to string
 * @param level Load level
 * @return String representation
 */
const char* load_level_to_string(load_level_t level);

/**
 * Convert trend type to string
 * @param trend Trend type
 * @return String representation
 */
const char* trend_type_to_string(trend_type_t trend);

/**
 * Validate dynamic configuration
 * @param config Dynamic configuration
 * @return 0 if valid, -1 if invalid
 */
int validate_dynamic_config(const dynamic_config_t *config);

/**
 * Print dynamic system status
 * @param system Dynamic system instance
 */
void print_dynamic_system_status(const dynamic_system_t *system);

// ============================================================================
// MACROS AND INLINE FUNCTIONS
// ============================================================================

// Scaling decision macros
#define IS_SCALE_UP(decision) ((decision) == SCALE_UP)
#define IS_SCALE_DOWN(decision) ((decision) == SCALE_DOWN)
#define IS_SCALE_NONE(decision) ((decision) == SCALE_NONE)

// Load level macros
#define IS_LOAD_LOW(level) ((level) == LOAD_LOW)
#define IS_LOAD_MEDIUM(level) ((level) == LOAD_MEDIUM)
#define IS_LOAD_HIGH(level) ((level) == LOAD_HIGH)

// Metrics validation macros
#define IS_VALID_CPU_USAGE(cpu) ((cpu) >= 0.0 && (cpu) <= 100.0)
#define IS_VALID_LATENCY(latency) ((latency) >= 0.0)
#define IS_VALID_PPS(pps) ((pps) >= 0)

// Threshold comparison macros
#define ABOVE_THRESHOLD(value, threshold) ((value) > (threshold))
#define BELOW_THRESHOLD(value, threshold) ((value) < (threshold))
#define WITHIN_THRESHOLD(value, threshold, tolerance) \
    (fabs((value) - (threshold)) <= (tolerance))

// Time-based macros
#define COOLDOWN_EXPIRED(last_time, cooldown_ms) \
    ((get_current_time_ms() - (last_time)) >= (cooldown_ms))

#define UPDATE_LAST_TIME(time_var) \
    ((time_var) = get_current_time_ms())

// Worker count validation
#define VALIDATE_WORKER_COUNT(count, min, max) \
    ((count) >= (min) && (count) <= (max))

// Inline utility functions
static inline double calculate_load_factor(double current_load, double max_load) {
    return (max_load > 0.0) ? (current_load / max_load) : 0.0;
}

static inline int should_scale_up(double cpu_usage, double threshold) {
    return cpu_usage > threshold;
}

static inline int should_scale_down(double cpu_usage, double threshold) {
    return cpu_usage < threshold;
}

static inline uint64_t ms_to_ns(uint64_t ms) {
    return ms * 1000000ULL;
}

static inline uint64_t us_to_ns(uint64_t us) {
    return us * 1000ULL;
}

static inline double ns_to_ms(uint64_t ns) {
    return (double)ns / 1000000.0;
}

#endif /* ETHUDP_DYNAMIC_H */