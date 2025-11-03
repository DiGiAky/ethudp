#ifndef ETHUDP_WORKERS_H
#define ETHUDP_WORKERS_H

#include "ethudp_common.h"
#include "ethudp_types.h"
#include "ethudp_config.h"

// Worker states
typedef enum {
    WORKER_STATE_IDLE = 0,
    WORKER_STATE_RUNNING,
    WORKER_STATE_STOPPING,
    WORKER_STATE_STOPPED,
    WORKER_STATE_ERROR
} ethudp_worker_state_t;

// Worker types
typedef enum {
    WORKER_TYPE_UDP = 0,
    WORKER_TYPE_RAW,
    WORKER_TYPE_KEEPALIVE,
    WORKER_TYPE_DYNAMIC
} ethudp_worker_type_t;

// Worker statistics
typedef struct {
    uint64_t packets_processed;
    uint64_t bytes_processed;
    uint64_t errors;
    uint64_t start_time;
    uint64_t last_activity;
    double cpu_usage;
    size_t memory_usage;
} ethudp_worker_stats_t;

// Worker thread structure
typedef struct {
    pthread_t thread_id;
    int worker_id;
    ethudp_worker_type_t type;
    ethudp_worker_state_t state;
    int cpu_affinity;
    void *context;
    ethudp_worker_stats_t stats;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    volatile int should_stop;
} ethudp_worker_t;

// Worker pool structure
typedef struct {
    ethudp_worker_t *udp_workers;
    ethudp_worker_t *raw_workers;
    ethudp_worker_t *keepalive_worker;
    int udp_worker_count;
    int raw_worker_count;
    int total_workers;
    pthread_mutex_t pool_mutex;
    volatile int pool_running;
    ethudp_config_t *config;
} ethudp_worker_pool_t;

// Function declarations

/**
 * Initialize worker pool
 */
int ethudp_worker_pool_init(ethudp_worker_pool_t *pool, const ethudp_config_t *config);

/**
 * Start all workers in the pool
 */
int ethudp_worker_pool_start(ethudp_worker_pool_t *pool);

/**
 * Stop all workers in the pool
 */
int ethudp_worker_pool_stop(ethudp_worker_pool_t *pool);

/**
 * Cleanup worker pool resources
 */
void ethudp_worker_pool_cleanup(ethudp_worker_pool_t *pool);

/**
 * Get worker pool statistics
 */
int ethudp_worker_pool_get_stats(const ethudp_worker_pool_t *pool, 
                                ethudp_worker_stats_t *total_stats);

/**
 * Scale worker pool dynamically
 */
int ethudp_worker_pool_scale(ethudp_worker_pool_t *pool, 
                            int new_udp_workers, int new_raw_workers);

/**
 * Initialize a single worker
 */
int ethudp_worker_init(ethudp_worker_t *worker, int worker_id, 
                      ethudp_worker_type_t type, int cpu_affinity);

/**
 * Start a single worker
 */
int ethudp_worker_start(ethudp_worker_t *worker, void *(*worker_func)(void *), void *context);

/**
 * Stop a single worker
 */
int ethudp_worker_stop(ethudp_worker_t *worker);

/**
 * Get worker statistics
 */
int ethudp_worker_get_stats(const ethudp_worker_t *worker, ethudp_worker_stats_t *stats);

/**
 * Update worker statistics
 */
void ethudp_worker_update_stats(ethudp_worker_t *worker, 
                               uint64_t packets, uint64_t bytes, uint64_t errors);

/**
 * Set worker CPU affinity
 */
int ethudp_worker_set_cpu_affinity(ethudp_worker_t *worker, int cpu_id);

/**
 * Check if worker is healthy
 */
int ethudp_worker_is_healthy(const ethudp_worker_t *worker);

/**
 * Worker thread functions
 */
void *ethudp_udp_worker_thread(void *arg);
void *ethudp_raw_worker_thread(void *arg);
void *ethudp_keepalive_worker_thread(void *arg);

/**
 * Worker pool monitoring
 */
int ethudp_worker_pool_monitor(ethudp_worker_pool_t *pool);

/**
 * Print worker pool status
 */
void ethudp_worker_pool_print_status(const ethudp_worker_pool_t *pool);

/**
 * Handle worker errors
 */
void ethudp_worker_handle_error(ethudp_worker_t *worker, const char *error_msg);

/**
 * Restart failed worker
 */
int ethudp_worker_restart(ethudp_worker_t *worker);

/**
 * Get optimal worker count based on system resources
 */
int ethudp_worker_get_optimal_count(ethudp_worker_type_t type);

/**
 * Balance load across workers
 */
int ethudp_worker_balance_load(ethudp_worker_pool_t *pool);

#endif // ETHUDP_WORKERS_H