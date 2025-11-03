#include "../include/ethudp_common.h"
#include "../include/ethudp_types.h"
#include "../include/ethudp_config.h"
#include "../include/ethudp_workers.h"
#include "../include/ethudp_utils.h"
#include "../include/ethudp_network.h"

// External variables from original code
extern int fdudp[2];
extern int fdraw;
extern int debug;
extern int got_signal;
extern volatile int pool_running;

/**
 * Initialize worker pool
 */
int ethudp_worker_pool_init(ethudp_worker_pool_t *pool, const ethudp_config_t *config) {
    if (!pool || !config) {
        return -1;
    }
    
    memset(pool, 0, sizeof(ethudp_worker_pool_t));
    
    pool->config = (ethudp_config_t *)config;
    pool->udp_worker_count = config->udp_workers;
    pool->raw_worker_count = config->raw_workers;
    pool->total_workers = pool->udp_worker_count + pool->raw_worker_count + 1; // +1 for keepalive
    
    // Initialize mutex
    if (pthread_mutex_init(&pool->pool_mutex, NULL) != 0) {
        return -1;
    }
    
    // Allocate UDP workers
    if (pool->udp_worker_count > 0) {
        pool->udp_workers = calloc(pool->udp_worker_count, sizeof(ethudp_worker_t));
        if (!pool->udp_workers) {
            pthread_mutex_destroy(&pool->pool_mutex);
            return -1;
        }
        
        for (int i = 0; i < pool->udp_worker_count; i++) {
            if (ethudp_worker_init(&pool->udp_workers[i], i, WORKER_TYPE_UDP, 
                                  config->cpu_affinity ? i % ethudp_get_cpu_count() : -1) != 0) {
                ethudp_worker_pool_cleanup(pool);
                return -1;
            }
        }
    }
    
    // Allocate RAW workers
    if (pool->raw_worker_count > 0) {
        pool->raw_workers = calloc(pool->raw_worker_count, sizeof(ethudp_worker_t));
        if (!pool->raw_workers) {
            ethudp_worker_pool_cleanup(pool);
            return -1;
        }
        
        for (int i = 0; i < pool->raw_worker_count; i++) {
            if (ethudp_worker_init(&pool->raw_workers[i], i, WORKER_TYPE_RAW,
                                  config->cpu_affinity ? (i + pool->udp_worker_count) % ethudp_get_cpu_count() : -1) != 0) {
                ethudp_worker_pool_cleanup(pool);
                return -1;
            }
        }
    }
    
    // Initialize keepalive worker
    pool->keepalive_worker = calloc(1, sizeof(ethudp_worker_t));
    if (!pool->keepalive_worker) {
        ethudp_worker_pool_cleanup(pool);
        return -1;
    }
    
    if (ethudp_worker_init(pool->keepalive_worker, 0, WORKER_TYPE_KEEPALIVE, -1) != 0) {
        ethudp_worker_pool_cleanup(pool);
        return -1;
    }
    
    pool->pool_running = 0;
    
    if (debug) {
        ethudp_debug("Worker pool initialized: %d UDP workers, %d RAW workers, 1 keepalive worker",
                    pool->udp_worker_count, pool->raw_worker_count);
    }
    
    return 0;
}

/**
 * Start all workers in the pool
 */
int ethudp_worker_pool_start(ethudp_worker_pool_t *pool) {
    if (!pool) {
        return -1;
    }
    
    pthread_mutex_lock(&pool->pool_mutex);
    
    if (pool->pool_running) {
        pthread_mutex_unlock(&pool->pool_mutex);
        return 0; // Already running
    }
    
    // Start UDP workers
    for (int i = 0; i < pool->udp_worker_count; i++) {
        if (ethudp_worker_start(&pool->udp_workers[i], ethudp_udp_worker_thread, pool) != 0) {
            ethudp_err_msg("Failed to start UDP worker %d", i);
            pthread_mutex_unlock(&pool->pool_mutex);
            return -1;
        }
    }
    
    // Start RAW workers
    for (int i = 0; i < pool->raw_worker_count; i++) {
        if (ethudp_worker_start(&pool->raw_workers[i], ethudp_raw_worker_thread, pool) != 0) {
            ethudp_err_msg("Failed to start RAW worker %d", i);
            pthread_mutex_unlock(&pool->pool_mutex);
            return -1;
        }
    }
    
    // Start keepalive worker
    if (ethudp_worker_start(pool->keepalive_worker, ethudp_keepalive_worker_thread, pool) != 0) {
        ethudp_err_msg("Failed to start keepalive worker");
        pthread_mutex_unlock(&pool->pool_mutex);
        return -1;
    }
    
    pool->pool_running = 1;
    
    pthread_mutex_unlock(&pool->pool_mutex);
    
    if (debug) {
        ethudp_debug("Worker pool started successfully");
    }
    
    return 0;
}

/**
 * Stop all workers in the pool
 */
int ethudp_worker_pool_stop(ethudp_worker_pool_t *pool) {
    if (!pool) {
        return -1;
    }
    
    pthread_mutex_lock(&pool->pool_mutex);
    
    if (!pool->pool_running) {
        pthread_mutex_unlock(&pool->pool_mutex);
        return 0; // Already stopped
    }
    
    pool->pool_running = 0;
    
    // Stop UDP workers
    for (int i = 0; i < pool->udp_worker_count; i++) {
        ethudp_worker_stop(&pool->udp_workers[i]);
    }
    
    // Stop RAW workers
    for (int i = 0; i < pool->raw_worker_count; i++) {
        ethudp_worker_stop(&pool->raw_workers[i]);
    }
    
    // Stop keepalive worker
    if (pool->keepalive_worker) {
        ethudp_worker_stop(pool->keepalive_worker);
    }
    
    pthread_mutex_unlock(&pool->pool_mutex);
    
    if (debug) {
        ethudp_debug("Worker pool stopped");
    }
    
    return 0;
}

/**
 * Cleanup worker pool resources
 */
void ethudp_worker_pool_cleanup(ethudp_worker_pool_t *pool) {
    if (!pool) {
        return;
    }
    
    // Stop all workers first
    ethudp_worker_pool_stop(pool);
    
    // Cleanup UDP workers
    if (pool->udp_workers) {
        for (int i = 0; i < pool->udp_worker_count; i++) {
            pthread_mutex_destroy(&pool->udp_workers[i].mutex);
            pthread_cond_destroy(&pool->udp_workers[i].cond);
        }
        free(pool->udp_workers);
        pool->udp_workers = NULL;
    }
    
    // Cleanup RAW workers
    if (pool->raw_workers) {
        for (int i = 0; i < pool->raw_worker_count; i++) {
            pthread_mutex_destroy(&pool->raw_workers[i].mutex);
            pthread_cond_destroy(&pool->raw_workers[i].cond);
        }
        free(pool->raw_workers);
        pool->raw_workers = NULL;
    }
    
    // Cleanup keepalive worker
    if (pool->keepalive_worker) {
        pthread_mutex_destroy(&pool->keepalive_worker->mutex);
        pthread_cond_destroy(&pool->keepalive_worker->cond);
        free(pool->keepalive_worker);
        pool->keepalive_worker = NULL;
    }
    
    pthread_mutex_destroy(&pool->pool_mutex);
    
    if (debug) {
        ethudp_debug("Worker pool cleanup completed");
    }
}

/**
 * Initialize a single worker
 */
int ethudp_worker_init(ethudp_worker_t *worker, int worker_id, 
                      ethudp_worker_type_t type, int cpu_affinity) {
    if (!worker) {
        return -1;
    }
    
    memset(worker, 0, sizeof(ethudp_worker_t));
    
    worker->worker_id = worker_id;
    worker->type = type;
    worker->state = WORKER_STATE_IDLE;
    worker->cpu_affinity = cpu_affinity;
    worker->should_stop = 0;
    
    // Initialize mutex and condition variable
    if (pthread_mutex_init(&worker->mutex, NULL) != 0) {
        return -1;
    }
    
    if (pthread_cond_init(&worker->cond, NULL) != 0) {
        pthread_mutex_destroy(&worker->mutex);
        return -1;
    }
    
    // Initialize statistics
    worker->stats.start_time = ethudp_get_current_time_ms();
    worker->stats.last_activity = worker->stats.start_time;
    
    return 0;
}

/**
 * Start a single worker
 */
int ethudp_worker_start(ethudp_worker_t *worker, void *(*worker_func)(void *), void *context) {
    if (!worker || !worker_func) {
        return -1;
    }
    
    pthread_mutex_lock(&worker->mutex);
    
    if (worker->state != WORKER_STATE_IDLE) {
        pthread_mutex_unlock(&worker->mutex);
        return -1; // Worker already started
    }
    
    worker->context = context;
    worker->should_stop = 0;
    worker->state = WORKER_STATE_RUNNING;
    
    if (pthread_create(&worker->thread_id, NULL, worker_func, worker) != 0) {
        worker->state = WORKER_STATE_ERROR;
        pthread_mutex_unlock(&worker->mutex);
        return -1;
    }
    
    // Set CPU affinity if specified
    if (worker->cpu_affinity >= 0) {
        ethudp_worker_set_cpu_affinity(worker, worker->cpu_affinity);
    }
    
    pthread_mutex_unlock(&worker->mutex);
    
    return 0;
}

/**
 * Stop a single worker
 */
int ethudp_worker_stop(ethudp_worker_t *worker) {
    if (!worker) {
        return -1;
    }
    
    pthread_mutex_lock(&worker->mutex);
    
    if (worker->state != WORKER_STATE_RUNNING) {
        pthread_mutex_unlock(&worker->mutex);
        return 0; // Already stopped
    }
    
    worker->should_stop = 1;
    worker->state = WORKER_STATE_STOPPING;
    
    // Signal the worker to wake up
    pthread_cond_signal(&worker->cond);
    
    pthread_mutex_unlock(&worker->mutex);
    
    // Wait for worker to finish
    if (pthread_join(worker->thread_id, NULL) != 0) {
        return -1;
    }
    
    pthread_mutex_lock(&worker->mutex);
    worker->state = WORKER_STATE_STOPPED;
    pthread_mutex_unlock(&worker->mutex);
    
    return 0;
}

/**
 * Update worker statistics
 */
void ethudp_worker_update_stats(ethudp_worker_t *worker, 
                               uint64_t packets, uint64_t bytes, uint64_t errors) {
    if (!worker) {
        return;
    }
    
    pthread_mutex_lock(&worker->mutex);
    
    worker->stats.packets_processed += packets;
    worker->stats.bytes_processed += bytes;
    worker->stats.errors += errors;
    worker->stats.last_activity = ethudp_get_current_time_ms();
    
    pthread_mutex_unlock(&worker->mutex);
}

/**
 * Set worker CPU affinity
 */
int ethudp_worker_set_cpu_affinity(ethudp_worker_t *worker, int cpu_id) {
    if (!worker || cpu_id < 0) {
        return -1;
    }
    
#ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    
    if (pthread_setaffinity_np(worker->thread_id, sizeof(cpu_set_t), &cpuset) != 0) {
        return -1;
    }
    
    worker->cpu_affinity = cpu_id;
    
    if (debug) {
        ethudp_debug("Worker %d (type %d) set to CPU %d", 
                    worker->worker_id, worker->type, cpu_id);
    }
#endif
    
    return 0;
}

/**
 * Check if worker is healthy
 */
int ethudp_worker_is_healthy(const ethudp_worker_t *worker) {
    if (!worker) {
        return 0;
    }
    
    uint64_t current_time = ethudp_get_current_time_ms();
    uint64_t inactive_time = current_time - worker->stats.last_activity;
    
    // Consider worker unhealthy if inactive for more than 30 seconds
    if (inactive_time > 30000) {
        return 0;
    }
    
    return (worker->state == WORKER_STATE_RUNNING);
}

/**
 * UDP worker thread function
 */
void *ethudp_udp_worker_thread(void *arg) {
    ethudp_worker_t *worker = (ethudp_worker_t *)arg;
    ethudp_worker_pool_t *pool = (ethudp_worker_pool_t *)worker->context;
    
    if (debug) {
        ethudp_debug("UDP worker %d started", worker->worker_id);
    }
    
    while (!worker->should_stop && pool->pool_running) {
        // Process UDP packets
        // This would integrate with the existing UDP processing logic
        
        // Update statistics
        ethudp_worker_update_stats(worker, 1, 0, 0);
        
        // Small sleep to prevent busy waiting
        ethudp_sleep_ms(1);
    }
    
    if (debug) {
        ethudp_debug("UDP worker %d stopped", worker->worker_id);
    }
    
    return NULL;
}

/**
 * RAW worker thread function
 */
void *ethudp_raw_worker_thread(void *arg) {
    ethudp_worker_t *worker = (ethudp_worker_t *)arg;
    ethudp_worker_pool_t *pool = (ethudp_worker_pool_t *)worker->context;
    
    if (debug) {
        ethudp_debug("RAW worker %d started", worker->worker_id);
    }
    
    while (!worker->should_stop && pool->pool_running) {
        // Process RAW packets
        // This would integrate with the existing RAW processing logic
        
        // Update statistics
        ethudp_worker_update_stats(worker, 1, 0, 0);
        
        // Small sleep to prevent busy waiting
        ethudp_sleep_ms(1);
    }
    
    if (debug) {
        ethudp_debug("RAW worker %d stopped", worker->worker_id);
    }
    
    return NULL;
}

/**
 * Keepalive worker thread function
 */
void *ethudp_keepalive_worker_thread(void *arg) {
    ethudp_worker_t *worker = (ethudp_worker_t *)arg;
    ethudp_worker_pool_t *pool = (ethudp_worker_pool_t *)worker->context;
    
    if (debug) {
        ethudp_debug("Keepalive worker started");
    }
    
    while (!worker->should_stop && pool->pool_running) {
        // Send keepalive packets
        // This would integrate with the existing keepalive logic
        ethudp_send_keepalive_to_udp();
        
        // Update statistics
        ethudp_worker_update_stats(worker, 0, 0, 0);
        
        // Sleep for 1 second
        sleep(1);
    }
    
    if (debug) {
        ethudp_debug("Keepalive worker stopped");
    }
    
    return NULL;
}

/**
 * Get worker pool statistics
 */
int ethudp_worker_pool_get_stats(const ethudp_worker_pool_t *pool, 
                                ethudp_worker_stats_t *total_stats) {
    if (!pool || !total_stats) {
        return -1;
    }
    
    memset(total_stats, 0, sizeof(ethudp_worker_stats_t));
    
    // Aggregate UDP worker stats
    for (int i = 0; i < pool->udp_worker_count; i++) {
        const ethudp_worker_t *worker = &pool->udp_workers[i];
        total_stats->packets_processed += worker->stats.packets_processed;
        total_stats->bytes_processed += worker->stats.bytes_processed;
        total_stats->errors += worker->stats.errors;
    }
    
    // Aggregate RAW worker stats
    for (int i = 0; i < pool->raw_worker_count; i++) {
        const ethudp_worker_t *worker = &pool->raw_workers[i];
        total_stats->packets_processed += worker->stats.packets_processed;
        total_stats->bytes_processed += worker->stats.bytes_processed;
        total_stats->errors += worker->stats.errors;
    }
    
    // Add keepalive worker stats
    if (pool->keepalive_worker) {
        total_stats->packets_processed += pool->keepalive_worker->stats.packets_processed;
        total_stats->bytes_processed += pool->keepalive_worker->stats.bytes_processed;
        total_stats->errors += pool->keepalive_worker->stats.errors;
    }
    
    total_stats->start_time = ethudp_get_current_time_ms();
    total_stats->last_activity = total_stats->start_time;
    
    return 0;
}

/**
 * Print worker pool status
 */
void ethudp_worker_pool_print_status(const ethudp_worker_pool_t *pool) {
    if (!pool) {
        return;
    }
    
    ethudp_worker_stats_t total_stats;
    ethudp_worker_pool_get_stats(pool, &total_stats);
    
    printf("Worker Pool Status:\n");
    printf("  Running: %s\n", pool->pool_running ? "Yes" : "No");
    printf("  UDP Workers: %d\n", pool->udp_worker_count);
    printf("  RAW Workers: %d\n", pool->raw_worker_count);
    printf("  Total Packets: %lu\n", total_stats.packets_processed);
    printf("  Total Bytes: %lu\n", total_stats.bytes_processed);
    printf("  Total Errors: %lu\n", total_stats.errors);
    
    // Print individual worker status
    for (int i = 0; i < pool->udp_worker_count; i++) {
        const ethudp_worker_t *worker = &pool->udp_workers[i];
        printf("  UDP Worker %d: State=%d, Packets=%lu, Errors=%lu\n",
               i, worker->state, worker->stats.packets_processed, worker->stats.errors);
    }
    
    for (int i = 0; i < pool->raw_worker_count; i++) {
        const ethudp_worker_t *worker = &pool->raw_workers[i];
        printf("  RAW Worker %d: State=%d, Packets=%lu, Errors=%lu\n",
               i, worker->state, worker->stats.packets_processed, worker->stats.errors);
    }
}

/**
 * Get optimal worker count based on system resources
 */
int ethudp_worker_get_optimal_count(ethudp_worker_type_t type) {
    int cpu_count = ethudp_get_cpu_count();
    
    switch (type) {
        case WORKER_TYPE_UDP:
            // For UDP workers, use half of available CPUs
            return (cpu_count > 2) ? cpu_count / 2 : 1;
            
        case WORKER_TYPE_RAW:
            // For RAW workers, use quarter of available CPUs
            return (cpu_count > 4) ? cpu_count / 4 : 1;
            
        case WORKER_TYPE_KEEPALIVE:
            // Always use 1 keepalive worker
            return 1;
            
        default:
            return 1;
    }
}

/**
 * Worker pool monitoring
 */
int ethudp_worker_pool_monitor(ethudp_worker_pool_t *pool) {
    if (!pool) {
        return -1;
    }
    
    int unhealthy_workers = 0;
    
    // Check UDP workers
    for (int i = 0; i < pool->udp_worker_count; i++) {
        if (!ethudp_worker_is_healthy(&pool->udp_workers[i])) {
            unhealthy_workers++;
            ethudp_err_msg("UDP worker %d is unhealthy", i);
        }
    }
    
    // Check RAW workers
    for (int i = 0; i < pool->raw_worker_count; i++) {
        if (!ethudp_worker_is_healthy(&pool->raw_workers[i])) {
            unhealthy_workers++;
            ethudp_err_msg("RAW worker %d is unhealthy", i);
        }
    }
    
    // Check keepalive worker
    if (pool->keepalive_worker && !ethudp_worker_is_healthy(pool->keepalive_worker)) {
        unhealthy_workers++;
        ethudp_err_msg("Keepalive worker is unhealthy");
    }
    
    return unhealthy_workers;
}