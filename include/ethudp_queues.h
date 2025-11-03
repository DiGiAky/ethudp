#ifndef ETHUDP_QUEUES_H
#define ETHUDP_QUEUES_H

#include "ethudp_common.h"
#include "ethudp_types.h"

// Queue types
typedef enum {
    QUEUE_TYPE_UDP_RX = 0,
    QUEUE_TYPE_UDP_TX,
    QUEUE_TYPE_RAW_RX,
    QUEUE_TYPE_RAW_TX,
    QUEUE_TYPE_CONTROL
} ethudp_queue_type_t;

// Queue item structure
typedef struct {
    uint8_t *data;
    size_t size;
    uint64_t timestamp;
    int priority;
    void *metadata;
} ethudp_queue_item_t;

// Lock-free queue node
typedef struct ethudp_queue_node {
    ethudp_queue_item_t item;
    struct ethudp_queue_node *next;
    volatile int ref_count;
} ethudp_queue_node_t;

// Lock-free queue structure
typedef struct {
    volatile ethudp_queue_node_t *head;
    volatile ethudp_queue_node_t *tail;
    volatile uint64_t enqueue_count;
    volatile uint64_t dequeue_count;
    volatile uint64_t drop_count;
    size_t max_size;
    size_t current_size;
    ethudp_queue_type_t type;
    pthread_mutex_t size_mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
    volatile int closed;
} ethudp_queue_t;

// Queue statistics
typedef struct {
    uint64_t enqueue_count;
    uint64_t dequeue_count;
    uint64_t drop_count;
    uint64_t current_size;
    uint64_t max_size;
    double avg_wait_time;
    double throughput;
} ethudp_queue_stats_t;

// Queue manager structure
typedef struct {
    ethudp_queue_t *udp_rx_queue;
    ethudp_queue_t *udp_tx_queue;
    ethudp_queue_t *raw_rx_queue;
    ethudp_queue_t *raw_tx_queue;
    ethudp_queue_t *control_queue;
    size_t default_queue_size;
    pthread_mutex_t manager_mutex;
    volatile int initialized;
} ethudp_queue_manager_t;

// Function declarations

/**
 * Initialize a lock-free queue
 */
int ethudp_queue_init(ethudp_queue_t *queue, size_t max_size, ethudp_queue_type_t type);

/**
 * Cleanup queue resources
 */
void ethudp_queue_cleanup(ethudp_queue_t *queue);

/**
 * Enqueue an item (non-blocking)
 */
int ethudp_queue_enqueue(ethudp_queue_t *queue, const ethudp_queue_item_t *item);

/**
 * Enqueue an item with timeout
 */
int ethudp_queue_enqueue_timeout(ethudp_queue_t *queue, const ethudp_queue_item_t *item, 
                                int timeout_ms);

/**
 * Dequeue an item (non-blocking)
 */
int ethudp_queue_dequeue(ethudp_queue_t *queue, ethudp_queue_item_t *item);

/**
 * Dequeue an item with timeout
 */
int ethudp_queue_dequeue_timeout(ethudp_queue_t *queue, ethudp_queue_item_t *item, 
                                int timeout_ms);

/**
 * Peek at the front item without removing it
 */
int ethudp_queue_peek(ethudp_queue_t *queue, ethudp_queue_item_t *item);

/**
 * Get current queue size
 */
size_t ethudp_queue_size(const ethudp_queue_t *queue);

/**
 * Check if queue is empty
 */
int ethudp_queue_is_empty(const ethudp_queue_t *queue);

/**
 * Check if queue is full
 */
int ethudp_queue_is_full(const ethudp_queue_t *queue);

/**
 * Clear all items from queue
 */
void ethudp_queue_clear(ethudp_queue_t *queue);

/**
 * Close queue (prevent further enqueues)
 */
void ethudp_queue_close(ethudp_queue_t *queue);

/**
 * Get queue statistics
 */
int ethudp_queue_get_stats(const ethudp_queue_t *queue, ethudp_queue_stats_t *stats);

/**
 * Reset queue statistics
 */
void ethudp_queue_reset_stats(ethudp_queue_t *queue);

/**
 * Initialize queue manager
 */
int ethudp_queue_manager_init(ethudp_queue_manager_t *manager, size_t default_queue_size);

/**
 * Cleanup queue manager
 */
void ethudp_queue_manager_cleanup(ethudp_queue_manager_t *manager);

/**
 * Get queue by type
 */
ethudp_queue_t *ethudp_queue_manager_get_queue(ethudp_queue_manager_t *manager, 
                                              ethudp_queue_type_t type);

/**
 * Get manager statistics
 */
int ethudp_queue_manager_get_stats(const ethudp_queue_manager_t *manager, 
                                  ethudp_queue_stats_t *total_stats);

/**
 * Print queue manager status
 */
void ethudp_queue_manager_print_status(const ethudp_queue_manager_t *manager);

/**
 * Create a queue item
 */
int ethudp_queue_item_create(ethudp_queue_item_t *item, const uint8_t *data, 
                            size_t size, int priority, void *metadata);

/**
 * Destroy a queue item
 */
void ethudp_queue_item_destroy(ethudp_queue_item_t *item);

/**
 * Clone a queue item
 */
int ethudp_queue_item_clone(ethudp_queue_item_t *dest, const ethudp_queue_item_t *src);

/**
 * Batch enqueue multiple items
 */
int ethudp_queue_enqueue_batch(ethudp_queue_t *queue, const ethudp_queue_item_t *items, 
                              size_t count, size_t *enqueued);

/**
 * Batch dequeue multiple items
 */
int ethudp_queue_dequeue_batch(ethudp_queue_t *queue, ethudp_queue_item_t *items, 
                              size_t max_count, size_t *dequeued);

/**
 * Set queue priority threshold
 */
int ethudp_queue_set_priority_threshold(ethudp_queue_t *queue, int threshold);

/**
 * Get queue type name
 */
const char *ethudp_queue_type_name(ethudp_queue_type_t type);

/**
 * Queue health check
 */
int ethudp_queue_health_check(const ethudp_queue_t *queue);

/**
 * Resize queue (if possible)
 */
int ethudp_queue_resize(ethudp_queue_t *queue, size_t new_max_size);

/**
 * Queue load balancing
 */
int ethudp_queue_balance_load(ethudp_queue_manager_t *manager);

/**
 * Memory pool for queue nodes
 */
typedef struct {
    ethudp_queue_node_t *free_nodes;
    size_t pool_size;
    size_t used_count;
    pthread_mutex_t pool_mutex;
} ethudp_queue_node_pool_t;

/**
 * Initialize node pool
 */
int ethudp_queue_node_pool_init(ethudp_queue_node_pool_t *pool, size_t initial_size);

/**
 * Cleanup node pool
 */
void ethudp_queue_node_pool_cleanup(ethudp_queue_node_pool_t *pool);

/**
 * Allocate node from pool
 */
ethudp_queue_node_t *ethudp_queue_node_pool_alloc(ethudp_queue_node_pool_t *pool);

/**
 * Return node to pool
 */
void ethudp_queue_node_pool_free(ethudp_queue_node_pool_t *pool, ethudp_queue_node_t *node);

#endif // ETHUDP_QUEUES_H