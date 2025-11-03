#include "../include/ethudp_common.h"
#include "../include/ethudp_types.h"
#include "../include/ethudp_queues.h"
#include "../include/ethudp_utils.h"

// Global node pool
static ethudp_queue_node_pool_t global_node_pool = {0};
static int node_pool_initialized = 0;

// Atomic operations for lock-free queue
#ifdef __GNUC__
#define ATOMIC_CAS(ptr, old, new) __sync_bool_compare_and_swap(ptr, old, new)
#define ATOMIC_LOAD(ptr) __sync_fetch_and_add((volatile uint64_t*)(ptr), 0)
#define ATOMIC_LOAD_CONST(ptr) __sync_fetch_and_add((volatile uint64_t*)(ptr), 0)
#define ATOMIC_INC(ptr) __sync_fetch_and_add(ptr, 1)
#define ATOMIC_DEC(ptr) __sync_fetch_and_sub(ptr, 1)
#else
#define ATOMIC_CAS(ptr, old, new) (*ptr == old ? (*ptr = new, 1) : 0)
#define ATOMIC_LOAD(ptr) (*ptr)
#define ATOMIC_LOAD_CONST(ptr) (*ptr)
#define ATOMIC_INC(ptr) (++(*ptr))
#define ATOMIC_DEC(ptr) (--(*ptr))
#endif

/**
 * Initialize node pool
 */
int ethudp_queue_node_pool_init(ethudp_queue_node_pool_t *pool, size_t initial_size) {
    if (!pool || initial_size == 0) {
        return -1;
    }
    
    memset(pool, 0, sizeof(ethudp_queue_node_pool_t));
    
    if (pthread_mutex_init(&pool->pool_mutex, NULL) != 0) {
        return -1;
    }
    
    // Pre-allocate nodes
    pool->pool_size = initial_size;
    ethudp_queue_node_t *nodes = calloc(initial_size, sizeof(ethudp_queue_node_t));
    if (!nodes) {
        pthread_mutex_destroy(&pool->pool_mutex);
        return -1;
    }
    
    // Link nodes together
    for (size_t i = 0; i < initial_size - 1; i++) {
        nodes[i].next = &nodes[i + 1];
    }
    nodes[initial_size - 1].next = NULL;
    
    pool->free_nodes = nodes;
    pool->used_count = 0;
    
    return 0;
}

/**
 * Cleanup node pool
 */
void ethudp_queue_node_pool_cleanup(ethudp_queue_node_pool_t *pool) {
    if (!pool) {
        return;
    }
    
    if (pool->free_nodes) {
        free(pool->free_nodes);
        pool->free_nodes = NULL;
    }
    
    pthread_mutex_destroy(&pool->pool_mutex);
    memset(pool, 0, sizeof(ethudp_queue_node_pool_t));
}

/**
 * Allocate node from pool
 */
ethudp_queue_node_t *ethudp_queue_node_pool_alloc(ethudp_queue_node_pool_t *pool) {
    if (!pool) {
        return NULL;
    }
    
    pthread_mutex_lock(&pool->pool_mutex);
    
    ethudp_queue_node_t *node = pool->free_nodes;
    if (node) {
        pool->free_nodes = node->next;
        pool->used_count++;
        memset(node, 0, sizeof(ethudp_queue_node_t));
        node->ref_count = 1;
    }
    
    pthread_mutex_unlock(&pool->pool_mutex);
    
    // If pool is empty, allocate new node
    if (!node) {
        node = calloc(1, sizeof(ethudp_queue_node_t));
        if (node) {
            node->ref_count = 1;
        }
    }
    
    return node;
}

/**
 * Return node to pool
 */
void ethudp_queue_node_pool_free(ethudp_queue_node_pool_t *pool, ethudp_queue_node_t *node) {
    if (!pool || !node) {
        return;
    }
    
    // Clean up node data
    if (node->item.data) {
        free(node->item.data);
        node->item.data = NULL;
    }
    
    pthread_mutex_lock(&pool->pool_mutex);
    
    if (pool->used_count > 0) {
        node->next = pool->free_nodes;
        pool->free_nodes = node;
        pool->used_count--;
    } else {
        // Pool is full, just free the node
        free(node);
    }
    
    pthread_mutex_unlock(&pool->pool_mutex);
}

/**
 * Initialize a lock-free queue
 */
int ethudp_queue_init(ethudp_queue_t *queue, size_t max_size, ethudp_queue_type_t type) {
    if (!queue || max_size == 0) {
        return -1;
    }
    
    memset(queue, 0, sizeof(ethudp_queue_t));
    
    // Initialize global node pool if not done
    if (!node_pool_initialized) {
        if (ethudp_queue_node_pool_init(&global_node_pool, max_size * 2) == 0) {
            node_pool_initialized = 1;
        }
    }
    
    // Create dummy head node
    ethudp_queue_node_t *dummy = ethudp_queue_node_pool_alloc(&global_node_pool);
    if (!dummy) {
        return -1;
    }
    
    dummy->next = NULL;
    queue->head = dummy;
    queue->tail = dummy;
    queue->max_size = max_size;
    queue->current_size = 0;
    queue->type = type;
    queue->closed = 0;
    
    if (pthread_mutex_init(&queue->size_mutex, NULL) != 0) {
        ethudp_queue_node_pool_free(&global_node_pool, dummy);
        return -1;
    }
    
    if (pthread_cond_init(&queue->not_empty, NULL) != 0) {
        pthread_mutex_destroy(&queue->size_mutex);
        ethudp_queue_node_pool_free(&global_node_pool, dummy);
        return -1;
    }
    
    if (pthread_cond_init(&queue->not_full, NULL) != 0) {
        pthread_mutex_destroy(&queue->size_mutex);
        pthread_cond_destroy(&queue->not_empty);
        ethudp_queue_node_pool_free(&global_node_pool, dummy);
        return -1;
    }
    
    return 0;
}

/**
 * Cleanup queue resources
 */
void ethudp_queue_cleanup(ethudp_queue_t *queue) {
    if (!queue) {
        return;
    }
    
    ethudp_queue_clear(queue);
    
    // Free dummy head node
    if (queue->head) {
        ethudp_queue_node_pool_free(&global_node_pool, (ethudp_queue_node_t *)queue->head);
    }
    
    pthread_mutex_destroy(&queue->size_mutex);
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
    
    memset(queue, 0, sizeof(ethudp_queue_t));
}

/**
 * Enqueue an item (non-blocking)
 */
int ethudp_queue_enqueue(ethudp_queue_t *queue, const ethudp_queue_item_t *item) {
    if (!queue || !item || queue->closed) {
        return -1;
    }
    
    pthread_mutex_lock(&queue->size_mutex);
    
    if (queue->current_size >= queue->max_size) {
        ATOMIC_INC(&queue->drop_count);
        pthread_mutex_unlock(&queue->size_mutex);
        return -2; // Queue full
    }
    
    pthread_mutex_unlock(&queue->size_mutex);
    
    // Allocate new node
    ethudp_queue_node_t *new_node = ethudp_queue_node_pool_alloc(&global_node_pool);
    if (!new_node) {
        ATOMIC_INC(&queue->drop_count);
        return -1;
    }
    
    // Copy item data
    if (ethudp_queue_item_clone(&new_node->item, item) != 0) {
        ethudp_queue_node_pool_free(&global_node_pool, new_node);
        ATOMIC_INC(&queue->drop_count);
        return -1;
    }
    
    new_node->next = NULL;
    
    // Lock-free enqueue
    while (1) {
        ethudp_queue_node_t *last = (ethudp_queue_node_t *)queue->tail;
        ethudp_queue_node_t *next = (ethudp_queue_node_t *)last->next;
        
        if (last == queue->tail) {
            if (next == NULL) {
                if (ATOMIC_CAS(&last->next, NULL, new_node)) {
                    break;
                }
            } else {
                ATOMIC_CAS(&queue->tail, last, next);
            }
        }
    }
    
    ATOMIC_CAS(&queue->tail, queue->tail, new_node);
    
    pthread_mutex_lock(&queue->size_mutex);
    queue->current_size++;
    ATOMIC_INC(&queue->enqueue_count);
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->size_mutex);
    
    return 0;
}

/**
 * Dequeue an item (non-blocking)
 */
int ethudp_queue_dequeue(ethudp_queue_t *queue, ethudp_queue_item_t *item) {
    if (!queue || !item) {
        return -1;
    }
    
    pthread_mutex_lock(&queue->size_mutex);
    
    if (queue->current_size == 0) {
        pthread_mutex_unlock(&queue->size_mutex);
        return -2; // Queue empty
    }
    
    pthread_mutex_unlock(&queue->size_mutex);
    
    // Lock-free dequeue
    while (1) {
        ethudp_queue_node_t *first = (ethudp_queue_node_t *)queue->head;
        ethudp_queue_node_t *last = (ethudp_queue_node_t *)queue->tail;
        ethudp_queue_node_t *next = (ethudp_queue_node_t *)first->next;
        
        if (first == queue->head) {
            if (first == last) {
                if (next == NULL) {
                    return -2; // Queue empty
                }
                ATOMIC_CAS(&queue->tail, last, next);
            } else {
                if (next == NULL) {
                    continue;
                }
                
                // Copy item data
                *item = next->item;
                
                if (ATOMIC_CAS(&queue->head, first, next)) {
                    ethudp_queue_node_pool_free(&global_node_pool, first);
                    break;
                }
            }
        }
    }
    
    pthread_mutex_lock(&queue->size_mutex);
    queue->current_size--;
    ATOMIC_INC(&queue->dequeue_count);
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->size_mutex);
    
    return 0;
}

/**
 * Enqueue an item with timeout
 */
int ethudp_queue_enqueue_timeout(ethudp_queue_t *queue, const ethudp_queue_item_t *item, 
                                int timeout_ms) {
    if (!queue || !item || queue->closed) {
        return -1;
    }
    
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += timeout_ms / 1000;
    timeout.tv_nsec += (timeout_ms % 1000) * 1000000;
    if (timeout.tv_nsec >= 1000000000) {
        timeout.tv_sec++;
        timeout.tv_nsec -= 1000000000;
    }
    
    pthread_mutex_lock(&queue->size_mutex);
    
    while (queue->current_size >= queue->max_size && !queue->closed) {
        int result = pthread_cond_timedwait(&queue->not_full, &queue->size_mutex, &timeout);
        if (result == ETIMEDOUT) {
            pthread_mutex_unlock(&queue->size_mutex);
            ATOMIC_INC(&queue->drop_count);
            return -3; // Timeout
        }
    }
    
    if (queue->closed) {
        pthread_mutex_unlock(&queue->size_mutex);
        return -1;
    }
    
    pthread_mutex_unlock(&queue->size_mutex);
    
    return ethudp_queue_enqueue(queue, item);
}

/**
 * Dequeue an item with timeout
 */
int ethudp_queue_dequeue_timeout(ethudp_queue_t *queue, ethudp_queue_item_t *item, 
                                int timeout_ms) {
    if (!queue || !item) {
        return -1;
    }
    
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += timeout_ms / 1000;
    timeout.tv_nsec += (timeout_ms % 1000) * 1000000;
    if (timeout.tv_nsec >= 1000000000) {
        timeout.tv_sec++;
        timeout.tv_nsec -= 1000000000;
    }
    
    pthread_mutex_lock(&queue->size_mutex);
    
    while (queue->current_size == 0 && !queue->closed) {
        int result = pthread_cond_timedwait(&queue->not_empty, &queue->size_mutex, &timeout);
        if (result == ETIMEDOUT) {
            pthread_mutex_unlock(&queue->size_mutex);
            return -3; // Timeout
        }
    }
    
    if (queue->closed && queue->current_size == 0) {
        pthread_mutex_unlock(&queue->size_mutex);
        return -1;
    }
    
    pthread_mutex_unlock(&queue->size_mutex);
    
    return ethudp_queue_dequeue(queue, item);
}

/**
 * Get current queue size
 */
size_t ethudp_queue_size(const ethudp_queue_t *queue) {
    if (!queue) {
        return 0;
    }
    
    return queue->current_size;
}

/**
 * Check if queue is empty
 */
int ethudp_queue_is_empty(const ethudp_queue_t *queue) {
    if (!queue) {
        return 1;
    }
    
    return (queue->current_size == 0);
}

/**
 * Check if queue is full
 */
int ethudp_queue_is_full(const ethudp_queue_t *queue) {
    if (!queue) {
        return 0;
    }
    
    return (queue->current_size >= queue->max_size);
}

/**
 * Clear all items from queue
 */
void ethudp_queue_clear(ethudp_queue_t *queue) {
    if (!queue) {
        return;
    }
    
    ethudp_queue_item_t item;
    while (ethudp_queue_dequeue(queue, &item) == 0) {
        ethudp_queue_item_destroy(&item);
    }
}

/**
 * Close queue
 */
void ethudp_queue_close(ethudp_queue_t *queue) {
    if (!queue) {
        return;
    }
    
    pthread_mutex_lock(&queue->size_mutex);
    queue->closed = 1;
    pthread_cond_broadcast(&queue->not_empty);
    pthread_cond_broadcast(&queue->not_full);
    pthread_mutex_unlock(&queue->size_mutex);
}

/**
 * Create a queue item
 */
int ethudp_queue_item_create(ethudp_queue_item_t *item, const uint8_t *data, 
                            size_t size, int priority, void *metadata) {
    if (!item || !data || size == 0) {
        return -1;
    }
    
    memset(item, 0, sizeof(ethudp_queue_item_t));
    
    item->data = malloc(size);
    if (!item->data) {
        return -1;
    }
    
    memcpy(item->data, data, size);
    item->size = size;
    item->priority = priority;
    item->metadata = metadata;
    item->timestamp = ethudp_get_current_time_us();
    
    return 0;
}

/**
 * Destroy a queue item
 */
void ethudp_queue_item_destroy(ethudp_queue_item_t *item) {
    if (!item) {
        return;
    }
    
    if (item->data) {
        free(item->data);
        item->data = NULL;
    }
    
    memset(item, 0, sizeof(ethudp_queue_item_t));
}

/**
 * Clone a queue item
 */
int ethudp_queue_item_clone(ethudp_queue_item_t *dest, const ethudp_queue_item_t *src) {
    if (!dest || !src) {
        return -1;
    }
    
    return ethudp_queue_item_create(dest, src->data, src->size, src->priority, src->metadata);
}

/**
 * Initialize queue manager
 */
int ethudp_queue_manager_init(ethudp_queue_manager_t *manager, size_t default_queue_size) {
    if (!manager || default_queue_size == 0) {
        return -1;
    }
    
    memset(manager, 0, sizeof(ethudp_queue_manager_t));
    
    manager->default_queue_size = default_queue_size;
    
    if (pthread_mutex_init(&manager->manager_mutex, NULL) != 0) {
        return -1;
    }
    
    // Initialize queues
    manager->udp_rx_queue = calloc(1, sizeof(ethudp_queue_t));
    manager->udp_tx_queue = calloc(1, sizeof(ethudp_queue_t));
    manager->raw_rx_queue = calloc(1, sizeof(ethudp_queue_t));
    manager->raw_tx_queue = calloc(1, sizeof(ethudp_queue_t));
    manager->control_queue = calloc(1, sizeof(ethudp_queue_t));
    
    if (!manager->udp_rx_queue || !manager->udp_tx_queue || 
        !manager->raw_rx_queue || !manager->raw_tx_queue || !manager->control_queue) {
        ethudp_queue_manager_cleanup(manager);
        return -1;
    }
    
    if (ethudp_queue_init(manager->udp_rx_queue, default_queue_size, QUEUE_TYPE_UDP_RX) != 0 ||
        ethudp_queue_init(manager->udp_tx_queue, default_queue_size, QUEUE_TYPE_UDP_TX) != 0 ||
        ethudp_queue_init(manager->raw_rx_queue, default_queue_size, QUEUE_TYPE_RAW_RX) != 0 ||
        ethudp_queue_init(manager->raw_tx_queue, default_queue_size, QUEUE_TYPE_RAW_TX) != 0 ||
        ethudp_queue_init(manager->control_queue, default_queue_size / 4, QUEUE_TYPE_CONTROL) != 0) {
        ethudp_queue_manager_cleanup(manager);
        return -1;
    }
    
    manager->initialized = 1;
    
    return 0;
}

/**
 * Cleanup queue manager
 */
void ethudp_queue_manager_cleanup(ethudp_queue_manager_t *manager) {
    if (!manager) {
        return;
    }
    
    if (manager->udp_rx_queue) {
        ethudp_queue_cleanup(manager->udp_rx_queue);
        free(manager->udp_rx_queue);
    }
    
    if (manager->udp_tx_queue) {
        ethudp_queue_cleanup(manager->udp_tx_queue);
        free(manager->udp_tx_queue);
    }
    
    if (manager->raw_rx_queue) {
        ethudp_queue_cleanup(manager->raw_rx_queue);
        free(manager->raw_rx_queue);
    }
    
    if (manager->raw_tx_queue) {
        ethudp_queue_cleanup(manager->raw_tx_queue);
        free(manager->raw_tx_queue);
    }
    
    if (manager->control_queue) {
        ethudp_queue_cleanup(manager->control_queue);
        free(manager->control_queue);
    }
    
    pthread_mutex_destroy(&manager->manager_mutex);
    
    memset(manager, 0, sizeof(ethudp_queue_manager_t));
}

/**
 * Get queue by type
 */
ethudp_queue_t *ethudp_queue_manager_get_queue(ethudp_queue_manager_t *manager, 
                                              ethudp_queue_type_t type) {
    if (!manager || !manager->initialized) {
        return NULL;
    }
    
    switch (type) {
        case QUEUE_TYPE_UDP_RX:
            return manager->udp_rx_queue;
        case QUEUE_TYPE_UDP_TX:
            return manager->udp_tx_queue;
        case QUEUE_TYPE_RAW_RX:
            return manager->raw_rx_queue;
        case QUEUE_TYPE_RAW_TX:
            return manager->raw_tx_queue;
        case QUEUE_TYPE_CONTROL:
            return manager->control_queue;
        default:
            return NULL;
    }
}

/**
 * Get queue type name
 */
const char *ethudp_queue_type_name(ethudp_queue_type_t type) {
    switch (type) {
        case QUEUE_TYPE_UDP_RX: return "UDP_RX";
        case QUEUE_TYPE_UDP_TX: return "UDP_TX";
        case QUEUE_TYPE_RAW_RX: return "RAW_RX";
        case QUEUE_TYPE_RAW_TX: return "RAW_TX";
        case QUEUE_TYPE_CONTROL: return "CONTROL";
        default: return "UNKNOWN";
    }
}

/**
 * Get queue statistics
 */
int ethudp_queue_get_stats(const ethudp_queue_t *queue, ethudp_queue_stats_t *stats) {
    if (!queue || !stats) {
        return -1;
    }
    
    memset(stats, 0, sizeof(ethudp_queue_stats_t));
    
    stats->enqueue_count = ATOMIC_LOAD_CONST(&queue->enqueue_count);
    stats->dequeue_count = ATOMIC_LOAD_CONST(&queue->dequeue_count);
    stats->drop_count = ATOMIC_LOAD_CONST(&queue->drop_count);
    stats->current_size = queue->current_size;
    stats->max_size = queue->max_size;
    
    // Calculate throughput (items per second)
    uint64_t total_items = stats->enqueue_count + stats->dequeue_count;
    if (total_items > 0) {
        stats->throughput = (double)total_items / 1.0; // Simplified calculation
    }
    
    return 0;
}

/**
 * Print queue manager status
 */
void ethudp_queue_manager_print_status(const ethudp_queue_manager_t *manager) {
    if (!manager || !manager->initialized) {
        printf("Queue manager not initialized\n");
        return;
    }
    
    printf("Queue Manager Status:\n");
    
    ethudp_queue_stats_t stats;
    
    if (ethudp_queue_get_stats(manager->udp_rx_queue, &stats) == 0) {
        printf("  UDP RX: Size=%lu/%lu, Enq=%lu, Deq=%lu, Drop=%lu\n",
               stats.current_size, stats.max_size, stats.enqueue_count, 
               stats.dequeue_count, stats.drop_count);
    }
    
    if (ethudp_queue_get_stats(manager->udp_tx_queue, &stats) == 0) {
        printf("  UDP TX: Size=%lu/%lu, Enq=%lu, Deq=%lu, Drop=%lu\n",
               stats.current_size, stats.max_size, stats.enqueue_count, 
               stats.dequeue_count, stats.drop_count);
    }
    
    if (ethudp_queue_get_stats(manager->raw_rx_queue, &stats) == 0) {
        printf("  RAW RX: Size=%lu/%lu, Enq=%lu, Deq=%lu, Drop=%lu\n",
               stats.current_size, stats.max_size, stats.enqueue_count, 
               stats.dequeue_count, stats.drop_count);
    }
    
    if (ethudp_queue_get_stats(manager->raw_tx_queue, &stats) == 0) {
        printf("  RAW TX: Size=%lu/%lu, Enq=%lu, Deq=%lu, Drop=%lu\n",
               stats.current_size, stats.max_size, stats.enqueue_count, 
               stats.dequeue_count, stats.drop_count);
    }
    
    if (ethudp_queue_get_stats(manager->control_queue, &stats) == 0) {
        printf("  CONTROL: Size=%lu/%lu, Enq=%lu, Deq=%lu, Drop=%lu\n",
               stats.current_size, stats.max_size, stats.enqueue_count, 
               stats.dequeue_count, stats.drop_count);
    }
}