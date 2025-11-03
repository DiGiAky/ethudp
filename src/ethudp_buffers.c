#include "../include/ethudp_common.h"
#include "../include/ethudp_types.h"
#include "../include/ethudp_buffers.h"
#include "../include/ethudp_utils.h"

// Buffer magic numbers for corruption detection
#define ETHUDP_BUFFER_MAGIC      0xDEADBEEF
#define ETHUDP_POOL_MAGIC        0xCAFEBABE
#define ETHUDP_BUFFER_GUARD      0x5A5A5A5A

// Atomic operations
#ifdef __GNUC__
#define ATOMIC_INC(ptr) __sync_fetch_and_add(ptr, 1)
#define ATOMIC_DEC(ptr) __sync_fetch_and_sub(ptr, 1)
#define ATOMIC_LOAD(ptr) __sync_fetch_and_add(ptr, 0)
#else
#define ATOMIC_INC(ptr) (++(*ptr))
#define ATOMIC_DEC(ptr) (--(*ptr))
#define ATOMIC_LOAD(ptr) (*ptr)
#endif

/**
 * Align size to specified boundary
 */
size_t ethudp_buffer_align_size(size_t size) {
    return (size + ETHUDP_BUFFER_ALIGNMENT - 1) & ~(ETHUDP_BUFFER_ALIGNMENT - 1);
}

/**
 * Aligned memory allocation
 */
void *ethudp_aligned_alloc(size_t alignment, size_t size) {
    void *ptr = NULL;
    
#ifdef _WIN32
    ptr = _aligned_malloc(size, alignment);
#else
    if (posix_memalign(&ptr, alignment, size) != 0) {
        ptr = NULL;
    }
#endif
    
    return ptr;
}

/**
 * Aligned memory free
 */
void ethudp_aligned_free(void *ptr) {
    if (!ptr) {
        return;
    }
    
#ifdef _WIN32
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

/**
 * Initialize a buffer
 */
int ethudp_buffer_init(ethudp_buffer_t *buffer, size_t size, ethudp_buffer_type_t type) {
    if (!buffer || size == 0) {
        return -1;
    }
    
    memset(buffer, 0, sizeof(ethudp_buffer_t));
    
    size_t aligned_size = ethudp_buffer_align_size(size);
    buffer->data = ethudp_aligned_alloc(ETHUDP_BUFFER_ALIGNMENT, aligned_size);
    if (!buffer->data) {
        return -1;
    }
    
    buffer->capacity = aligned_size;
    buffer->size = 0;
    buffer->used = 0;
    buffer->type = type;
    buffer->state = BUFFER_STATE_FREE;
    buffer->magic = ETHUDP_BUFFER_MAGIC;
    buffer->alloc_time = ethudp_get_current_time_us();
    buffer->last_access = buffer->alloc_time;
    buffer->ref_count = 1;
    buffer->next = NULL;
    buffer->metadata = NULL;
    
    return 0;
}

/**
 * Cleanup buffer
 */
void ethudp_buffer_cleanup(ethudp_buffer_t *buffer) {
    if (!buffer) {
        return;
    }
    
    if (buffer->data) {
        ethudp_aligned_free(buffer->data);
        buffer->data = NULL;
    }
    
    buffer->magic = 0;
    memset(buffer, 0, sizeof(ethudp_buffer_t));
}

/**
 * Check buffer corruption
 */
int ethudp_buffer_check_corruption(const ethudp_buffer_t *buffer) {
    if (!buffer) {
        return -1;
    }
    
    if (buffer->magic != ETHUDP_BUFFER_MAGIC) {
        return -1; // Corrupted
    }
    
    if (buffer->size > buffer->capacity) {
        return -1; // Size corruption
    }
    
    if (buffer->used > buffer->size) {
        return -1; // Used corruption
    }
    
    return 0; // OK
}

/**
 * Validate buffer
 */
int ethudp_buffer_validate(const ethudp_buffer_t *buffer) {
    if (!buffer || !buffer->data) {
        return -1;
    }
    
    return ethudp_buffer_check_corruption(buffer);
}

/**
 * Resize buffer
 */
int ethudp_buffer_resize(ethudp_buffer_t *buffer, size_t new_size) {
    if (!buffer || ethudp_buffer_validate(buffer) != 0) {
        return -1;
    }
    
    if (new_size <= buffer->capacity) {
        buffer->size = new_size;
        if (buffer->used > new_size) {
            buffer->used = new_size;
        }
        return 0;
    }
    
    size_t aligned_size = ethudp_buffer_align_size(new_size);
    uint8_t *new_data = ethudp_aligned_alloc(ETHUDP_BUFFER_ALIGNMENT, aligned_size);
    if (!new_data) {
        return -1;
    }
    
    if (buffer->used > 0) {
        memcpy(new_data, buffer->data, buffer->used);
    }
    
    ethudp_aligned_free(buffer->data);
    buffer->data = new_data;
    buffer->capacity = aligned_size;
    buffer->size = new_size;
    buffer->last_access = ethudp_get_current_time_us();
    
    return 0;
}

/**
 * Append data to buffer
 */
int ethudp_buffer_append(ethudp_buffer_t *buffer, const uint8_t *data, size_t size) {
    if (!buffer || !data || size == 0 || ethudp_buffer_validate(buffer) != 0) {
        return -1;
    }
    
    if (buffer->used + size > buffer->capacity) {
        if (ethudp_buffer_resize(buffer, buffer->used + size) != 0) {
            return -1;
        }
    }
    
    memcpy(buffer->data + buffer->used, data, size);
    buffer->used += size;
    if (buffer->used > buffer->size) {
        buffer->size = buffer->used;
    }
    buffer->last_access = ethudp_get_current_time_us();
    
    return 0;
}

/**
 * Prepend data to buffer
 */
int ethudp_buffer_prepend(ethudp_buffer_t *buffer, const uint8_t *data, size_t size) {
    if (!buffer || !data || size == 0 || ethudp_buffer_validate(buffer) != 0) {
        return -1;
    }
    
    if (buffer->used + size > buffer->capacity) {
        if (ethudp_buffer_resize(buffer, buffer->used + size) != 0) {
            return -1;
        }
    }
    
    if (buffer->used > 0) {
        memmove(buffer->data + size, buffer->data, buffer->used);
    }
    
    memcpy(buffer->data, data, size);
    buffer->used += size;
    if (buffer->used > buffer->size) {
        buffer->size = buffer->used;
    }
    buffer->last_access = ethudp_get_current_time_us();
    
    return 0;
}

/**
 * Insert data at offset
 */
int ethudp_buffer_insert(ethudp_buffer_t *buffer, size_t offset, 
                        const uint8_t *data, size_t size) {
    if (!buffer || !data || size == 0 || ethudp_buffer_validate(buffer) != 0) {
        return -1;
    }
    
    if (offset > buffer->used) {
        return -1;
    }
    
    if (buffer->used + size > buffer->capacity) {
        if (ethudp_buffer_resize(buffer, buffer->used + size) != 0) {
            return -1;
        }
    }
    
    if (offset < buffer->used) {
        memmove(buffer->data + offset + size, buffer->data + offset, 
                buffer->used - offset);
    }
    
    memcpy(buffer->data + offset, data, size);
    buffer->used += size;
    if (buffer->used > buffer->size) {
        buffer->size = buffer->used;
    }
    buffer->last_access = ethudp_get_current_time_us();
    
    return 0;
}

/**
 * Remove data from buffer
 */
int ethudp_buffer_remove(ethudp_buffer_t *buffer, size_t offset, size_t size) {
    if (!buffer || ethudp_buffer_validate(buffer) != 0) {
        return -1;
    }
    
    if (offset >= buffer->used || size == 0) {
        return -1;
    }
    
    if (offset + size > buffer->used) {
        size = buffer->used - offset;
    }
    
    if (offset + size < buffer->used) {
        memmove(buffer->data + offset, buffer->data + offset + size,
                buffer->used - offset - size);
    }
    
    buffer->used -= size;
    buffer->last_access = ethudp_get_current_time_us();
    
    return 0;
}

/**
 * Clear buffer
 */
void ethudp_buffer_clear(ethudp_buffer_t *buffer) {
    if (!buffer) {
        return;
    }
    
    buffer->used = 0;
    buffer->size = 0;
    buffer->last_access = ethudp_get_current_time_us();
}

/**
 * Copy buffer
 */
int ethudp_buffer_copy(ethudp_buffer_t *dest, const ethudp_buffer_t *src) {
    if (!dest || !src || ethudp_buffer_validate(src) != 0) {
        return -1;
    }
    
    if (dest->capacity < src->used) {
        if (ethudp_buffer_resize(dest, src->used) != 0) {
            return -1;
        }
    }
    
    memcpy(dest->data, src->data, src->used);
    dest->used = src->used;
    dest->size = src->size;
    dest->type = src->type;
    dest->last_access = ethudp_get_current_time_us();
    
    return 0;
}

/**
 * Clone buffer
 */
int ethudp_buffer_clone(ethudp_buffer_t **dest, const ethudp_buffer_t *src) {
    if (!dest || !src || ethudp_buffer_validate(src) != 0) {
        return -1;
    }
    
    *dest = calloc(1, sizeof(ethudp_buffer_t));
    if (!*dest) {
        return -1;
    }
    
    if (ethudp_buffer_init(*dest, src->capacity, src->type) != 0) {
        free(*dest);
        *dest = NULL;
        return -1;
    }
    
    if (ethudp_buffer_copy(*dest, src) != 0) {
        ethudp_buffer_cleanup(*dest);
        free(*dest);
        *dest = NULL;
        return -1;
    }
    
    return 0;
}

/**
 * Compare buffers
 */
int ethudp_buffer_compare(const ethudp_buffer_t *buf1, const ethudp_buffer_t *buf2) {
    if (!buf1 || !buf2) {
        return -1;
    }
    
    if (ethudp_buffer_validate(buf1) != 0 || ethudp_buffer_validate(buf2) != 0) {
        return -1;
    }
    
    if (buf1->used != buf2->used) {
        return (buf1->used < buf2->used) ? -1 : 1;
    }
    
    return memcmp(buf1->data, buf2->data, buf1->used);
}

/**
 * Reference buffer
 */
void ethudp_buffer_ref(ethudp_buffer_t *buffer) {
    if (!buffer) {
        return;
    }
    
    ATOMIC_INC(&buffer->ref_count);
}

/**
 * Unreference buffer
 */
void ethudp_buffer_unref(ethudp_buffer_t *buffer) {
    if (!buffer) {
        return;
    }
    
    if (ATOMIC_DEC(&buffer->ref_count) == 1) {
        ethudp_buffer_cleanup(buffer);
    }
}

/**
 * Get buffer data
 */
uint8_t *ethudp_buffer_get_data(const ethudp_buffer_t *buffer) {
    if (!buffer || ethudp_buffer_validate(buffer) != 0) {
        return NULL;
    }
    
    return buffer->data;
}

/**
 * Get buffer size
 */
size_t ethudp_buffer_get_size(const ethudp_buffer_t *buffer) {
    if (!buffer) {
        return 0;
    }
    
    return buffer->used;
}

/**
 * Get buffer capacity
 */
size_t ethudp_buffer_get_capacity(const ethudp_buffer_t *buffer) {
    if (!buffer) {
        return 0;
    }
    
    return buffer->capacity;
}

/**
 * Get free space
 */
size_t ethudp_buffer_get_free_space(const ethudp_buffer_t *buffer) {
    if (!buffer) {
        return 0;
    }
    
    return buffer->capacity - buffer->used;
}

/**
 * Check if buffer is empty
 */
int ethudp_buffer_is_empty(const ethudp_buffer_t *buffer) {
    if (!buffer) {
        return 1;
    }
    
    return (buffer->used == 0);
}

/**
 * Check if buffer is full
 */
int ethudp_buffer_is_full(const ethudp_buffer_t *buffer) {
    if (!buffer) {
        return 0;
    }
    
    return (buffer->used >= buffer->capacity);
}

/**
 * Initialize buffer pool
 */
int ethudp_buffer_pool_init(ethudp_buffer_pool_t *pool, size_t buffer_size, 
                           size_t pool_size, ethudp_buffer_type_t type) {
    if (!pool || buffer_size == 0 || pool_size == 0) {
        return -1;
    }
    
    memset(pool, 0, sizeof(ethudp_buffer_pool_t));
    
    pool->buffer_size = ethudp_buffer_align_size(buffer_size);
    pool->pool_size = pool_size;
    pool->type = type;
    pool->magic = ETHUDP_POOL_MAGIC;
    
    if (pthread_mutex_init(&pool->pool_mutex, NULL) != 0) {
        return -1;
    }
    
    if (pthread_cond_init(&pool->buffer_available, NULL) != 0) {
        pthread_mutex_destroy(&pool->pool_mutex);
        return -1;
    }
    
    // Allocate buffer array
    pool->all_buffers = calloc(pool_size, sizeof(ethudp_buffer_t));
    if (!pool->all_buffers) {
        pthread_mutex_destroy(&pool->pool_mutex);
        pthread_cond_destroy(&pool->buffer_available);
        return -1;
    }
    
    // Initialize buffers and link them
    for (size_t i = 0; i < pool_size; i++) {
        if (ethudp_buffer_init(&pool->all_buffers[i], buffer_size, type) != 0) {
            // Cleanup already initialized buffers
            for (size_t j = 0; j < i; j++) {
                ethudp_buffer_cleanup(&pool->all_buffers[j]);
            }
            free(pool->all_buffers);
            pthread_mutex_destroy(&pool->pool_mutex);
            pthread_cond_destroy(&pool->buffer_available);
            return -1;
        }
        
        pool->all_buffers[i].state = BUFFER_STATE_FREE;
        
        if (i < pool_size - 1) {
            pool->all_buffers[i].next = &pool->all_buffers[i + 1];
        } else {
            pool->all_buffers[i].next = NULL;
        }
    }
    
    pool->free_list = &pool->all_buffers[0];
    pool->free_count = pool_size;
    pool->allocated_count = 0;
    pool->initialized = 1;
    
    return 0;
}

/**
 * Cleanup buffer pool
 */
void ethudp_buffer_pool_cleanup(ethudp_buffer_pool_t *pool) {
    if (!pool || !pool->initialized) {
        return;
    }
    
    pthread_mutex_lock(&pool->pool_mutex);
    
    if (pool->all_buffers) {
        for (size_t i = 0; i < pool->pool_size; i++) {
            ethudp_buffer_cleanup(&pool->all_buffers[i]);
        }
        free(pool->all_buffers);
        pool->all_buffers = NULL;
    }
    
    pool->initialized = 0;
    pool->magic = 0;
    
    pthread_mutex_unlock(&pool->pool_mutex);
    
    pthread_mutex_destroy(&pool->pool_mutex);
    pthread_cond_destroy(&pool->buffer_available);
    
    memset(pool, 0, sizeof(ethudp_buffer_pool_t));
}

/**
 * Allocate buffer from pool
 */
ethudp_buffer_t *ethudp_buffer_pool_alloc(ethudp_buffer_pool_t *pool) {
    if (!pool || !pool->initialized || pool->magic != ETHUDP_POOL_MAGIC) {
        return NULL;
    }
    
    pthread_mutex_lock(&pool->pool_mutex);
    
    ethudp_buffer_t *buffer = pool->free_list;
    if (buffer) {
        pool->free_list = buffer->next;
        buffer->next = NULL;
        buffer->state = BUFFER_STATE_ALLOCATED;
        buffer->alloc_time = ethudp_get_current_time_us();
        buffer->last_access = buffer->alloc_time;
        buffer->ref_count = 1;
        
        pool->free_count--;
        pool->allocated_count++;
        
        if (pool->allocated_count > pool->stats.peak_allocated) {
            pool->stats.peak_allocated = pool->allocated_count;
        }
        
        pool->stats.alloc_count++;
    } else {
        pool->stats.alloc_failures++;
    }
    
    pthread_mutex_unlock(&pool->pool_mutex);
    
    return buffer;
}

/**
 * Allocate buffer with timeout
 */
ethudp_buffer_t *ethudp_buffer_pool_alloc_timeout(ethudp_buffer_pool_t *pool, int timeout_ms) {
    if (!pool || !pool->initialized || pool->magic != ETHUDP_POOL_MAGIC) {
        return NULL;
    }
    
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += timeout_ms / 1000;
    timeout.tv_nsec += (timeout_ms % 1000) * 1000000;
    if (timeout.tv_nsec >= 1000000000) {
        timeout.tv_sec++;
        timeout.tv_nsec -= 1000000000;
    }
    
    pthread_mutex_lock(&pool->pool_mutex);
    
    while (pool->free_count == 0) {
        int result = pthread_cond_timedwait(&pool->buffer_available, 
                                          &pool->pool_mutex, &timeout);
        if (result == ETIMEDOUT) {
            pthread_mutex_unlock(&pool->pool_mutex);
            pool->stats.alloc_failures++;
            return NULL;
        }
    }
    
    ethudp_buffer_t *buffer = ethudp_buffer_pool_alloc(pool);
    
    pthread_mutex_unlock(&pool->pool_mutex);
    
    return buffer;
}

/**
 * Free buffer to pool
 */
int ethudp_buffer_pool_free(ethudp_buffer_pool_t *pool, ethudp_buffer_t *buffer) {
    if (!pool || !buffer || !pool->initialized || pool->magic != ETHUDP_POOL_MAGIC) {
        return -1;
    }
    
    if (ethudp_buffer_validate(buffer) != 0) {
        pool->stats.corruption_detected++;
        return -1;
    }
    
    pthread_mutex_lock(&pool->pool_mutex);
    
    // Clear buffer data
    ethudp_buffer_clear(buffer);
    buffer->state = BUFFER_STATE_FREE;
    buffer->ref_count = 0;
    
    // Add to free list
    buffer->next = pool->free_list;
    pool->free_list = buffer;
    
    pool->free_count++;
    pool->allocated_count--;
    pool->stats.free_count++;
    
    pthread_cond_signal(&pool->buffer_available);
    pthread_mutex_unlock(&pool->pool_mutex);
    
    return 0;
}

/**
 * Get pool statistics
 */
int ethudp_buffer_pool_get_stats(const ethudp_buffer_pool_t *pool, 
                                ethudp_buffer_pool_stats_t *stats) {
    if (!pool || !stats || !pool->initialized) {
        return -1;
    }
    
    pthread_mutex_lock((pthread_mutex_t *)&pool->pool_mutex);
    
    stats->total_buffers = pool->pool_size;
    stats->free_buffers = pool->free_count;
    stats->allocated_buffers = pool->allocated_count;
    stats->peak_allocated = pool->stats.peak_allocated;
    stats->alloc_count = pool->stats.alloc_count;
    stats->free_count = pool->stats.free_count;
    stats->alloc_failures = pool->stats.alloc_failures;
    stats->corruption_detected = pool->stats.corruption_detected;
    
    // Calculate average times (simplified)
    stats->avg_alloc_time_us = 1.0;
    stats->avg_free_time_us = 1.0;
    
    pthread_mutex_unlock((pthread_mutex_t *)&pool->pool_mutex);
    
    return 0;
}

/**
 * Print pool statistics
 */
void ethudp_buffer_pool_print_stats(const ethudp_buffer_pool_t *pool) {
    if (!pool || !pool->initialized) {
        printf("Buffer pool not initialized\n");
        return;
    }
    
    ethudp_buffer_pool_stats_t stats;
    if (ethudp_buffer_pool_get_stats(pool, &stats) != 0) {
        printf("Failed to get pool statistics\n");
        return;
    }
    
    printf("Buffer Pool Statistics (%s):\n", ethudp_buffer_type_name(pool->type));
    printf("  Total Buffers: %lu\n", stats.total_buffers);
    printf("  Free Buffers: %lu\n", stats.free_buffers);
    printf("  Allocated Buffers: %lu\n", stats.allocated_buffers);
    printf("  Peak Allocated: %lu\n", stats.peak_allocated);
    printf("  Total Allocations: %lu\n", stats.alloc_count);
    printf("  Total Frees: %lu\n", stats.free_count);
    printf("  Allocation Failures: %lu\n", stats.alloc_failures);
    printf("  Corruption Detected: %lu\n", stats.corruption_detected);
    printf("  Buffer Size: %lu bytes\n", pool->buffer_size);
}

/**
 * Initialize buffer manager
 */
int ethudp_buffer_manager_init(ethudp_buffer_manager_t *manager,
                              size_t packet_size, size_t packet_count,
                              size_t control_size, size_t control_count,
                              size_t temp_size, size_t temp_count) {
    if (!manager || packet_count == 0 || control_count == 0 || temp_count == 0) {
        return -1;
    }
    
    memset(manager, 0, sizeof(ethudp_buffer_manager_t));
    
    if (pthread_mutex_init(&manager->manager_mutex, NULL) != 0) {
        return -1;
    }
    
    manager->default_packet_size = packet_size;
    manager->default_control_size = control_size;
    manager->default_temp_size = temp_size;
    
    // Initialize pools
    manager->packet_pool = calloc(1, sizeof(ethudp_buffer_pool_t));
    manager->control_pool = calloc(1, sizeof(ethudp_buffer_pool_t));
    manager->temp_pool = calloc(1, sizeof(ethudp_buffer_pool_t));
    
    if (!manager->packet_pool || !manager->control_pool || !manager->temp_pool) {
        ethudp_buffer_manager_cleanup(manager);
        return -1;
    }
    
    if (ethudp_buffer_pool_init(manager->packet_pool, packet_size, packet_count, 
                               BUFFER_TYPE_PACKET) != 0 ||
        ethudp_buffer_pool_init(manager->control_pool, control_size, control_count, 
                               BUFFER_TYPE_CONTROL) != 0 ||
        ethudp_buffer_pool_init(manager->temp_pool, temp_size, temp_count, 
                               BUFFER_TYPE_TEMP) != 0) {
        ethudp_buffer_manager_cleanup(manager);
        return -1;
    }
    
    manager->initialized = 1;
    
    return 0;
}

/**
 * Cleanup buffer manager
 */
void ethudp_buffer_manager_cleanup(ethudp_buffer_manager_t *manager) {
    if (!manager) {
        return;
    }
    
    if (manager->packet_pool) {
        ethudp_buffer_pool_cleanup(manager->packet_pool);
        free(manager->packet_pool);
    }
    
    if (manager->control_pool) {
        ethudp_buffer_pool_cleanup(manager->control_pool);
        free(manager->control_pool);
    }
    
    if (manager->temp_pool) {
        ethudp_buffer_pool_cleanup(manager->temp_pool);
        free(manager->temp_pool);
    }
    
    pthread_mutex_destroy(&manager->manager_mutex);
    
    memset(manager, 0, sizeof(ethudp_buffer_manager_t));
}

/**
 * Allocate buffer from manager
 */
ethudp_buffer_t *ethudp_buffer_manager_alloc(ethudp_buffer_manager_t *manager,
                                            ethudp_buffer_type_t type) {
    if (!manager || !manager->initialized) {
        return NULL;
    }
    
    ethudp_buffer_pool_t *pool = ethudp_buffer_manager_get_pool(manager, type);
    if (!pool) {
        return NULL;
    }
    
    return ethudp_buffer_pool_alloc(pool);
}

/**
 * Allocate buffer with timeout
 */
ethudp_buffer_t *ethudp_buffer_manager_alloc_timeout(ethudp_buffer_manager_t *manager,
                                                    ethudp_buffer_type_t type, int timeout_ms) {
    if (!manager || !manager->initialized) {
        return NULL;
    }
    
    ethudp_buffer_pool_t *pool = ethudp_buffer_manager_get_pool(manager, type);
    if (!pool) {
        return NULL;
    }
    
    return ethudp_buffer_pool_alloc_timeout(pool, timeout_ms);
}

/**
 * Free buffer to manager
 */
int ethudp_buffer_manager_free(ethudp_buffer_manager_t *manager, ethudp_buffer_t *buffer) {
    if (!manager || !buffer || !manager->initialized) {
        return -1;
    }
    
    ethudp_buffer_pool_t *pool = ethudp_buffer_manager_get_pool(manager, buffer->type);
    if (!pool) {
        return -1;
    }
    
    return ethudp_buffer_pool_free(pool, buffer);
}

/**
 * Get pool by type
 */
ethudp_buffer_pool_t *ethudp_buffer_manager_get_pool(ethudp_buffer_manager_t *manager,
                                                     ethudp_buffer_type_t type) {
    if (!manager || !manager->initialized) {
        return NULL;
    }
    
    switch (type) {
        case BUFFER_TYPE_PACKET:
            return manager->packet_pool;
        case BUFFER_TYPE_CONTROL:
            return manager->control_pool;
        case BUFFER_TYPE_TEMP:
            return manager->temp_pool;
        default:
            return NULL;
    }
}

/**
 * Print manager status
 */
void ethudp_buffer_manager_print_status(const ethudp_buffer_manager_t *manager) {
    if (!manager || !manager->initialized) {
        printf("Buffer manager not initialized\n");
        return;
    }
    
    printf("Buffer Manager Status:\n");
    
    if (manager->packet_pool) {
        ethudp_buffer_pool_print_stats(manager->packet_pool);
    }
    
    if (manager->control_pool) {
        ethudp_buffer_pool_print_stats(manager->control_pool);
    }
    
    if (manager->temp_pool) {
        ethudp_buffer_pool_print_stats(manager->temp_pool);
    }
}

/**
 * Get buffer type name
 */
const char *ethudp_buffer_type_name(ethudp_buffer_type_t type) {
    switch (type) {
        case BUFFER_TYPE_PACKET: return "PACKET";
        case BUFFER_TYPE_CONTROL: return "CONTROL";
        case BUFFER_TYPE_TEMP: return "TEMP";
        default: return "UNKNOWN";
    }
}

/**
 * Get buffer state name
 */
const char *ethudp_buffer_state_name(ethudp_buffer_state_t state) {
    switch (state) {
        case BUFFER_STATE_FREE: return "FREE";
        case BUFFER_STATE_ALLOCATED: return "ALLOCATED";
        case BUFFER_STATE_IN_USE: return "IN_USE";
        case BUFFER_STATE_CORRUPTED: return "CORRUPTED";
        default: return "UNKNOWN";
    }
}