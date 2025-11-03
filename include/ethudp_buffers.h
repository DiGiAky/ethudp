#ifndef ETHUDP_BUFFERS_H
#define ETHUDP_BUFFERS_H

#include "ethudp_common.h"
#include "ethudp_types.h"

// Buffer pool configuration
#define ETHUDP_BUFFER_POOL_MIN_SIZE     64
#define ETHUDP_BUFFER_POOL_MAX_SIZE     65536
#define ETHUDP_BUFFER_POOL_DEFAULT_SIZE 1024
#define ETHUDP_BUFFER_ALIGNMENT         64

// Buffer types
typedef enum {
    BUFFER_TYPE_PACKET = 0,
    BUFFER_TYPE_CONTROL,
    BUFFER_TYPE_TEMP,
    BUFFER_TYPE_MAX
} ethudp_buffer_type_t;

// Buffer states
typedef enum {
    BUFFER_STATE_FREE = 0,
    BUFFER_STATE_ALLOCATED,
    BUFFER_STATE_IN_USE,
    BUFFER_STATE_CORRUPTED
} ethudp_buffer_state_t;

// Buffer structure
typedef struct ethudp_buffer {
    uint8_t *data;                    // Buffer data
    size_t size;                      // Buffer size
    size_t capacity;                  // Buffer capacity
    size_t used;                      // Used bytes
    ethudp_buffer_type_t type;        // Buffer type
    ethudp_buffer_state_t state;      // Buffer state
    uint32_t magic;                   // Magic number for corruption detection
    uint64_t alloc_time;              // Allocation timestamp
    uint64_t last_access;             // Last access timestamp
    int ref_count;                    // Reference count
    struct ethudp_buffer *next;       // Next buffer in pool
    void *metadata;                   // Optional metadata
} ethudp_buffer_t;

// Buffer pool statistics
typedef struct {
    size_t total_buffers;             // Total buffers in pool
    size_t free_buffers;              // Free buffers
    size_t allocated_buffers;         // Allocated buffers
    size_t peak_allocated;            // Peak allocation count
    uint64_t alloc_count;             // Total allocations
    uint64_t free_count;              // Total frees
    uint64_t alloc_failures;          // Allocation failures
    uint64_t corruption_detected;     // Corruption detections
    double avg_alloc_time_us;         // Average allocation time
    double avg_free_time_us;          // Average free time
} ethudp_buffer_pool_stats_t;

// Buffer pool structure
typedef struct {
    ethudp_buffer_t *free_list;       // Free buffer list
    ethudp_buffer_t *all_buffers;     // All buffers array
    size_t buffer_size;               // Size of each buffer
    size_t pool_size;                 // Number of buffers in pool
    size_t free_count;                // Number of free buffers
    size_t allocated_count;           // Number of allocated buffers
    ethudp_buffer_type_t type;        // Pool type
    pthread_mutex_t pool_mutex;       // Pool mutex
    pthread_cond_t buffer_available;  // Buffer available condition
    ethudp_buffer_pool_stats_t stats; // Pool statistics
    int initialized;                  // Initialization flag
    uint32_t magic;                   // Pool magic number
} ethudp_buffer_pool_t;

// Buffer manager structure
typedef struct {
    ethudp_buffer_pool_t *packet_pool;    // Packet buffer pool
    ethudp_buffer_pool_t *control_pool;   // Control buffer pool
    ethudp_buffer_pool_t *temp_pool;      // Temporary buffer pool
    pthread_mutex_t manager_mutex;        // Manager mutex
    int initialized;                      // Initialization flag
    size_t default_packet_size;           // Default packet buffer size
    size_t default_control_size;          // Default control buffer size
    size_t default_temp_size;             // Default temp buffer size
} ethudp_buffer_manager_t;

// Buffer pool functions
int ethudp_buffer_pool_init(ethudp_buffer_pool_t *pool, size_t buffer_size, 
                           size_t pool_size, ethudp_buffer_type_t type);
void ethudp_buffer_pool_cleanup(ethudp_buffer_pool_t *pool);
ethudp_buffer_t *ethudp_buffer_pool_alloc(ethudp_buffer_pool_t *pool);
ethudp_buffer_t *ethudp_buffer_pool_alloc_timeout(ethudp_buffer_pool_t *pool, int timeout_ms);
int ethudp_buffer_pool_free(ethudp_buffer_pool_t *pool, ethudp_buffer_t *buffer);
int ethudp_buffer_pool_resize(ethudp_buffer_pool_t *pool, size_t new_size);
int ethudp_buffer_pool_get_stats(const ethudp_buffer_pool_t *pool, 
                                ethudp_buffer_pool_stats_t *stats);
void ethudp_buffer_pool_print_stats(const ethudp_buffer_pool_t *pool);

// Buffer functions
int ethudp_buffer_init(ethudp_buffer_t *buffer, size_t size, ethudp_buffer_type_t type);
void ethudp_buffer_cleanup(ethudp_buffer_t *buffer);
int ethudp_buffer_resize(ethudp_buffer_t *buffer, size_t new_size);
int ethudp_buffer_append(ethudp_buffer_t *buffer, const uint8_t *data, size_t size);
int ethudp_buffer_prepend(ethudp_buffer_t *buffer, const uint8_t *data, size_t size);
int ethudp_buffer_insert(ethudp_buffer_t *buffer, size_t offset, 
                        const uint8_t *data, size_t size);
int ethudp_buffer_remove(ethudp_buffer_t *buffer, size_t offset, size_t size);
void ethudp_buffer_clear(ethudp_buffer_t *buffer);
int ethudp_buffer_copy(ethudp_buffer_t *dest, const ethudp_buffer_t *src);
int ethudp_buffer_clone(ethudp_buffer_t **dest, const ethudp_buffer_t *src);
int ethudp_buffer_compare(const ethudp_buffer_t *buf1, const ethudp_buffer_t *buf2);
int ethudp_buffer_validate(const ethudp_buffer_t *buffer);
void ethudp_buffer_ref(ethudp_buffer_t *buffer);
void ethudp_buffer_unref(ethudp_buffer_t *buffer);

// Buffer data access functions
uint8_t *ethudp_buffer_get_data(const ethudp_buffer_t *buffer);
size_t ethudp_buffer_get_size(const ethudp_buffer_t *buffer);
size_t ethudp_buffer_get_capacity(const ethudp_buffer_t *buffer);
size_t ethudp_buffer_get_free_space(const ethudp_buffer_t *buffer);
int ethudp_buffer_is_empty(const ethudp_buffer_t *buffer);
int ethudp_buffer_is_full(const ethudp_buffer_t *buffer);

// Buffer manager functions
int ethudp_buffer_manager_init(ethudp_buffer_manager_t *manager,
                              size_t packet_size, size_t packet_count,
                              size_t control_size, size_t control_count,
                              size_t temp_size, size_t temp_count);
void ethudp_buffer_manager_cleanup(ethudp_buffer_manager_t *manager);
ethudp_buffer_t *ethudp_buffer_manager_alloc(ethudp_buffer_manager_t *manager,
                                            ethudp_buffer_type_t type);
ethudp_buffer_t *ethudp_buffer_manager_alloc_timeout(ethudp_buffer_manager_t *manager,
                                                    ethudp_buffer_type_t type, int timeout_ms);
int ethudp_buffer_manager_free(ethudp_buffer_manager_t *manager, ethudp_buffer_t *buffer);
ethudp_buffer_pool_t *ethudp_buffer_manager_get_pool(ethudp_buffer_manager_t *manager,
                                                     ethudp_buffer_type_t type);
void ethudp_buffer_manager_print_status(const ethudp_buffer_manager_t *manager);

// Utility functions
const char *ethudp_buffer_type_name(ethudp_buffer_type_t type);
const char *ethudp_buffer_state_name(ethudp_buffer_state_t state);
size_t ethudp_buffer_align_size(size_t size);
int ethudp_buffer_check_corruption(const ethudp_buffer_t *buffer);

// Memory alignment helpers
void *ethudp_aligned_alloc(size_t alignment, size_t size);
void ethudp_aligned_free(void *ptr);

#endif // ETHUDP_BUFFERS_H