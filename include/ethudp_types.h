/* EthUDP Type Definitions
 * Core data structures and type definitions
 * by james@ustc.edu.cn 2009.04.02
 */

#ifndef ETHUDP_TYPES_H
#define ETHUDP_TYPES_H

#include "ethudp_common.h"

// Ensure MAX_BATCH_SIZE is defined
#ifndef MAX_BATCH_SIZE
#define MAX_BATCH_SIZE 1024
#endif

// Forward declarations
typedef struct worker_context worker_context_t;
typedef struct worker_pool worker_pool_t;
typedef struct lockfree_queue lockfree_queue_t;
typedef struct buffer_pool buffer_pool_t;
typedef struct queue_node queue_node_t;
typedef struct dynamic_system dynamic_system_t;

// ============================================================================
// NETWORK STRUCTURES
// ============================================================================

// Ethernet header structure
struct _EtherHeader {
    uint16_t destMAC1;
    uint32_t destMAC2;
    uint16_t srcMAC1;
    uint32_t srcMAC2;
    uint32_t VLANTag;
    uint16_t type;
    int32_t payload;
} __attribute__ ((packed));

typedef struct _EtherHeader EtherPacket;

// Packet buffer structure
struct packet_buf {
    time_t rcvt;        // recv time, 0 if not valid
    int len;            // buf len
    unsigned char *buf; // packet header is 8 bytes: UDPFRG+seq
};

// Packet batch structure for batch processing
struct packet_batch {
    int count;
    struct {
        int len;
        unsigned char data[MAX_PACKET_SIZE];
        struct timespec timestamp;
    } packets[MAX_BATCH_SIZE];
};

// ============================================================================
// QUEUE AND BUFFER STRUCTURES
// ============================================================================

// Lock-free queue node for RAW→UDP communication
struct queue_node {
    volatile struct queue_node *next;
    void *data;
    size_t size;
    int len;
    unsigned char packet_data[MAX_PACKET_SIZE];
    struct timespec timestamp;
};

// Lock-free queue structure
struct lockfree_queue {
    volatile struct queue_node *head;
    volatile struct queue_node *tail;
    volatile long long enqueue_count;
    volatile long long dequeue_count;
    int capacity;
    volatile int current_size;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
};

// Buffer pool for memory management
struct buffer_pool {
    void **buffers;
    volatile int head;
    volatile int tail;
    int total_buffers;
    int buffer_size;
    int pool_size;
    int available_count;
    pthread_mutex_t lock;
    pthread_mutex_t mutex;
};

// ============================================================================
// WORKER STRUCTURES
// ============================================================================

// Worker context structure
struct worker_context {
    // Identification
    int worker_id;
    int worker_type;  // WORKER_TYPE_UDP_TO_RAW or WORKER_TYPE_RAW_TO_UDP
    
    // Threading
    pthread_t thread_id;
    volatile int running;
    volatile int should_stop;
    
    // Networking
    int sockfd;
    int socket_index;
    char *local_host;
    char *local_port;
    struct sockaddr_storage local_addr;
    struct sockaddr_storage remote_addr;
    
    // Performance
    int cpu_affinity;
    int numa_node;
    
    // Buffers and queues
    struct buffer_pool *packet_pool;
    struct lockfree_queue *input_queue;
    struct lockfree_queue *output_queue;
    
    // Statistics
    volatile long long packets_processed;
    volatile long long bytes_processed;
    volatile long long errors;
    volatile long long queue_full_drops;
    volatile uint64_t total_latency_us;  // Added for compatibility
    volatile uint32_t current_queue_depth;  // Added for compatibility
    
    // Timing
    struct timespec start_time;
    struct timespec last_stats_time;
};

// Worker pool management
struct worker_pool {
    struct worker_context *udp_workers;
    struct worker_context *raw_workers;
    int udp_worker_count;
    int raw_worker_count;
    
    // Threading
    volatile int running;
    pthread_t stats_thread;
    
    // Shared resources
    struct lockfree_queue raw_queue;
    struct buffer_pool *shared_buffer_pool;
    
    // Configuration
    int batch_size;
    int queue_size;
    int enable_cpu_affinity;
    int enable_so_reuseport;
    int enable_numa_opt;
    int enable_batch_processing;
    
    // Statistics
    volatile long long total_packets_processed;
    volatile long long total_bytes_processed;
    volatile long long total_errors;
};

// ============================================================================
// DYNAMIC THREAD MANAGEMENT STRUCTURES
// ============================================================================

// System metrics for dynamic scaling
typedef struct {
    // Network metrics
    uint64_t packets_per_second;
    uint64_t bytes_per_second;
    double average_latency_ms;
    double avg_latency_us;  // Added for compatibility
    double jitter_ms;
    uint32_t packet_loss_rate;
    
    // System metrics
    double cpu_usage_percent;
    uint64_t memory_usage_bytes;
    double memory_usage_percent;  // Added for compatibility
    uint32_t active_connections;
    
    // Worker metrics
    uint32_t udp_workers_active;
    uint32_t raw_workers_active;
    double udp_workers_utilization;
    double raw_workers_utilization;
    uint32_t active_workers;  // Added for compatibility
    
    // Queue metrics
    uint32_t udp_queue_depth;
    uint32_t raw_queue_depth;
    uint32_t queue_depth;  // Added for compatibility
    double queue_wait_time_ms;
    
    // Timestamp
    uint64_t timestamp;  // Changed to uint64_t for compatibility
} system_metrics_t;

// Metrics history for pattern analysis
typedef struct {
    system_metrics_t samples[METRICS_HISTORY_SIZE];
    uint32_t current_index;
    uint32_t sample_count;
    uint32_t count;  // Added for compatibility
    double avg_cpu;  // Added for compatibility
    double avg_pps;  // Added for compatibility
    double avg_latency;  // Added for compatibility
    double avg_queue_depth;  // Added for compatibility
    pthread_mutex_t mutex;
} metrics_history_t;

// Dynamic configuration with adaptive thresholds
typedef struct {
    // Adaptive thresholds
    double high_load_threshold;
    double low_load_threshold;
    double cpu_threshold_scale_up;
    double cpu_threshold_scale_down;
    double cpu_threshold_high;      // Added for compatibility
    double cpu_threshold_low;       // Added for compatibility
    double pps_threshold_high;      // Added for compatibility
    double pps_threshold_low;       // Added for compatibility
    double latency_threshold_high;  // Added for compatibility
    double latency_threshold_low;   // Added for compatibility
    uint32_t queue_threshold_high;  // Added for compatibility
    uint32_t queue_threshold_low;   // Added for compatibility
    
    // System limits
    uint32_t min_udp_workers;
    uint32_t max_udp_workers;
    uint32_t min_raw_workers;
    uint32_t max_raw_workers;
    uint32_t min_workers;           // Added for compatibility
    uint32_t max_workers;           // Added for compatibility
    
    // Scaling parameters
    uint32_t scale_up_cooldown_ms;
    uint32_t scale_down_cooldown_ms;
    uint32_t scale_cooldown_ms;     // Added for compatibility
    uint32_t monitoring_interval_ms; // Added for compatibility
    double scale_factor;
    
    // Prediction parameters
    double prediction_weight;
    uint32_t pattern_learning_window;
    
    // Auto-tuning
    bool auto_tune_enabled;
    int enable_auto_tuning;         // Added for compatibility
    int enable_pattern_prediction;  // Added for compatibility
    struct timespec last_adjustment;
} dynamic_config_t;

// Scaling decision types
typedef enum {
    SCALE_NONE,
    SCALE_UP,
    SCALE_DOWN
} scale_decision_t;

// Load level enumeration
typedef enum {
    LOAD_LOW,
    LOAD_MEDIUM,
    LOAD_HIGH
} load_level_t;

// Worker load information for load balancing
typedef struct {
    uint32_t worker_id;
    double current_load;
    uint32_t queue_depth;
    double processing_time_avg;
    bool is_overloaded;
} worker_load_info_t;

// Trend types for load pattern detection
typedef enum {
    TREND_STABLE,
    TREND_INCREASING,
    TREND_DECREASING,
    TREND_VOLATILE
} trend_type_t;

// Load pattern detection
typedef struct {
    double hourly_multipliers[24];
    double daily_multipliers[7];
    double seasonal_factor;
    bool pattern_detected;
    trend_type_t trend;  // Added for compatibility
    double confidence;   // Added for compatibility
    uint64_t last_update; // Added for compatibility
    load_level_t predicted_load; // Predicted load level
} load_pattern_t;

// Atomic metrics for lock-free collection
typedef struct {
    _Atomic uint64_t packets_processed;
    _Atomic uint64_t bytes_processed;
    _Atomic uint64_t processing_time_ns;
    _Atomic uint32_t queue_depth;
    _Atomic double cpu_usage;
} atomic_metrics_t;

// Dynamic worker manager state
typedef struct {
    // Active workers
    worker_context_t* udp_workers;
    worker_context_t* raw_workers;
    uint32_t udp_worker_count;
    uint32_t raw_worker_count;
    
    // Load balancing
    worker_load_info_t* worker_loads;
    uint32_t load_info_count;
    
    // Scaling state
    uint64_t last_scale_up_time;
    uint64_t last_scale_down_time;
    scale_decision_t last_decision;
    
    // Thread safety
    pthread_mutex_t manager_mutex;
} dynamic_worker_manager_t;

// Dynamic memory manager
typedef struct {
    // Buffer pools
    buffer_pool_t** buffer_pools;
    uint32_t pool_count;
    
    // Memory statistics
    uint64_t total_allocated;
    uint64_t total_freed;
    uint64_t peak_usage;
    
    // Adaptive sizing
    uint32_t current_buffer_size;
    uint32_t optimal_buffer_size;
    
    // Thread safety
    pthread_mutex_t memory_mutex;
} dynamic_memory_manager_t;

// RCU (Read-Copy-Update) configuration
typedef struct {
    void* current_config;
    void* pending_config;
    uint64_t grace_period_start;
    volatile bool update_in_progress;
    pthread_mutex_t rcu_mutex;
} rcu_config_t;

// Main dynamic system structure
struct dynamic_system {
    // Configuration
    dynamic_config_t config;
    rcu_config_t rcu_config;
    
    // Metrics and history
    system_metrics_t current_metrics;
    metrics_history_t metrics_history;
    load_pattern_t load_pattern;
    
    // Managers
    dynamic_worker_manager_t worker_manager;
    dynamic_memory_manager_t memory_manager;
    
    // Threading
    pthread_t metrics_thread;
    pthread_t scaling_thread;
    pthread_t monitor_thread;
    volatile bool running;
    volatile bool should_stop;
    
    // Timing
    uint64_t last_scale_time;
    
    // Synchronization
    pthread_mutex_t system_mutex;
    pthread_cond_t metrics_cond;
    
    // Statistics
    uint64_t total_scale_ups;
    uint64_t total_scale_downs;
    uint64_t total_decisions;
    double avg_decision_time_ms;
};

// ============================================================================
// CONFIGURATION STRUCTURES
// ============================================================================

// Main configuration structure
typedef struct {
    // Network configuration
    int mode;                    // MODEE, MODEI, MODEB, etc.
    int master_slave;           // 0=master only, 1=master+slave
    char interface_name[64];    // Network interface name
    int mtu;                    // MTU maximum
    char local_host[256];       // Local host address
    char local_port[32];        // Local port
    char remote_host[256];      // Remote host address
    char remote_port[32];       // Remote port
    char dev_name[IFNAMSIZ];    // Device name
    char name[256];             // Name/identifier
    char run_cmd[256];          // Command to run
    
    // Worker configuration
    int udp_workers;            // Number of UDP workers
    int raw_workers;            // Number of RAW workers
    int batch_size;             // Batch size for processing
    int enable_cpu_affinity;    // Enable CPU affinity
    int cpu_affinity;           // CPU affinity setting
    
    // Dynamic scaling configuration
    int enable_dynamic_scaling; // Enable dynamic scaling
    double cpu_threshold_high;  // High CPU threshold
    double cpu_threshold_low;   // Low CPU threshold
    
    // Security configuration
    char password[256];         // Password for authentication
    int encryption_type;        // Encryption type (XOR, AES, etc.)
    char encryption_key[256];   // Encryption key
    int compression_enabled;    // Enable LZ4 compression
    int lz4;                    // LZ4 compression flag
    unsigned char enc_key[256]; // Encryption key bytes
    int enc_algorithm;          // Encryption algorithm
    int enc_key_len;            // Encryption key length
    
    // Network options
    int read_only;              // Read only mode
    int write_only;             // Write only mode
    int nopromisc;              // No promiscuous mode
    int fixmss;                 // Fix MSS
    int vlan_map;               // VLAN mapping
    int packet_len;             // Packet length
    
    // Debug and logging
    int debug;                  // Debug level
    int daemon;                 // Run as daemon
    int run_seconds;            // Run for specified seconds (0 = infinite)
    int benchmark;              // Benchmark mode
    
    // Advanced options
    int nat_mode;               // NAT mode enabled
    int loopback_check;         // Loopback check enabled
    int jumbo_frame;            // Jumbo frame support
    
    // Socket buffer sizes
    int socket_rcvbuf_size;     // Socket receive buffer size
    int socket_sndbuf_size;     // Socket send buffer size
    
    // Additional flags
    int encryption_enabled;     // Encryption enabled flag
    int keepalive_interval;     // Keepalive interval in seconds
    int worker_timeout;         // Worker timeout in seconds
    int stats_interval;         // Statistics interval in seconds
    
    // Queue and buffer configuration
    int queue_size;             // Queue size
    int enable_so_reuseport;    // Enable SO_REUSEPORT
    int enable_numa_optimization; // Enable NUMA optimization
    int enable_batch_processing; // Enable batch processing
    int packet_buffer_count;    // Packet buffer count
    int packet_buffer_size;     // Packet buffer size
} ethudp_config_t;

#endif /* ETHUDP_TYPES_H */