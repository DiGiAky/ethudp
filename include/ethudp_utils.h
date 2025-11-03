/* EthUDP Utility Functions
 * Utility functions, error handling, and helper routines
 * by james@ustc.edu.cn 2009.04.02
 */

#ifndef ETHUDP_UTILS_H
#define ETHUDP_UTILS_H

#include "ethudp_common.h"
#include "ethudp_types.h"

// ============================================================================
// ERROR HANDLING AND LOGGING
// ============================================================================

// Note: err_quit is defined as a macro in ethudp_common.h

// Note: err_sys, err_msg, and Debug are defined as macros in ethudp_common.h

// Note: err_sys, err_msg, and Debug are defined as macros in ethudp_common.h

/**
 * Internal error handling function
 * @param errnoflag Error number flag
 * @param level Error level
 * @param fmt Format string
 * @param ap Variable argument list
 */
void err_doit(int errnoflag, int level, const char *fmt, va_list ap);

// ============================================================================
// TIME AND TIMING UTILITIES
// ============================================================================

/**
 * Get current time in milliseconds
 * @return Current time in milliseconds
 */
uint64_t get_current_time_ms(void);

/**
 * Get current time in milliseconds (EthUDP version)
 * @return Current time in milliseconds
 */
uint64_t ethudp_get_current_time_ms(void);

/**
 * Get current time in microseconds
 * @return Current time in microseconds
 */
uint64_t get_current_time_us(void);

/**
 * Get current time in microseconds (EthUDP version)
 * @return Current time in microseconds
 */
uint64_t ethudp_get_current_time_us(void);

/**
 * Get current time as timespec
 * @param ts Timespec structure to fill
 * @return 0 on success, -1 on error
 */
int get_current_timespec(struct timespec *ts);

/**
 * Calculate time difference in milliseconds
 * @param start Start time
 * @param end End time
 * @return Time difference in milliseconds
 */
double timespec_diff_ms(const struct timespec *start, const struct timespec *end);

/**
 * Calculate time difference in microseconds
 * @param start Start time
 * @param end End time
 * @return Time difference in microseconds
 */
double timespec_diff_us(const struct timespec *start, const struct timespec *end);

/**
 * Add milliseconds to timespec
 * @param ts Timespec structure
 * @param ms Milliseconds to add
 */
void timespec_add_ms(struct timespec *ts, uint64_t ms);

/**
 * Sleep for specified milliseconds
 * @param ms Milliseconds to sleep
 * @return 0 on success, -1 on error
 */
int sleep_ms(uint64_t ms);

/**
 * Sleep for specified milliseconds (EthUDP version)
 * @param milliseconds Milliseconds to sleep
 */
void ethudp_sleep_ms(uint32_t milliseconds);

/**
 * Sleep for specified microseconds
 * @param us Microseconds to sleep
 * @return 0 on success, -1 on error
 */
int sleep_us(uint64_t us);

// ============================================================================
// SYSTEM MONITORING
// ============================================================================

/**
 * Get current CPU usage percentage
 * @return CPU usage percentage (0.0-100.0)
 */
double get_cpu_usage(void);

/**
 * Get current memory usage in bytes
 * @return Memory usage in bytes
 */
uint64_t get_memory_usage(void);

/**
 * Get memory usage in bytes (EthUDP version)
 * @return Memory usage in bytes
 */
uint64_t ethudp_get_memory_usage(void);

/**
 * Get CPU usage percentage (EthUDP version)
 * @return CPU usage percentage
 */
double ethudp_get_cpu_usage(void);

/**
 * Get system load average
 * @param load1 1-minute load average (output)
 * @param load5 5-minute load average (output)
 * @param load15 15-minute load average (output)
 * @return 0 on success, -1 on error
 */
int get_system_load(double *load1, double *load5, double *load15);

/**
 * Get number of CPU cores
 * @return Number of CPU cores, -1 on error
 */
int get_cpu_count(void);

/**
 * Get number of CPU cores (EthUDP version)
 * @return Number of CPU cores, -1 on error
 */
int ethudp_get_cpu_count(void);

/**
 * Error message function
 * @param fmt Format string
 * @param ... Variable arguments
 */
void ethudp_err_msg(const char *fmt, ...);

/**
 * Debug message function
 * @param fmt Format string
 * @param ... Variable arguments
 */
void ethudp_debug(const char *fmt, ...);

/**
 * Error quit function
 * @param fmt Format string
 * @param ... Variable arguments
 */
void ethudp_err_quit(const char *fmt, ...);

/**
  * System error function
  * @param fmt Format string
  * @param ... Variable arguments
  */
 void ethudp_err_sys(const char *fmt, ...);
 
 /**
 * Get available memory in bytes
 * @return Available memory in bytes, -1 on error
 */
uint64_t get_available_memory(void);

/**
 * Get network interface statistics
 * @param interface Interface name
 * @param rx_bytes Received bytes (output)
 * @param tx_bytes Transmitted bytes (output)
 * @param rx_packets Received packets (output)
 * @param tx_packets Transmitted packets (output)
 * @return 0 on success, -1 on error
 */
int get_interface_stats(const char *interface, uint64_t *rx_bytes, 
                       uint64_t *tx_bytes, uint64_t *rx_packets, 
                       uint64_t *tx_packets);

// ============================================================================
// PROCESS AND THREAD UTILITIES
// ============================================================================

/**
 * Initialize daemon process
 * @param nochdir Don't change directory if non-zero
 * @param noclose Don't close file descriptors if non-zero
 * @return 0 on success, -1 on error
 */
int daemon_init(int nochdir, int noclose);

/**
 * Initialize daemon with logging
 * @param pname Program name for logging
 * @param facility Syslog facility
 */
void ethudp_daemon_init(const char *pname, int facility);

/**
 * Set thread CPU affinity
 * @param thread_id Thread ID (0 for current thread)
 * @param cpu_id CPU ID to bind to
 * @return 0 on success, -1 on error
 */
int set_thread_affinity(pthread_t thread_id, int cpu_id);

/**
 * Set thread priority
 * @param thread_id Thread ID (0 for current thread)
 * @param priority Priority level
 * @return 0 on success, -1 on error
 */
int set_thread_priority(pthread_t thread_id, int priority);

/**
 * Set thread name for debugging
 * @param thread_id Thread ID (0 for current thread)
 * @param name Thread name
 * @return 0 on success, -1 on error
 */
int set_thread_name(pthread_t thread_id, const char *name);

/**
 * Get thread statistics
 * @param thread_id Thread ID
 * @param cpu_time CPU time used (output)
 * @param memory_usage Memory usage (output)
 * @return 0 on success, -1 on error
 */
int get_thread_stats(pthread_t thread_id, uint64_t *cpu_time, 
                    uint64_t *memory_usage);

// ============================================================================
// MEMORY MANAGEMENT
// ============================================================================

/**
 * Allocate aligned memory
 * @param size Size to allocate
 * @param alignment Alignment requirement
 * @return Pointer to allocated memory, NULL on error
 */
void* aligned_alloc_safe(size_t size, size_t alignment);

/**
 * Free aligned memory
 * @param ptr Pointer to memory to free
 */
void aligned_free_safe(void *ptr);

/**
 * Allocate zero-initialized memory
 * @param count Number of elements
 * @param size Size of each element
 * @return Pointer to allocated memory, NULL on error
 */
void* calloc_safe(size_t count, size_t size);

/**
 * Reallocate memory safely
 * @param ptr Original pointer
 * @param new_size New size
 * @return Pointer to reallocated memory, NULL on error
 */
void* realloc_safe(void *ptr, size_t new_size);

/**
 * Duplicate string safely
 * @param str String to duplicate
 * @return Pointer to duplicated string, NULL on error
 */
char* strdup_safe(const char *str);

/**
 * Copy memory safely
 * @param dest Destination buffer
 * @param src Source buffer
 * @param n Number of bytes to copy
 * @return Pointer to destination, NULL on error
 */
void* memcpy_safe(void *dest, const void *src, size_t n);

/**
 * Set memory safely
 * @param s Memory area to set
 * @param c Value to set
 * @param n Number of bytes to set
 * @return Pointer to memory area, NULL on error
 */
void* memset_safe(void *s, int c, size_t n);

// ============================================================================
// STRING UTILITIES
// ============================================================================

/**
 * Copy string safely
 * @param dest Destination buffer
 * @param src Source string
 * @param dest_size Size of destination buffer
 * @return 0 on success, -1 on error
 */
int strcpy_safe(char *dest, const char *src, size_t dest_size);

/**
 * Concatenate strings safely
 * @param dest Destination buffer
 * @param src Source string
 * @param dest_size Size of destination buffer
 * @return 0 on success, -1 on error
 */
int strcat_safe(char *dest, const char *src, size_t dest_size);

/**
 * Format string safely
 * @param dest Destination buffer
 * @param dest_size Size of destination buffer
 * @param fmt Format string
 * @param ... Variable arguments
 * @return Number of characters written, -1 on error
 */
int snprintf_safe(char *dest, size_t dest_size, const char *fmt, ...);

/**
 * Trim whitespace from string
 * @param str String to trim (modified in place)
 * @return Pointer to trimmed string
 */
char* str_trim(char *str);

/**
 * Convert string to lowercase
 * @param str String to convert (modified in place)
 * @return Pointer to converted string
 */
char* str_tolower(char *str);

/**
 * Convert string to uppercase
 * @param str String to convert (modified in place)
 * @return Pointer to converted string
 */
char* str_toupper(char *str);

/**
 * Check if string starts with prefix
 * @param str String to check
 * @param prefix Prefix to check for
 * @return 1 if starts with prefix, 0 otherwise
 */
int str_startswith(const char *str, const char *prefix);

/**
 * Check if string ends with suffix
 * @param str String to check
 * @param suffix Suffix to check for
 * @return 1 if ends with suffix, 0 otherwise
 */
int str_endswith(const char *str, const char *suffix);

// ============================================================================
// FILE AND PATH UTILITIES
// ============================================================================

/**
 * Check if file exists
 * @param path File path
 * @return 1 if exists, 0 if not, -1 on error
 */
int file_exists(const char *path);

/**
 * Check if directory exists
 * @param path Directory path
 * @return 1 if exists, 0 if not, -1 on error
 */
int dir_exists(const char *path);

/**
 * Create directory recursively
 * @param path Directory path
 * @param mode Directory permissions
 * @return 0 on success, -1 on error
 */
int mkdir_recursive(const char *path, mode_t mode);

/**
 * Get file size
 * @param path File path
 * @return File size in bytes, -1 on error
 */
off_t get_file_size(const char *path);

/**
 * Read entire file into buffer
 * @param path File path
 * @param buffer Buffer to store file contents (output)
 * @param buffer_size Size of buffer
 * @return Number of bytes read, -1 on error
 */
ssize_t read_file(const char *path, void *buffer, size_t buffer_size);

/**
 * Write buffer to file
 * @param path File path
 * @param buffer Buffer containing data to write
 * @param size Number of bytes to write
 * @return Number of bytes written, -1 on error
 */
ssize_t write_file(const char *path, const void *buffer, size_t size);

/**
 * Get basename from path
 * @param path File path
 * @return Pointer to basename
 */
const char* get_basename(const char *path);

/**
 * Get directory name from path
 * @param path File path
 * @param dirname Buffer to store directory name (output)
 * @param dirname_size Size of dirname buffer
 * @return 0 on success, -1 on error
 */
int get_dirname(const char *path, char *dirname, size_t dirname_size);

// ============================================================================
// HASH AND CHECKSUM UTILITIES
// ============================================================================

/**
 * Calculate CRC32 checksum
 * @param data Data to checksum
 * @param len Data length
 * @return CRC32 checksum
 */
uint32_t crc32_checksum(const void *data, size_t len);

/**
 * Calculate MD5 hash
 * @param data Data to hash
 * @param len Data length
 * @param hash Buffer to store hash (16 bytes)
 * @return 0 on success, -1 on error
 */
int md5_hash(const void *data, size_t len, unsigned char *hash);

/**
 * Calculate SHA256 hash
 * @param data Data to hash
 * @param len Data length
 * @param hash Buffer to store hash (32 bytes)
 * @return 0 on success, -1 on error
 */
int sha256_hash(const void *data, size_t len, unsigned char *hash);

/**
 * Convert hash to hex string
 * @param hash Hash bytes
 * @param hash_len Hash length
 * @param hex_str Buffer to store hex string (output)
 * @param hex_str_size Size of hex string buffer
 * @return 0 on success, -1 on error
 */
int hash_to_hex(const unsigned char *hash, size_t hash_len, 
               char *hex_str, size_t hex_str_size);

// ============================================================================
// RANDOM NUMBER GENERATION
// ============================================================================

/**
 * Initialize random number generator
 * @param seed Random seed (0 for time-based seed)
 */
void random_init(unsigned int seed);

/**
 * Generate random integer
 * @param min Minimum value (inclusive)
 * @param max Maximum value (inclusive)
 * @return Random integer in range [min, max]
 */
int random_int(int min, int max);

/**
 * Generate random double
 * @param min Minimum value (inclusive)
 * @param max Maximum value (exclusive)
 * @return Random double in range [min, max)
 */
double random_double(double min, double max);

/**
 * Generate random bytes
 * @param buffer Buffer to store random bytes
 * @param size Number of bytes to generate
 * @return 0 on success, -1 on error
 */
int random_bytes(void *buffer, size_t size);

// ============================================================================
// SIGNAL HANDLING
// ============================================================================

/**
 * Install signal handler
 * @param signum Signal number
 * @param handler Signal handler function
 * @return 0 on success, -1 on error
 */
int install_signal_handler(int signum, void (*handler)(int));

/**
 * Block signal for current thread
 * @param signum Signal number
 * @return 0 on success, -1 on error
 */
int block_signal(int signum);

/**
 * Unblock signal for current thread
 * @param signum Signal number
 * @return 0 on success, -1 on error
 */
int unblock_signal(int signum);

/**
 * Wait for signal
 * @param signum Signal number to wait for
 * @param timeout_ms Timeout in milliseconds (0 for no timeout)
 * @return Signal number received, -1 on timeout or error
 */
int wait_for_signal(int signum, int timeout_ms);

// ============================================================================
// PERFORMANCE UTILITIES
// ============================================================================

/**
 * Start performance timer
 * @param timer Timer structure to initialize
 * @return 0 on success, -1 on error
 */
int perf_timer_start(struct timespec *timer);

/**
 * Stop performance timer and get elapsed time
 * @param timer Timer structure
 * @return Elapsed time in microseconds, -1 on error
 */
double perf_timer_stop(const struct timespec *timer);

/**
 * Get CPU cycle count (if available)
 * @return CPU cycle count
 */
uint64_t get_cpu_cycles(void);

/**
 * Convert CPU cycles to nanoseconds
 * @param cycles CPU cycles
 * @return Nanoseconds
 */
uint64_t cycles_to_ns(uint64_t cycles);

// ============================================================================
// PERFORMANCE COUNTER
// ============================================================================

/**
 * Performance counter structure
 */
typedef struct {
    uint64_t start_time;    // Start time in microseconds
    uint64_t total_time;    // Total accumulated time
    uint64_t min_time;      // Minimum time recorded
    uint64_t max_time;      // Maximum time recorded
    uint64_t count;         // Number of measurements
} ethudp_perf_counter_t;

/**
 * Initialize performance counter
 * @param counter Counter to initialize
 */
void ethudp_perf_counter_init(ethudp_perf_counter_t *counter);

/**
 * Start performance measurement
 * @param counter Counter to start
 */
void ethudp_perf_counter_start(ethudp_perf_counter_t *counter);

/**
 * Stop performance measurement
 * @param counter Counter to stop
 */
void ethudp_perf_counter_stop(ethudp_perf_counter_t *counter);

/**
 * Get average time in microseconds
 * @param counter Counter to query
 * @return Average time in microseconds
 */
double ethudp_perf_counter_get_avg_us(const ethudp_perf_counter_t *counter);

/**
 * Get average time in milliseconds
 * @param counter Counter to query
 * @return Average time in milliseconds
 */
double ethudp_perf_counter_get_avg_ms(const ethudp_perf_counter_t *counter);

/**
 * Reset performance counter
 * @param counter Counter to reset
 */
void ethudp_perf_counter_reset(ethudp_perf_counter_t *counter);

// ============================================================================
// UTILITY MACROS
// ============================================================================

// Safe string operations
#define SAFE_STRCPY(dest, src) strcpy_safe(dest, src, sizeof(dest))
#define SAFE_STRCAT(dest, src) strcat_safe(dest, src, sizeof(dest))
#define SAFE_SNPRINTF(dest, fmt, ...) snprintf_safe(dest, sizeof(dest), fmt, ##__VA_ARGS__)

// Memory operations
#define SAFE_FREE(ptr) do { if (ptr) { free(ptr); (ptr) = NULL; } } while(0)
#define SAFE_CLOSE(fd) do { if ((fd) >= 0) { close(fd); (fd) = -1; } } while(0)

// Array size
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

// Min/Max macros
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

// Alignment macros
#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))
#define ALIGN_DOWN(x, align) ((x) & ~((align) - 1))
#define IS_ALIGNED(x, align) (((x) & ((align) - 1)) == 0)

// Bit manipulation
#define SET_BIT(var, bit) ((var) |= (1 << (bit)))
#define CLEAR_BIT(var, bit) ((var) &= ~(1 << (bit)))
#define TOGGLE_BIT(var, bit) ((var) ^= (1 << (bit)))
#define TEST_BIT(var, bit) (((var) >> (bit)) & 1)

#endif /* ETHUDP_UTILS_H */