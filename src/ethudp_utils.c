/**
 * @file ethudp_utils.c
 * @brief Utility functions for EthUDP
 * 
 * This module contains utility functions for error handling, logging,
 * time management, system monitoring, and other common operations.
 */

#include "ethudp_utils.h"
#include "ethudp_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>

// External variables from main application
extern int daemon_proc;
extern volatile int debug;
extern char name[MAXLEN];

// ============================================================================
// ERROR HANDLING AND LOGGING
// ============================================================================

void ethudp_err_doit(int errnoflag, int level, const char *fmt, va_list ap)
{
    int errno_save, n;
    char buf[MAXLEN];

    errno_save = errno;    /* value caller might want printed */
    vsnprintf(buf, sizeof(buf), fmt, ap);    /* this is safe */
    n = strlen(buf);
    if (errnoflag)
        snprintf(buf + n, sizeof(buf) - n, ": %s", strerror(errno_save));
    strcat(buf, "\n");

    if (daemon_proc) {
        if (name[0])
            syslog(level, "%s: %s", name, buf);
        else
            syslog(level, "%s", buf);
    } else {
        fflush(stdout);    /* in case stdout and stderr are the same */
        if (name[0]) {
            fputs(name, stderr);
            fputs(": ", stderr);
        }
        fputs(buf, stderr);
        fflush(stderr);
    }
    return;
}

void ethudp_err_msg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    ethudp_err_doit(0, LOG_INFO, fmt, ap);
    va_end(ap);
    return;
}

void ethudp_debug(const char *fmt, ...)
{
    va_list ap;
    if (debug) {
        va_start(ap, fmt);
        ethudp_err_doit(0, LOG_INFO, fmt, ap);
        va_end(ap);
    }
    return;
}

void ethudp_err_quit(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    ethudp_err_doit(0, LOG_ERR, fmt, ap);
    va_end(ap);
    exit(1);
}

void ethudp_err_sys(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    ethudp_err_doit(1, LOG_ERR, fmt, ap);
    va_end(ap);
    exit(1);
}

// ============================================================================
// DAEMON INITIALIZATION
// ============================================================================

void ethudp_daemon_init(const char *pname, int facility)
{
    int i;
    pid_t pid;
    if ((pid = fork()) != 0)
        exit(0);    /* parent terminates */

    /* 41st child continues */
    setsid();        /* become session leader */

    signal(SIGHUP, SIG_IGN);
    if ((pid = fork()) != 0)
        exit(0);    /* 1st child terminates */

    /* 42nd child continues */
    daemon_proc = 1;    /* for our err_XXX() functions */

    umask(0);        /* clear our file mode creation mask */

    for (i = 0; i < MAXFD; i++)
        close(i);

    openlog(pname, LOG_PID, facility);
}

// ============================================================================
// TIME MANAGEMENT
// ============================================================================

uint64_t ethudp_get_current_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

uint64_t ethudp_get_current_time_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

void ethudp_sleep_ms(uint32_t milliseconds)
{
    struct timespec ts;
    ts.tv_sec = milliseconds / 1000;
    ts.tv_nsec = (milliseconds % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

void ethudp_sleep_us(uint32_t microseconds)
{
    struct timespec ts;
    ts.tv_sec = microseconds / 1000000;
    ts.tv_nsec = (microseconds % 1000000) * 1000;
    nanosleep(&ts, NULL);
}

// ============================================================================
// SYSTEM MONITORING
// ============================================================================

double ethudp_get_cpu_usage(void)
{
    static uint64_t last_idle = 0, last_total = 0;
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) return 0.0;
    
    uint64_t user, nice, system, idle, iowait, irq, softirq, steal;
    if (fscanf(fp, "cpu %lu %lu %lu %lu %lu %lu %lu %lu", 
               &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal) != 8) {
        fclose(fp);
        return 0.0;
    }
    fclose(fp);
    
    uint64_t total = user + nice + system + idle + iowait + irq + softirq + steal;
    uint64_t diff_idle = idle - last_idle;
    uint64_t diff_total = total - last_total;
    
    last_idle = idle;
    last_total = total;
    
    if (diff_total == 0) return 0.0;
    return (double)(diff_total - diff_idle) / diff_total * 100.0;
}

uint64_t ethudp_get_memory_usage(void)
{
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return 0;
    
    uint64_t total = 0, available = 0;
    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "MemTotal: %lu kB", &total) == 1) continue;
        if (sscanf(line, "MemAvailable: %lu kB", &available) == 1) break;
    }
    fclose(fp);
    
    return total > 0 ? ((total - available) * 1024) : 0;
}

int ethudp_get_cpu_count(void)
{
    return sysconf(_SC_NPROCESSORS_ONLN);
}

// ============================================================================
// PROCESS AND THREAD MANAGEMENT
// ============================================================================

int ethudp_set_thread_cpu_affinity(pthread_t thread, int cpu_id)
{
#ifdef __linux__
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    
    if (pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset) != 0) {
        ethudp_debug("Warning: Failed to set CPU affinity to CPU %d", cpu_id);
        return -1;
    }
    
    ethudp_debug("Thread assigned to CPU %d", cpu_id);
    return 0;
#else
    return 0;
#endif
}

int ethudp_set_current_thread_cpu_affinity(int cpu_id)
{
    return ethudp_set_thread_cpu_affinity(pthread_self(), cpu_id);
}

pid_t ethudp_create_process(void)
{
    return fork();
}

int ethudp_wait_for_process(pid_t pid, int *status)
{
    return waitpid(pid, status, 0);
}

// ============================================================================
// MEMORY MANAGEMENT
// ============================================================================

void* ethudp_malloc_aligned(size_t size, size_t alignment)
{
    void *ptr;
    if (posix_memalign(&ptr, alignment, size) != 0) {
        return NULL;
    }
    return ptr;
}

void ethudp_free_aligned(void *ptr)
{
    free(ptr);
}

void* ethudp_calloc_safe(size_t nmemb, size_t size)
{
    // Check for overflow
    if (nmemb != 0 && size > SIZE_MAX / nmemb) {
        errno = ENOMEM;
        return NULL;
    }
    return calloc(nmemb, size);
}

void* ethudp_realloc_safe(void *ptr, size_t old_size, size_t new_size)
{
    void *new_ptr = realloc(ptr, new_size);
    if (new_ptr && new_size > old_size) {
        // Zero out the new memory
        memset((char*)new_ptr + old_size, 0, new_size - old_size);
    }
    return new_ptr;
}

// ============================================================================
// STRING MANIPULATION
// ============================================================================

char* ethudp_strdup_safe(const char *s)
{
    if (!s) return NULL;
    
    size_t len = strlen(s) + 1;
    char *copy = malloc(len);
    if (copy) {
        memcpy(copy, s, len);
    }
    return copy;
}

int ethudp_snprintf_safe(char *str, size_t size, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    int result = vsnprintf(str, size, format, ap);
    va_end(ap);
    
    // Ensure null termination
    if (size > 0) {
        str[size - 1] = '\0';
    }
    
    return result;
}

void ethudp_str_trim(char *str)
{
    if (!str) return;
    
    // Trim leading whitespace
    char *start = str;
    while (*start && isspace(*start)) {
        start++;
    }
    
    // Trim trailing whitespace
    char *end = str + strlen(str) - 1;
    while (end > start && isspace(*end)) {
        end--;
    }
    
    // Move trimmed string to beginning and null terminate
    size_t len = end - start + 1;
    memmove(str, start, len);
    str[len] = '\0';
}

int ethudp_str_starts_with(const char *str, const char *prefix)
{
    if (!str || !prefix) return 0;
    return strncmp(str, prefix, strlen(prefix)) == 0;
}

int ethudp_str_ends_with(const char *str, const char *suffix)
{
    if (!str || !suffix) return 0;
    
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    
    if (suffix_len > str_len) return 0;
    
    return strcmp(str + str_len - suffix_len, suffix) == 0;
}

// ============================================================================
// FILE AND PATH OPERATIONS
// ============================================================================

int ethudp_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

int ethudp_is_directory(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

int ethudp_is_regular_file(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
}

size_t ethudp_get_file_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return st.st_size;
}

int ethudp_create_directory(const char *path, mode_t mode)
{
    return mkdir(path, mode);
}

int ethudp_create_directory_recursive(const char *path, mode_t mode)
{
    char *path_copy = ethudp_strdup_safe(path);
    if (!path_copy) return -1;
    
    char *p = path_copy;
    int result = 0;
    
    // Skip leading slash
    if (*p == '/') p++;
    
    while (*p) {
        // Find next slash
        while (*p && *p != '/') p++;
        
        // Temporarily null terminate
        char saved = *p;
        *p = '\0';
        
        // Create directory if it doesn't exist
        if (!ethudp_file_exists(path_copy)) {
            if (mkdir(path_copy, mode) != 0 && errno != EEXIST) {
                result = -1;
                break;
            }
        }
        
        // Restore character and continue
        *p = saved;
        if (*p) p++;
    }
    
    free(path_copy);
    return result;
}

// ============================================================================
// HASH AND CHECKSUM CALCULATIONS
// ============================================================================

uint32_t ethudp_hash_djb2(const char *str)
{
    uint32_t hash = 5381;
    int c;
    
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    
    return hash;
}

uint32_t ethudp_hash_fnv1a(const void *data, size_t len)
{
    const uint8_t *bytes = (const uint8_t*)data;
    uint32_t hash = 2166136261u;
    
    for (size_t i = 0; i < len; i++) {
        hash ^= bytes[i];
        hash *= 16777619u;
    }
    
    return hash;
}

uint16_t ethudp_checksum_internet(const void *data, size_t len)
{
    const uint16_t *words = (const uint16_t*)data;
    uint32_t sum = 0;
    
    // Sum all 16-bit words
    while (len > 1) {
        sum += *words++;
        len -= 2;
    }
    
    // Add odd byte if present
    if (len == 1) {
        sum += *(const uint8_t*)words << 8;
    }
    
    // Add carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

uint32_t ethudp_crc32(const void *data, size_t len)
{
    static uint32_t crc_table[256];
    static int table_computed = 0;
    
    // Generate CRC table if not done yet
    if (!table_computed) {
        for (int i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int j = 0; j < 8; j++) {
                if (c & 1) {
                    c = 0xEDB88320 ^ (c >> 1);
                } else {
                    c = c >> 1;
                }
            }
            crc_table[i] = c;
        }
        table_computed = 1;
    }
    
    const uint8_t *bytes = (const uint8_t*)data;
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < len; i++) {
        crc = crc_table[(crc ^ bytes[i]) & 0xFF] ^ (crc >> 8);
    }
    
    return crc ^ 0xFFFFFFFF;
}

// ============================================================================
// RANDOM NUMBER GENERATION
// ============================================================================

static uint32_t rng_state = 1;

void ethudp_srand(uint32_t seed)
{
    rng_state = seed ? seed : 1;
}

uint32_t ethudp_rand(void)
{
    // Linear congruential generator
    rng_state = rng_state * 1103515245 + 12345;
    return rng_state;
}

uint32_t ethudp_rand_range(uint32_t min, uint32_t max)
{
    if (min >= max) return min;
    return min + (ethudp_rand() % (max - min + 1));
}

void ethudp_rand_bytes(void *buffer, size_t size)
{
    uint8_t *bytes = (uint8_t*)buffer;
    for (size_t i = 0; i < size; i++) {
        bytes[i] = ethudp_rand() & 0xFF;
    }
}

// ============================================================================
// SIGNAL HANDLING
// ============================================================================

static volatile sig_atomic_t signal_received = 0;
static int last_signal = 0;

static void signal_handler(int sig)
{
    signal_received = 1;
    last_signal = sig;
}

int ethudp_setup_signal_handler(int sig, void (*handler)(int))
{
    struct sigaction sa;
    sa.sa_handler = handler ? handler : signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    
    return sigaction(sig, &sa, NULL);
}

int ethudp_block_signal(int sig)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, sig);
    return pthread_sigmask(SIG_BLOCK, &set, NULL);
}

int ethudp_unblock_signal(int sig)
{
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, sig);
    return pthread_sigmask(SIG_UNBLOCK, &set, NULL);
}

int ethudp_wait_for_signal(void)
{
    while (!signal_received) {
        ethudp_sleep_ms(10);
    }
    signal_received = 0;
    return last_signal;
}

// ============================================================================
// PERFORMANCE MEASUREMENT
// ============================================================================

void ethudp_perf_counter_init(ethudp_perf_counter_t *counter)
{
    memset(counter, 0, sizeof(*counter));
    counter->start_time = ethudp_get_current_time_us();
}

void ethudp_perf_counter_start(ethudp_perf_counter_t *counter)
{
    counter->start_time = ethudp_get_current_time_us();
}

void ethudp_perf_counter_stop(ethudp_perf_counter_t *counter)
{
    uint64_t end_time = ethudp_get_current_time_us();
    uint64_t duration = end_time - counter->start_time;
    
    counter->total_time += duration;
    counter->count++;
    
    if (duration < counter->min_time || counter->min_time == 0) {
        counter->min_time = duration;
    }
    if (duration > counter->max_time) {
        counter->max_time = duration;
    }
}

double ethudp_perf_counter_get_avg_us(const ethudp_perf_counter_t *counter)
{
    return counter->count > 0 ? (double)counter->total_time / counter->count : 0.0;
}

double ethudp_perf_counter_get_avg_ms(const ethudp_perf_counter_t *counter)
{
    return ethudp_perf_counter_get_avg_us(counter) / 1000.0;
}

void ethudp_perf_counter_reset(ethudp_perf_counter_t *counter)
{
    memset(counter, 0, sizeof(*counter));
}

// ============================================================================
// UTILITY MACROS IMPLEMENTATION
// ============================================================================

void ethudp_swap_bytes(void *a, void *b, size_t size)
{
    uint8_t *pa = (uint8_t*)a;
    uint8_t *pb = (uint8_t*)b;
    
    for (size_t i = 0; i < size; i++) {
        uint8_t temp = pa[i];
        pa[i] = pb[i];
        pb[i] = temp;
    }
}