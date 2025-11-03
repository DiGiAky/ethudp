/* EthUDP Configuration Management
 * Configuration parsing, validation, and management
 * by james@ustc.edu.cn 2009.04.02
 */

#ifndef ETHUDP_CONFIG_H
#define ETHUDP_CONFIG_H

#include "ethudp_common.h"
#include "ethudp_types.h"

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

// Default configuration values
#define DEFAULT_UDP_WORKERS         4
#define DEFAULT_RAW_WORKERS         2
#define DEFAULT_BATCH_SIZE          32
#define DEFAULT_MTU                 1500
#define DEFAULT_CPU_THRESHOLD_HIGH  80.0
#define DEFAULT_CPU_THRESHOLD_LOW   30.0
#define DEFAULT_DEBUG_LEVEL         0
#define DEFAULT_RUN_SECONDS         0

// Configuration file paths
#define CONFIG_FILE_PATH            "/etc/ethudp.conf"
#define USER_CONFIG_PATH            "~/.ethudp.conf"
#define LOCAL_CONFIG_PATH           "./ethudp.conf"

// Configuration validation limits
#define MIN_WORKERS                 1
#define MAX_WORKERS                 64
#define MIN_BATCH_SIZE              1
#define MAX_BATCH_SIZE              1024
#define MIN_MTU                     576
#define MAX_MTU                     9000
#define MIN_CPU_THRESHOLD           1.0
#define MAX_CPU_THRESHOLD           99.0

// ============================================================================
// CONFIGURATION FUNCTIONS
// ============================================================================

/**
 * Initialize configuration with default values
 * @param config Pointer to configuration structure
 * @return 0 on success, -1 on error
 */
int ethudp_config_init(ethudp_config_t *config);

/**
 * Parse command line arguments
 * @param config Pointer to configuration structure
 * @param argc Argument count
 * @param argv Argument vector
 * @return 0 on success, -1 on error
 */
int ethudp_config_parse_args(ethudp_config_t *config, int argc, char *argv[]);

/**
 * Parse command line arguments (full version with mode and arg_index)
 * @param config Pointer to configuration structure
 * @param argc Argument count
 * @param argv Argument vector
 * @param mode Pointer to mode variable (output)
 * @param arg_index Pointer to argument index (output)
 * @return 0 on success, -1 on error
 */
int ethudp_config_parse_args_full(ethudp_config_t *config, int argc, char *argv[], 
                                 int *mode, int *arg_index);

/**
 * Load configuration from file
 * @param config Pointer to configuration structure
 * @param filename Configuration file path (NULL for default)
 * @return 0 on success, -1 on error
 */
int ethudp_config_load_file(ethudp_config_t *config, const char *filename);

/**
 * Save configuration to file
 * @param config Pointer to configuration structure
 * @param filename Configuration file path (NULL for default)
 * @return 0 on success, -1 on error
 */
int ethudp_config_save_file(const ethudp_config_t *config, const char *filename);

/**
 * Validate configuration parameters
 * @param config Pointer to configuration structure
 * @return 0 if valid, -1 if invalid
 */
int ethudp_config_validate(const ethudp_config_t *config);

/**
 * Print configuration summary
 * @param config Pointer to configuration structure
 */
void ethudp_config_print(const ethudp_config_t *config);

/**
 * Print usage information
 * @param program_name Program name from argv[0]
 */
void ethudp_config_print_usage(const char *program_name);

/**
 * Print usage information (short form)
 */
void ethudp_config_usage(void);

/**
 * Get configuration value by key
 * @param config Pointer to configuration structure
 * @param key Configuration key name
 * @param value Buffer to store the value
 * @param value_size Size of value buffer
 * @return 0 on success, -1 on error
 */
int ethudp_config_get_value(const ethudp_config_t *config, const char *key, 
                           char *value, size_t value_size);

/**
 * Set configuration value by key
 * @param config Pointer to configuration structure
 * @param key Configuration key name
 * @param value Value to set
 * @return 0 on success, -1 on error
 */
int ethudp_config_set_value(ethudp_config_t *config, const char *key, 
                           const char *value);

/**
 * Clone configuration structure
 * @param dest Destination configuration structure
 * @param src Source configuration structure
 * @return 0 on success, -1 on error
 */
int ethudp_config_clone(ethudp_config_t *dest, const ethudp_config_t *src);

/**
 * Compare two configuration structures
 * @param config1 First configuration structure
 * @param config2 Second configuration structure
 * @return 0 if equal, non-zero if different
 */
int ethudp_config_compare(const ethudp_config_t *config1, const ethudp_config_t *config2);

/**
 * Apply runtime configuration changes
 * @param config New configuration to apply
 * @return 0 on success, -1 on error
 */
int ethudp_config_apply_runtime_changes(const ethudp_config_t *config);

/**
 * Get configuration as JSON string
 * @param config Pointer to configuration structure
 * @param json_buffer Buffer to store JSON string
 * @param buffer_size Size of JSON buffer
 * @return 0 on success, -1 on error
 */
int ethudp_config_to_json(const ethudp_config_t *config, char *json_buffer, 
                         size_t buffer_size);

/**
 * Load configuration from JSON string
 * @param config Pointer to configuration structure
 * @param json_string JSON configuration string
 * @return 0 on success, -1 on error
 */
int ethudp_config_from_json(ethudp_config_t *config, const char *json_string);

// ============================================================================
// CONFIGURATION MACROS
// ============================================================================

// Configuration validation macros
#define VALIDATE_RANGE(value, min, max) \
    ((value) >= (min) && (value) <= (max))

#define VALIDATE_STRING(str, max_len) \
    ((str) != NULL && strlen(str) > 0 && strlen(str) < (max_len))

#define VALIDATE_PORT(port) \
    VALIDATE_RANGE(port, 1, 65535)

#define VALIDATE_WORKERS(workers) \
    VALIDATE_RANGE(workers, MIN_WORKERS, MAX_WORKERS)

#define VALIDATE_BATCH_SIZE(batch) \
    VALIDATE_RANGE(batch, MIN_BATCH_SIZE, MAX_BATCH_SIZE)

#define VALIDATE_MTU(mtu) \
    VALIDATE_RANGE(mtu, MIN_MTU, MAX_MTU)

#define VALIDATE_CPU_THRESHOLD(threshold) \
    VALIDATE_RANGE(threshold, MIN_CPU_THRESHOLD, MAX_CPU_THRESHOLD)

// Configuration access macros
#define CONFIG_GET_MODE(config)         ((config)->mode)
#define CONFIG_GET_UDP_WORKERS(config)  ((config)->udp_workers)
#define CONFIG_GET_RAW_WORKERS(config)  ((config)->raw_workers)
#define CONFIG_GET_BATCH_SIZE(config)   ((config)->batch_size)
#define CONFIG_GET_DEBUG_LEVEL(config)  ((config)->debug)

#define CONFIG_SET_MODE(config, val)         ((config)->mode = (val))
#define CONFIG_SET_UDP_WORKERS(config, val)  ((config)->udp_workers = (val))
#define CONFIG_SET_RAW_WORKERS(config, val)  ((config)->raw_workers = (val))
#define CONFIG_SET_BATCH_SIZE(config, val)   ((config)->batch_size = (val))
#define CONFIG_SET_DEBUG_LEVEL(config, val)  ((config)->debug = (val))

// Configuration flags
#define CONFIG_IS_MASTER_SLAVE(config)      ((config)->master_slave)
#define CONFIG_IS_DYNAMIC_SCALING(config)   ((config)->enable_dynamic_scaling)
#define CONFIG_IS_CPU_AFFINITY(config)      ((config)->enable_cpu_affinity)
#define CONFIG_IS_DAEMON(config)            ((config)->daemon)
#define CONFIG_IS_DEBUG(config)             ((config)->debug > 0)
#define CONFIG_IS_NAT_MODE(config)          ((config)->nat_mode)
#define CONFIG_IS_COMPRESSION(config)       ((config)->compression_enabled)

// ============================================================================
// GLOBAL CONFIGURATION
// ============================================================================

// Global configuration instance (defined in ethudp_config.c)
extern ethudp_config_t g_ethudp_config;

// Configuration initialization flag
extern int g_config_initialized;

// Configuration file watcher (for runtime updates)
extern int g_config_watch_fd;

/**
 * Get global configuration instance
 * @return Pointer to global configuration
 */
static inline ethudp_config_t* ethudp_get_global_config(void) {
    return &g_ethudp_config;
}

/**
 * Check if configuration is initialized
 * @return 1 if initialized, 0 otherwise
 */
static inline int ethudp_config_is_initialized(void) {
    return g_config_initialized;
}

#endif /* ETHUDP_CONFIG_H */