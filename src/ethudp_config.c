#include "../include/ethudp_common.h"
#include "../include/ethudp_types.h"
#include "../include/ethudp_config.h"
#include "../include/ethudp_utils.h"

// Forward declaration
void usage(void);

// Configuration limits
#define MIN_WORKERS 1
#define MAX_WORKERS 64
#define MIN_BATCH_SIZE 1
#define MAX_BATCH_SIZE 1024
#define MIN_QUEUE_SIZE 64
// MAX_QUEUE_SIZE, MIN_WORKER_TIMEOUT and MAX_WORKER_TIMEOUT are defined in ethudp_common.h
// #define MAX_WORKER_TIMEOUT 60000  // Already defined in ethudp_common.h as 300

// Configuration parsing constants
#define CONFIG_LINE_MAX 256
#define CONFIG_KEY_MAX 64
#define CONFIG_VALUE_MAX 128

// Mode constants
// Mode definitions already exist in ethudp_common.h
// #define MODE_E 1  // Already defined in ethudp_common.h as MODEE
// #define MODE_I 2  // Already defined in ethudp_common.h as MODEI
// #define MODE_B 3  // Already defined in ethudp_common.h as MODEB
// #define MODE_T 4  // Already defined in ethudp_common.h as MODET
// #define MODE_U 5  // Already defined in ethudp_common.h as MODEU

// Global configuration instance
extern ethudp_config_t global_config;

// Forward declarations
int load_vlan_map(const char *filename);

// External variables from original code
extern char mypassword[MAXLEN];
extern char enc_key[MAXLEN];
extern int enc_key_len;
extern int enc_algorithm;
extern int master_slave;
extern int fixmss;
extern int mtu;
extern int read_only;
extern int loopback_check;
extern int write_only;
extern int nopromisc;
extern int lz4;
extern char dev_name[MAXLEN];
extern char run_cmd[MAXLEN];
extern int run_seconds;
extern int debug;
extern int vlan_map;
extern int my_vlan[4096];
extern char syslog_name[MAXLEN];
extern int packet_len;

/**
 * Initialize configuration with default values
 */
int ethudp_config_init(ethudp_config_t *config) {
    if (!config) {
        return -1;
    }
    
    memset(config, 0, sizeof(ethudp_config_t));
    
    // Set default values
    config->udp_workers = DEFAULT_UDP_WORKERS;
    config->raw_workers = DEFAULT_RAW_WORKERS;
    config->cpu_affinity = DEFAULT_CPU_AFFINITY;
    config->batch_size = DEFAULT_BATCH_SIZE;
    config->enable_dynamic_scaling = DEFAULT_DYNAMIC_SCALING;
    config->queue_size = DEFAULT_QUEUE_SIZE;
    config->keepalive_interval = DEFAULT_KEEPALIVE_INTERVAL;
    config->worker_timeout = DEFAULT_WORKER_TIMEOUT;
    

    config->debug = 0;
    config->compression_enabled = 0;
    config->encryption_enabled = 0;
    config->daemon = 0;
    config->benchmark = 0;
    
    return 0;
}

/**
 * Display usage information (short form)
 */
void ethudp_config_usage(void) {
    usage();
}

/**
 * Display usage information
 */
void usage(void) {
    printf("EthUDP Version: %s, by james@ustc.edu.cn (https://github.com/bg6cq/ethudp)\n", ETHUDP_VERSION);
    printf("Usage:\n");
    printf("./EthUDP -e [ options ] localip localport remoteip remoteport eth? \\\n");
    printf("            [ localip localport remoteip remoteport ]\n");
    printf("./EthUDP -i [ options ] localip localport remoteip remoteport ipaddress masklen \\\n");
    printf("            [ localip localport remoteip remoteport ]\n");
    printf("./EthUDP -b [ options ] localip localport remoteip remoteport bridge \\\n");
    printf("            [ localip localport remoteip remoteport ]\n");
    printf("./EthUDP -t localip localport remoteip remoteport eth? [ pcap_filter_string ]\n");
    printf(" options:\n");
    printf("    -p password\n");
    printf("    -enc [ xor|aes-128|aes-192|aes-256 ]\n");
    printf("    -k key_string\n");
    printf("    -lz4 [ 0-9 ]     lz4 acceleration, default is 0(disable), 1 is best, 9 is fast\n");
    printf("    -mss mss         change tcp SYN mss\n");
    printf("    -mtu mtu         fragment udp to mtu - 28 bytes packets, 1036 - 1500\n");
    printf("    -map vlanmap.txt vlan maping\n");
    printf("    -dev dev_name    rename tap interface to dev_name(mode i & b)\n");
    printf("    -n name          name for syslog prefix\n");
    printf("    -c run_cmd       run run_cmd after tunnel connected\n");
    printf("    -x run_seconds   child process exit after run_seconds run\n");
    printf("    -d    enable debug\n");
    printf("    -r    read only of ethernet interface\n");
    printf("    -w    write only of ethernet interface\n");
    printf("    -B    benchmark\n");
    printf("    -l    packet_len\n");
    printf("    -nopromisc    do not set ethernet interface to promisc mode(mode e)\n");
    printf("    -noloopcheck  do not check loopback(-r default do check)\n");
    printf("    -loopcheck    do check loopback\n");
    printf(" HUP  signal: print statistics\n");
    printf(" USR1 signal: reset statistics\n");
    exit(1);
}

/**
 * Parse command line arguments (simplified version)
 */
int ethudp_config_parse_args(ethudp_config_t *config, int argc, char *argv[]) {
    int mode, arg_index;
    return ethudp_config_parse_args_full(config, argc, argv, &mode, &arg_index);
}

/**
 * Parse command line arguments (full version)
 */
int ethudp_config_parse_args_full(ethudp_config_t *config, int argc, char *argv[], 
                            int *mode, int *arg_index) {
    if (!config || !argv || !mode || !arg_index) {
        return -1;
    }
    
    int i = 1;
    int got_one;
    
    *mode = -1;
    *arg_index = 0;
    
    // Parse options
    do {
        got_one = 1;
        if (i >= argc) {
            got_one = 0;
        } else if (strcmp(argv[i], "-e") == 0) {
            *mode = MODE_E;
        } else if (strcmp(argv[i], "-i") == 0) {
            *mode = MODE_I;
        } else if (strcmp(argv[i], "-b") == 0) {
            *mode = MODE_B;
        } else if (strcmp(argv[i], "-t") == 0) {
            *mode = MODE_T;
        } else if (strcmp(argv[i], "-u") == 0) {
            *mode = MODE_U;
        } else if (strcmp(argv[i], "-d") == 0) {
            debug = 1;
        } else if (strcmp(argv[i], "-h") == 0) {
            usage();
        } else if (strcmp(argv[i], "-f") == 0) {
            i++;
            if (argc - i <= 0) usage();
            fixmss = atoi(argv[i]);
        } else if (strcmp(argv[i], "-m") == 0) {
            i++;
            if (argc - i <= 0) usage();
            mtu = atoi(argv[i]);
        } else if (strcmp(argv[i], "-p") == 0) {
            i++;
            if (argc - i <= 0) usage();
            memset(mypassword, 0, MAXLEN);
            strncpy(mypassword, argv[i], MAXLEN - 1);
        } else if (strcmp(argv[i], "-k") == 0) {
            i++;
            if (argc - i <= 0) usage();
            memset(enc_key, 0, MAXLEN);
            strncpy(enc_key, argv[i], MAXLEN - 1);
            enc_key_len = strlen(enc_key);
        } else if (strcmp(argv[i], "-enc") == 0) {
            i++;
            if (argc - i <= 0) usage();
            if (strcmp(argv[i], "xor") == 0) {
                enc_algorithm = 1;
            } else if (strcmp(argv[i], "aes-128") == 0) {
                enc_algorithm = 2;
            } else if (strcmp(argv[i], "aes-192") == 0) {
                enc_algorithm = 3;
            } else if (strcmp(argv[i], "aes-256") == 0) {
                enc_algorithm = 4;
            } else {
                printf("Invalid encryption algorithm: %s\n", argv[i]);
                usage();
            }
        } else if (strcmp(argv[i], "-lz4") == 0) {
            i++;
            if (argc - i <= 0) usage();
            lz4 = atoi(argv[i]);
            if (lz4 < 0 || lz4 > 9) {
                printf("Invalid lz4 acceleration: %d (0-9)\n", lz4);
                usage();
            }
        } else if (strcmp(argv[i], "-mss") == 0) {
            i++;
            if (argc - i <= 0) usage();
            fixmss = atoi(argv[i]);
        } else if (strcmp(argv[i], "-mtu") == 0) {
            i++;
            if (argc - i <= 0) usage();
            mtu = atoi(argv[i]);
            if (mtu < 1036 || mtu > 1500) {
                printf("Invalid MTU: %d (1036-1500)\n", mtu);
                usage();
            }
        } else if (strcmp(argv[i], "-map") == 0) {
            i++;
            if (argc - i <= 0) usage();
            if (load_vlan_map(argv[i]) != 0) {
                printf("Failed to load VLAN map from %s\n", argv[i]);
                return -1;
            }
            vlan_map = 1;
        } else if (strcmp(argv[i], "-dev") == 0) {
            i++;
            if (argc - i <= 0) usage();
            memset(dev_name, 0, MAXLEN);
            strncpy(dev_name, argv[i], MAXLEN - 1);
        } else if (strcmp(argv[i], "-n") == 0) {
            i++;
            if (argc - i <= 0) usage();
            memset(syslog_name, 0, MAXLEN);
            strncpy(syslog_name, argv[i], MAXLEN - 1);
        } else if (strcmp(argv[i], "-x") == 0) {
            i++;
            if (argc - i <= 0) usage();
            run_seconds = atoi(argv[i]);
        } else if (strcmp(argv[i], "-B") == 0) {
            config->benchmark = 1;
        } else if (strcmp(argv[i], "-l") == 0) {
            i++;
            if (argc - i <= 0) usage();
            packet_len = atoi(argv[i]);
        } else if (strcmp(argv[i], "-nopromisc") == 0) {
            nopromisc = 1;
        } else if (strcmp(argv[i], "-noloopcheck") == 0) {
            loopback_check = 0;
        } else if (strcmp(argv[i], "-loopcheck") == 0) {
            loopback_check = 1;
        } else if (strcmp(argv[i], "-a") == 0) {
            i++;
            if (argc - i <= 0) usage();
            enc_algorithm = atoi(argv[i]);
        } else if (strcmp(argv[i], "-r") == 0) {
            read_only = 1;
        } else if (strcmp(argv[i], "-w") == 0) {
            write_only = 1;
        } else if (strcmp(argv[i], "-z") == 0) {
            lz4 = 1;
        } else if (strcmp(argv[i], "-v") == 0) {
            i++;
            if (argc - i <= 0) usage();
            if (load_vlan_map(argv[i]) != 0) {
                printf("Failed to load VLAN map from %s\n", argv[i]);
                return -1;
            }
            vlan_map = 1;
        } else if (strcmp(argv[i], "-s") == 0) {
            i++;
            if (argc - i <= 0) usage();
            run_seconds = atoi(argv[i]);
        } else if (strcmp(argv[i], "-c") == 0) {
            i++;
            if (argc - i <= 0) usage();
            memset(run_cmd, 0, MAXLEN);
            strncpy(run_cmd, argv[i], MAXLEN - 1);
        } else if (strcmp(argv[i], "-wu") == 0) {
            i++;
            if (argc - i <= 0) usage();
            config->udp_workers = atoi(argv[i]);
            if (config->udp_workers < 1 || config->udp_workers > MAX_WORKERS) {
                printf("invalid UDP workers count %d (1-%d)\n", 
                       config->udp_workers, MAX_WORKERS);
                usage();
            }
        } else if (strcmp(argv[i], "-wr") == 0) {
            i++;
            if (argc - i <= 0) usage();
            config->raw_workers = atoi(argv[i]);
            if (config->raw_workers < 1 || config->raw_workers > MAX_WORKERS) {
                printf("invalid RAW workers count %d (1-%d)\n", 
                       config->raw_workers, MAX_WORKERS);
                usage();
            }
        } else if (strcmp(argv[i], "-a") == 0) {
            i++;
            if (argc - i <= 0) usage();
            config->cpu_affinity = atoi(argv[i]);
            if (config->cpu_affinity < 0 || config->cpu_affinity > 1) {
                printf("invalid CPU affinity value %d (0 or 1)\n", 
                       config->cpu_affinity);
                usage();
            }
        } else if (strcmp(argv[i], "-bs") == 0) {
            i++;
            if (argc - i <= 0) usage();
            config->batch_size = atoi(argv[i]);
            if (config->batch_size < 1 || config->batch_size > MAX_BATCH_SIZE) {
                printf("invalid batch size %d (1-%d)\n", 
                       config->batch_size, MAX_BATCH_SIZE);
                usage();
            }
        } else if (strcmp(argv[i], "-ds") == 0) {
            i++;
            if (argc - i <= 0) usage();
            config->enable_dynamic_scaling = atoi(argv[i]);
            if (config->enable_dynamic_scaling < 0 || config->enable_dynamic_scaling > 1) {
                printf("invalid dynamic scaling value %d (0 or 1)\n", 
                       config->enable_dynamic_scaling);
                usage();
            }
        } else {
            got_one = 0;
        }
        
        if (got_one) {
            i++;
        }
    } while (got_one);
    
    // Validate argument count based on mode
    if ((*mode == MODE_E) || (*mode == MODE_B)) {
        if (argc - i == 9) {
            master_slave = 1;
        } else if (argc - i != 5) {
            usage();
        }
    }
    
    if (*mode == MODE_I) {
        if (argc - i == 10) {
            master_slave = 1;
        } else if (argc - i != 6) {
            usage();
        }
    }
    
    if (*mode == MODE_T || *mode == MODE_U) {
        if (argc - i < 5) {
            usage();
        }
    }
    
    // Set default encryption if needed
    if ((enc_algorithm != 0) && (enc_key_len == 0)) {
        memset(enc_key, 0, MAXLEN);
        strncpy(enc_key, "123456", MAXLEN - 1);
        enc_key_len = strlen(enc_key);
    } else if ((enc_algorithm == 0) && (enc_key_len != 0)) {
        enc_algorithm = AES_128;
    }
    
    if (*mode == -1) {
        usage();
    }
    
    *arg_index = i;
    return 0;
}

/**
 * Load VLAN mapping from file
 */
int load_vlan_map(const char *filename) {
    FILE *fp;
    char line[256];
    int from_vlan, to_vlan;
    
    if (!filename) {
        return -1;
    }
    
    // Initialize VLAN mapping to identity
    for (int i = 0; i < 4096; i++) {
        my_vlan[i] = i;
    }
    
    fp = fopen(filename, "r");
    if (!fp) {
        printf("Cannot open VLAN map file: %s\n", filename);
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }
        
        if (sscanf(line, "%d %d", &from_vlan, &to_vlan) == 2) {
            if (from_vlan >= 0 && from_vlan < 4096 && 
                to_vlan >= 0 && to_vlan < 4096) {
                my_vlan[from_vlan] = to_vlan;
            }
        }
    }
    
    fclose(fp);
    return 0;
}

/**
 * Print current configuration
 */
void ethudp_config_print(const ethudp_config_t *config) {
    if (!config) {
        return;
    }
    
    printf("Configuration:\n");
    printf("         debug = %d\n", debug);
    printf("          mode = %d (0 raw eth bridge, 1 interface, 2 bridge, 3 tcpdump, 4 tcpdump udp)\n", config->mode);
    printf("      password = %s\n", mypassword);
    printf(" enc_algorithm = %s\n", enc_algorithm == XOR ? "xor"
#ifdef ENABLE_OPENSSL
           : enc_algorithm == AES_128 ? "aes-128" 
           : enc_algorithm == AES_192 ? "aes-192" 
           : enc_algorithm == AES_256 ? "aes-256"
#endif
           : "none");
    printf("       enc_key = %s\n", enc_key);
    printf("       key_len = %d\n", enc_key_len);
    printf("  master_slave = %d\n", master_slave);
    printf("           mss = %d\n", fixmss);
    printf("           mtu = %d\n", mtu);
    printf("     read_only = %d\n", read_only);
    printf("loopback_check = %d\n", loopback_check);
    printf("    write_only = %d\n", write_only);
    printf("     nopromisc = %d\n", nopromisc);
    printf("           lz4 = %d\n", lz4);
    printf("      dev_name = %s\n", dev_name);
    printf("       run_cmd = %s\n", run_cmd);
    printf("   run_seconds = %d\n", run_seconds);
    printf("   udp_workers = %d\n", config->udp_workers);
    printf("   raw_workers = %d\n", config->raw_workers);
    printf("  cpu_affinity = %d\n", config->cpu_affinity);
    printf("    batch_size = %d\n", config->batch_size);
    printf("dynamic_scaling = %d\n", config->enable_dynamic_scaling);
    
    if (vlan_map) {
        printf("vlan mapping:\n");
        for (int vlan = 0; vlan < 4095; vlan++) {
            if (my_vlan[vlan] != vlan) {
                printf(" %4d --> %4d\n", vlan, my_vlan[vlan]);
            }
        }
    }
    printf("\n");
}

/**
 * Validate configuration
 */
int ethudp_config_validate(const ethudp_config_t *config) {
    if (!config) {
        return -1;
    }
    
    // Validate worker counts
    if (config->udp_workers < MIN_WORKERS || config->udp_workers > MAX_WORKERS) {
        printf("Invalid UDP workers count: %d (range: %d-%d)\n", 
               config->udp_workers, MIN_WORKERS, MAX_WORKERS);
        return -1;
    }
    
    if (config->raw_workers < MIN_WORKERS || config->raw_workers > MAX_WORKERS) {
        printf("Invalid RAW workers count: %d (range: %d-%d)\n", 
               config->raw_workers, MIN_WORKERS, MAX_WORKERS);
        return -1;
    }
    
    // Validate batch size
    if (config->batch_size < MIN_BATCH_SIZE || config->batch_size > MAX_BATCH_SIZE) {
        printf("Invalid batch size: %d (range: %d-%d)\n", 
               config->batch_size, MIN_BATCH_SIZE, MAX_BATCH_SIZE);
        return -1;
    }
    
    // Validate buffer sizes
    if (config->queue_size < MIN_QUEUE_SIZE || config->queue_size > MAX_QUEUE_SIZE) {
        printf("Invalid queue size: %d (range: %d-%d)\n", 
               config->queue_size, MIN_QUEUE_SIZE, MAX_QUEUE_SIZE);
        return -1;
    }
    
    // Validate timeouts
    if (config->worker_timeout < MIN_WORKER_TIMEOUT || 
        config->worker_timeout > MAX_WORKER_TIMEOUT) {
        printf("Invalid worker timeout: %d (range: %d-%d)\n", 
               config->worker_timeout, MIN_WORKER_TIMEOUT, MAX_WORKER_TIMEOUT);
        return -1;
    }
    
    return 0;
}

/**
 * Load configuration from file
 */
int ethudp_config_load(ethudp_config_t *config, const char *filename) {
    FILE *fp;
    char line[CONFIG_LINE_MAX];
    char key[CONFIG_KEY_MAX];
    char value[CONFIG_VALUE_MAX];
    
    if (!config || !filename) {
        return -1;
    }
    
    fp = fopen(filename, "r");
    if (!fp) {
        return -1;
    }
    
    while (fgets(line, sizeof(line), fp)) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') {
            continue;
        }
        
        if (sscanf(line, "%s = %s", key, value) == 2) {
            ethudp_config_set_value(config, key, value);
        }
    }
    
    fclose(fp);
    return 0;
}

/**
 * Save configuration to file
 */
int ethudp_config_save(const ethudp_config_t *config, const char *filename) {
    FILE *fp;
    
    if (!config || !filename) {
        return -1;
    }
    
    fp = fopen(filename, "w");
    if (!fp) {
        return -1;
    }
    
    fprintf(fp, "# EthUDP Configuration File\n");
    fprintf(fp, "# Generated automatically\n\n");
    
    fprintf(fp, "udp_workers = %d\n", config->udp_workers);
    fprintf(fp, "raw_workers = %d\n", config->raw_workers);
    fprintf(fp, "cpu_affinity = %d\n", config->cpu_affinity);
    fprintf(fp, "batch_size = %d\n", config->batch_size);
    fprintf(fp, "enable_dynamic_scaling = %d\n", config->enable_dynamic_scaling);
    fprintf(fp, "queue_size = %d\n", config->queue_size);
    fprintf(fp, "worker_timeout = %d\n", config->worker_timeout);
    fprintf(fp, "keepalive_interval = %d\n", config->keepalive_interval);
    fprintf(fp, "debug = %d\n", config->debug);
    fprintf(fp, "compression_enabled = %d\n", config->compression_enabled);
    fprintf(fp, "encryption_enabled = %d\n", config->encryption_enabled);
    fprintf(fp, "vlan_map = %d\n", config->vlan_map);
    fprintf(fp, "daemon = %d\n", config->daemon);
    fprintf(fp, "benchmark = %d\n", config->benchmark);
    
    fclose(fp);
    return 0;
}

/**
 * Set configuration value by key
 */
int ethudp_config_set_value(ethudp_config_t *config, const char *key, const char *value) {
    if (!config || !key || !value) {
        return -1;
    }
    
    if (strcmp(key, "udp_workers") == 0) {
        config->udp_workers = atoi(value);
    } else if (strcmp(key, "raw_workers") == 0) {
        config->raw_workers = atoi(value);
    } else if (strcmp(key, "cpu_affinity") == 0) {
        config->cpu_affinity = atoi(value);
    } else if (strcmp(key, "batch_size") == 0) {
        config->batch_size = atoi(value);
    } else if (strcmp(key, "enable_dynamic_scaling") == 0) {
        config->enable_dynamic_scaling = atoi(value);
    } else if (strcmp(key, "queue_size") == 0) {
        config->queue_size = atoi(value);
    } else if (strcmp(key, "worker_timeout") == 0) {
        config->worker_timeout = atoi(value);
    } else if (strcmp(key, "keepalive_interval") == 0) {
        config->keepalive_interval = atoi(value);
    } else if (strcmp(key, "debug") == 0) {
        config->debug = atoi(value);
    } else if (strcmp(key, "compression_enabled") == 0) {
        config->compression_enabled = atoi(value);
    } else if (strcmp(key, "encryption_enabled") == 0) {
        config->encryption_enabled = atoi(value);
    } else if (strcmp(key, "daemon") == 0) {
        config->daemon = atoi(value);
    } else if (strcmp(key, "benchmark") == 0) {
        config->benchmark = atoi(value);
    } else {
        return -1; // Unknown key
    }
    
    return 0;
}

/**
 * Get configuration value by key
 */
int ethudp_config_get_value(const ethudp_config_t *config, const char *key, char *value, size_t value_size) {
    if (!config || !key || !value || value_size == 0) {
        return -1;
    }
    
    if (strcmp(key, "udp_workers") == 0) {
        snprintf(value, value_size, "%d", config->udp_workers);
    } else if (strcmp(key, "raw_workers") == 0) {
        snprintf(value, value_size, "%d", config->raw_workers);
    } else if (strcmp(key, "cpu_affinity") == 0) {
        snprintf(value, value_size, "%d", config->cpu_affinity);
    } else if (strcmp(key, "batch_size") == 0) {
        snprintf(value, value_size, "%d", config->batch_size);
    } else if (strcmp(key, "enable_dynamic_scaling") == 0) {
        snprintf(value, value_size, "%d", config->enable_dynamic_scaling);
    } else if (strcmp(key, "queue_size") == 0) {
        snprintf(value, value_size, "%d", config->queue_size);
    } else if (strcmp(key, "worker_timeout") == 0) {
        snprintf(value, value_size, "%d", config->worker_timeout);
    } else if (strcmp(key, "keepalive_interval") == 0) {
        snprintf(value, value_size, "%d", config->keepalive_interval);
    } else if (strcmp(key, "debug") == 0) {
        snprintf(value, value_size, "%d", config->debug);
    } else if (strcmp(key, "compression_enabled") == 0) {
        snprintf(value, value_size, "%d", config->compression_enabled);
    } else if (strcmp(key, "encryption_enabled") == 0) {
        snprintf(value, value_size, "%d", config->encryption_enabled);
    } else if (strcmp(key, "daemon") == 0) {
        snprintf(value, value_size, "%d", config->daemon);
    } else if (strcmp(key, "benchmark") == 0) {
        snprintf(value, value_size, "%d", config->benchmark);
    } else {
        return -1; // Unknown key
    }
    
    return 0;
}

/**
 * Clone configuration
 */
int ethudp_config_clone(ethudp_config_t *dest, const ethudp_config_t *src) {
    if (!dest || !src) {
        return -1;
    }
    
    memcpy(dest, src, sizeof(ethudp_config_t));
    return 0;
}

/**
 * Compare two configurations
 */
int ethudp_config_compare(const ethudp_config_t *config1, const ethudp_config_t *config2) {
    if (!config1 || !config2) {
        return -1;
    }
    
    return memcmp(config1, config2, sizeof(ethudp_config_t));
}

/**
 * Apply runtime configuration changes
 */
int ethudp_config_apply_runtime_changes(const ethudp_config_t *config) {
    if (!config) {
        return -1;
    }
    
    // Apply runtime configuration changes to global variables
    // This function would typically update global configuration state
    // For now, we just validate the configuration
    return ethudp_config_validate(config);
}