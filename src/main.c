/**
 * @file main.c
 * @brief Main application entry point for EthUDP
 * 
 * This is the main application file that handles initialization,
 * argument parsing, and coordination of all EthUDP modules.
 */

#include "ethudp_common.h"
#include "ethudp_config.h"
#include "ethudp_network.h"
#include "ethudp_utils.h"
#include "ethudp_dynamic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/wait.h>
#include <pcap.h>

// Global variables (defined in ethudp_common.h)
int daemon_proc = 0;
volatile int debug = 0;
int mode = -1;
int mtu = 0;
int udp_frg_seq = 0;
int master_slave = 0;
int read_only = 0, write_only = 0;
int fixmss = 0;
int nopromisc = 0;
int loopback_check = 0;
int packet_len = 1500;
char name[MAXLEN];
char run_cmd[MAXLEN];
char dev_name[IFNAMSIZ];
char syslog_name[MAXLEN];
int run_seconds = 0;

int32_t ifindex;

char mypassword[MAXLEN];
int enc_algorithm;
unsigned char enc_key[MAXLEN];
#ifdef ENABLE_OPENSSL
unsigned char enc_iv[EVP_MAX_IV_LENGTH];
#endif
int enc_key_len = 0;

int fdudp[2], fdraw;
int nat[2];
pcap_t *pcap_handle;

int lz4 = 0;
volatile long long udp_total = 0;
volatile long long compress_overhead = 0;
volatile long long compress_save = 0;
volatile long long encrypt_overhead = 0;

int vlan_map = 0;
int my_vlan[4096];
int remote_vlan[4096];

volatile struct sockaddr_storage local_addr[2];
volatile struct sockaddr_storage cmd_remote_addr[2];
volatile struct sockaddr_storage remote_addr[2];
volatile unsigned long myticket, last_pong[2];
volatile unsigned long ping_send[2], ping_recv[2], pong_send[2], pong_recv[2];
volatile unsigned long raw_send_pkt, raw_send_byte, raw_recv_pkt, raw_recv_byte;
volatile unsigned long udp_send_pkt[2], udp_send_byte[2], udp_recv_pkt[2], udp_recv_byte[2];
volatile unsigned long udp_send_err[2], raw_send_err;
volatile int master_status = STATUS_BAD;
volatile int slave_status = STATUS_BAD;
volatile int current_remote = MASTER;
volatile int got_signal = 1;

// Global configuration and worker pool
ethudp_config_t global_config = {
    .mode = -1,
    .debug = 0,
    .master_slave = 0,
    
    .udp_workers = DEFAULT_UDP_WORKERS,
    .raw_workers = DEFAULT_RAW_WORKERS,
    .batch_size = DEFAULT_BATCH_SIZE,
    .queue_size = DEFAULT_QUEUE_SIZE,
    
    .enable_so_reuseport = ENABLE_SO_REUSEPORT,
    .enable_cpu_affinity = ENABLE_CPU_AFFINITY,
    .cpu_affinity = 0,
    .enable_numa_optimization = ENABLE_NUMA_OPT,
    .enable_batch_processing = ENABLE_BATCH_PROCESSING,
    .enable_dynamic_scaling = 1,
    
    .packet_buffer_count = DEFAULT_BUFFER_COUNT,
    .packet_buffer_size = MAX_PACKET_SIZE,
    .socket_rcvbuf_size = 16 * 1024 * 1024,
    .socket_sndbuf_size = 16 * 1024 * 1024,
    
    .encryption_enabled = 0,
    .compression_enabled = 0,
    
    .keepalive_interval = 10,
    .worker_timeout = 30,
    .stats_interval = 5
};

struct worker_pool global_worker_pool;
dynamic_system_t* global_dynamic_system = NULL;

// Forward declarations
void print_worker_statistics(void) {
    printf("Worker Statistics:\n");
    printf("  UDP Workers: %d\n", global_worker_pool.udp_worker_count);
    printf("  RAW Workers: %d\n", global_worker_pool.raw_worker_count);
    // TODO: Add detailed statistics
}

void reset_worker_statistics(void) {
    printf("Resetting worker statistics...\n");
    // TODO: Reset worker counters
}
void* process_udp_to_raw_worker(void *arg);
void* process_raw_to_udp_worker(void *arg);
void* worker_stats_reporter(void *arg);
void* process_udp_to_raw_master(void *arg);
void* process_udp_to_raw_slave(void *arg);
void* send_keepalive_to_udp(void *arg);
void process_raw_to_udp(void);
int start_worker_threads(void) {
    printf("Starting worker threads...\n");
    // TODO: Initialize and start worker threads
    return 0;
}

int stop_worker_threads(void) {
    printf("Stopping worker threads...\n");
    // TODO: Stop and cleanup worker threads
    return 0;
}
void read_vlan_map_file(const char *filename);

// Signal handlers
void sig_handler_hup(int signo)
{
    got_signal = 1;
    // Print worker statistics if using optimized system
    if (global_worker_pool.running) {
        print_worker_statistics();
    }
}

void sig_handler_usr1(int signo)
{
    udp_total = compress_overhead = compress_save = encrypt_overhead = 0;
    raw_send_pkt = raw_send_byte = raw_recv_pkt = raw_recv_byte = 0;
    udp_send_pkt[0] = udp_send_byte[0] = udp_recv_pkt[0] = udp_recv_byte[0] = 0;
    udp_send_pkt[1] = udp_send_byte[1] = udp_recv_pkt[1] = udp_recv_byte[1] = 0;
    
    // Reset worker statistics if using optimized system
    if (global_worker_pool.running) {
        reset_worker_statistics();
    }
}

// Benchmark function
#define BENCHCNT 300000

void do_benchmark(void)
{
#ifdef ENABLE_OPENSSL
    u_int8_t buf[MAX_PACKET_SIZE];
    u_int8_t nbuf[MAX_PACKET_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned long int pkt_cnt;
    unsigned long int pkt_len = 0, pkt_len_send = 0;
    int len;
    struct timeval start_tm, end_tm;
    gettimeofday(&start_tm, NULL);
    fprintf(stderr, "benchmarking for %d packets, %d size...\n", BENCHCNT, packet_len);
    fprintf(stderr, "enc_algorithm = %s\n",
        enc_algorithm == XOR ? "xor" : enc_algorithm == AES_128 ? "aes-128" : enc_algorithm == AES_192 ? "aes-192" : enc_algorithm ==
        AES_256 ? "aes-256" : "none");
    fprintf(stderr, "      enc_key = %s\n", enc_key);
    fprintf(stderr, "      key_len = %d\n", enc_key_len);
    fprintf(stderr, "          lz4 = %d\n", lz4);
    pkt_cnt = BENCHCNT;
    memset(buf, 'a', packet_len);

    while (1) {
        len = packet_len;
        pkt_len += len;
        len = do_encrypt(buf, len, nbuf);
        pkt_len_send += len;
        pkt_cnt--;
        if (pkt_cnt == 0)
            break;
    }
    gettimeofday(&end_tm, NULL);
    float tspan = ((end_tm.tv_sec - start_tm.tv_sec) * 1000000L + end_tm.tv_usec) - start_tm.tv_usec;
    tspan = tspan / 1000000L;
    fprintf(stderr, "%0.3f seconds\n", tspan);
    fprintf(stderr, "PPS: %.0f PKT/S, %lu(%lu) Byte, %.0f(%.0f) Byte/S\n", (float)BENCHCNT / tspan, pkt_len, pkt_len_send, 1.0 * pkt_len / tspan,
        1.0 * pkt_len_send / tspan);
    fprintf(stderr, "UDP BPS: %.0f(%.0f) BPS\n", 8.0 * pkt_len / tspan, 8.0 * pkt_len_send / tspan);
#endif
    exit(0);
}

// Initialize application
int initialize_application(void)
{
    // Initialize global variables
    memset(name, 0, MAXLEN);
    memset(run_cmd, 0, MAXLEN);
    memset(dev_name, 0, IFNAMSIZ);
    memset(mypassword, 0, MAXLEN);
    memset(enc_key, 0, MAXLEN);
    
    // Initialize VLAN mapping
    for (int i = 0; i < 4096; i++) {
        my_vlan[i] = i;
        remote_vlan[i] = i;
    }
    
    // Initialize network addresses
    memset((void*)local_addr, 0, sizeof(local_addr));
    memset((void*)cmd_remote_addr, 0, sizeof(cmd_remote_addr));
    memset((void*)remote_addr, 0, sizeof(remote_addr));
    
    // Initialize statistics
    myticket = 0;
    last_pong[0] = last_pong[1] = 0;
    ping_send[0] = ping_send[1] = 0;
    ping_recv[0] = ping_recv[1] = 0;
    pong_send[0] = pong_send[1] = 0;
    pong_recv[0] = pong_recv[1] = 0;
    raw_send_pkt = raw_send_byte = raw_recv_pkt = raw_recv_byte = 0;
    udp_send_pkt[0] = udp_send_byte[0] = udp_recv_pkt[0] = udp_recv_byte[0] = 0;
    udp_send_pkt[1] = udp_send_byte[1] = udp_recv_pkt[1] = udp_recv_byte[1] = 0;
    udp_send_err[0] = udp_send_err[1] = 0;
    raw_send_err = 0;
    
    // Initialize worker pool
    memset(&global_worker_pool, 0, sizeof(global_worker_pool));
    
    return 0;
}

// Setup network connections based on mode
int setup_network_connections(int argc, char *argv[], int arg_start)
{
    int i = arg_start;
    
    if (mode == MODEE) {    // eth bridge mode
        fdudp[MASTER] = ethudp_udp_xconnect(argv[i], argv[i + 1], argv[i + 2], argv[i + 3], MASTER);
        if (master_slave)
            fdudp[SLAVE] = ethudp_udp_xconnect(argv[i + 5], argv[i + 6], argv[i + 7], argv[i + 8], SLAVE);
        fdraw = ethudp_open_rawsocket(argv[i + 4], &ifindex);
    } else if (mode == MODEI) {    // interface mode
        char *actualname = NULL;
        char buf[MAXLEN];
        fdudp[MASTER] = ethudp_udp_xconnect(argv[i], argv[i + 1], argv[i + 2], argv[i + 3], MASTER);
        if (master_slave)
            fdudp[SLAVE] = ethudp_udp_xconnect(argv[i + 6], argv[i + 7], argv[i + 8], argv[i + 9], SLAVE);
        fdraw = ethudp_open_tun("tap", &actualname);
        if (dev_name[0])
            snprintf(buf, MAXLEN, "%s link set %s name %s; %s addr add %s/%s dev %s; %s link set %s up",
                 IPCMD, actualname, dev_name, IPCMD, argv[i + 4], argv[i + 5], dev_name, IPCMD, dev_name);
        else
            snprintf(buf, MAXLEN, "%s addr add %s/%s dev %s; %s link set %s up", IPCMD, argv[i + 4], argv[i + 5], actualname, IPCMD, actualname);
        if (debug)
            printf(" run cmd: %s\n", buf);
        if (system(buf) != 0)
            printf(" run cmd: %s returned not 0\n", buf);
        if (debug) {
            snprintf(buf, MAXLEN, "%s addr", IPCMD);
            if (system(buf) != 0)
                printf(" run cmd: %s returned not 0\n", buf);
        }
    } else if (mode == MODEB) {    // bridge mode
        char *actualname = NULL;
        char buf[MAXLEN];
        fdudp[MASTER] = ethudp_udp_xconnect(argv[i], argv[i + 1], argv[i + 2], argv[i + 3], MASTER);
        if (master_slave)
            fdudp[SLAVE] = ethudp_udp_xconnect(argv[i + 5], argv[i + 6], argv[i + 7], argv[i + 8], SLAVE);
        fdraw = ethudp_open_tun("tap", &actualname);
        if (dev_name[0])
            snprintf(buf, MAXLEN, "%s link set %s name %s; %s link set %s up; %s addif %s %s",
                 IPCMD, actualname, dev_name, IPCMD, dev_name, BRIDGECMD, argv[i + 4], dev_name);
        else
            snprintf(buf, MAXLEN, "%s link set %s up; %s addif %s %s", IPCMD, actualname, BRIDGECMD, argv[i + 4], actualname);
        if (debug)
            printf(" run cmd: %s\n", buf);
        if (system(buf) != 0)
            printf(" run cmd: %s returned not 0\n", buf);
        if (debug) {
            snprintf(buf, MAXLEN, "%s addr", IPCMD);
            if (system(buf) != 0)
                printf(" run cmd: %s returned not 0\n", buf);
            snprintf(buf, MAXLEN, "%s show", BRIDGECMD);
            if (system(buf) != 0)
                printf(" run cmd: %s returned not 0\n", buf);
        }
    } else if ((mode == MODET) || (mode == MODEU)) {    // tcpdump mode
        char errbuf[PCAP_ERRBUF_SIZE];
        read_only = 1;
        fdudp[MASTER] = ethudp_udp_xconnect(argv[i], argv[i + 1], argv[i + 2], argv[i + 3], MASTER);
        pcap_handle = pcap_open_live(argv[i + 4], MAX_PACKET_SIZE, 0, 1000, errbuf);
        if (argc - i == 6) {
            struct bpf_program pgm;
            if (pcap_compile(pcap_handle, &pgm, argv[i + 5], 1, PCAP_NETMASK_UNKNOWN) == -1) {
                err_msg("pcap_filter compile error\n");
                exit(0);
            }
            if (pcap_setfilter(pcap_handle, &pgm) == -1) {
                err_msg("pcap_setfilter error\n");
                exit(0);
            }
        }
    }
    
    return 0;
}

// Run the main application loop
int run_application(void)
{
    pthread_t tid;
    
    // Check if we should use the new optimized worker system
    if (global_config.udp_workers > 1 || global_config.raw_workers > 1 || 
        global_config.cpu_affinity || global_config.batch_size > 1 || 
        global_config.enable_dynamic_scaling) {
        
        // Use new optimized worker system
        Debug("Using optimized worker system with dynamic scaling: %s", 
              global_config.enable_dynamic_scaling ? "enabled" : "disabled");
        
        // Initialize dynamic thread management system
        if (global_config.enable_dynamic_scaling) {
            global_dynamic_system = malloc(sizeof(dynamic_system_t));
            if (ethudp_init_dynamic_system(global_dynamic_system) != 0) {
                err_sys("Failed to initialize dynamic system");
            }
            if (global_dynamic_system == NULL) {
                err_sys("Failed to initialize dynamic system");
            }
            Debug("Dynamic thread management system initialized");
        }
        
        // Start worker threads
        if (start_worker_threads() != 0) {
            err_sys("Failed to start worker threads");
        }
        
        // Start dynamic system if enabled
        if (global_config.enable_dynamic_scaling && global_dynamic_system) {
            if (ethudp_start_dynamic_system(global_dynamic_system) != 0) {
                err_sys("Failed to start dynamic system");
            }
            Debug("Dynamic scaling system started");
        }
        
        // Keep alive thread for non-tcpdump modes
        if ((mode != MODET) && (mode != MODEU)) {
            if (pthread_create(&tid, NULL, (void *)send_keepalive_to_udp, NULL) != 0)
                err_sys("pthread_create send_keepalive error");
        }
        
        // Main thread handles RAW socket reading for tcpdump modes
        if (mode == MODET || mode == MODEU) {
            process_raw_to_udp();
        } else {
            // For other modes, main thread can sleep or handle signals
            while (global_worker_pool.running) {
                sleep(1);
            }
        }
        
        // Cleanup
        if (global_config.enable_dynamic_scaling) {
            ethudp_stop_dynamic_system(global_dynamic_system);
            Debug("Dynamic thread management system stopped");
            free(global_dynamic_system);
            global_dynamic_system = NULL;
        }
        stop_worker_threads();
        
    } else {
        // Use original single-threaded system for compatibility
        Debug("Using original single-threaded system");
        
        // create a pthread to forward packets from master udp to raw
        if (pthread_create(&tid, NULL, (void *)process_udp_to_raw_master, NULL) != 0)
            err_sys("pthread_create udp_to_raw_master error");

        // create a pthread to forward packets from slave udp to raw
        if (master_slave)
            if (pthread_create(&tid, NULL, (void *)process_udp_to_raw_slave, NULL) != 0)
                err_sys("pthread_create udp_to_raw_slave error");

        if ((mode != MODET) && (mode != MODEU))
            if (pthread_create(&tid, NULL, (void *)send_keepalive_to_udp, NULL) != 0)
                err_sys("pthread_create send_keepalive error");

        //  forward packets from raw to udp
        process_raw_to_udp();
    }
    
    return 0;
}

// Main function
int main(int argc, char *argv[])
{
    
    // Initialize application
    if (initialize_application() != 0) {
        err_quit("Failed to initialize application");
    }
    
    // Parse command line arguments
    ethudp_config_t config;
    ethudp_config_init(&config);
    
    int arg_start = ethudp_config_parse_args(&config, argc, argv);
    if (arg_start < 0) {
        ethudp_config_usage();
        exit(1);
    }
    
    // Apply configuration to global variables
    debug = config.debug;
    mode = config.mode;
    master_slave = config.master_slave;
    read_only = config.read_only;
    write_only = config.write_only;
    nopromisc = config.nopromisc;
    loopback_check = config.loopback_check;
    fixmss = config.fixmss;
    mtu = config.mtu;
    lz4 = config.lz4;
    packet_len = config.packet_len;
    run_seconds = config.run_seconds;
    enc_algorithm = config.enc_algorithm;
    enc_key_len = config.enc_key_len;
    vlan_map = config.vlan_map;
    
    // Copy string fields
    strncpy(name, config.name, MAXLEN - 1);
    strncpy(run_cmd, config.run_cmd, MAXLEN - 1);
    strncpy(dev_name, config.dev_name, IFNAMSIZ - 1);
    strncpy(mypassword, config.password, MAXLEN - 1);
    memcpy(enc_key, config.enc_key, MAXLEN);
    
    // Copy global config
    global_config.mode = config.mode;
    global_config.debug = config.debug;
    global_config.master_slave = config.master_slave;
    global_config.udp_workers = config.udp_workers;
    global_config.raw_workers = config.raw_workers;
    global_config.cpu_affinity = config.cpu_affinity;
    global_config.batch_size = config.batch_size;
    global_config.enable_dynamic_scaling = config.enable_dynamic_scaling;
    
    // Validate configuration
    if (ethudp_config_validate(&config) != 0) {
        err_quit("Invalid configuration");
    }
    
    // Print configuration if debug mode
    if (debug) {
        ethudp_config_print(&config);
    }
    
    // Handle benchmark mode
    if (config.benchmark) {
        do_benchmark();
    }
    
    // Daemonize if not in debug mode
    if (debug == 0) {
        ethudp_daemon_init("EthUDP", LOG_DAEMON);
        while (1) {
            int pid;
            pid = fork();
            if (pid == 0)    // child do the job
                break;
            else if (pid == -1)    // error
                exit(0);
            else
                wait(NULL);    // parent wait for child
            sleep(2);    // wait 2 second, and rerun
        }
    }
    
    // Setup signal handlers
    signal(SIGHUP, sig_handler_hup);
    signal(SIGUSR1, sig_handler_usr1);
    
    // Setup network connections
    if (setup_network_connections(argc, argv, arg_start) != 0) {
        err_quit("Failed to setup network connections");
    }
    
    // Run user command if specified
    if (run_cmd[0]) {
        if (debug)
            printf(" run user cmd: %s\n", run_cmd);
        if (system(run_cmd) != 0)
            printf(" run cmd: %s returned not 0\n", run_cmd);
    }
    
    // Run main application
    return run_application();
}

// ============================================================================
// STUB IMPLEMENTATIONS FOR MISSING FUNCTIONS
// ============================================================================

void* process_udp_to_raw_master(void *arg)
{
    // TODO: Implement UDP to RAW master processing
    Debug("process_udp_to_raw_master thread started");
    while (1) {
        sleep(1);
        // Basic implementation would read from UDP socket and forward to RAW
    }
    return NULL;
}

void* process_udp_to_raw_slave(void *arg)
{
    // TODO: Implement UDP to RAW slave processing
    Debug("process_udp_to_raw_slave thread started");
    while (1) {
        sleep(1);
        // Basic implementation would read from UDP socket and forward to RAW
    }
    return NULL;
}

void* send_keepalive_to_udp(void *arg)
{
    // TODO: Implement keepalive sending
    Debug("send_keepalive_to_udp thread started");
    while (1) {
        sleep(30); // Send keepalive every 30 seconds
        // Basic implementation would send keepalive packets
    }
    return NULL;
}

void process_raw_to_udp(void)
{
    // TODO: Implement RAW to UDP processing
    Debug("process_raw_to_udp started");
    while (1) {
        sleep(1);
        // Basic implementation would read from RAW socket and forward to UDP
    }
}