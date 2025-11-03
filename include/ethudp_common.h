/* EthUDP Common Definitions
 * Common constants, macros and includes used across all modules
 * by james@ustc.edu.cn 2009.04.02
 */

#ifndef ETHUDP_COMMON_H
#define ETHUDP_COMMON_H

// Guard for GNU source extensions
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// Standard includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <time.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <lz4.h>

// LZ4 compression constants
#define LZ4_COMPRESS_LEVEL      1
#define LZ4_ACCELERATION        1
#define LZ4_SPACE               64  // Extra space for LZ4 compression overhead
#include <pcap.h>
#include <sched.h>
#include <numa.h>
#include <sys/mman.h>

// OpenSSL support
#define ENABLE_OPENSSL 1
#ifdef ENABLE_OPENSSL
#include <openssl/evp.h>
#define AES_128 2
#define AES_192 3
#define AES_256 4
#else
#define EVP_MAX_BLOCK_LENGTH 0
#endif

// Packet auxdata support for VLAN
#define HAVE_PACKET_AUXDATA 1

// Core constants
#define MAXLEN              2048
#define MAX_PACKET_SIZE     9234    // Jumbo Frame
#define MAXFD               64

// Status definitions
#define STATUS_BAD          0
#define STATUS_OK           1
#define MASTER              0
#define SLAVE               1
#define ETHP8021Q           0x8100

// Mode definitions
#define MODEE               0       // raw ether bridge mode
#define MODEI               1       // tap interface mode
#define MODEB               2       // bridge mode
#define MODET               3       // tcpdump full packet to remote
#define MODEU               4       // tcpdump udp packet to remote

// Mode aliases for consistency
#define MODE_E              MODEE
#define MODE_I              MODEI
#define MODE_B              MODEB
#define MODE_T              MODET
#define MODE_U              MODEU

// Multiprocess optimization constants
#define DEFAULT_UDP_WORKERS     4
#define DEFAULT_RAW_WORKERS     2
#define DEFAULT_BATCH_SIZE      32
#define DEFAULT_QUEUE_SIZE      1024
#define DEFAULT_BUFFER_COUNT    2048

// Worker types
#define WORKER_TYPE_UDP_TO_RAW  0
#define WORKER_TYPE_RAW_TO_UDP  1

// Optimization flags
#define ENABLE_SO_REUSEPORT     1
#define ENABLE_CPU_AFFINITY     1
#define ENABLE_NUMA_OPT         1
#define ENABLE_BATCH_PROCESSING 1

// Encryption types
#define XOR                 1

// System commands
#define IPCMD               "/sbin/ip"
#define BRIDGECMD           "/usr/sbin/brctl"

// Utility macros
#define max(a,b)            ((a) > (b) ? (a) : (b))
#define min(a,b)            ((a) < (b) ? (a) : (b))

// Packet buffer constants
#define MAXPKTS             65536

// Dynamic thread management constants
#define METRICS_HISTORY_SIZE    3600  // 1 hour with samples every second

// Configuration defaults
#define DEFAULT_KEEPALIVE_INTERVAL  10
#define DEFAULT_WORKER_TIMEOUT      30
#define DEFAULT_STATS_INTERVAL      5
#define DEFAULT_CPU_AFFINITY        0
#define DEFAULT_DYNAMIC_SCALING     1

// Limits
#define MAX_WORKERS                 64
#define MAX_WORKER_TIMEOUT          300
#define MIN_WORKER_TIMEOUT          5
#define MIN_WORKERS                 1
#define MIN_BATCH_SIZE              1
#define MIN_QUEUE_SIZE              64
#define MAX_QUEUE_SIZE              65536

// Configuration file constants
#define CONFIG_LINE_MAX             256
#define CONFIG_KEY_MAX              64
#define CONFIG_VALUE_MAX            128

// Loopback detection constants
#define LOOPBACK_HISTORY_SIZE       64      // Number of recent packets to track
#define LOOPBACK_THRESHOLD          10      // Max duplicate packets before loop detection

// VLAN support
#ifdef HAVE_PACKET_AUXDATA
#define VLAN_TAG_LEN        4
struct vlan_tag {
    u_int16_t vlan_tpid;    /* ETH_P_8021Q */
    u_int16_t vlan_tci;     /* VLAN TCI */
};
#endif

// Global VLAN protocol identifier
// ETHP8021Q is now defined as a macro above

// Version information
extern const char *VERSION;

// Debug macros
#ifdef DEBUG
#define Debug(fmt, ...) do { \
    if (debug) { \
        fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__); \
    } \
} while(0)
#else
#define Debug(fmt, ...) do { } while(0)
#endif

// Error handling macros (for compatibility with old code)
#define err_msg(fmt, ...) do { \
    fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__); \
} while(0)

#define err_quit(fmt, ...) do { \
    fprintf(stderr, "[FATAL] " fmt "\n", ##__VA_ARGS__); \
    exit(1); \
} while(0)

#define err_sys(fmt, ...) do { \
    fprintf(stderr, "[SYSTEM] " fmt ": %s\n", ##__VA_ARGS__, strerror(errno)); \
    exit(1); \
} while(0)

#endif /* ETHUDP_COMMON_H */