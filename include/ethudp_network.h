/* EthUDP Network Functions
 * Network operations, socket management, and packet processing
 * by james@ustc.edu.cn 2009.04.02
 */

#ifndef ETHUDP_NETWORK_H
#define ETHUDP_NETWORK_H

#include "ethudp_common.h"
#include "ethudp_types.h"

// ============================================================================
// NETWORK CONSTANTS
// ============================================================================

// Socket options
#define SOCKET_RECV_BUFFER_SIZE     (4 * 1024 * 1024)  // 4MB
#define SOCKET_SEND_BUFFER_SIZE     (4 * 1024 * 1024)  // 4MB
#define SOCKET_TIMEOUT_SEC          5
#define SOCKET_TIMEOUT_USEC         0

// Packet processing
#define PACKET_HEADER_SIZE          8
#define FRAGMENT_HEADER_SIZE        8
#define KEEPALIVE_INTERVAL_SEC      30
#define KEEPALIVE_TIMEOUT_SEC       90

// Network interface
#define MAX_INTERFACE_NAME_LEN      64
#define MAX_MAC_ADDRESS_LEN         18

// ============================================================================
// SOCKET MANAGEMENT
// ============================================================================

/**
 * Create and configure UDP socket
 * @param local_host Local host address (NULL for any)
 * @param local_port Local port
 * @param reuse_port Enable SO_REUSEPORT
 * @return Socket file descriptor, -1 on error
 */
int ethudp_create_udp_socket(const char *local_host, const char *local_port, 
                            int reuse_port);

/**
 * Create and configure RAW socket
 * @param interface_name Network interface name
 * @param protocol Protocol type (ETH_P_ALL, etc.)
 * @return Socket file descriptor, -1 on error
 */
int ethudp_create_raw_socket(const char *interface_name, int protocol);

/**
 * Configure socket options for optimal performance
 * @param sockfd Socket file descriptor
 * @param socket_type Socket type (UDP or RAW)
 * @return 0 on success, -1 on error
 */
int ethudp_configure_socket(int sockfd, int socket_type);

/**
 * Set socket non-blocking mode
 * @param sockfd Socket file descriptor
 * @param non_blocking 1 for non-blocking, 0 for blocking
 * @return 0 on success, -1 on error
 */
int ethudp_set_socket_nonblocking(int sockfd, int non_blocking);

/**
 * Set socket CPU affinity
 * @param sockfd Socket file descriptor
 * @param cpu_id CPU ID to bind to
 * @return 0 on success, -1 on error
 */
int ethudp_set_socket_affinity(int sockfd, int cpu_id);

/**
 * Close socket safely
 * @param sockfd Socket file descriptor
 * @return 0 on success, -1 on error
 */
int ethudp_close_socket(int sockfd);

/**
 * Create UDP cross-connection
 * @param lhost Local host
 * @param lserv Local service/port
 * @param rhost Remote host
 * @param rserv Remote service/port
 * @param index Connection index
 * @return Socket file descriptor, -1 on error
 */
int ethudp_udp_xconnect(char *lhost, char *lserv, char *rhost, char *rserv, int index);

/**
 * Open raw socket for interface
 * @param ifname Interface name
 * @param rifindex Interface index (output)
 * @return Socket file descriptor, -1 on error
 */
int ethudp_open_rawsocket(char *ifname, int32_t *rifindex);

/**
 * Open TUN/TAP interface
 * @param dev Device type ("tun" or "tap")
 * @param actual Actual device name (output)
 * @return File descriptor, -1 on error
 */
int ethudp_open_tun(const char *dev, char **actual);

// ============================================================================
// ENCRYPTION AND DECRYPTION
// ============================================================================

/**
 * Encrypt packet data
 * @param buf Input buffer
 * @param len Input length
 * @param nbuf Output buffer
 * @return Encrypted length, -1 on error
 */
int do_encrypt(uint8_t *buf, int len, uint8_t *nbuf);

/**
 * Decrypt packet data
 * @param buf Input buffer
 * @param len Input length
 * @param nbuf Output buffer
 * @return Decrypted length, -1 on error
 */
int do_decrypt(uint8_t *buf, int len, uint8_t *nbuf);

// ============================================================================
// PACKET PROCESSING
// ============================================================================

/**
 * Send UDP packet to remote host
 * @param sockfd Socket file descriptor
 * @param data Packet data
 * @param len Data length
 * @param remote_addr Remote address
 * @return Number of bytes sent, -1 on error
 */
ssize_t ethudp_send_udp_packet(int sockfd, const void *data, size_t len,
                              const struct sockaddr *remote_addr);

/**
 * Send UDP packet to remote by index
 * @param buf Buffer containing packet data
 * @param len Length of packet data
 * @param index Remote index
 */
void ethudp_send_udp_to_remote(uint8_t *buf, int len, int index);

/**
 * Receive UDP packet from socket
 * @param sockfd Socket file descriptor
 * @param buffer Buffer to store packet data
 * @param buffer_size Buffer size
 * @param src_addr Source address (output)
 * @return Number of bytes received, -1 on error
 */
ssize_t ethudp_recv_udp_packet(int sockfd, void *buffer, size_t buffer_size,
                              struct sockaddr *src_addr);

/**
 * Send RAW Ethernet packet
 * @param sockfd Socket file descriptor
 * @param data Packet data
 * @param len Data length
 * @param dest_mac Destination MAC address
 * @return Number of bytes sent, -1 on error
 */
ssize_t ethudp_send_raw_packet(int sockfd, const void *data, size_t len,
                              const unsigned char *dest_mac);

/**
 * Receive RAW Ethernet packet
 * @param sockfd Socket file descriptor
 * @param buffer Buffer to store packet data
 * @param buffer_size Buffer size
 * @param src_mac Source MAC address (output)
 * @return Number of bytes received, -1 on error
 */
ssize_t ethudp_recv_raw_packet(int sockfd, void *buffer, size_t buffer_size,
                              unsigned char *src_mac);

/**
 * Process packet batch for improved performance
 * @param batch Packet batch structure
 * @param process_func Function to process each packet
 * @param context Processing context
 * @return Number of packets processed, -1 on error
 */
int ethudp_process_packet_batch(struct packet_batch *batch,
                               int (*process_func)(void *data, size_t len, void *ctx),
                               void *context);

// ============================================================================
// FRAGMENTATION AND REASSEMBLY
// ============================================================================

/**
 * Fragment large packet for transmission
 * @param data Original packet data
 * @param len Original packet length
 * @param mtu Maximum transmission unit
 * @param fragments Array to store fragments (output)
 * @param max_fragments Maximum number of fragments
 * @return Number of fragments created, -1 on error
 */
int ethudp_fragment_packet(const void *data, size_t len, int mtu,
                          struct packet_buf *fragments, int max_fragments);

/**
 * Reassemble fragmented packet
 * @param fragments Array of packet fragments
 * @param fragment_count Number of fragments
 * @param reassembled_data Buffer for reassembled data (output)
 * @param buffer_size Size of reassembled data buffer
 * @return Length of reassembled packet, -1 on error
 */
ssize_t ethudp_reassemble_packet(const struct packet_buf *fragments,
                                int fragment_count, void *reassembled_data,
                                size_t buffer_size);

/**
 * Check if packet is fragmented
 * @param data Packet data
 * @param len Packet length
 * @return 1 if fragmented, 0 if not, -1 on error
 */
int ethudp_is_fragmented_packet(const void *data, size_t len);

// ============================================================================
// ADDRESS RESOLUTION
// ============================================================================

/**
 * Resolve hostname to address
 * @param hostname Hostname to resolve
 * @param port Port number
 * @param addr_info Address info structure (output)
 * @return 0 on success, -1 on error
 */
int ethudp_resolve_address(const char *hostname, const char *port,
                          struct addrinfo **addr_info);

/**
 * Get local MAC address for interface
 * @param interface_name Network interface name
 * @param mac_addr Buffer to store MAC address (6 bytes)
 * @return 0 on success, -1 on error
 */
int ethudp_get_local_mac(const char *interface_name, unsigned char *mac_addr);

/**
 * Get remote MAC address via ARP
 * @param interface_name Network interface name
 * @param ip_addr IP address to resolve
 * @param mac_addr Buffer to store MAC address (6 bytes)
 * @return 0 on success, -1 on error
 */
int ethudp_get_remote_mac(const char *interface_name, const char *ip_addr,
                         unsigned char *mac_addr);

/**
 * Convert sockaddr to string representation
 * @param addr Socket address
 * @param addr_str Buffer to store address string
 * @param addr_str_size Size of address string buffer
 * @return 0 on success, -1 on error
 */
int ethudp_sockaddr_to_string(const struct sockaddr *addr, char *addr_str,
                             size_t addr_str_size);

/**
 * Print address info
 * @param index Address index
 */
void ethudp_print_addrinfo(int index);

// ============================================================================
// KEEPALIVE AND CONNECTION MANAGEMENT
// ============================================================================

/**
 * Send keepalive packet
 * @param sockfd Socket file descriptor
 * @param remote_addr Remote address
 * @return 0 on success, -1 on error
 */
int ethudp_send_keepalive(int sockfd, const struct sockaddr *remote_addr);

/**
 * Send keepalive packets to UDP remote
 */
void ethudp_send_keepalive_to_udp(void);

/**
 * Check if packet is keepalive
 * @param data Packet data
 * @param len Packet length
 * @return 1 if keepalive, 0 if not, -1 on error
 */
int ethudp_is_keepalive_packet(const void *data, size_t len);

/**
 * Handle keepalive timeout
 * @param context Worker context
 * @return 0 on success, -1 on error
 */
int ethudp_handle_keepalive_timeout(worker_context_t *context);

// ============================================================================
// NETWORK STATISTICS
// ============================================================================

/**
 * Get network interface statistics
 * @param interface_name Network interface name
 * @param rx_packets Received packets (output)
 * @param tx_packets Transmitted packets (output)
 * @param rx_bytes Received bytes (output)
 * @param tx_bytes Transmitted bytes (output)
 * @return 0 on success, -1 on error
 */
int ethudp_get_interface_stats(const char *interface_name,
                              uint64_t *rx_packets, uint64_t *tx_packets,
                              uint64_t *rx_bytes, uint64_t *tx_bytes);

/**
 * Get socket statistics
 * @param sockfd Socket file descriptor
 * @param rx_queue_size Receive queue size (output)
 * @param tx_queue_size Transmit queue size (output)
 * @return 0 on success, -1 on error
 */
int ethudp_get_socket_stats(int sockfd, int *rx_queue_size, int *tx_queue_size);

/**
 * Calculate network latency
 * @param start_time Start timestamp
 * @param end_time End timestamp
 * @return Latency in microseconds
 */
double ethudp_calculate_latency_us(const struct timespec *start_time,
                                  const struct timespec *end_time);

// ============================================================================
// VLAN SUPPORT
// ============================================================================

/**
 * Add VLAN tag to packet
 * @param data Original packet data
 * @param len Original packet length
 * @param vlan_id VLAN ID
 * @param tagged_data Buffer for tagged packet (output)
 * @param buffer_size Size of tagged data buffer
 * @return Length of tagged packet, -1 on error
 */
ssize_t ethudp_add_vlan_tag(const void *data, size_t len, uint16_t vlan_id,
                           void *tagged_data, size_t buffer_size);

/**
 * Remove VLAN tag from packet
 * @param data Tagged packet data
 * @param len Tagged packet length
 * @param vlan_id VLAN ID (output)
 * @param untagged_data Buffer for untagged packet (output)
 * @param buffer_size Size of untagged data buffer
 * @return Length of untagged packet, -1 on error
 */
ssize_t ethudp_remove_vlan_tag(const void *data, size_t len, uint16_t *vlan_id,
                              void *untagged_data, size_t buffer_size);

/**
 * Check if packet has VLAN tag
 * @param data Packet data
 * @param len Packet length
 * @return 1 if VLAN tagged, 0 if not, -1 on error
 */
int ethudp_is_vlan_tagged(const void *data, size_t len);

// ============================================================================
// ENCRYPTION AND COMPRESSION
// ============================================================================

/**
 * Encrypt packet data
 * @param data Original packet data
 * @param len Original packet length
 * @param key Encryption key
 * @param encrypted_data Buffer for encrypted data (output)
 * @param buffer_size Size of encrypted data buffer
 * @return Length of encrypted data, -1 on error
 */
ssize_t ethudp_encrypt_packet(const void *data, size_t len, const char *key,
                             void *encrypted_data, size_t buffer_size);

/**
 * Decrypt packet data
 * @param data Encrypted packet data
 * @param len Encrypted packet length
 * @param key Decryption key
 * @param decrypted_data Buffer for decrypted data (output)
 * @param buffer_size Size of decrypted data buffer
 * @return Length of decrypted data, -1 on error
 */
ssize_t ethudp_decrypt_packet(const void *data, size_t len, const char *key,
                             void *decrypted_data, size_t buffer_size);

/**
 * Compress packet data using LZ4
 * @param data Original packet data
 * @param len Original packet length
 * @param compressed_data Buffer for compressed data (output)
 * @param buffer_size Size of compressed data buffer
 * @return Length of compressed data, -1 on error
 */
ssize_t ethudp_compress_packet(const void *data, size_t len,
                              void *compressed_data, size_t buffer_size);

/**
 * Decompress packet data using LZ4
 * @param data Compressed packet data
 * @param len Compressed packet length
 * @param decompressed_data Buffer for decompressed data (output)
 * @param buffer_size Size of decompressed data buffer
 * @return Length of decompressed data, -1 on error
 */
ssize_t ethudp_decompress_packet(const void *data, size_t len,
                                void *decompressed_data, size_t buffer_size);

// ============================================================================
// CORE PROCESSING FUNCTIONS
// ============================================================================

/**
 * UDP to RAW worker thread function
 * @param arg Worker context
 * @return NULL
 */
void* process_udp_to_raw_worker(void *arg);

/**
 * RAW to UDP worker thread function
 * @param arg Worker context
 * @return NULL
 */
void* process_raw_to_udp_worker(void *arg);

/**
 * UDP to RAW master processing function
 * @param arg Thread argument (unused)
 * @return NULL
 */
void* process_udp_to_raw_master(void *arg);

/**
 * RAW to UDP main processing function
 */
void process_raw_to_udp(void);

/**
 * Fix MSS in TCP packets
 * @param buf Packet buffer
 * @param len Packet length
 * @return Processed length, -1 on error
 */
int fix_mss(uint8_t *buf, int len);

/**
 * Check if packet should be dropped due to loopback
 * @param buf Packet buffer
 * @param len Packet length
 * @return 1 if should drop, 0 if should process, -1 on error
 */
int do_loopback_check(uint8_t *buf, int len);

// ============================================================================
// NETWORK UTILITIES
// ============================================================================

/**
 * Calculate checksum for packet
 * @param data Packet data
 * @param len Packet length
 * @return Checksum value
 */
uint16_t ethudp_calculate_checksum(const void *data, size_t len);

/**
 * Verify packet checksum
 * @param data Packet data
 * @param len Packet length
 * @param expected_checksum Expected checksum value
 * @return 1 if valid, 0 if invalid, -1 on error
 */
int ethudp_verify_checksum(const void *data, size_t len, uint16_t expected_checksum);

/**
 * Get optimal MTU for path
 * @param dest_addr Destination address
 * @return Optimal MTU size, -1 on error
 */
int ethudp_get_path_mtu(const struct sockaddr *dest_addr);

/**
 * Test network connectivity
 * @param host Destination host
 * @param port Destination port
 * @return 1 if reachable, 0 if not, -1 on error
 */
int ethudp_test_connectivity(const char *host, const char *port);

#endif /* ETHUDP_NETWORK_H */