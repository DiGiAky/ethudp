#include "../include/ethudp_common.h"
#include "../include/ethudp_types.h"
#include "../include/ethudp_config.h"
#include "../include/ethudp_network.h"
#include "../include/ethudp_utils.h"

// External variables from original code
extern int fdudp[2];
extern int fdraw;
extern int ifindex;
extern int nat[2];
extern volatile int debug;
extern int mode;
extern int master_slave;
extern int current_remote;
extern int read_only;
extern int write_only;
extern int nopromisc;
extern int loopback_check;
extern int fixmss;
extern int mtu;
extern int lz4;
extern int vlan_map;
extern int my_vlan[4096];
extern int remote_vlan[4096];
extern char enc_key[MAXLEN];
extern int enc_key_len;
extern int enc_algorithm;
extern unsigned char enc_iv[EVP_MAX_IV_LENGTH];
extern struct sockaddr_storage local_addr[2];
extern struct sockaddr_storage remote_addr[2];
extern struct sockaddr_storage cmd_remote_addr[2];
extern pcap_t *pcap_handle;
extern uint16_t udp_frg_seq;
extern uint64_t udp_send_pkt[2];
extern uint64_t udp_send_byte[2];
extern uint64_t udp_send_err[2];
extern uint64_t udp_recv_pkt[2];
extern uint64_t udp_recv_byte[2];
extern uint64_t raw_recv_pkt;
extern uint64_t raw_recv_byte;
extern uint64_t raw_send_pkt;
extern uint64_t raw_send_byte;
extern uint64_t raw_send_err;
extern uint64_t ping_send[2];
extern uint64_t ping_recv[2];
extern uint64_t pong_send[2];
extern uint64_t pong_recv[2];
extern int master_status;
extern int slave_status;
extern uint64_t myticket;
extern uint64_t udp_total;
extern uint64_t compress_save;
extern uint64_t compress_overhead;
extern uint64_t encrypt_overhead;
extern char mypassword[MAXLEN];
extern int run_seconds;
extern int got_signal;

// Forward declarations for utility functions
extern int udp_server(const char *host, const char *port);
extern int do_encrypt(uint8_t *buf, int len, uint8_t *nbuf);
extern int do_loopback_check(uint8_t *buf, int len);
extern int fix_mss(uint8_t *buf, int len);
extern void printPacket(uint8_t *buf, int len, const char *prefix);

// External worker pool for statistics
extern worker_pool_t global_worker_pool;

/**
 * Create and configure UDP socket connection
 */
int ethudp_udp_xconnect(char *lhost, char *lserv, char *rhost, char *rserv, int index) {
    int sockfd, n;
    struct addrinfo hints, *res, *ressave;

    sockfd = udp_server(lhost, lserv);

    // Set socket buffer size
    n = 10 * 1024 * 1024;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n));
    if (debug) {
        socklen_t ln;
        if (getsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &n, &ln) == 0)
            Debug("UDP socket RCVBUF setting to %d\n", n);
    }

    // Set IP_MTU_DISCOVER, otherwise UDP has DFbit set
    n = 0;
    if (setsockopt(sockfd, IPPROTO_IP, IP_MTU_DISCOVER, &n, sizeof(n)) != 0)
        err_msg("udp_xconnect setsockopt returned error, errno %d\n", errno);

    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if ((n = getaddrinfo(rhost, rserv, &hints, &res)) != 0)
        err_quit("udp_xconnect error for %s, %s", rhost, rserv);
    ressave = res;

    do {
        void *raddr;
        if (res->ai_family == AF_INET) {    // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
            raddr = &(ipv4->sin_addr);
            if ((memcmp(raddr, "\0\0\0\0", 4) == 0) || (ipv4->sin_port == 0)) {
                Debug("nat = 1");
                nat[index] = 1;
                memcpy((void *)&(cmd_remote_addr[index]), res->ai_addr, res->ai_addrlen);
                freeaddrinfo(ressave);
                return sockfd;
            }
        } else {    // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
            raddr = &(ipv6->sin6_addr);
            if ((memcmp(raddr, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) == 0) || (ipv6->sin6_port == 0)) {
                Debug("nat = 1");
                nat[index] = 1;
                memcpy((void *)&(cmd_remote_addr[index]), res->ai_addr, res->ai_addrlen);
                freeaddrinfo(ressave);
                return sockfd;
            }
        }

        if (connect(sockfd, res->ai_addr, res->ai_addrlen) == 0) {
            memcpy((void *)&(cmd_remote_addr[index]), res->ai_addr, res->ai_addrlen);
            memcpy((void *)&(remote_addr[index]), res->ai_addr, res->ai_addrlen);
            break;    /* success */
        }
    }
    while ((res = res->ai_next) != NULL);

    if (res == NULL)    /* errno set from final connect() */
        err_sys("udp_xconnect error for %s, %s", rhost, rserv);

    freeaddrinfo(ressave);

    return (sockfd);
}

/**
 * Open a raw socket for the network interface
 */
int ethudp_open_rawsocket(char *ifname, int32_t *rifindex) {
    unsigned char buf[MAX_PACKET_SIZE] __attribute__((unused));
    int32_t ifindex;
    struct ifreq ifr;
    struct sockaddr_ll sll;
    int n __attribute__((unused));

    int32_t fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1)
        err_sys("socket %s - ", ifname);

    // get interface index
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
        err_sys("SIOCGIFINDEX %s - ", ifname);
    ifindex = ifr.ifr_ifindex;
    *rifindex = ifindex;

    if (!nopromisc) {    // set promiscuous mode
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
        ioctl(fd, SIOCGIFFLAGS, &ifr);
        ifr.ifr_flags |= IFF_PROMISC;
        ioctl(fd, SIOCSIFFLAGS, &ifr);
    }

    memset(&sll, 0xff, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifindex;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) == -1)
        err_sys("bind %s - ", ifname);

    /* flush all received packets. 
     *
     * raw-socket receives packets from all interfaces
     * when the socket is not bound to an interface
     */
    int32_t i, l = 0;
    do {
        fd_set fds;
        struct timeval t;
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        memset(&t, 0, sizeof(t));
        i = select(FD_SETSIZE, &fds, NULL, NULL, &t);
        if (i > 0) {
            recv(fd, buf, i, 0);
            l++;
        };
        Debug("interface %d flushed %d packets", ifindex, l);
    }
    while (i > 0);

    /* Enable auxillary data if supported and reserve room for
     * reconstructing VLAN headers. */
#ifdef HAVE_PACKET_AUXDATA
    int val = 1;
    if (setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, &val, sizeof(val)) == -1 && errno != ENOPROTOOPT) {
        err_sys("setsockopt(packet_auxdata): %s", strerror(errno));
    }
#endif                /* HAVE_PACKET_AUXDATA */

    Debug("%s opened (fd=%d interface=%d)", ifname, fd, ifindex);

    n = 10 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n));
    if (debug) {
        socklen_t ln;
        if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, &ln) == 0) {
            Debug("RAW socket RCVBUF setting to %d", n);
        }
    }

    return fd;
}

/**
 * Open TUN/TAP interface
 */
int ethudp_open_tun(const char *dev, char **actual) {
    struct ifreq ifr;
    int fd;
    char *device = "/dev/net/tun";    //RedHat tun
    int size;

    if ((fd = open(device, O_RDWR)) < 0) {
        Debug("Cannot open TUN/TAP dev %s", device);
        exit(1);
    }
    
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_NO_PI;
    if (!strncmp(dev, "tun", 3)) {
        ifr.ifr_flags |= IFF_TUN;
    } else if (!strncmp(dev, "tap", 3)) {
        ifr.ifr_flags |= IFF_TAP;
    } else {
        Debug("I don't recognize device %s as a TUN or TAP device", dev);
        exit(1);
    }
    
    if (strlen(dev) > 3)    //unit number specified? 
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        Debug("Cannot ioctl TUNSETIFF %s", dev);
        exit(1);
    }
    
    Debug("TUN/TAP device %s opened", ifr.ifr_name);
    size = strlen(ifr.ifr_name) + 1;
    *actual = (char *)malloc(size);
    memcpy(*actual, ifr.ifr_name, size);
    
    // Set socket buffer size
    int n = 10 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n));
    if (debug) {
        socklen_t ln = sizeof(n);
        if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &n, &ln) == 0)
            Debug("RAW socket RCVBUF setting to %d", n);
    }
    
    return fd;
}

/**
 * Send fragmented UDP packet
 */
void ethudp_send_frag_udp(uint8_t *buf, int len, int index) {
    unsigned char newbuf[MAX_PACKET_SIZE];
    if (len >= 2000)    // should not go here
        return;
    if (len <= 1000)    // should not go here
        return;
        
    memcpy(newbuf, "UDPFRG", 6);
    newbuf[6] = (udp_frg_seq >> 8) & 0xff;
    newbuf[7] = udp_frg_seq & 0xff;
    memcpy(newbuf + 8, buf, 1000);
    if (debug)
        Debug("send frag %d, len=1000, total_len=%d", udp_frg_seq, len);
    ethudp_send_udp_to_remote(newbuf, 1008, index);
    udp_frg_seq++;
    if (udp_frg_seq >= MAXPKTS)
        udp_frg_seq = 0;
        
    newbuf[6] = (udp_frg_seq >> 8) & 0xff;
    newbuf[7] = udp_frg_seq & 0xff;
    memcpy(newbuf + 8, buf + 1000, len - 1000);
    if (debug)
        Debug("send frag %d, len=%d, total_len=%d", udp_frg_seq, len - 1000, len);
    ethudp_send_udp_to_remote(newbuf, 8 + len - 1000, index);
    udp_frg_seq++;
    if (udp_frg_seq >= MAXPKTS)
        udp_frg_seq = 0;
}

/**
 * Send UDP packet to remote
 */
void ethudp_send_udp_to_remote(uint8_t *buf, int len, int index) {
    if ((mtu > 0) && (len > mtu - 28))
        return ethudp_send_frag_udp(buf, len, index);
        
    if (nat[index]) {
        char rip[200] __attribute__((unused));
        if (remote_addr[index].ss_family == AF_INET) {
            struct sockaddr_in *r = (struct sockaddr_in *)(&remote_addr[index]);
            if (debug)
                Debug("nat mode: send len %d to %s:%d", len, 
                      inet_ntop(r->sin_family, (void *)&r->sin_addr, rip, 200), 
                      ntohs(r->sin_port));
            if (r->sin_port) {
                sendto(fdudp[index], buf, len, 0, 
                       (struct sockaddr *)&remote_addr[index], 
                       sizeof(struct sockaddr_storage));
                udp_send_pkt[index]++;
                udp_send_byte[index] += len;
            }
        } else if (remote_addr[index].ss_family == AF_INET6) {
            struct sockaddr_in6 *r = (struct sockaddr_in6 *)&remote_addr[index];
            if (debug)
                Debug("nat mode: send len %d to [%s]:%d", len, 
                      inet_ntop(r->sin6_family, (void *)&r->sin6_addr, rip, 200), 
                      ntohs(r->sin6_port));
            if (r->sin6_port) {
                sendto(fdudp[index], buf, len, 0, 
                       (struct sockaddr *)&remote_addr[index], 
                       sizeof(struct sockaddr_storage));
                udp_send_pkt[index]++;
                udp_send_byte[index] += len;
            }
        }
    } else {
        if (write(fdudp[index], buf, len) != len)
            udp_send_err[index]++;
        else {
            udp_send_pkt[index]++;
            udp_send_byte[index] += len;
        }
    }
}

/**
 * Save remote address for NAT mode
 */
void ethudp_save_remote_addr(struct sockaddr_storage *rmt, int sock_len, int index) {
    char rip[200];
    if (memcmp((void *)rmt, (void *)(&remote_addr[index]), sock_len) == 0)
        return;
        
    if (rmt->ss_family == AF_INET) {
        struct sockaddr_in *r = (struct sockaddr_in *)rmt;
        struct sockaddr_in *cmdr = (struct sockaddr_in *)&cmd_remote_addr[index];
        if (((cmdr->sin_addr.s_addr == 0) || (cmdr->sin_addr.s_addr == r->sin_addr.s_addr))
            && ((cmdr->sin_port == 0) || (cmdr->sin_port == r->sin_port))) {
            memcpy((void *)&remote_addr[index], rmt, sock_len);
            err_msg("nat mode, change %s remote to %s:%d", 
                    index == 0 ? "master" : "slave",
                    inet_ntop(r->sin_family, (void *)&r->sin_addr, rip, 200), 
                    ntohs(r->sin_port));
        } else {
            err_msg("nat mode, do not change %s remote to %s:%d", 
                    index == 0 ? "master" : "slave",
                    inet_ntop(r->sin_family, (void *)&r->sin_addr, rip, 200), 
                    ntohs(r->sin_port));
        }
    } else if (rmt->ss_family == AF_INET6) {
        struct sockaddr_in6 *r = (struct sockaddr_in6 *)rmt;
        struct sockaddr_in6 *cmdr = (struct sockaddr_in6 *)&cmd_remote_addr[index];
        if (((memcmp(&cmdr->sin6_addr, &in6addr_any, sizeof(in6addr_any)) == 0) || 
             (memcmp(&cmdr->sin6_addr, &r->sin6_addr, sizeof(r->sin6_addr)) == 0))
            && ((cmdr->sin6_port == 0) || (cmdr->sin6_port == r->sin6_port))) {
            memcpy((void *)&remote_addr[index], rmt, sock_len);
            err_msg("nat mode, change %s remote to [%s]:%d", 
                    index == 0 ? "master" : "slave",
                    inet_ntop(r->sin6_family, (void *)&r->sin6_addr, rip, 200), 
                    ntohs(r->sin6_port));
        } else {
            err_msg("nat mode, do not change %s remote to [%s]:%d", 
                    index == 0 ? "master" : "slave",
                    inet_ntop(r->sin6_family, (void *)&r->sin6_addr, rip, 200), 
                    ntohs(r->sin6_port));
        }
    }
}

/**
 * Print address information
 */
void ethudp_print_addrinfo(int index) {
    char localip[200];
    char cmd_remoteip[200];
    char remoteip[200];
    
    if (local_addr[index].ss_family == AF_INET) {
        struct sockaddr_in *r = (struct sockaddr_in *)(&local_addr[index]);
        int lp, c_rp, rp;
        lp = ntohs(r->sin_port);
        inet_ntop(AF_INET, &r->sin_addr, localip, 200);
        r = (struct sockaddr_in *)(&cmd_remote_addr[index]);
        c_rp = ntohs(r->sin_port);
        inet_ntop(AF_INET, &r->sin_addr, cmd_remoteip, 200);
        r = (struct sockaddr_in *)(&remote_addr[index]);
        rp = ntohs(r->sin_port);
        inet_ntop(AF_INET, &r->sin_addr, remoteip, 200);
        if (nat[index])
            err_msg("%s: ST:%d %s:%d --> %s:%d(%s:%d)", 
                    index == 0 ? "MASTER" : " SLAVE", 
                    index == 0 ? master_status : slave_status, 
                    localip, lp, remoteip, rp, cmd_remoteip, c_rp);
        else
            err_msg("%s: ST:%d %s:%d --> %s:%d", 
                    index == 0 ? "MASTER" : " SLAVE", 
                    index == 0 ? master_status : slave_status, 
                    localip, lp, remoteip, rp);
    } else if (local_addr[index].ss_family == AF_INET6) {
        struct sockaddr_in6 *r = (struct sockaddr_in6 *)(&local_addr[index]);
        int lp, c_rp, rp;
        lp = ntohs(r->sin6_port);
        inet_ntop(AF_INET6, &r->sin6_addr, localip, 200);
        r = (struct sockaddr_in6 *)(&cmd_remote_addr[index]);
        c_rp = ntohs(r->sin6_port);
        inet_ntop(AF_INET6, &r->sin6_addr, cmd_remoteip, 200);
        r = (struct sockaddr_in6 *)(&remote_addr[index]);
        rp = ntohs(r->sin6_port);
        inet_ntop(AF_INET6, &r->sin6_addr, remoteip, 200);
        if (nat[index])
            err_msg("%s: ST:%d [%s]:%d --> [%s]:%d([%s]:%d)", 
                    index == 0 ? "MASTER" : " SLAVE", 
                    index == 0 ? master_status : slave_status, 
                    localip, lp, remoteip, rp, cmd_remoteip, c_rp);
        else
            err_msg("%s: ST:%d [%s]:%d --> [%s]:%d", 
                    index == 0 ? "MASTER" : " SLAVE", 
                    index == 0 ? master_status : slave_status, 
                    localip, lp, remoteip, rp);
    }
}

/**
 * Process packets from raw socket to UDP
 */
void ethudp_process_raw_to_udp(void) {
    uint8_t *buf, mybuf[MAX_PACKET_SIZE + VLAN_TAG_LEN];
    uint8_t nbuf[MAX_PACKET_SIZE + VLAN_TAG_LEN + EVP_MAX_BLOCK_LENGTH + LZ4_SPACE];
    uint8_t *pbuf;
    int len;
    int offset = 0;

    while (1) {        // read from eth rawsocket
        if (mode == MODE_E) {
            buf = mybuf;
#ifdef HAVE_PACKET_AUXDATA
            struct sockaddr from;
            struct iovec iov;
            struct msghdr msg;
            struct cmsghdr *cmsg;
            union {
                struct cmsghdr cmsg;
                char buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
            } cmsg_buf;
            msg.msg_name = &from;
            msg.msg_namelen = sizeof(from);
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_control = &cmsg_buf;
            msg.msg_controllen = sizeof(cmsg_buf);
            msg.msg_flags = 0;

            offset = VLAN_TAG_LEN;
            iov.iov_len = MAX_PACKET_SIZE;
            iov.iov_base = buf + offset;
            len = recvmsg(fdraw, &msg, MSG_TRUNC);
            if (len <= 0)
                continue;
            if (len >= MAX_PACKET_SIZE) {
                err_msg("recv long pkt from raw, len=%d", len);
                len = MAX_PACKET_SIZE;
            }
            for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                struct tpacket_auxdata *aux;
                struct vlan_tag *tag;

                if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct tpacket_auxdata))
                    || cmsg->cmsg_level != SOL_PACKET || cmsg->cmsg_type != PACKET_AUXDATA)
                    continue;

                aux = (struct tpacket_auxdata *)CMSG_DATA(cmsg);

#if defined(TP_STATUS_VLAN_VALID)
                if ((aux->tp_vlan_tci == 0)
                    && !(aux->tp_status & TP_STATUS_VLAN_VALID))
#else
                if (aux->tp_vlan_tci == 0)    /* this is ambigious but without the */
#endif
                    continue;

                if (debug)
                    Debug("len=%d, iov_len=%d, ", len, (int)iov.iov_len);

                len = len > iov.iov_len ? iov.iov_len : len;
                if (len < 12)    // MAC_len * 2
                    break;
                if (debug)
                    Debug("len=%d", len);

                memmove(buf, buf + VLAN_TAG_LEN, 12);
                offset = 0;

                /*
                 * Now insert the tag.
                 */
                tag = (struct vlan_tag *)(buf + 12);
                if (debug)
                    Debug("insert vlan id, recv len=%d", len);

#ifdef TP_STATUS_VLAN_TPID_VALID
                tag->vlan_tpid = ((aux->tp_vlan_tpid || (aux->tp_status & TP_STATUS_VLAN_TPID_VALID)) ? 
                                  htons(aux->tp_vlan_tpid) : ETHP8021Q);
#else
                tag->vlan_tpid = ETHP8021Q;
#endif
                tag->vlan_tci = htons(aux->tp_vlan_tci);

                /* Add the tag to the packet lengths.
                 */
                len += VLAN_TAG_LEN;
                break;
            }
#else
            len = recv(fdraw, buf, MAX_PACKET_SIZE, 0);
#endif
        } else if ((mode == MODE_I) || (mode == MODE_B)) {
            buf = mybuf;
            len = read(fdraw, buf, MAX_PACKET_SIZE);
            if (len >= MAX_PACKET_SIZE) {
                err_msg("recv long pkt from raw, len=%d", len);
                len = MAX_PACKET_SIZE;
            }
        } else if (mode == MODE_T) {
            struct pcap_pkthdr *header;
            int r = pcap_next_ex(pcap_handle, &header, (const u_char **)&buf);
            if (r <= 0)
                continue;
            len = header->len;
        } else if (mode == MODE_U) {
            struct pcap_pkthdr *header;
            int r = pcap_next_ex(pcap_handle, &header, (const u_char **)&buf);
            if (r <= 0)
                continue;
            len = header->len;
        } else
            return;

        if (len <= 0)
            continue;
        if (write_only)
            continue;    // write only

        raw_recv_pkt++;
        raw_recv_byte += len;
        if (loopback_check && do_loopback_check(buf + offset, len))
            continue;
        if (debug) {
            printPacket(buf + offset, len, "from local  rawsocket:");
            if (offset)
                Debug("offset=%d", offset);
        }
        if (!read_only && fixmss)    // read only, no fix_mss
            fix_mss(buf + offset, len);

        if (vlan_map && len >= 16) {
            struct vlan_tag *tag;
            tag = (struct vlan_tag *)(buf + offset + 12);
            if (tag->vlan_tpid == ETHP8021Q) {
                int vlan;
                vlan = ntohs(tag->vlan_tci) & 0xfff;
                if (my_vlan[vlan] != vlan) {
                    tag->vlan_tci = htons((ntohs(tag->vlan_tci) & 0xf000) + my_vlan[vlan]);
                    if (debug) {
                        if (debug)
                            Debug("maping vlan %d to %d", vlan, my_vlan[vlan]);
                        printPacket(buf + offset, len, "from local  rawsocket:");
                    }
                }
            }
        }
        if ((enc_key_len > 0) || (lz4 > 0)) {
            len = do_encrypt((uint8_t *) buf + offset, len, nbuf);
            pbuf = nbuf;
        } else
            pbuf = buf + offset;
            
        if (mode == MODE_U) { // find the UDP packet
            uint8_t *packet;
            if (len < 40)
                return;
            packet = buf + 12;      // skip ethernet dst & src addr
            len -= 12;
            if ((packet[0] == 0x81) && (packet[1] == 0x00)) {       // skip 802.1Q tag 0x8100
                packet += 4;
                len -= 4;
            }
            if ((packet[0] == 0x08) && (packet[1] == 0x00)) {       // IPv4 packet 0x0800
                packet += 2;
                len -= 2;
                struct iphdr *ip = (struct iphdr *)packet;
                if (ip->version != 4)
                    return; // only support IPv4
                if (ntohs(ip->frag_off) & 0x1fff)
                    return; // not the first fragment
                if (ip->protocol != IPPROTO_UDP)
                    return; // not UDP packet
                if (ntohs(ip->tot_len) > len)
                    return; // tot_len should < len

                struct udphdr *udph = (struct udphdr *)(packet + ip->ihl * 4);
                pbuf = packet + ip->ihl * 4 + 8;
                len = ntohs(udph->len) - 8;
            } else
                return;
        }

        ethudp_send_udp_to_remote(pbuf, len, current_remote);
    }
}

/**
 * Send keepalive packets to UDP remote
 */
void ethudp_send_keepalive_to_udp(void) {
    uint8_t buf[MAX_PACKET_SIZE + EVP_MAX_BLOCK_LENGTH];
    uint8_t nbuf[MAX_PACKET_SIZE + EVP_MAX_BLOCK_LENGTH];
    uint8_t *pbuf;
    int len;
    static uint32_t lasttm;
    
    while (1) {
        if (got_signal || (myticket >= lasttm + 3600)) {    // log ping/pong every hour
            err_msg("============= version: %s, myticket=%lu, master_slave=%d, current_remote=%s, loopback_check=%d",
                ETHUDP_VERSION, myticket, master_slave, current_remote == 0 ? "MASTER" : "SLAVE", loopback_check);
            ethudp_print_addrinfo(MASTER);
            if (master_slave)
                ethudp_print_addrinfo(SLAVE);
            err_msg("master ping_send/pong_recv: %lu/%lu, ping_recv/pong_send: %lu/%lu, udp_send_err: %lu",
                ping_send[MASTER], pong_recv[MASTER], ping_recv[MASTER], pong_send[MASTER], udp_send_err[MASTER]);
            if (master_slave)
                err_msg(" slave ping_send/pong_recv: %lu/%lu, ping_recv/pong_send: %lu/%lu, udp_send_err: %lu", 
                        ping_send[SLAVE], pong_recv[SLAVE], ping_recv[SLAVE], pong_send[SLAVE], udp_send_err[SLAVE]);
            if (myticket >= lasttm + 3600) {
                ping_send[MASTER] = ping_send[SLAVE] = ping_recv[MASTER] = ping_recv[SLAVE] = 0;
                pong_send[MASTER] = pong_send[SLAVE] = pong_recv[MASTER] = pong_recv[SLAVE] = 0;
                lasttm = myticket;
            }
            err_msg("       raw interface recv:%lu/%lu send:%lu/%lu, raw_send_err: %lu", 
                    raw_recv_pkt, raw_recv_byte, raw_send_pkt, raw_send_byte, raw_send_err);
            err_msg("master udp interface recv:%lu/%lu send:%lu/%lu", 
                    udp_recv_pkt[MASTER], udp_recv_byte[MASTER], udp_send_pkt[MASTER], udp_send_byte[MASTER]);
            if (master_slave)
                err_msg(" slave udp interface recv:%lu/%lu send:%lu/%lu", 
                        udp_recv_pkt[SLAVE], udp_recv_byte[SLAVE], udp_send_pkt[SLAVE], udp_send_byte[SLAVE]);
            err_msg("udp %lu bytes, lz4 save %lu bytes, lz4 overhead %lu bytes, encrypt overhead %lu bytes, %.0f%%",
                udp_total, compress_save, compress_overhead, encrypt_overhead,
                100.0 * (udp_total - compress_save + compress_overhead + encrypt_overhead) / udp_total);
            got_signal = 0;
        }
        myticket++;
        if (run_seconds > 0) {
            if (myticket > run_seconds) {
                err_msg("run_seconds %d expired, exit", run_seconds);
                exit(0);
            }
        }
        if (mypassword[0]) {
            len = snprintf((char *)buf, MAX_PACKET_SIZE, "PASSWORD:%s", mypassword);
            if (debug)
                Debug("send password: %s", buf);
            len++;
            if ((enc_key_len > 0) || (lz4 > 0)) {
                len = do_encrypt((uint8_t *) buf, len, nbuf);
                pbuf = nbuf;
            } else
                pbuf = buf;
            if (nat[MASTER] == 0)
                ethudp_send_udp_to_remote(pbuf, len, MASTER);    // send to master
            if (master_slave && (nat[SLAVE] == 0))
                ethudp_send_udp_to_remote(pbuf, len, SLAVE);    // send to slave
        }
        sleep(1);
    }
}

/**
 * XOR encryption
 */
int ethudp_xor_encrypt(uint8_t *buf, int n, uint8_t *nbuf) {
    int i;
    for (i = 0; i < n; i++)
        nbuf[i] = buf[i] ^ enc_key[i % enc_key_len];
    return n;
}

#ifdef ENABLE_OPENSSL
/**
 * OpenSSL encryption
 */
int ethudp_openssl_encrypt(uint8_t *buf, int len, uint8_t *nbuf) {
    EVP_CIPHER_CTX *ctx;
    int outlen1, outlen2;
#ifdef DEBUGSSL
    Debug("aes encrypt len=%d", len);
#endif
    ctx = EVP_CIPHER_CTX_new();
    if (enc_algorithm == AES_128)
        EVP_EncryptInit(ctx, EVP_aes_128_cbc(), (const unsigned char *)enc_key, (const unsigned char *)enc_iv);
    else if (enc_algorithm == AES_192)
        EVP_EncryptInit(ctx, EVP_aes_192_cbc(), (const unsigned char *)enc_key, (const unsigned char *)enc_iv);
    else if (enc_algorithm == AES_256)
        EVP_EncryptInit(ctx, EVP_aes_256_cbc(), (const unsigned char *)enc_key, (const unsigned char *)enc_iv);
    EVP_EncryptUpdate(ctx, nbuf, &outlen1, buf, len);
    EVP_EncryptFinal(ctx, nbuf + outlen1, &outlen2);
    len = outlen1 + outlen2;

#ifdef DEBUGSSL
    Debug("after aes encrypt len=%d", len);
#endif
    EVP_CIPHER_CTX_free(ctx);
    return len;
}

/**
 * OpenSSL decryption
 */
int ethudp_openssl_decrypt(uint8_t *buf, int len, uint8_t *nbuf) {
    EVP_CIPHER_CTX *ctx;
    int outlen1, outlen2;
#ifdef DEBUGSSL
    Debug("aes decrypt len=%d", len);
#endif
    ctx = EVP_CIPHER_CTX_new();
    if (enc_algorithm == AES_128)
        EVP_DecryptInit(ctx, EVP_aes_128_cbc(), (const unsigned char *)enc_key, (const unsigned char *)enc_iv);
    else if (enc_algorithm == AES_192)
        EVP_DecryptInit(ctx, EVP_aes_192_cbc(), (const unsigned char *)enc_key, (const unsigned char *)enc_iv);
    else if (enc_algorithm == AES_256)
        EVP_DecryptInit(ctx, EVP_aes_256_cbc(), (const unsigned char *)enc_key, (const unsigned char *)enc_iv);
    if (EVP_DecryptUpdate(ctx, nbuf, &outlen1, buf, len) != 1 || 
        EVP_DecryptFinal(ctx, nbuf + outlen1, &outlen2) != 1)
        len = 0;
    else
        len = outlen1 + outlen2;

#ifdef DEBUGSSL
    Debug("after aes decrypt len=%d", len);
#endif
    EVP_CIPHER_CTX_free(ctx);
    return len;
}
#endif

/**
 * Set socket to non-blocking mode
 */
int ethudp_set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    return fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
}

/**
 * Set socket buffer sizes
 */
int ethudp_set_socket_buffer_size(int sockfd, int buffer_size) {
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size)) != 0) {
        return -1;
    }
    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)) != 0) {
        return -1;
    }
    return 0;
}

/**
 * Get network interface MTU
 */
int ethudp_get_interface_mtu(const char *ifname) {
    int sockfd;
    struct ifreq ifr;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }
    
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    
    if (ioctl(sockfd, SIOCGIFMTU, &ifr) < 0) {
        close(sockfd);
        return -1;
    }
    
    close(sockfd);
    return ifr.ifr_mtu;
}

/**
 * Test network connectivity
 */
int ethudp_test_connectivity(const char *host, const char *port) {
    struct addrinfo hints, *res;
    int sockfd;
    int result = -1;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(host, port, &hints, &res) != 0) {
        return -1;
    }
    
    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd >= 0) {
        if (connect(sockfd, res->ai_addr, res->ai_addrlen) == 0) {
            result = 0;
        }
        close(sockfd);
    }
    
    freeaddrinfo(res);
    return result;
}

/**
 * Calculate network checksum
 */
uint16_t ethudp_calculate_checksum(const void *data, size_t len) {
    const uint16_t *buf = (const uint16_t *)data;
    uint32_t sum = 0;
    
    // Sum all 16-bit words
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    
    // Add odd byte if present
    if (len == 1) {
        sum += *(const uint8_t *)buf << 8;
    }
    
    // Add carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

// ============================================================================
// STUB IMPLEMENTATIONS FOR MISSING FUNCTIONS
// ============================================================================

/**
 * UDP server function - Create and configure UDP server socket
 * @param host Local host address (NULL for any interface)
 * @param port Local port to bind to
 * @return Socket file descriptor on success, -1 on error
 */
int udp_server(const char *host, const char *port) {
    int sockfd;
    struct addrinfo hints, *res, *ressave;
    int reuse = 1;
    int buffer_size = SOCKET_RECV_BUFFER_SIZE;
    
    Debug("udp_server: Creating UDP server on host=%s, port=%s", 
          host ? host : "ANY", port);
    
    // Initialize hints for getaddrinfo
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;        // IPv4 or IPv6
    hints.ai_socktype = SOCK_DGRAM;     // UDP socket
    hints.ai_flags = AI_PASSIVE;        // For server socket
    
    // Resolve address information
    int n = getaddrinfo(host, port, &hints, &res);
    if (n != 0) {
        err_msg("udp_server: getaddrinfo error for %s:%s - %s", 
                host ? host : "ANY", port, gai_strerror(n));
        return -1;
    }
    ressave = res;
    
    // Try each address until we successfully bind
    do {
        sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (sockfd < 0) {
            continue;  // Try next address
        }
        
        // Set socket options for reuse
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
            err_msg("udp_server: setsockopt SO_REUSEADDR failed");
            close(sockfd);
            continue;
        }
        
#ifdef SO_REUSEPORT
        // Enable SO_REUSEPORT for better performance with multiple workers
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
            Debug("udp_server: SO_REUSEPORT not supported, continuing without it");
        }
#endif
        
        // Set receive buffer size
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size)) < 0) {
            err_msg("udp_server: setsockopt SO_RCVBUF failed");
        }
        
        // Set send buffer size
        if (setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size)) < 0) {
            err_msg("udp_server: setsockopt SO_SNDBUF failed");
        }
        
        // Bind to the address
        if (bind(sockfd, res->ai_addr, res->ai_addrlen) == 0) {
            break;  // Success
        }
        
        // Bind failed, close socket and try next address
        err_msg("udp_server: bind failed for address");
        close(sockfd);
        sockfd = -1;
        
    } while ((res = res->ai_next) != NULL);
    
    // Clean up address info
    freeaddrinfo(ressave);
    
    if (sockfd < 0) {
        err_msg("udp_server: Failed to create and bind UDP server socket");
        return -1;
    }
    
    // Get and log the actual bound address
    struct sockaddr_storage bound_addr;
    socklen_t addr_len = sizeof(bound_addr);
    if (getsockname(sockfd, (struct sockaddr*)&bound_addr, &addr_len) == 0) {
        char host_str[NI_MAXHOST], port_str[NI_MAXSERV];
        if (getnameinfo((struct sockaddr*)&bound_addr, addr_len,
                       host_str, sizeof(host_str),
                       port_str, sizeof(port_str),
                       NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
            Debug("udp_server: Successfully bound to %s:%s (fd=%d)", 
                  host_str, port_str, sockfd);
        }
    }
    
    // Set socket to non-blocking mode for better performance
    if (ethudp_set_nonblocking(sockfd) < 0) {
        err_msg("udp_server: Failed to set socket non-blocking");
        close(sockfd);
        return -1;
    }
    
    Debug("udp_server: UDP server socket created successfully (fd=%d)", sockfd);
    return sockfd;
}

/**
 * Loopback check function - Detects and prevents network loops
 * This function analyzes packets to detect potential loopback conditions
 * that could cause infinite packet loops in the EthUDP tunnel
 */
int do_loopback_check(uint8_t *buf, int len) {
    if (!buf || len < 8) {
        return 0; // Invalid parameters or packet too small
    }
    
    static uint32_t loopback_sequence = 0;
    static uint32_t last_loopback_check = 0;
    static struct {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint16_t src_port;
        uint16_t dst_port;
        uint32_t timestamp;
        uint32_t count;
    } recent_packets[LOOPBACK_HISTORY_SIZE];
    static int recent_packet_index = 0;
    static pthread_mutex_t loopback_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    // Get current timestamp
    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC, &current_time);
    uint32_t timestamp = current_time.tv_sec;
    
    // Check for EthUDP header first
    if (len >= 8 && memcmp(buf, "UDPFRG", 6) == 0) {
        // This is an EthUDP packet - check sequence number
        uint16_t seq __attribute__((unused)) = ntohs(*(uint16_t*)(buf + 6));
        
        // Skip EthUDP header for further analysis
        buf += 8;
        len -= 8;
        
        Debug("do_loopback_check: EthUDP packet detected, seq=%u", seq);
    }
    
    // Minimum IP header check
    if (len < 20) {
        return 0; // Packet too small for IP analysis
    }
    
    struct iphdr *iph = (struct iphdr *)buf;
    
    // Validate IP header
    if (iph->version != 4 || len < (iph->ihl * 4)) {
        return 0; // Not IPv4 or invalid header length
    }
    
    uint32_t src_ip = ntohl(iph->saddr);
    uint32_t dst_ip = ntohl(iph->daddr);
    uint16_t src_port = 0, dst_port = 0;
    
    // Extract port information if available
    int ip_header_len = iph->ihl * 4;
    if (len >= ip_header_len + 4) {
        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr *)(buf + ip_header_len);
            if (len >= ip_header_len + sizeof(struct udphdr)) {
                src_port = ntohs(udph->source);
                dst_port = ntohs(udph->dest);
            }
        } else if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)(buf + ip_header_len);
            if (len >= ip_header_len + sizeof(struct tcphdr)) {
                src_port = ntohs(tcph->source);
                dst_port = ntohs(tcph->dest);
            }
        }
    }
    
    // Thread-safe access to recent packets history
    pthread_mutex_lock(&loopback_mutex);
    
    // Check for immediate loopback (same source/destination)
    if (src_ip == dst_ip && src_port == dst_port && src_port != 0) {
        pthread_mutex_unlock(&loopback_mutex);
        Debug("do_loopback_check: Immediate loopback detected (src=dst=%08x:%u)", src_ip, src_port);
        return 1; // Loopback detected
    }
    
    // Check against recent packets for potential loops
    int loop_detected = 0;
    uint32_t duplicate_count = 0;
    
    for (int i = 0; i < LOOPBACK_HISTORY_SIZE; i++) {
        // Skip empty entries
        if (recent_packets[i].timestamp == 0) {
            continue;
        }
        
        // Clean old entries (older than 30 seconds)
        if (timestamp - recent_packets[i].timestamp > 30) {
            memset(&recent_packets[i], 0, sizeof(recent_packets[i]));
            continue;
        }
        
        // Check for exact match (potential loop)
        if (recent_packets[i].src_ip == src_ip &&
            recent_packets[i].dst_ip == dst_ip &&
            recent_packets[i].src_port == src_port &&
            recent_packets[i].dst_port == dst_port) {
            
            recent_packets[i].count++;
            duplicate_count = recent_packets[i].count;
            
            // If we see the same packet pattern too frequently, it's likely a loop
            if (duplicate_count > LOOPBACK_THRESHOLD) {
                loop_detected = 1;
                Debug("do_loopback_check: Loop detected - packet pattern seen %u times", duplicate_count);
                break;
            }
        }
        
        // Check for bidirectional pattern (A→B followed by B→A rapidly)
        if (recent_packets[i].src_ip == dst_ip &&
            recent_packets[i].dst_ip == src_ip &&
            recent_packets[i].src_port == dst_port &&
            recent_packets[i].dst_port == src_port &&
            (timestamp - recent_packets[i].timestamp) < 2) { // Within 2 seconds
            
            Debug("do_loopback_check: Bidirectional pattern detected (potential ping-pong)");
            // This might be normal bidirectional traffic, so we're more lenient
            if (duplicate_count > LOOPBACK_THRESHOLD * 2) {
                loop_detected = 1;
                break;
            }
        }
    }
    
    // Add current packet to history if not a detected loop
    if (!loop_detected) {
        // Find an empty slot or overwrite the oldest
        int slot = recent_packet_index;
        recent_packets[slot].src_ip = src_ip;
        recent_packets[slot].dst_ip = dst_ip;
        recent_packets[slot].src_port = src_port;
        recent_packets[slot].dst_port = dst_port;
        recent_packets[slot].timestamp = timestamp;
        recent_packets[slot].count = 1;
        
        recent_packet_index = (recent_packet_index + 1) % LOOPBACK_HISTORY_SIZE;
    }
    
    // Update global loopback statistics
    loopback_sequence++;
    if (timestamp != last_loopback_check) {
        last_loopback_check = timestamp;
        
        // Periodic cleanup and statistics
        if (debug && (loopback_sequence % 1000 == 0)) {
            int active_entries = 0;
            for (int i = 0; i < LOOPBACK_HISTORY_SIZE; i++) {
                if (recent_packets[i].timestamp != 0 && 
                    timestamp - recent_packets[i].timestamp <= 30) {
                    active_entries++;
                }
            }
            Debug("do_loopback_check: Statistics - checked %u packets, %d active history entries", 
                  loopback_sequence, active_entries);
        }
    }
    
    pthread_mutex_unlock(&loopback_mutex);
    
    if (loop_detected) {
        err_msg("do_loopback_check: Network loop detected and blocked (src=%08x:%u, dst=%08x:%u, count=%u)", 
                src_ip, src_port, dst_ip, dst_port, duplicate_count);
        
        // Update error statistics if available
        if (global_worker_pool.running) {
            __sync_fetch_and_add(&global_worker_pool.total_errors, 1);
        }
    }
    
    return loop_detected ? 1 : 0;
}

/**
 * Print packet function (stub)
 */
void printPacket(uint8_t *buf, int len, const char *prefix) {
    if (debug) {
        Debug("%s: packet length=%d", prefix ? prefix : "PACKET", len);
    }
}

/**
 * Fix MSS function - TCP MSS clamping for different MTUs
 * This function modifies TCP SYN packets to clamp the MSS option
 * to prevent fragmentation issues with tunneling
 */
int fix_mss(uint8_t *buf, int len) {
    if (!fixmss || len < 20) {
        return len; // MSS fixing disabled or packet too small
    }
    
    // Check if this is an IP packet
    struct iphdr *iph = (struct iphdr *)buf;
    
    // Validate IP header
    if (len < sizeof(struct iphdr) || iph->version != 4) {
        return len; // Not IPv4 or too small
    }
    
    int ip_header_len = iph->ihl * 4;
    if (ip_header_len < 20 || len < ip_header_len) {
        return len; // Invalid IP header length
    }
    
    // Check if this is a TCP packet
    if (iph->protocol != IPPROTO_TCP) {
        return len; // Not TCP
    }
    
    // Calculate TCP header offset
    uint8_t *tcp_start = buf + ip_header_len;
    int remaining_len = len - ip_header_len;
    
    if (remaining_len < sizeof(struct tcphdr)) {
        return len; // TCP header too small
    }
    
    struct tcphdr *tcph = (struct tcphdr *)tcp_start;
    int tcp_header_len = tcph->doff * 4;
    
    if (tcp_header_len < 20 || remaining_len < tcp_header_len) {
        return len; // Invalid TCP header length
    }
    
    // Only process SYN packets (where MSS option is present)
    if (!tcph->syn) {
        return len; // Not a SYN packet
    }
    
    // Calculate maximum MSS based on MTU
    // MTU - IP header (20) - TCP header (20) - EthUDP overhead (8) - safety margin (4)
    int max_mss = mtu - 20 - 20 - 8 - 4;
    if (max_mss < 536) {
        max_mss = 536; // Minimum safe MSS
    }
    if (max_mss > 1460) {
        max_mss = 1460; // Standard Ethernet MSS
    }
    
    // Look for MSS option in TCP options
    uint8_t *options = tcp_start + 20; // Start of TCP options
    int options_len = tcp_header_len - 20;
    int i = 0;
    
    while (i < options_len) {
        uint8_t option_type = options[i];
        
        if (option_type == 0) {
            // End of options
            break;
        } else if (option_type == 1) {
            // NOP option
            i++;
            continue;
        } else if (option_type == 2) {
            // MSS option
            if (i + 3 < options_len && options[i + 1] == 4) {
                // Valid MSS option (type=2, length=4, value=2 bytes)
                uint16_t current_mss = ntohs(*(uint16_t *)(options + i + 2));
                
                if (current_mss > max_mss) {
                    // Clamp MSS to maximum allowed value
                    *(uint16_t *)(options + i + 2) = htons(max_mss);
                    
                    // Recalculate TCP checksum
                    tcph->check = 0;
                    
                    // Calculate pseudo header checksum
                    uint32_t pseudo_sum = 0;
                    pseudo_sum += (iph->saddr >> 16) + (iph->saddr & 0xFFFF);
                    pseudo_sum += (iph->daddr >> 16) + (iph->daddr & 0xFFFF);
                    pseudo_sum += htons(IPPROTO_TCP);
                    pseudo_sum += htons(remaining_len);
                    
                    // Add TCP header and data to checksum
                    uint16_t *tcp_words = (uint16_t *)tcp_start;
                    for (int j = 0; j < remaining_len / 2; j++) {
                        pseudo_sum += ntohs(tcp_words[j]);
                    }
                    
                    // Handle odd byte
                    if (remaining_len % 2) {
                        pseudo_sum += tcp_start[remaining_len - 1] << 8;
                    }
                    
                    // Fold carry bits
                    while (pseudo_sum >> 16) {
                        pseudo_sum = (pseudo_sum & 0xFFFF) + (pseudo_sum >> 16);
                    }
                    
                    tcph->check = htons(~pseudo_sum);
                    
                    // Also recalculate IP checksum
                    iph->check = 0;
                    uint32_t ip_sum = 0;
                    uint16_t *ip_words = (uint16_t *)buf;
                    for (int j = 0; j < ip_header_len / 2; j++) {
                        ip_sum += ntohs(ip_words[j]);
                    }
                    
                    // Fold carry bits
                    while (ip_sum >> 16) {
                        ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
                    }
                    
                    iph->check = htons(~ip_sum);
                    
                    Debug("fix_mss: Clamped MSS from %u to %u", current_mss, max_mss);
                }
                break;
            }
            i += 4; // MSS option is always 4 bytes
        } else {
            // Other options with length field
            if (i + 1 >= options_len) {
                break; // Malformed options
            }
            uint8_t option_len = options[i + 1];
            if (option_len < 2 || i + option_len > options_len) {
                break; // Invalid option length
            }
            i += option_len;
        }
    }
    
    return len; // Return original length (packet modified in-place)
}

/**
 * Enhanced encryption/decryption function
 * Supports XOR, AES-128, AES-192, AES-256 algorithms
 * Automatically handles both encryption and decryption based on context
 */
int do_encrypt(uint8_t *buf, int len, uint8_t *nbuf) {
    if (len <= 0 || !buf || !nbuf) {
        err_msg("do_encrypt: Invalid parameters (len=%d, buf=%p, nbuf=%p)", len, buf, nbuf);
        return -1;
    }
    
    // Check if encryption is enabled
    if (enc_algorithm == 0 || enc_key_len == 0) {
        // No encryption, just copy
        if (buf != nbuf) {
            memcpy(nbuf, buf, len);
        }
        return len;
    }
    
    int result = -1;
    
    switch (enc_algorithm) {
        case XOR:
            if (enc_key_len > 0) {
                result = ethudp_xor_encrypt(buf, len, nbuf);
#ifdef DEBUG
                if (__builtin_expect(debug > 2, 0)) {
                    Debug_Hot("do_encrypt: XOR encryption/decryption completed (%d bytes)", result);
                }
#endif
            } else {
                err_msg("do_encrypt: XOR encryption requested but no key provided");
                result = -1;
            }
            break;
            
#ifdef ENABLE_OPENSSL
        case AES_128:
        case AES_192:
        case AES_256:
            // Validate key length for AES algorithms
            int required_key_len = 0;
            const char *alg_name = "";
            
            switch (enc_algorithm) {
                case AES_128:
                    required_key_len = 16;
                    alg_name = "AES-128";
                    break;
                case AES_192:
                    required_key_len = 24;
                    alg_name = "AES-192";
                    break;
                case AES_256:
                    required_key_len = 32;
                    alg_name = "AES-256";
                    break;
            }
            
            if (enc_key_len < required_key_len) {
                err_msg("do_encrypt: %s requires %d-byte key, but only %d bytes provided", 
                        alg_name, required_key_len, enc_key_len);
                result = -1;
                break;
            }
            
            // Check if this looks like encrypted data (for decryption)
            // Encrypted data typically has different characteristics than plain text
            bool is_encrypted_data = false;
            
            // Simple heuristic: if packet starts with known EthUDP headers, it's likely plaintext
            if (len >= 6) {
                if (memcmp(buf, "UDPFRG", 6) == 0 || memcmp(buf, "UDPSLV", 6) == 0) {
                    // This is plaintext with EthUDP header - encrypt it
                    is_encrypted_data = false;
                } else {
                    // This might be encrypted data - try to decrypt it
                    is_encrypted_data = true;
                }
            }
            
            if (is_encrypted_data) {
                // Attempt decryption
                result = ethudp_openssl_decrypt(buf, len, nbuf);
                if (result > 0 && debug > 2) {
                    Debug("do_encrypt: %s decryption completed (%d→%d bytes)", alg_name, len, result);
                }
            } else {
                // Perform encryption
                result = ethudp_openssl_encrypt(buf, len, nbuf);
                if (result > 0 && debug > 2) {
                    Debug("do_encrypt: %s encryption completed (%d→%d bytes)", alg_name, len, result);
                }
            }
            
            if (result <= 0) {
                err_msg("do_encrypt: %s operation failed", alg_name);
            }
            break;
#endif
            
        default:
            err_msg("do_encrypt: Unsupported encryption algorithm: %d", enc_algorithm);
            result = -1;
            break;
    }
    
    // Fallback: if encryption failed, copy original data
    if (result <= 0) {
        if (buf != nbuf) {
            memcpy(nbuf, buf, len);
        }
        return len;
    }
    
    return result;
}

/**
 * Dedicated decryption function for explicit decryption operations
 */
int do_decrypt(uint8_t *buf, int len, uint8_t *nbuf) {
    if (len <= 0 || !buf || !nbuf) {
        err_msg("do_decrypt: Invalid parameters (len=%d, buf=%p, nbuf=%p)", len, buf, nbuf);
        return -1;
    }
    
    // Check if encryption is enabled
    if (enc_algorithm == 0 || enc_key_len == 0) {
        // No encryption, just copy
        if (buf != nbuf) {
            memcpy(nbuf, buf, len);
        }
        return len;
    }
    
    int result = -1;
    
    switch (enc_algorithm) {
        case XOR:
            // XOR is symmetric - same operation for encrypt/decrypt
            if (enc_key_len > 0) {
                result = ethudp_xor_encrypt(buf, len, nbuf);
#ifdef DEBUG
                if (__builtin_expect(debug > 2, 0)) {
                    Debug_Hot("do_decrypt: XOR decryption completed (%d bytes)", result);
                }
#endif
            } else {
                err_msg("do_decrypt: XOR decryption requested but no key provided");
                result = -1;
            }
            break;
            
#ifdef ENABLE_OPENSSL
        case AES_128:
        case AES_192:
        case AES_256:
            result = ethudp_openssl_decrypt(buf, len, nbuf);
            if (result > 0 && debug > 2) {
                const char *alg_name __attribute__((unused)) = (enc_algorithm == AES_128) ? "AES-128" :
                                      (enc_algorithm == AES_192) ? "AES-192" : "AES-256";
                Debug("do_decrypt: %s decryption completed (%d→%d bytes)", alg_name, len, result);
            }
            break;
#endif
            
        default:
            err_msg("do_decrypt: Unsupported encryption algorithm: %d", enc_algorithm);
            result = -1;
            break;
    }
    
    // Fallback: if decryption failed, copy original data
    if (result <= 0) {
        if (buf != nbuf) {
            memcpy(nbuf, buf, len);
        }
        return len;
    }
    
    return result;
}

/**
 * Worker thread functions - UDP to RAW processing
 */
void* process_udp_to_raw_worker(void *arg) {
    worker_context_t *ctx = (worker_context_t *)arg;
    if (!ctx) {
        err_msg("process_udp_to_raw_worker: Invalid worker context");
        return NULL;
    }
    
    Debug("UDP→RAW Worker %d started (thread_id=%lu, cpu_affinity=%d)", 
          ctx->worker_id, (unsigned long)pthread_self(), ctx->cpu_affinity);
    
    // Set CPU affinity if specified
    if (ctx->cpu_affinity >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(ctx->cpu_affinity, &cpuset);
        if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
            err_msg("Worker %d: Failed to set CPU affinity to %d", 
                    ctx->worker_id, ctx->cpu_affinity);
        } else {
            Debug("Worker %d: Set CPU affinity to %d", ctx->worker_id, ctx->cpu_affinity);
        }
    }
    
    // Allocate packet buffers
    unsigned char recv_buf[MAX_PACKET_SIZE];
    unsigned char send_buf[MAX_PACKET_SIZE + 8]; // Extra space for headers
    struct sockaddr_storage client_addr;
    socklen_t client_len = sizeof(client_addr);
    
    // Main processing loop
    while (ctx->running && !ctx->should_stop) {
        // Receive UDP packet
        ssize_t recv_len = recvfrom(fdudp[ctx->socket_index], recv_buf, sizeof(recv_buf), 
                                   MSG_DONTWAIT, (struct sockaddr*)&client_addr, &client_len);
        
        if (recv_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No data available, yield CPU briefly
                usleep(100); // 100 microseconds
                continue;
            } else {
                err_msg("Worker %d: recvfrom error: %s", ctx->worker_id, strerror(errno));
                ctx->errors++;
                continue;
            }
        }
        
        if (recv_len == 0) {
            continue; // Empty packet
        }
        
        // Update statistics
        ctx->packets_processed++;
        ctx->bytes_processed += recv_len;
        
        // Process packet based on mode
        int processed_len = recv_len;
        
        // Apply loopback check if enabled
        if (loopback_check && do_loopback_check(recv_buf, recv_len)) {
            Debug("Worker %d: Packet failed loopback check, dropping", ctx->worker_id);
            continue;
        }
        
        // Apply MSS fixing if enabled
        if (fixmss) {
            processed_len = fix_mss(recv_buf, recv_len);
            if (processed_len < 0) {
                err_msg("Worker %d: MSS fixing failed", ctx->worker_id);
                ctx->errors++;
                continue;
            }
        }
        
        // Apply encryption if configured
        if (enc_algorithm != 0) {
            processed_len = do_encrypt(recv_buf, processed_len, send_buf);
            if (processed_len < 0) {
                err_msg("Worker %d: Encryption failed", ctx->worker_id);
                ctx->errors++;
                continue;
            }
        } else {
            // No encryption, just copy
            memcpy(send_buf, recv_buf, processed_len);
        }
        
        // Add EthUDP header (8 bytes: "UDPFRG" + sequence)
        memmove(send_buf + 8, send_buf, processed_len);
        memcpy(send_buf, "UDPFRG", 6);
        uint16_t seq = htons((uint16_t)(ctx->packets_processed & 0xFFFF));
        memcpy(send_buf + 6, &seq, 2);
        processed_len += 8;
        
        // Send to RAW socket
        ssize_t sent_len = write(fdraw, send_buf, processed_len);
        if (sent_len < 0) {
            err_msg("Worker %d: write to RAW socket failed: %s", 
                    ctx->worker_id, strerror(errno));
            ctx->errors++;
            continue;
        }
        
        if (sent_len != processed_len) {
            err_msg("Worker %d: Partial write to RAW socket (%zd/%d bytes)", 
                    ctx->worker_id, sent_len, processed_len);
            ctx->errors++;
        }
        
        // Debug packet processing
#ifdef DEBUG
        if (__builtin_expect(debug > 1, 0)) {
            Debug_Hot("Worker %d: Processed UDP→RAW packet: %zd→%d bytes", 
                      ctx->worker_id, recv_len, processed_len);
        }
#endif
    }
    
    Debug("UDP→RAW Worker %d stopped (processed %lld packets, %lld bytes, %lld errors)", 
          ctx->worker_id, ctx->packets_processed, ctx->bytes_processed, ctx->errors);
    
    ctx->running = 0;
    return NULL;
}

void* process_raw_to_udp_worker(void *arg) {
    worker_context_t *ctx = (worker_context_t *)arg;
    if (!ctx) {
        err_msg("process_raw_to_udp_worker: Invalid worker context");
        return NULL;
    }
    
    Debug("RAW→UDP Worker %d started (thread_id=%lu, cpu_affinity=%d)", 
          ctx->worker_id, (unsigned long)pthread_self(), ctx->cpu_affinity);
    
    // Set CPU affinity if specified
    if (ctx->cpu_affinity >= 0) {
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(ctx->cpu_affinity, &cpuset);
        if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0) {
            err_msg("Worker %d: Failed to set CPU affinity to %d", 
                    ctx->worker_id, ctx->cpu_affinity);
        } else {
            Debug("Worker %d: Set CPU affinity to %d", ctx->worker_id, ctx->cpu_affinity);
        }
    }
    
    // Allocate packet buffers
    unsigned char recv_buf[MAX_PACKET_SIZE + 8]; // Extra space for headers
    unsigned char send_buf[MAX_PACKET_SIZE];
    struct sockaddr_in dest_addr;
    
    // Initialize destination address structure
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    
    // Main processing loop
    while (ctx->running && !ctx->should_stop) {
        // Receive RAW packet
        ssize_t recv_len = read(fdraw, recv_buf, sizeof(recv_buf));
        
        if (recv_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No data available, yield CPU briefly
                usleep(100); // 100 microseconds
                continue;
            } else {
                err_msg("Worker %d: read from RAW socket error: %s", 
                        ctx->worker_id, strerror(errno));
                ctx->errors++;
                continue;
            }
        }
        
        if (recv_len < 8) {
            // Packet too small to contain EthUDP header
            continue;
        }
        
        // Verify EthUDP header
        if (memcmp(recv_buf, "UDPFRG", 6) != 0) {
            Debug("Worker %d: Invalid EthUDP header, dropping packet", ctx->worker_id);
            continue;
        }
        
        // Extract sequence number (for debugging/statistics)
        uint16_t seq __attribute__((unused)) = ntohs(*(uint16_t*)(recv_buf + 6));
        
        // Skip EthUDP header (8 bytes)
        unsigned char *payload = recv_buf + 8;
        int payload_len = recv_len - 8;
        
        // Update statistics
        ctx->packets_processed++;
        ctx->bytes_processed += payload_len;
        
        // Process packet based on mode
        int processed_len = payload_len;
        
        // Apply decryption if configured
        if (enc_algorithm != 0) {
            processed_len = do_encrypt(payload, payload_len, send_buf); // decrypt is same function
            if (processed_len < 0) {
                err_msg("Worker %d: Decryption failed", ctx->worker_id);
                ctx->errors++;
                continue;
            }
        } else {
            // No decryption, just copy
            memcpy(send_buf, payload, processed_len);
        }
        
        // Apply MSS fixing if enabled (reverse operation)
        if (fixmss) {
            processed_len = fix_mss(send_buf, processed_len);
            if (processed_len < 0) {
                err_msg("Worker %d: MSS fixing failed", ctx->worker_id);
                ctx->errors++;
                continue;
            }
        }
        
        // Extract destination from packet or use configured destination
        if (remote_addr[MASTER].ss_family == AF_INET) {
            struct sockaddr_in *remote_in = (struct sockaddr_in*)&remote_addr[MASTER];
            dest_addr.sin_addr.s_addr = remote_in->sin_addr.s_addr;
        } else {
            // Try to extract destination from IP header if available
            if (processed_len >= 20) { // Minimum IP header size
                struct iphdr *ip_hdr = (struct iphdr*)send_buf;
                if (ip_hdr->version == 4) {
                    dest_addr.sin_addr.s_addr = ip_hdr->daddr;
                } else {
                    err_msg("Worker %d: No destination IP configured and cannot extract from packet", 
                            ctx->worker_id);
                    ctx->errors++;
                    continue;
                }
            } else {
                err_msg("Worker %d: Packet too small to extract destination", ctx->worker_id);
                ctx->errors++;
                continue;
            }
        }
        
        // Set destination port
        if (remote_addr[MASTER].ss_family == AF_INET) {
            struct sockaddr_in *remote_in = (struct sockaddr_in*)&remote_addr[MASTER];
            dest_addr.sin_port = remote_in->sin_port;
        } else {
            // Try to extract port from UDP header if available
            if (processed_len >= 28) { // IP header (20) + UDP header (8)
                struct iphdr *ip_hdr = (struct iphdr*)send_buf;
                if (ip_hdr->protocol == IPPROTO_UDP) {
                    struct udphdr *udp_hdr = (struct udphdr*)(send_buf + (ip_hdr->ihl * 4));
                    dest_addr.sin_port = udp_hdr->dest;
                } else {
                    dest_addr.sin_port = htons(8080);  // Default UDP port
                }
            } else {
                dest_addr.sin_port = htons(8080);  // Default UDP port
            }
        }
        
        // Send to UDP socket
        ssize_t sent_len = sendto(fdudp[ctx->socket_index], send_buf, processed_len, 0,
                                 (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        
        if (sent_len < 0) {
            err_msg("Worker %d: sendto UDP socket failed: %s", 
                    ctx->worker_id, strerror(errno));
            ctx->errors++;
            continue;
        }
        
        if (sent_len != processed_len) {
            err_msg("Worker %d: Partial send to UDP socket (%zd/%d bytes)", 
                    ctx->worker_id, sent_len, processed_len);
            ctx->errors++;
        }
        
        // Debug packet processing
#ifdef DEBUG
        if (__builtin_expect(debug > 1, 0)) {
            char dest_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &dest_addr.sin_addr, dest_ip_str, INET_ADDRSTRLEN);
            Debug_Hot("Worker %d: Processed RAW→UDP packet: %zd→%d bytes, seq=%u, dest=%s:%d", 
                      ctx->worker_id, recv_len, processed_len, seq, 
                      dest_ip_str, ntohs(dest_addr.sin_port));
        }
#endif
    }
    
    Debug("RAW→UDP Worker %d stopped (processed %lld packets, %lld bytes, %lld errors)", 
          ctx->worker_id, ctx->packets_processed, ctx->bytes_processed, ctx->errors);
    
    ctx->running = 0;
    return NULL;
}