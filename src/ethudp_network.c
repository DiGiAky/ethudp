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
extern int debug;
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
extern char enc_iv[16];
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
    unsigned char buf[MAX_PACKET_SIZE];
    int32_t ifindex;
    struct ifreq ifr;
    struct sockaddr_ll sll;
    int n;

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
        char rip[200];
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
 * UDP server function (stub)
 */
int udp_server(const char *host, const char *port) {
    // TODO: Implement UDP server functionality
    Debug("udp_server called with host=%s, port=%s", host, port);
    return -1;
}

/**
 * Loopback check function (stub)
 */
int do_loopback_check(uint8_t *buf, int len) {
    // TODO: Implement loopback check
    return 0;
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
 * Fix MSS function (stub)
 */
int fix_mss(uint8_t *buf, int len) {
    // TODO: Implement MSS fixing
    return len;
}

/**
 * Encryption function (stub)
 */
int do_encrypt(uint8_t *buf, int len, uint8_t *nbuf) {
    // TODO: Implement proper encryption
    if (enc_algorithm == XOR && enc_key_len > 0) {
        return ethudp_xor_encrypt(buf, len, nbuf);
    }
#ifdef ENABLE_OPENSSL
    else if (enc_algorithm >= AES_128 && enc_algorithm <= AES_256) {
        return ethudp_openssl_encrypt(buf, len, nbuf);
    }
#endif
    else {
        // No encryption, just copy
        memcpy(nbuf, buf, len);
        return len;
    }
}

/**
 * Worker thread functions (stubs)
 */
void* process_udp_to_raw_worker(void *arg) {
    // TODO: Implement UDP to RAW worker
    Debug("process_udp_to_raw_worker started");
    while (1) {
        sleep(1);
    }
    return NULL;
}

void* process_raw_to_udp_worker(void *arg) {
    // TODO: Implement RAW to UDP worker
    Debug("process_raw_to_udp_worker started");
    while (1) {
        sleep(1);
    }
    return NULL;
}