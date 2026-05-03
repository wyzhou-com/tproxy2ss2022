#ifndef TPROXY2SS2022_NETUTILS_H
#define TPROXY2SS2022_NETUTILS_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define IP4BINLEN 4
#define IP6BINLEN 16

#define IP4STRLEN INET_ADDRSTRLEN
#define IP6STRLEN INET6_ADDRSTRLEN
#define PORTSTRLEN 6

#define IP4STR_LOOPBACK "127.0.0.1"
#define IP6STR_LOOPBACK "::1"

#define UDP_CTRLMESG_BUFSIZ 64
#define UDP_DATAGRAM_MAXSIZ 65507 /* 65535 - iphdr(20) - udphdr(8) */

#define SOCKS5_RESP_HEADER_PREFIX_LEN 5 /* VER(1) + REP(1) + RSV(1) + ATYP(1) + first-addr-byte(1) */

typedef uint32_t ipaddr4_t;
typedef uint8_t  ipaddr6_t[16];

typedef union {
    ipaddr4_t ip4;
    ipaddr6_t ip6;
} ipaddr_t;

typedef uint16_t portno_t;

typedef struct {
    ipaddr_t ip;
    portno_t port;
} ip_port_t;

typedef struct sockaddr_in  skaddr4_t;
typedef struct sockaddr_in6 skaddr6_t;

void set_nofile_limit(size_t nofile);
size_t get_nofile_limit(void);

int get_ipstr_family(const char *ipstr);
void build_socket_addr(int family, void *skaddr, const char *ipstr, portno_t portno);
void parse_socket_addr(const void *skaddr, char *ipstr, portno_t *portno);

int new_nonblock_pipefd(int pipefd[2]); /* return 0:success, -1:error */

int new_tcp_listen_sockfd(int family, bool is_reuse_port, bool is_tfo_accept);
int new_tcp_connect_sockfd(int family, uint8_t tcp_syncnt);

int new_udp_tprecv_sockfd(int family, bool is_reuse_port);
int new_udp_tpsend_sockfd(int family);
int new_udp_normal_sockfd(int family);

bool get_tcp_orig_dstaddr(int family, int sockfd, void *dstaddr);
bool get_udp_orig_dstaddr(int family, struct msghdr *msg, void *dstaddr);

/* same as `accept()`, just a simple wrapper */
int tcp_accept(int sockfd, void *addr, socklen_t *addrlen);

typedef enum {
    TCP_CONNECT_FAILED      = -1,
    TCP_CONNECT_IN_PROGRESS = 0,
    TCP_CONNECT_CONNECTED   = 1,
} tcp_connect_result_t;

/* tfo_succ if tfo_nsend >= 0; may fall back to plain connect */
tcp_connect_result_t tcp_connect(int sockfd, const void *addr, const void *tfo_data, size_t tfo_datalen, ssize_t *tfo_nsend);

/* on connect error, errno is set appropriately */
bool tcp_has_error(int sockfd);

/* set so_linger(delay=0) and call close(sockfd) */
void tcp_close_by_rst(int sockfd);

#endif /* TPROXY2SS2022_NETUTILS_H */
