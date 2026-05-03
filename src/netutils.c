#include "netutils.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "logutils.h"

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN 23
#endif

#ifndef MSG_FASTOPEN
#define MSG_FASTOPEN 0x20000000
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif

#ifndef IPV6_TRANSPARENT
#define IPV6_TRANSPARENT 75
#endif

#ifndef IP_RECVORIGDSTADDR
#define IP_RECVORIGDSTADDR 20
#endif

#ifndef IPV6_RECVORIGDSTADDR
#define IPV6_RECVORIGDSTADDR 74
#endif

void set_nofile_limit(size_t nofile) {
    if (setrlimit(RLIMIT_NOFILE, &(struct rlimit) {
    nofile, nofile
}) < 0) {
        LOGERR("[set_nofile_limit] setrlimit(nofile, %zu): %s", nofile, strerror(errno));
    }
}

size_t get_nofile_limit(void) {
    struct rlimit v;
    if (getrlimit(RLIMIT_NOFILE, &v) < 0) {
        LOGERR("[get_nofile_limit] getrlimit(nofile): %s", strerror(errno));
        v.rlim_cur = 0;
    }
    return v.rlim_cur;
}

int get_ipstr_family(const char *ipstr) {
    if (!ipstr) {
        return -1; /* invalid */
    }
    ipaddr6_t ipaddr; /* save output */
    if (inet_pton(AF_INET, ipstr, &ipaddr) == 1) {
        return AF_INET;
    }
    if (inet_pton(AF_INET6, ipstr, &ipaddr) == 1) {
        return AF_INET6;
    }
    return -1; /* invalid */
}

void build_socket_addr(int family, void *skaddr, const char *ipstr, portno_t portno) {
    if (family == AF_INET) {
        skaddr4_t *addr = skaddr;
        addr->sin_family = AF_INET;
        inet_pton(AF_INET, ipstr, &addr->sin_addr);
        addr->sin_port = htons(portno);
    } else {
        skaddr6_t *addr = skaddr;
        addr->sin6_family = AF_INET6;
        inet_pton(AF_INET6, ipstr, &addr->sin6_addr);
        addr->sin6_port = htons(portno);
    }
}

void parse_socket_addr(const void *skaddr, char *ipstr, portno_t *portno) {
    if (((const skaddr4_t *)skaddr)->sin_family == AF_INET) {
        const skaddr4_t *addr = skaddr;
        inet_ntop(AF_INET, &addr->sin_addr, ipstr, IP4STRLEN);
        *portno = ntohs(addr->sin_port);
    } else {
        const skaddr6_t *addr = skaddr;
        inet_ntop(AF_INET6, &addr->sin6_addr, ipstr, IP6STRLEN);
        *portno = ntohs(addr->sin6_port);
    }
}

static inline void set_non_block(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        LOGERR("[set_non_block] fcntl(%d, F_GETFL): %s", sockfd, strerror(errno));
        return;
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        LOGERR("[set_non_block] fcntl(%d, F_SETFL): %s", sockfd, strerror(errno));
        return;
    }
}

static inline void set_ipv6_only(int sockfd) {
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &(int) {
    1
}, sizeof(int)) < 0) {
        LOGERR("[set_ipv6_only] setsockopt(%d, IPV6_V6ONLY): %s", sockfd, strerror(errno));
    }
}

static inline void set_reuse_addr(int sockfd) {
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int) {
    1
}, sizeof(int)) < 0) {
        LOGERR("[set_reuse_addr] setsockopt(%d, SO_REUSEADDR): %s", sockfd, strerror(errno));
    }
}

static inline void set_reuse_port(int sockfd) {
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &(int) {
    1
}, sizeof(int)) < 0) {
        LOGERR("[set_reuse_port] setsockopt(%d, SO_REUSEPORT): %s", sockfd, strerror(errno));
    }
}

static inline void set_tfo_accept(int sockfd) {
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_FASTOPEN, &(int) {
    5
}, sizeof(int)) < 0) {
        LOGERR("[set_tfo_accept] setsockopt(%d, TCP_FASTOPEN): %s", sockfd, strerror(errno));
    }
}

static inline void set_tcp_syncnt(int sockfd, int syncnt) {
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_SYNCNT, &syncnt, sizeof(int)) < 0) {
        LOGERR("[set_tcp_syncnt] setsockopt(%d, TCP_SYNCNT): %s", sockfd, strerror(errno));
    }
}

static inline void set_tcp_nodelay(int sockfd) {
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &(int) {
    1
}, sizeof(int)) < 0) {
        LOGERR("[set_tcp_nodelay] setsockopt(%d, TCP_NODELAY): %s", sockfd, strerror(errno));
    }
}

static inline void set_tcp_quickack(int sockfd) {
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_QUICKACK, &(int) {
    1
}, sizeof(int)) < 0) {
        LOGERR("[set_tcp_quickack] setsockopt(%d, TCP_QUICKACK): %s", sockfd, strerror(errno));
    }
}

static inline void set_tcp_solinger0(int sockfd) {
    if (setsockopt(sockfd, SOL_SOCKET, SO_LINGER, &(struct linger) {
    .l_onoff = 1, .l_linger = 0
}, sizeof(struct linger)) < 0) {
        LOGERR("[set_tcp_solinger0] setsockopt(%d, SO_LINGER): %s", sockfd, strerror(errno));
    }
}

static inline void set_tcp_keepalive(int sockfd) {
    /* enable tcp_keepalive */
    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &(int) {
    1
}, sizeof(int)) < 0) {
        LOGERR("[set_tcp_keepalive] setsockopt(%d, SO_KEEPALIVE): %s", sockfd, strerror(errno));
        return;
    }
    /* tcp connection idle sec */
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &(int) {
    60
}, sizeof(int)) < 0) {
        LOGERR("[set_tcp_keepalive] setsockopt(%d, TCP_KEEPIDLE): %s", sockfd, strerror(errno));
        return;
    }
    /* keepalive probe retry max count */
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &(int) {
    3
}, sizeof(int)) < 0) {
        LOGERR("[set_tcp_keepalive] setsockopt(%d, TCP_KEEPCNT): %s", sockfd, strerror(errno));
        return;
    }
    /* keepalive probe retry interval sec */
    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &(int) {
    5
}, sizeof(int)) < 0) {
        LOGERR("[set_tcp_keepalive] setsockopt(%d, TCP_KEEPINTVL): %s", sockfd, strerror(errno));
        return;
    }
}

static inline bool set_ip_transparent(int family, int sockfd) {
    if (family == AF_INET) {
        if (setsockopt(sockfd, IPPROTO_IP, IP_TRANSPARENT, &(int) {
        1
    }, sizeof(int)) < 0) {
            LOGERR("[set_ip_transparent] setsockopt(%d, IP_TRANSPARENT): %s", sockfd, strerror(errno));
            return false;
        }
    } else {
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_TRANSPARENT, &(int) {
        1
    }, sizeof(int)) < 0) {
            LOGERR("[set_ip_transparent] setsockopt(%d, IPV6_TRANSPARENT): %s", sockfd, strerror(errno));
            return false;
        }
    }
    return true;
}

static inline bool set_recv_origdstaddr(int family, int sockfd) {
    if (family == AF_INET) {
        if (setsockopt(sockfd, IPPROTO_IP, IP_RECVORIGDSTADDR, &(int) {
        1
    }, sizeof(int)) < 0) {
            LOGERR("[set_recv_origdstaddr] setsockopt(%d, IP_RECVORIGDSTADDR): %s", sockfd, strerror(errno));
            return false;
        }
    } else {
        if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVORIGDSTADDR, &(int) {
        1
    }, sizeof(int)) < 0) {
            LOGERR("[set_recv_origdstaddr] setsockopt(%d, IPV6_RECVORIGDSTADDR): %s", sockfd, strerror(errno));
            return false;
        }
    }
    return true;
}

static inline int close_and_fail(int sockfd) {
    int saved_errno = errno;
    close(sockfd);
    errno = saved_errno;
    return -1;
}

static inline void setup_accepted_sockfd(int sockfd) {
    set_non_block(sockfd);
    set_tcp_nodelay(sockfd);
    set_tcp_quickack(sockfd);
    set_tcp_keepalive(sockfd);
}

int new_nonblock_pipefd(int pipefd[2]) {
    if (pipe(pipefd) < 0) {
        LOGERR("[new_nonblock_pipefd] pipe(%p): %s", (void *)pipefd, strerror(errno));
        pipefd[0] = pipefd[1] = -1;
        return -1;
    }
    set_non_block(pipefd[0]);
    set_non_block(pipefd[1]);
    return 0;
}

static inline int new_nonblock_sockfd(int family, int sktype) {
    int sockfd = socket(family, sktype, 0);
    if (sockfd < 0) {
        LOGERR("[new_nonblock_sockfd] socket(%s, %s): %s", family == AF_INET ? "AF_INET" : "AF_INET6", sktype == SOCK_STREAM ? "SOCK_STREAM" : "SOCK_DGRAM", strerror(errno));
        return -1;
    }
    set_non_block(sockfd);
    if (family == AF_INET6) {
        set_ipv6_only(sockfd);
    }
    set_reuse_addr(sockfd);
    return sockfd;
}

int new_tcp_listen_sockfd(int family, bool is_reuse_port, bool is_tfo_accept) {
    int sockfd = new_nonblock_sockfd(family, SOCK_STREAM);
    if (sockfd < 0) {
        return sockfd;
    }
    if (!set_ip_transparent(family, sockfd)) {
        return close_and_fail(sockfd);
    }
    if (is_reuse_port) {
        set_reuse_port(sockfd);
    }
    if (is_tfo_accept) {
        set_tfo_accept(sockfd);
    }
    return sockfd;
}

int new_tcp_connect_sockfd(int family, uint8_t tcp_syncnt) {
    int sockfd = new_nonblock_sockfd(family, SOCK_STREAM);
    if (sockfd < 0) {
        return sockfd;
    }
    set_tcp_nodelay(sockfd);
    set_tcp_quickack(sockfd);
    set_tcp_keepalive(sockfd);
    if (tcp_syncnt) {
        set_tcp_syncnt(sockfd, tcp_syncnt);
    }
    return sockfd;
}

int new_udp_tprecv_sockfd(int family, bool is_reuse_port) {
    int sockfd = new_nonblock_sockfd(family, SOCK_DGRAM);
    if (sockfd < 0) {
        return sockfd;
    }
    if (!set_ip_transparent(family, sockfd)) {
        return close_and_fail(sockfd);
    }
    if (!set_recv_origdstaddr(family, sockfd)) {
        return close_and_fail(sockfd);
    }
    if (is_reuse_port) {
        set_reuse_port(sockfd);
    }
    return sockfd;
}

int new_udp_tpsend_sockfd(int family) {
    int sockfd = new_nonblock_sockfd(family, SOCK_DGRAM);
    if (sockfd < 0) {
        return sockfd;
    }
    if (!set_ip_transparent(family, sockfd)) {
        return close_and_fail(sockfd);
    }
    return sockfd;
}

int new_udp_normal_sockfd(int family) {
    return new_nonblock_sockfd(family, SOCK_DGRAM);
}

bool get_tcp_orig_dstaddr(int family, int sockfd, void *dstaddr) {
    socklen_t addrlen = (family == AF_INET) ? sizeof(skaddr4_t) : sizeof(skaddr6_t);
    if (getsockname(sockfd, dstaddr, &addrlen) < 0) {
        LOGERR("[get_tcp_orig_dstaddr] addr_family:%s, getsockname(%d): %s", (family == AF_INET) ? "inet" : "inet6", sockfd, strerror(errno));
        return false;
    }
    return true;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare" /* CMSG_NXTHDR */
bool get_udp_orig_dstaddr(int family, struct msghdr *msg, void *dstaddr) {
    if (family == AF_INET) {
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_RECVORIGDSTADDR) {
                memcpy(dstaddr, CMSG_DATA(cmsg), sizeof(skaddr4_t));
                return true;
            }
        }
    } else {
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
            if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_RECVORIGDSTADDR) {
                memcpy(dstaddr, CMSG_DATA(cmsg), sizeof(skaddr6_t));
                return true;
            }
        }
    }
    return false;
}
#pragma GCC diagnostic pop

/* same as `accept()`, just a simple wrapper */
int tcp_accept(int sockfd, void *addr, socklen_t *addrlen) {
    int newsockfd = accept(sockfd, addr, addrlen);
    if (newsockfd >= 0) {
        setup_accepted_sockfd(newsockfd);
    }
    return newsockfd;
}

static inline bool should_fallback_from_tfo(int err) {
    switch (err) {
        case EINVAL:
        case ENOPROTOOPT:
        case EOPNOTSUPP:
        case EPROTONOSUPPORT:
            return true;
#ifdef ENOTSUP
#if ENOTSUP != EOPNOTSUPP
        case ENOTSUP:
            return true;
#endif
#endif
        default:
            return false;
    }
}

static inline tcp_connect_result_t tcp_plain_connect(int sockfd, const void *addr, socklen_t addrlen) {
    if (connect(sockfd, addr, addrlen) == 0) {
        return TCP_CONNECT_CONNECTED;
    }
    return errno == EINPROGRESS ? TCP_CONNECT_IN_PROGRESS : TCP_CONNECT_FAILED;
}

/* tfo_succ if tfo_nsend >= 0; may fall back to plain connect */
tcp_connect_result_t tcp_connect(int sockfd, const void *addr, const void *tfo_data, size_t tfo_datalen, ssize_t *tfo_nsend) {
    socklen_t addrlen = ((skaddr4_t *)addr)->sin_family == AF_INET ? sizeof(skaddr4_t) : sizeof(skaddr6_t);
    if (tfo_data && tfo_datalen && tfo_nsend) {
        do {
            *tfo_nsend = sendto(sockfd, tfo_data, tfo_datalen, MSG_FASTOPEN, addr, addrlen);
        } while (*tfo_nsend < 0 && errno == EINTR);
        if (*tfo_nsend >= 0 || errno == EINPROGRESS) {
            return TCP_CONNECT_IN_PROGRESS;
        }

        int saved_errno = errno;
        if (!should_fallback_from_tfo(saved_errno)) {
            return TCP_CONNECT_FAILED;
        }

        IF_VERBOSE {
            LOGINF_RAW("[tcp_connect] MSG_FASTOPEN unavailable: %s, falling back to connect()",
                       strerror(saved_errno));
        }
        *tfo_nsend = -1;
        return tcp_plain_connect(sockfd, addr, addrlen);
    }
    return tcp_plain_connect(sockfd, addr, addrlen);
}

/* on connect error, errno is set appropriately */
bool tcp_has_error(int sockfd) {
    return getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &errno, &(socklen_t) {
        sizeof(errno)
    }) < 0 || errno;
}

/* set so_linger(delay=0) and call close(sockfd) */
void tcp_close_by_rst(int sockfd) {
    set_tcp_solinger0(sockfd);
    close(sockfd);
}
