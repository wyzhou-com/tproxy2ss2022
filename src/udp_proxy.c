#include "udp_proxy.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ctx.h"
#include "fakedns.h"
#include "logutils.h"
#include "server_selector.h"

/* symmetric_key is hashed as a whole struct; both endpoints must be tightly packed. */
_Static_assert(sizeof(udp_symmetric_key_t) == 2 * sizeof(udp_endpoint_key_t),
               "udp_symmetric_key_t must be tightly packed for memcmp hashing");

/* Reply-path recovery uses offsetof; watcher must be at offset 0. */
_Static_assert(offsetof(udp_session_t, server_watcher) == 0,
               "server_watcher must be first in udp_session_t");

static __thread ss2022_client_ctx g_udp_ss_ctx[SS_MAX_SERVERS];
static __thread bool              g_udp_ss_ctx_ready[SS_MAX_SERVERS];
static __thread uint8_t           g_udp_seal_buf[UDP_DATAGRAM_MAXSIZ];

static ss2022_client_ctx *udp_ctx_get(int server_idx) {
    if (!g_udp_ss_ctx_ready[server_idx]) {
        ss_server_t *srv = &g_ss_servers[server_idx];
        if (ss2022_client_ctx_init(&g_udp_ss_ctx[server_idx],
                                   srv->method, srv->psk) != SS2022_OK)
            return NULL;
        g_udp_ss_ctx_ready[server_idx] = true;
    }
    return &g_udp_ss_ctx[server_idx];
}

typedef enum {
    UDP_ENTRY_INDEXED,
    UDP_ENTRY_DETACHED,
} udp_entry_state_t;

typedef struct {
    udp_endpoint_key_t client_endpoint;
    udp_endpoint_key_t original_target_endpoint;   /* network byte order port */
    bool               uses_fakedns;
    ss2022_addr        ss_target;
} udp_ingress_t;

typedef struct {
    udp_tproxy_entry_t *source_entry;
    struct mmsghdr      msg;
    struct iovec        iov;
    skaddr6_t           client_addr;
} udp_tproxy_send_t;

/* Per-thread batch I/O buffers. */
static __thread struct mmsghdr  g_tprecv_msgs[UDP_BATCH_SIZE];
static __thread struct iovec    g_tprecv_iovs[UDP_BATCH_SIZE];
static __thread char            g_tprecv_ctrl_bufs[UDP_BATCH_SIZE][UDP_CTRLMESG_BUFSIZ];
static __thread skaddr6_t       g_tprecv_skaddrs[UDP_BATCH_SIZE];

static __thread struct mmsghdr  g_server_reply_msgs[UDP_BATCH_SIZE];
static __thread struct mmsghdr  g_tpsend_msgs[UDP_BATCH_SIZE];
static __thread struct iovec    g_server_reply_iovs[UDP_BATCH_SIZE];

static inline udp_endpoint_key_t udp_endpoint_from_skaddr(const skaddr6_t *skaddr, bool is_ipv4) {
    udp_endpoint_key_t ep;
    memset(&ep, 0, sizeof(ep));
    if (is_ipv4) {
        const skaddr4_t *sa4 = (const skaddr4_t *)skaddr;
        ep.family = AF_INET;
        ep.port   = sa4->sin_port;
        memcpy(ep.addr, &sa4->sin_addr.s_addr, IP4BINLEN);
    } else {
        ep.family = AF_INET6;
        ep.port   = skaddr->sin6_port;
        memcpy(ep.addr, &skaddr->sin6_addr.s6_addr, IP6BINLEN);
    }
    return ep;
}

static inline void udp_endpoint_to_skaddr(skaddr6_t *dst, const udp_endpoint_key_t *ep) {
    memset(dst, 0, sizeof(*dst));
    if (ep->family == AF_INET) {
        skaddr4_t *a = (void *)dst;
        a->sin_family = AF_INET;
        memcpy(&a->sin_addr.s_addr, ep->addr, IP4BINLEN);
        a->sin_port   = ep->port;
    } else {
        dst->sin6_family = AF_INET6;
        memcpy(&dst->sin6_addr.s6_addr, ep->addr, IP6BINLEN);
        dst->sin6_port  = ep->port;
    }
}

static inline void udp_endpoint_to_string(const udp_endpoint_key_t *ep, char ipstr[IP6STRLEN], portno_t *portno) {
    if (ep->family == AF_INET) {
        inet_ntop(AF_INET, ep->addr, ipstr, IP6STRLEN);
    } else {
        inet_ntop(AF_INET6, ep->addr, ipstr, IP6STRLEN);
    }
    *portno = ntohs(ep->port);
}

static void udp_log_relay_send_to_server(const udp_session_t *session,
        const udp_endpoint_key_t *target,
        ssize_t nsend) {
    ss_server_t *srv = &g_ss_servers[session->server_idx];
    char client_ipstr[IP6STRLEN];
    char target_ipstr[IP6STRLEN];
    portno_t client_port;
    portno_t target_port;

    udp_endpoint_to_string(&session->client_endpoint, client_ipstr, &client_port);
    udp_endpoint_to_string(target, target_ipstr, &target_port);

    LOGINF_RAW("[udp_relay]  relay: %s#%hu -> %s#%hu -> %s#%hu, nsend:%zd",
               client_ipstr, client_port,
               srv->ipstr, srv->portno,
               target_ipstr, target_port,
               nsend);
}

static void udp_log_tproxy_send_to_client(const udp_session_t *session,
        const udp_endpoint_key_t *reply_src,
        int npackets) {
    ss_server_t *srv = &g_ss_servers[session->server_idx];
    char client_ipstr[IP6STRLEN];
    char reply_src_ipstr[IP6STRLEN];
    portno_t client_port;
    portno_t reply_src_port;

    udp_endpoint_to_string(&session->client_endpoint, client_ipstr, &client_port);
    udp_endpoint_to_string(reply_src, reply_src_ipstr, &reply_src_port);

    LOGINF_RAW("[udp_tproxy] relay: %s#%hu <- %s#%hu <- %s#%hu, npackets:%d",
               client_ipstr, client_port,
               srv->ipstr, srv->portno,
               reply_src_ipstr, reply_src_port,
               npackets);
}

static void udp_log_session_route(const char *action, const udp_ingress_t *pkt) {
    char client_ipstr[IP6STRLEN];
    char target_ipstr[IP6STRLEN];
    portno_t client_port;
    portno_t target_port;
    const char *nat_type = pkt->uses_fakedns ? "symmetric" : "fullcone";

    udp_endpoint_to_string(&pkt->client_endpoint, client_ipstr, &client_port);
    udp_endpoint_to_string(&pkt->original_target_endpoint, target_ipstr, &target_port);

    LOGINF_RAW("[udp_session] %s %s session: %s#%hu -> %s#%hu",
               action, nat_type, client_ipstr, client_port, target_ipstr, target_port);
}

static void udp_log_tproxy_entry_route(const char *action,
                                       const udp_endpoint_key_t *reply_src,
                                       const udp_endpoint_key_t *client,
                                       int sockfd) {
    char reply_src_ipstr[IP6STRLEN];
    char client_ipstr[IP6STRLEN];
    portno_t reply_src_port;
    portno_t client_port;

    udp_endpoint_to_string(reply_src, reply_src_ipstr, &reply_src_port);
    udp_endpoint_to_string(client, client_ipstr, &client_port);

    LOGINF_RAW("[udp_tproxy] %s entry: %s#%hu <- %s#%hu, fd:%d",
               action,
               reply_src_ipstr, reply_src_port,
               client_ipstr, client_port,
               sockfd);
}

/* Convert an ss2022_addr (host-byte-order port) to udp_endpoint_key_t (network-byte-order port). */
static udp_endpoint_key_t udp_endpoint_from_addr(const ss2022_addr *addr) {
    udp_endpoint_key_t ep;
    memset(&ep, 0, sizeof(ep));
    if (addr->type == SS2022_ADDR_IPV4) {
        ep.family = AF_INET;
        ep.port   = htons(addr->port);
        memcpy(ep.addr, addr->u.ipv4, IP4BINLEN);
    } else if (addr->type == SS2022_ADDR_IPV6) {
        ep.family = AF_INET6;
        ep.port   = htons(addr->port);
        memcpy(ep.addr, addr->u.ipv6, IP6BINLEN);
    }
    return ep;
}

static bool udp_ingress_get_sender(struct msghdr *msg, skaddr6_t *skaddr) {
    if (msg->msg_namelen == sizeof(skaddr4_t)) {
        memcpy(skaddr, msg->msg_name, sizeof(skaddr4_t));
        return true;
    }
    if (msg->msg_namelen == sizeof(skaddr6_t)) {
        memcpy(skaddr, msg->msg_name, sizeof(skaddr6_t));
        return true;
    }

    LOGERR("[udp_ingress] invalid msg_namelen: %d", (int)msg->msg_namelen);
    return false;
}

static bool udp_ingress_resolve_fakedns(const skaddr6_t *original_target_skaddr, bool is_ipv4, const char **fake_domain) {
    *fake_domain = NULL;
    if (!(g_options & OPT_ENABLE_FAKEDNS) || !is_ipv4) {
        return true;
    }

    uint32_t target_ip = ((const skaddr4_t *)original_target_skaddr)->sin_addr.s_addr;
    bool is_miss;
    *fake_domain = fakedns_try_resolve(target_ip, &is_miss);
    if (is_miss) {
        LOGERR("[udp_fakedns] miss for FakeIP: %u.%u.%u.%u, dropping packet",
               ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
               ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3]);
        return false;
    }

    IF_VERBOSE if (*fake_domain) {
        LOGINF_RAW("[udp_fakedns] hit: %u.%u.%u.%u -> %s",
                   ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                   ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3],
                   *fake_domain);
    }
    return true;
}

static bool udp_ingress_parse(struct msghdr *msg, size_t nrecv, bool is_ipv4, udp_ingress_t *pkt) {
    skaddr6_t client_skaddr;
    skaddr6_t original_target_skaddr;

    if (!udp_ingress_get_sender(msg, &client_skaddr)) {
        return false;
    }

    pkt->client_endpoint = udp_endpoint_from_skaddr(&client_skaddr, is_ipv4);

    IF_VERBOSE {
        char client_ipstr[IP6STRLEN];
        portno_t client_port;
        udp_endpoint_to_string(&pkt->client_endpoint, client_ipstr, &client_port);
        LOGINF_RAW("[udp_ingress] recv from %s#%hu, nrecv:%zu", client_ipstr, client_port, nrecv);
    }

    if (!get_udp_orig_dstaddr(is_ipv4 ? AF_INET : AF_INET6, msg, &original_target_skaddr)) {
        LOGERR("[udp_ingress] destination address not found in udp msg");
        return false;
    }

    const char *fake_domain = NULL;
    if (!udp_ingress_resolve_fakedns(&original_target_skaddr, is_ipv4, &fake_domain)) {
        return false;
    }

    pkt->original_target_endpoint   = udp_endpoint_from_skaddr(&original_target_skaddr, is_ipv4);
    pkt->uses_fakedns = (fake_domain != NULL);

    memset(&pkt->ss_target, 0, sizeof(pkt->ss_target));
    if (fake_domain) {
        size_t domain_len = strlen(fake_domain);
        if (domain_len == 0 || domain_len > sizeof(pkt->ss_target.u.domain.name)) {
            LOGERR("[udp_ingress] invalid fakedns domain length: %zu", domain_len);
            return false;
        }
        pkt->ss_target.type = SS2022_ADDR_DOMAIN;
        pkt->ss_target.port = ntohs(((const skaddr4_t *)&original_target_skaddr)->sin_port);
        pkt->ss_target.u.domain.len = (uint8_t)domain_len;
        memcpy(pkt->ss_target.u.domain.name, fake_domain, domain_len);
    } else if (is_ipv4) {
        const skaddr4_t *sa4 = (const skaddr4_t *)&original_target_skaddr;
        pkt->ss_target.type = SS2022_ADDR_IPV4;
        pkt->ss_target.port = ntohs(sa4->sin_port);
        memcpy(pkt->ss_target.u.ipv4, &sa4->sin_addr.s_addr, IP4BINLEN);
    } else {
        pkt->ss_target.type = SS2022_ADDR_IPV6;
        pkt->ss_target.port = ntohs(original_target_skaddr.sin6_port);
        memcpy(pkt->ss_target.u.ipv6, &original_target_skaddr.sin6_addr.s6_addr, IP6BINLEN);
    }

    if (nrecv > UDP_DATAGRAM_MAXSIZ - UDP_SS2022_SEAL_OVERHEAD) {
        LOGWAR("[udp_ingress] packet too large to seal (%zu + %d > %d), dropping",
               nrecv, UDP_SS2022_SEAL_OVERHEAD, UDP_DATAGRAM_MAXSIZ);
        return false;
    }

    return true;
}

static udp_session_t *udp_session_lookup(const udp_ingress_t *pkt, const udp_symmetric_key_t *symmetric_key) {
    if (symmetric_key) {
        udp_symmetric_node_t *node = udp_symmetric_node_find(&g_udp_symmetric_table, symmetric_key);
        if (node) {
            IF_VERBOSE {
                udp_log_session_route("reuse", pkt);
            }
            return node->session;
        }
        return NULL;
    }

    udp_fullcone_node_t *node = udp_fullcone_node_find(&g_udp_fullcone_table, &pkt->client_endpoint);
    if (node) {
        IF_VERBOSE {
            udp_log_session_route("reuse", pkt);
        }
        return node->session;
    }
    return NULL;
}

static inline void udp_session_touch(udp_session_t *session, ev_tstamp now) {
    if (session->fullcone_node) {
        session->fullcone_node->last_active = now;
    } else {
        session->symmetric_node->last_active = now;
    }
}

static void udp_session_free(evloop_t *evloop, udp_session_t *session) {
    ev_io_stop(evloop, &session->server_watcher);
    close(session->server_watcher.fd);
    ss2022_udp_client_session_free(&session->ss_session);
    mempool_free_sized(g_udp_session_pool, session, sizeof(*session));
}

static void udp_tproxy_entry_free(udp_tproxy_entry_t *entry) {
    close(entry->udp_sockfd);
    mempool_free_sized(g_udp_tproxy_pool, entry, sizeof(*entry));
}

/* Indexed entries still live in their hash table and must be deleted first.
 * Detached entries were already removed by LRU_DEFINE_ADD. */
static void udp_session_close(evloop_t *evloop, udp_session_t *session, udp_entry_state_t state) {
    assert((session->fullcone_node != NULL) ^ (session->symmetric_node != NULL));
    if (session->fullcone_node) {
        udp_fullcone_node_t *node = session->fullcone_node;
        if (state == UDP_ENTRY_INDEXED) {
            udp_fullcone_node_del(&g_udp_fullcone_table, node);
        }
        mempool_free_sized(g_udp_fullcone_node_pool, node, sizeof(*node));
        session->fullcone_node = NULL;
    } else {
        udp_symmetric_node_t *node = session->symmetric_node;
        if (state == UDP_ENTRY_INDEXED) {
            udp_symmetric_node_del(&g_udp_symmetric_table, node);
        }
        mempool_free_sized(g_udp_symmetric_node_pool, node, sizeof(*node));
        session->symmetric_node = NULL;
    }
    udp_session_free(evloop, session);
}

static void udp_session_close_indexed(evloop_t *evloop, udp_session_t *session) {
    udp_session_close(evloop, session, UDP_ENTRY_INDEXED);
}

static void udp_session_close_detached(evloop_t *evloop, udp_session_t *session) {
    udp_session_close(evloop, session, UDP_ENTRY_DETACHED);
}

static void udp_tproxy_entry_close(evloop_t *evloop __attribute__((unused)), udp_tproxy_entry_t *entry) {
    udp_tproxy_entry_del(&g_udp_tproxy_table, entry);
    udp_tproxy_entry_free(entry);
}

static bool udp_session_register_fullcone(evloop_t *evloop, udp_session_t *session, ev_tstamp now) {
    udp_fullcone_node_t *node = mempool_alloc_sized(g_udp_fullcone_node_pool, sizeof(*node));
    if (!node) {
        LOGERR("[udp_session] mempool alloc failed for fullcone-node");
        return false;
    }

    node->key         = session->client_endpoint;
    node->session     = session;
    node->last_active = now;
    session->fullcone_node = node;

    udp_fullcone_node_t *victim = udp_fullcone_node_add(&g_udp_fullcone_table, node);
    if (victim) {
        LOGINF("[udp_session] fullcone table full, evicting least active entry");
        udp_session_close_detached(evloop, victim->session);
    }
    return true;
}

static bool udp_session_register_symmetric(evloop_t *evloop, udp_session_t *session, const udp_symmetric_key_t *symmetric_key, ev_tstamp now) {
    assert(symmetric_key);

    udp_symmetric_node_t *node = mempool_alloc_sized(g_udp_symmetric_node_pool, sizeof(*node));
    if (!node) {
        LOGERR("[udp_session] mempool alloc failed for symmetric-node");
        return false;
    }

    node->key         = *symmetric_key;
    node->session     = session;
    node->last_active = now;
    session->symmetric_node = node;

    udp_symmetric_node_t *victim = udp_symmetric_node_add(&g_udp_symmetric_table, node);
    if (victim) {
        LOGINF("[udp_session] symmetric table full, evicting least active entry");
        udp_session_close_detached(evloop, victim->session);
    }
    return true;
}

static int udp_relay_connect_server(const ss_server_t *srv) {
    int udp_sockfd = new_udp_normal_sockfd(srv->skaddr.sin6_family);
    if (udp_sockfd < 0) {
        LOGERR("[udp_relay] new_udp_normal_sockfd: %s", strerror(errno));
        return -1;
    }

    bool server_is_ipv4 = srv->skaddr.sin6_family == AF_INET;
    if (connect(udp_sockfd, (const void *)&srv->skaddr, server_is_ipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t)) < 0) {
        LOGERR("[udp_relay] connect to %s#%hu: %s", srv->ipstr, srv->portno, strerror(errno));
        close(udp_sockfd);
        return -1;
    }

    return udp_sockfd;
}

static udp_tproxy_entry_t *udp_tproxy_entry_get_or_create(evloop_t *evloop,
        const udp_endpoint_key_t *reply_src,
        const udp_endpoint_key_t *client,
        udp_tproxy_entry_t **deferred_evict,
        int *deferred_evict_count) {
    udp_tproxy_entry_t *tproxy_entry = udp_tproxy_entry_find(&g_udp_tproxy_table, reply_src);
    if (tproxy_entry) {
        tproxy_entry->last_active = ev_now(evloop);
        IF_VERBOSE {
            udp_log_tproxy_entry_route("reuse", reply_src, client, tproxy_entry->udp_sockfd);
        }
        return tproxy_entry;
    }

    skaddr6_t fromskaddr;
    udp_endpoint_to_skaddr(&fromskaddr, reply_src);

    bool reply_src_is_ipv4 = (reply_src->family == AF_INET);
    int tproxy_sockfd = new_udp_tpsend_sockfd(reply_src_is_ipv4 ? AF_INET : AF_INET6);
    if (tproxy_sockfd < 0) {
        LOGERR("[udp_tproxy] new_udp_tpsend_sockfd: %s", strerror(errno));
        return NULL;
    }

    if (bind(tproxy_sockfd, (void *)&fromskaddr, reply_src_is_ipv4 ? sizeof(skaddr4_t) : sizeof(skaddr6_t)) < 0) {
        char bind_ipstr[IP6STRLEN];
        portno_t bind_port;
        parse_socket_addr(&fromskaddr, bind_ipstr, &bind_port);
        LOGERR("[udp_tproxy] bind tproxy_sockfd to %s#%hu: %s", bind_ipstr, bind_port, strerror(errno));
        close(tproxy_sockfd);
        return NULL;
    }

    tproxy_entry = mempool_alloc_sized(g_udp_tproxy_pool, sizeof(*tproxy_entry));
    if (!tproxy_entry) {
        LOGERR("[udp_tproxy] mempool alloc failed for tproxy entry");
        close(tproxy_sockfd);
        return NULL;
    }

    tproxy_entry->key = *reply_src;
    tproxy_entry->udp_sockfd = tproxy_sockfd;
    tproxy_entry->last_active = ev_now(evloop);

    udp_tproxy_entry_t *victim = udp_tproxy_entry_add(&g_udp_tproxy_table, tproxy_entry);
    if (victim) {
        LOGINF("[udp_tproxy] tproxy table full, deferring eviction");
        deferred_evict[(*deferred_evict_count)++] = victim;
    }

    IF_VERBOSE {
        udp_log_tproxy_entry_route("new", reply_src, client, tproxy_sockfd);
    }
    return tproxy_entry;
}

static void udp_tproxy_queue_client_send(udp_tproxy_send_t *slot,
        udp_tproxy_entry_t *tproxy_entry,
        const uint8_t *payload, size_t payload_len,
        const udp_endpoint_key_t *client) {
    udp_endpoint_to_skaddr(&slot->client_addr, client);

    slot->source_entry = tproxy_entry;
    slot->iov.iov_base = (void *)payload;
    slot->iov.iov_len = payload_len;
    slot->msg.msg_hdr.msg_name = &slot->client_addr;
    slot->msg.msg_hdr.msg_namelen = client->family == AF_INET ? sizeof(skaddr4_t) : sizeof(skaddr6_t);
    slot->msg.msg_hdr.msg_iov = &slot->iov;
    slot->msg.msg_hdr.msg_iovlen = 1;
    slot->msg.msg_hdr.msg_control = NULL;
    slot->msg.msg_hdr.msg_controllen = 0;
}

static void udp_tproxy_flush_client_sends(const udp_session_t *session, udp_tproxy_send_t batch_sends[], int send_count) {
    if (send_count <= 0) {
        return;
    }

    uint16_t indices[UDP_BATCH_SIZE];
    for (int k = 0; k < send_count; k++) {
        indices[k] = (uint16_t)k;
    }

    for (int i = 0; i < send_count;) {
        udp_tproxy_entry_t *entry = batch_sends[indices[i]].source_entry;
        int group_count = 0;

        for (int j = i; j < send_count; j++) {
            if (batch_sends[indices[j]].source_entry == entry) {
                if (j != i + group_count) {
                    uint16_t tmp = indices[i + group_count];
                    indices[i + group_count] = indices[j];
                    indices[j] = tmp;
                }
                group_count++;
            }
        }

        for (int k = 0; k < group_count; k++) {
            g_tpsend_msgs[k] = batch_sends[indices[i + k]].msg;
        }

        int sent;
        do {
            sent = sendmmsg(entry->udp_sockfd, g_tpsend_msgs, (unsigned int)group_count, 0);
        } while (sent < 0 && errno == EINTR);
        if (sent < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOGERR("[udp_tproxy] sendmmsg failed: %s", strerror(errno));
            }
        } else {
            if (sent < group_count) {
                LOGWAR("[udp_tproxy] sendmmsg partial: sent=%d/%d, dropped=%d",
                       sent, group_count, group_count - sent);
            }
            IF_VERBOSE {
                udp_log_tproxy_send_to_client(session, &entry->key, sent);
            }
        }

        i += group_count;
    }
}

static void udp_relay_on_server_reply(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *server_watcher = (evio_t *)watcher;
    udp_session_t *session = (void *)((uint8_t *)server_watcher - offsetof(udp_session_t, server_watcher));

    int retval;
    do {
        retval = recvmmsg(server_watcher->fd, g_server_reply_msgs, UDP_BATCH_SIZE, 0, NULL);
    } while (retval < 0 && errno == EINTR);

    if (retval < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[udp_relay] recv reply: %s", strerror(errno));
        }
        return;
    }

    if (retval == 0) return;

    udp_tproxy_send_t batch_sends[UDP_BATCH_SIZE];
    int send_count = 0;

    udp_tproxy_entry_t *deferred_evict[UDP_BATCH_SIZE];
    int deferred_evict_count = 0;

    udp_session_touch(session, ev_now(evloop));

    for (int i = 0; i < retval; i++) {
        uint8_t *buffer = (uint8_t *)g_udp_batch_buffer[i];
        size_t nrecv = (size_t)g_server_reply_msgs[i].msg_len;

        ss2022_addr source_addr;
        size_t plain_len = 0;
        int ret = ss2022_udp_client_open(&session->ss_session,
                                         buffer, nrecv,
                                         &source_addr,
                                         buffer, sizeof(g_udp_batch_buffer[i]),
                                         &plain_len);
        if (ret != SS2022_OK) {
            IF_VERBOSE {
                LOGINF_RAW("[udp_relay] ss2022 open failed: %d", ret);
            }
            continue;
        }

        udp_endpoint_key_t reply_src;
        if (session->uses_fakedns) {
            reply_src = session->original_target_endpoint;
        } else {
            if (source_addr.type != SS2022_ADDR_IPV4 && source_addr.type != SS2022_ADDR_IPV6) {
                LOGERR("[udp_relay] unexpected address type in reply: %d", (int)source_addr.type);
                continue;
            }
            reply_src = udp_endpoint_from_addr(&source_addr);
        }

        udp_tproxy_entry_t *tproxy_entry = udp_tproxy_entry_get_or_create(evloop, &reply_src, &session->client_endpoint,
                                           deferred_evict, &deferred_evict_count);
        if (!tproxy_entry) {
            continue;
        }

        udp_tproxy_queue_client_send(&batch_sends[send_count], tproxy_entry,
                                     buffer, plain_len, &session->client_endpoint);
        send_count++;
        assert(send_count <= UDP_BATCH_SIZE);
    }

    udp_tproxy_flush_client_sends(session, batch_sends, send_count);

    /* LRU add already removed deferred evictions from the table. */
    for (int i = 0; i < deferred_evict_count; i++) {
        udp_tproxy_entry_free(deferred_evict[i]);
    }
}

static udp_session_t *udp_session_create(evloop_t *evloop, const udp_ingress_t *pkt, const udp_symmetric_key_t *symmetric_key) {
    ss_server_t *srv = server_selector_best_udp();
    int server_idx = (int)(srv - g_ss_servers);

    int udp_sockfd = udp_relay_connect_server(srv);
    if (udp_sockfd < 0) {
        return NULL;
    }

    udp_session_t *session = mempool_alloc_sized(g_udp_session_pool, sizeof(*session));
    if (!session) {
        LOGERR("[udp_session] mempool alloc failed for session");
        close(udp_sockfd);
        return NULL;
    }

    session->client_endpoint          = pkt->client_endpoint;
    session->original_target_endpoint = pkt->original_target_endpoint;
    session->uses_fakedns             = pkt->uses_fakedns;
    session->server_idx               = (uint8_t)server_idx;
    session->fullcone_node            = NULL;
    session->symmetric_node           = NULL;
    ev_tstamp now                     = ev_now(evloop);

    ss2022_client_ctx *ctx = udp_ctx_get(server_idx);
    if (!ctx) {
        LOGERR("[udp_session] ss2022 ctx init failed");
        close(udp_sockfd);
        mempool_free_sized(g_udp_session_pool, session, sizeof(*session));
        return NULL;
    }
    if (ss2022_udp_client_session_init(&session->ss_session, ctx) != SS2022_OK) {
        LOGERR("[udp_session] ss2022 udp session init failed");
        close(udp_sockfd);
        mempool_free_sized(g_udp_session_pool, session, sizeof(*session));
        return NULL;
    }

    ev_io_init(&session->server_watcher, udp_relay_on_server_reply, udp_sockfd, EV_READ);
    ev_io_start(evloop, &session->server_watcher);

    bool indexed = session->uses_fakedns
                   ? udp_session_register_symmetric(evloop, session, symmetric_key, now)
                   : udp_session_register_fullcone(evloop, session, now);
    if (!indexed) {
        udp_session_free(evloop, session);
        return NULL;
    }

    assert((session->fullcone_node != NULL) ^ (session->symmetric_node != NULL));
    IF_VERBOSE {
        udp_log_session_route("new", pkt);
    }
    return session;
}

static void udp_relay_send_to_server(udp_session_t *session,
                                     const ss2022_addr *target,
                                     const udp_endpoint_key_t *original_target_endpoint,
                                     const uint8_t *payload, size_t payload_len) {
    size_t out_len = 0;
    int ret = ss2022_udp_client_seal(&session->ss_session, target,
                                     payload, payload_len,
                                     g_udp_seal_buf, sizeof(g_udp_seal_buf), &out_len);
    if (ret != SS2022_OK) {
        LOGERR("[udp_relay] ss2022 seal failed: %d", ret);
        return;
    }

    ssize_t nsend;
    do {
        nsend = send(session->server_watcher.fd, g_udp_seal_buf, out_len, 0);
    } while (nsend < 0 && errno == EINTR);
    if (nsend < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            ss_server_t *srv = &g_ss_servers[session->server_idx];
            LOGERR("[udp_relay] send to %s#%hu: %s", srv->ipstr, srv->portno, strerror(errno));
        }
        return;
    }
    if (nsend == 0) {
        ss_server_t *srv = &g_ss_servers[session->server_idx];
        LOGWAR("[udp_relay] send to %s#%hu returned 0, dropping packet", srv->ipstr, srv->portno);
        return;
    }

    IF_VERBOSE {
        udp_log_relay_send_to_server(session, original_target_endpoint, nsend);
    }
}

static void udp_proxy_handle_ingress(evloop_t *evloop, evio_t *tprecv_watcher, struct msghdr *msg, size_t nrecv, uint8_t *buffer) {
    bool is_ipv4 = (intptr_t)tprecv_watcher->data;
    udp_ingress_t pkt;
    udp_symmetric_key_t symmetric_key;
    const udp_symmetric_key_t *symmetric_key_ptr = NULL;

    if (!udp_ingress_parse(msg, nrecv, is_ipv4, &pkt)) {
        return;
    }

    if (pkt.uses_fakedns) {
        symmetric_key = (udp_symmetric_key_t) {
            .client = pkt.client_endpoint,
            .target = pkt.original_target_endpoint,
        };
        symmetric_key_ptr = &symmetric_key;
    }

    udp_session_t *session = udp_session_lookup(&pkt, symmetric_key_ptr);
    if (!session) {
        session = udp_session_create(evloop, &pkt, symmetric_key_ptr);
        if (!session) {
            return;
        }
    } else {
        udp_session_touch(session, ev_now(evloop));
    }

    udp_relay_send_to_server(session, &pkt.ss_target, &pkt.original_target_endpoint, buffer, nrecv);
}

void udp_proxy_on_recvmsg(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *tprecv_watcher = (evio_t *)watcher;
    bool is_ipv4 = (intptr_t)tprecv_watcher->data;

    for (int i = 0; i < UDP_BATCH_SIZE; i++) {
        g_tprecv_msgs[i].msg_hdr.msg_namelen    = sizeof(skaddr6_t);
        g_tprecv_msgs[i].msg_hdr.msg_controllen = UDP_CTRLMESG_BUFSIZ;
    }

    int retval;
    do {
        retval = recvmmsg(tprecv_watcher->fd, g_tprecv_msgs, UDP_BATCH_SIZE, 0, NULL);
    } while (retval < 0 && errno == EINTR);

    if (retval < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[udp_proxy] recvmmsg from udp%s socket: %s", is_ipv4 ? "4" : "6", strerror(errno));
        }
        return;
    }

    if (retval == 0) return;

    for (int i = 0; i < retval; i++) {
        udp_proxy_handle_ingress(evloop, tprecv_watcher, &g_tprecv_msgs[i].msg_hdr, (size_t)g_tprecv_msgs[i].msg_len, (uint8_t *)g_udp_batch_buffer[i]);
    }
}

#define GC_INTERVAL_SEC      10.0

static __thread evtimer_t g_gc_timer;

static inline bool udp_gc_is_idle(ev_tstamp now, ev_tstamp last_active, ev_tstamp timeout) {
    return (now - last_active) >= timeout;
}

static ev_tstamp udp_gc_tproxy_timeout(void) {
    return (ev_tstamp)g_udp_idletimeout_sec / 2.0;
}

static void udp_log_gc_evicted(const char *table_name, int evicted) {
    if (evicted > 0) {
        LOGINF("[udp_gc] %s evicted: %d", table_name, evicted);
    }
}

static int udp_gc_sweep_fullcone_sessions(evloop_t *evloop, ev_tstamp now, ev_tstamp timeout) {
    int evicted = 0;
    udp_fullcone_node_t *cur, *tmp;

    MYLRU_HASH_FOR(g_udp_fullcone_table, cur, tmp) {
        if (udp_gc_is_idle(now, cur->last_active, timeout)) {
            udp_session_close_indexed(evloop, cur->session);
            evicted++;
        }
    }
    return evicted;
}

static int udp_gc_sweep_symmetric_sessions(evloop_t *evloop, ev_tstamp now, ev_tstamp timeout) {
    int evicted = 0;
    udp_symmetric_node_t *cur, *tmp;

    MYLRU_HASH_FOR(g_udp_symmetric_table, cur, tmp) {
        if (udp_gc_is_idle(now, cur->last_active, timeout)) {
            udp_session_close_indexed(evloop, cur->session);
            evicted++;
        }
    }
    return evicted;
}

static int udp_gc_sweep_tproxy_entries(evloop_t *evloop, ev_tstamp now, ev_tstamp timeout) {
    int evicted = 0;
    udp_tproxy_entry_t *cur, *tmp;

    MYLRU_HASH_FOR(g_udp_tproxy_table, cur, tmp) {
        if (udp_gc_is_idle(now, cur->last_active, timeout)) {
            udp_tproxy_entry_close(evloop, cur);
            evicted++;
        }
    }
    return evicted;
}

static void udp_gc_on_tick(evloop_t *evloop, struct ev_watcher *watcher __attribute__((unused)), int revents __attribute__((unused))) {
    ev_tstamp now = ev_now(evloop);
    ev_tstamp session_timeout = (ev_tstamp)g_udp_idletimeout_sec;
    ev_tstamp tproxy_timeout = udp_gc_tproxy_timeout();

    udp_log_gc_evicted("fullcone table", udp_gc_sweep_fullcone_sessions(evloop, now, session_timeout));
    udp_log_gc_evicted("symmetric table", udp_gc_sweep_symmetric_sessions(evloop, now, session_timeout));
    udp_log_gc_evicted("tproxy table", udp_gc_sweep_tproxy_entries(evloop, now, tproxy_timeout));
}

void udp_proxy_gc_start(evloop_t *evloop) {
    ev_timer_init(&g_gc_timer, udp_gc_on_tick, GC_INTERVAL_SEC, GC_INTERVAL_SEC);
    ev_timer_start(evloop, &g_gc_timer);
}

void udp_proxy_gc_stop(evloop_t *evloop) {
    ev_timer_stop(evloop, &g_gc_timer);
}

static void udp_fullcone_session_clear_cb(void *evloop_ctx, udp_fullcone_node_t *node) {
    udp_session_close_indexed((evloop_t *)evloop_ctx, node->session);
}

static void udp_symmetric_session_clear_cb(void *evloop_ctx, udp_symmetric_node_t *node) {
    udp_session_close_indexed((evloop_t *)evloop_ctx, node->session);
}

static void udp_tproxy_entry_clear_cb(void *evloop_ctx, udp_tproxy_entry_t *entry) {
    udp_tproxy_entry_close((evloop_t *)evloop_ctx, entry);
}

void udp_proxy_thread_init(void) {
    for (int i = 0; i < UDP_BATCH_SIZE; i++) {
        g_tprecv_iovs[i].iov_base            = g_udp_batch_buffer[i];
        g_tprecv_iovs[i].iov_len             = UDP_DATAGRAM_MAXSIZ;
        g_tprecv_msgs[i].msg_hdr.msg_name    = &g_tprecv_skaddrs[i];
        g_tprecv_msgs[i].msg_hdr.msg_iov     = &g_tprecv_iovs[i];
        g_tprecv_msgs[i].msg_hdr.msg_iovlen  = 1;
        g_tprecv_msgs[i].msg_hdr.msg_control = g_tprecv_ctrl_bufs[i];

        g_server_reply_iovs[i].iov_base               = g_udp_batch_buffer[i];
        g_server_reply_iovs[i].iov_len                = UDP_DATAGRAM_MAXSIZ;
        g_server_reply_msgs[i].msg_hdr.msg_name       = NULL;
        g_server_reply_msgs[i].msg_hdr.msg_namelen    = 0;
        g_server_reply_msgs[i].msg_hdr.msg_iov        = &g_server_reply_iovs[i];
        g_server_reply_msgs[i].msg_hdr.msg_iovlen     = 1;
        g_server_reply_msgs[i].msg_hdr.msg_control    = NULL;
        g_server_reply_msgs[i].msg_hdr.msg_controllen = 0;
    }
}

void udp_proxy_close_all_sessions(evloop_t *evloop) {
    LOGINF("[udp_proxy] cleaning up remaining sessions...");

    udp_proxy_gc_stop(evloop);
    udp_fullcone_node_clear(&g_udp_fullcone_table, udp_fullcone_session_clear_cb, evloop);
    udp_symmetric_node_clear(&g_udp_symmetric_table, udp_symmetric_session_clear_cb, evloop);
    udp_tproxy_entry_clear(&g_udp_tproxy_table, udp_tproxy_entry_clear_cb, evloop);
}

void udp_proxy_ctx_cleanup(void) {
    for (int i = 0; i < SS_MAX_SERVERS; i++) {
        if (g_udp_ss_ctx_ready[i]) {
            ss2022_client_ctx_free(&g_udp_ss_ctx[i]);
            g_udp_ss_ctx_ready[i] = false;
        }
    }
}
