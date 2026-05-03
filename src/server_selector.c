#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ctx.h"
#include "ev_types.h"
#include "logutils.h"
#include "netutils.h"
#include "server_selector.h"

ss_server_t g_ss_servers[SS_MAX_SERVERS];
int         g_ss_server_count = 0;
_Atomic int g_ss_best_tcp_idx = 0;
_Atomic int g_ss_best_udp_idx = 0;

static int       g_probes_remaining = 0;
static evtimer_t g_check_timer;

static ss2022_client_ctx g_ss_ctx[SS_MAX_SERVERS];
static bool              g_ss_ctx_ready[SS_MAX_SERVERS];

static ss2022_client_ctx *ss_ctx_get(int idx) {
    if (!g_ss_ctx_ready[idx]) {
        if (ss2022_client_ctx_init(&g_ss_ctx[idx],
                                   g_ss_servers[idx].method,
                                   g_ss_servers[idx].psk) != SS2022_OK) {
            LOGERR("[server_selector] ss2022 ctx init failed for server [%d]", idx);
            return NULL;
        }
        g_ss_ctx_ready[idx] = true;
    }
    return &g_ss_ctx[idx];
}

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a;
    uint32_t y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

static uint32_t ss_compute_score(ss_sample_t *window, int count, int head, ev_tstamp now) {
    uint32_t latencies[SS_WINDOW_SLOTS];
    int n = 0, fail = 0;

    for (int i = 0; i < count; i++) {
        int slot = (head - count + i + SS_WINDOW_SLOTS) % SS_WINDOW_SLOTS;
        ss_sample_t *s = &window[slot];
        if (now - s->ts > SS_WINDOW_SEC)
            continue;
        if (s->errored) {
            fail++;
        } else {
            latencies[n++] = s->latency_ms < SS_MAX_RTT_MS ? s->latency_ms : SS_MAX_RTT_MS;
        }
    }

    int total = n + fail;
    if (total == 0)
        return UINT32_MAX;

    double fail_rate = (double)fail / (double)total;

    if (n == 0)
        return (uint32_t)((1.0 + fail_rate * 3.0 + 1.0) / 5.0 * 10000.0);

    qsort(latencies, (size_t)n, sizeof(uint32_t), cmp_u32);
    uint32_t median = latencies[n / 2];

    uint32_t deviations[SS_WINDOW_SLOTS];
    for (int i = 0; i < n; i++) {
        uint32_t d = latencies[i] > median ? latencies[i] - median : median - latencies[i];
        deviations[i] = d;
    }
    qsort(deviations, (size_t)n, sizeof(uint32_t), cmp_u32);
    uint32_t mad = deviations[n / 2];

    double nrtt = (double)median / (double)SS_MAX_RTT_MS;
    double nmad  = (double)mad    / (double)SS_MAX_RTT_MS;
    if (nrtt > 1.0) nrtt = 1.0;
    if (nmad > 1.0) nmad = 1.0;

    return (uint32_t)((nrtt + fail_rate * 3.0 + nmad) / 5.0 * 10000.0);
}

static void ss_push_tcp_sample(ss_server_t *srv, uint32_t latency_ms, bool errored, ev_tstamp now) {
    int slot = srv->tcp_window_head;
    srv->tcp_window[slot] = (ss_sample_t) {
        latency_ms, errored, now
    };
    srv->tcp_window_head = (slot + 1) % SS_WINDOW_SLOTS;
    if (srv->tcp_window_count < SS_WINDOW_SLOTS)
        srv->tcp_window_count++;
    uint32_t score = ss_compute_score(srv->tcp_window, srv->tcp_window_count,
                                      srv->tcp_window_head, now);
    atomic_store_explicit(&srv->tcp_score, score, memory_order_release);
}

static void ss_push_udp_sample(ss_server_t *srv, uint32_t latency_ms, bool errored, ev_tstamp now) {
    int slot = srv->udp_window_head;
    srv->udp_window[slot] = (ss_sample_t) {
        latency_ms, errored, now
    };
    srv->udp_window_head = (slot + 1) % SS_WINDOW_SLOTS;
    if (srv->udp_window_count < SS_WINDOW_SLOTS)
        srv->udp_window_count++;
    uint32_t score = ss_compute_score(srv->udp_window, srv->udp_window_count,
                                      srv->udp_window_head, now);
    atomic_store_explicit(&srv->udp_score, score, memory_order_release);
}

#define SS_SWITCH_THRESHOLD 6u

static void ss_update_best(void) {
    int best_tcp = atomic_load_explicit(&g_ss_best_tcp_idx, memory_order_relaxed);
    int best_udp = atomic_load_explicit(&g_ss_best_udp_idx, memory_order_relaxed);
    uint32_t best_tcp_score = atomic_load_explicit(&g_ss_servers[best_tcp].tcp_score, memory_order_acquire);
    uint32_t best_udp_score = atomic_load_explicit(&g_ss_servers[best_udp].udp_score, memory_order_acquire);

    for (int i = 0; i < g_ss_server_count; i++) {
        uint32_t ts = atomic_load_explicit(&g_ss_servers[i].tcp_score, memory_order_acquire);
        uint32_t us = atomic_load_explicit(&g_ss_servers[i].udp_score, memory_order_acquire);
        if (ts < best_tcp_score && best_tcp_score - ts > SS_SWITCH_THRESHOLD) {
            best_tcp_score = ts;
            best_tcp = i;
        }
        if (us < best_udp_score && best_udp_score - us > SS_SWITCH_THRESHOLD) {
            best_udp_score = us;
            best_udp = i;
        }
    }

    int prev_tcp = atomic_exchange_explicit(&g_ss_best_tcp_idx, best_tcp, memory_order_acq_rel);
    int prev_udp = atomic_exchange_explicit(&g_ss_best_udp_idx, best_udp, memory_order_acq_rel);

    if (prev_tcp != best_tcp)
        LOG_ALWAYS_INF("[server_selector] TCP best changed: [%d] %s:%u -> [%d] %s:%u (score %u)",
                       prev_tcp, g_ss_servers[prev_tcp].ipstr, (unsigned)g_ss_servers[prev_tcp].portno,
                       best_tcp,  g_ss_servers[best_tcp].ipstr,  (unsigned)g_ss_servers[best_tcp].portno,
                       best_tcp_score);

    if (prev_udp != best_udp)
        LOG_ALWAYS_INF("[server_selector] UDP best changed: [%d] %s:%u -> [%d] %s:%u (score %u)",
                       prev_udp, g_ss_servers[prev_udp].ipstr, (unsigned)g_ss_servers[prev_udp].portno,
                       best_udp,  g_ss_servers[best_udp].ipstr,  (unsigned)g_ss_servers[best_udp].portno,
                       best_udp_score);
}

static void probe_maybe_update_best(void) {
    if (--g_probes_remaining <= 0) {
        g_probes_remaining = 0;
        ss_update_best();
    }
}

#define TCP_PROBE_SEND_BUF_SIZE 1024
#define TCP_PROBE_RECV_BUF_SIZE ((size_t)UINT16_MAX + 2u + 16u)
#define TCP_PROBE_STATUS_LEN    12u
#define TCP_PROBE_LENGTH_LEN    (2u + 16u)

static const char TCP_PROBE_REQUEST[] =
    "GET /generate_204 HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";

typedef enum {
    TCP_PROBE_CONNECTING,
    TCP_PROBE_RECV_RESP_HDR,
    TCP_PROBE_RECV_PAYLOAD,
    TCP_PROBE_RECV_LENGTH,
} tcp_probe_state_t;

typedef struct {
    ss2022_tcp_client tcp_client;
    evloop_t *evloop;
    ev_tstamp start_ts;

    size_t   send_len;
    size_t   send_off;
    size_t   buf_len;
    size_t   buf_need;
    size_t   status_len;

    evio_t    io_watcher;
    evtimer_t timeout_timer;
    int       server_idx;
    int       sockfd;
    tcp_probe_state_t state;
    uint16_t response_payload_len;

    uint8_t  status[TCP_PROBE_STATUS_LEN];
    uint8_t  send_buf[TCP_PROBE_SEND_BUF_SIZE];
    uint8_t  buf[TCP_PROBE_RECV_BUF_SIZE];
} ss_tcp_probe_t;

static ss_tcp_probe_t g_tcp_probes[SS_MAX_SERVERS];

static void tcp_probe_consume(ss_tcp_probe_t *p, size_t n) {
    p->buf_len -= n;
    if (p->buf_len > 0)
        memmove(p->buf, p->buf + n, p->buf_len);
}

static void tcp_probe_finish(ss_tcp_probe_t *p, uint32_t latency_ms, bool errored) {
    ev_io_stop(p->evloop, &p->io_watcher);
    ev_timer_stop(p->evloop, &p->timeout_timer);
    close(p->sockfd);
    p->sockfd = -1;
    ss2022_tcp_client_free(&p->tcp_client);

    ss_server_t *srv = &g_ss_servers[p->server_idx];
    ss_push_tcp_sample(srv, latency_ms, errored, ev_now(p->evloop));

    LOGINF("[server_selector] tcp [%d] %s:%u: %s %ums score=%u",
           p->server_idx, srv->ipstr, (unsigned)srv->portno,
           errored ? "error" : "ok", latency_ms,
           atomic_load_explicit(&srv->tcp_score, memory_order_relaxed));

    if (!errored)
        ss_update_best();
    probe_maybe_update_best();
}

static void tcp_probe_on_recv(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    (void)evloop;
    ss_tcp_probe_t *p = watcher->data;

    if (p->buf_len == sizeof(p->buf)) {
        tcp_probe_finish(p, (uint32_t)((ev_now(p->evloop) - p->start_ts) * 1000.0), true);
        return;
    }

    ssize_t nr = recv(p->sockfd, p->buf + p->buf_len,
                      sizeof(p->buf) - p->buf_len, 0);
    if (nr < 0) {
        if (errno == EINTR)
            return;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        tcp_probe_finish(p, (uint32_t)((ev_now(p->evloop) - p->start_ts) * 1000.0), true);
        return;
    }
    if (nr == 0) {
        tcp_probe_finish(p, (uint32_t)((ev_now(p->evloop) - p->start_ts) * 1000.0), true);
        return;
    }
    p->buf_len += (size_t)nr;

    while (p->buf_len >= p->buf_need) {
        if (p->state == TCP_PROBE_RECV_RESP_HDR) {
            int ret = ss2022_tcp_client_open_response_header(
                          &p->tcp_client, p->buf, p->buf_need, &p->response_payload_len);
            if (ret != SS2022_OK) {
                LOGERR("[server_selector] tcp [%d]: open_response_header failed: %d",
                       p->server_idx, ret);
                tcp_probe_finish(p, (uint32_t)((ev_now(p->evloop) - p->start_ts) * 1000.0), true);
                return;
            }

            tcp_probe_consume(p, p->buf_need);

            p->state    = TCP_PROBE_RECV_PAYLOAD;
            p->buf_need = (size_t)p->response_payload_len + 16u;
            if (p->buf_need > sizeof(p->buf)) {
                tcp_probe_finish(p, (uint32_t)((ev_now(p->evloop) - p->start_ts) * 1000.0), true);
                return;
            }
            continue;
        }

        if (p->state == TCP_PROBE_RECV_LENGTH) {
            int ret = ss2022_tcp_client_open_length(
                          &p->tcp_client, p->buf, TCP_PROBE_LENGTH_LEN,
                          &p->response_payload_len);
            if (ret != SS2022_OK) {
                LOGERR("[server_selector] tcp [%d]: open_length failed: %d",
                       p->server_idx, ret);
                tcp_probe_finish(p, (uint32_t)((ev_now(p->evloop) - p->start_ts) * 1000.0), true);
                return;
            }

            tcp_probe_consume(p, TCP_PROBE_LENGTH_LEN);

            p->state    = TCP_PROBE_RECV_PAYLOAD;
            p->buf_need = (size_t)p->response_payload_len + 16u;
            if (p->buf_need > sizeof(p->buf)) {
                tcp_probe_finish(p, (uint32_t)((ev_now(p->evloop) - p->start_ts) * 1000.0), true);
                return;
            }
            continue;
        }

        if (p->state != TCP_PROBE_RECV_PAYLOAD)
            return;

        uint8_t plain[UINT16_MAX];
        size_t  plain_len = 0;
        int ret = ss2022_tcp_client_open_payload(
                      &p->tcp_client,
                      p->buf, p->buf_need,
                      plain, p->buf_need - 16u,
                      &plain_len);

        uint32_t elapsed = (uint32_t)((ev_now(p->evloop) - p->start_ts) * 1000.0);
        if (ret != SS2022_OK) {
            LOGERR("[server_selector] tcp [%d]: open_payload failed: %d", p->server_idx, ret);
            tcp_probe_finish(p, elapsed, true);
            return;
        }

        size_t copy_len = TCP_PROBE_STATUS_LEN - p->status_len;
        if (copy_len > plain_len)
            copy_len = plain_len;
        if (copy_len > 0) {
            memcpy(p->status + p->status_len, plain, copy_len);
            p->status_len += copy_len;
        }

        tcp_probe_consume(p, p->buf_need);

        if (p->status_len >= TCP_PROBE_STATUS_LEN) {
            bool ok = (memcmp(p->status, "HTTP/1.1 204", TCP_PROBE_STATUS_LEN) == 0 ||
                       memcmp(p->status, "HTTP/1.0 204", TCP_PROBE_STATUS_LEN) == 0);
            if (!ok)
                LOGINF("[server_selector] tcp [%d]: unexpected HTTP response", p->server_idx);
            tcp_probe_finish(p, elapsed, !ok);
            return;
        }

        p->state    = TCP_PROBE_RECV_LENGTH;
        p->buf_need = TCP_PROBE_LENGTH_LEN;
    }
}

static void tcp_probe_on_send(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    (void)evloop;
    ss_tcp_probe_t *p = watcher->data;

    while (p->send_off < p->send_len) {
        ssize_t ns = send(p->sockfd,
                          p->send_buf + p->send_off,
                          p->send_len - p->send_off, 0);
        if (ns < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (!ev_is_active(&p->io_watcher))
                    ev_io_start(p->evloop, &p->io_watcher);
                return;
            }
            LOGERR("[server_selector] tcp [%d]: send: %s", p->server_idx, strerror(errno));
            tcp_probe_finish(p, (uint32_t)((ev_now(p->evloop) - p->start_ts) * 1000.0), true);
            return;
        }
        if (ns == 0) {
            tcp_probe_finish(p, (uint32_t)((ev_now(p->evloop) - p->start_ts) * 1000.0), true);
            return;
        }
        p->send_off += (size_t)ns;
    }

    if (ev_is_active(&p->io_watcher))
        ev_io_stop(p->evloop, &p->io_watcher);

    p->state    = TCP_PROBE_RECV_RESP_HDR;
    p->buf_len  = 0;
    p->status_len = 0;
    p->buf_need = ss2022_tcp_client_response_header_size(&p->tcp_client);
    if (p->buf_need == 0 || p->buf_need > sizeof(p->buf)) {
        tcp_probe_finish(p, (uint32_t)((ev_now(p->evloop) - p->start_ts) * 1000.0), true);
        return;
    }

    ev_io_set(&p->io_watcher, p->sockfd, EV_READ);
    ev_set_cb(&p->io_watcher, tcp_probe_on_recv);
    ev_io_start(p->evloop, &p->io_watcher);
}

static void tcp_probe_on_connected(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    ss_tcp_probe_t *p = watcher->data;

    if (tcp_has_error(p->sockfd)) {
        tcp_probe_finish(p, (uint32_t)((ev_now(p->evloop) - p->start_ts) * 1000.0), true);
        return;
    }

    ss2022_addr target = {
        .type = SS2022_ADDR_DOMAIN,
        .port = 80,
        .u.domain.len = 10,
    };
    memcpy(target.u.domain.name, "google.com", 10);

    int ret = ss2022_tcp_client_build_request_header(
                  &p->tcp_client, &target,
                  (const uint8_t *)TCP_PROBE_REQUEST, sizeof(TCP_PROBE_REQUEST) - 1,
                  p->send_buf, sizeof(p->send_buf), &p->send_len);
    if (ret != SS2022_OK) {
        LOGERR("[server_selector] tcp [%d]: build_request_header failed: %d", p->server_idx, ret);
        tcp_probe_finish(p, (uint32_t)((ev_now(p->evloop) - p->start_ts) * 1000.0), true);
        return;
    }
    p->send_off = 0;

    ev_set_cb(&p->io_watcher, tcp_probe_on_send);
    ev_invoke(evloop, watcher, EV_WRITE);
}

static void tcp_probe_on_timeout(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    (void)evloop;
    ss_tcp_probe_t *p = watcher->data;
    tcp_probe_finish(p, SS_MAX_RTT_MS, true);
}

static void tcp_probe_start(evloop_t *evloop, int idx) {
    ss_server_t    *srv = &g_ss_servers[idx];
    ss_tcp_probe_t *p   = &g_tcp_probes[idx];

    ss2022_client_ctx *ctx = ss_ctx_get(idx);
    if (!ctx || ss2022_tcp_client_init(&p->tcp_client, ctx) != SS2022_OK) {
        ss_push_tcp_sample(srv, SS_MAX_RTT_MS, true, ev_now(evloop));
        probe_maybe_update_best();
        return;
    }

    int family = (srv->skaddr.sin6_family == AF_INET6) ? AF_INET6 : AF_INET;
    int fd = new_tcp_connect_sockfd(family, 0);
    if (fd < 0) {
        LOGERR("[server_selector] tcp [%d]: new_tcp_connect_sockfd: %s", idx, strerror(errno));
        ss2022_tcp_client_free(&p->tcp_client);
        ss_push_tcp_sample(srv, SS_MAX_RTT_MS, true, ev_now(evloop));
        probe_maybe_update_best();
        return;
    }

    p->evloop     = evloop;
    p->server_idx = idx;
    p->sockfd     = fd;
    p->start_ts   = ev_now(evloop);
    p->state      = TCP_PROBE_CONNECTING;
    p->io_watcher.data    = p;
    p->timeout_timer.data = p;

    ev_io_init(&p->io_watcher, tcp_probe_on_connected, fd, EV_WRITE);
    ev_timer_init(&p->timeout_timer, tcp_probe_on_timeout, SS_CHECK_TIMEOUT, 0.0);
    ev_timer_start(evloop, &p->timeout_timer);

    ssize_t nsend = -1;
    tcp_connect_result_t conn = tcp_connect(fd, &srv->skaddr, NULL, 0, &nsend);

    if (conn == TCP_CONNECT_FAILED) {
        ev_timer_stop(evloop, &p->timeout_timer);
        close(fd);
        p->sockfd = -1;
        ss2022_tcp_client_free(&p->tcp_client);
        ss_push_tcp_sample(srv, SS_MAX_RTT_MS, true, ev_now(evloop));
        probe_maybe_update_best();
        return;
    }

    if (conn == TCP_CONNECT_CONNECTED) {
        tcp_probe_on_connected(evloop, (struct ev_watcher *)&p->io_watcher, EV_WRITE);
    } else {
        ev_io_start(evloop, &p->io_watcher);
    }
}

typedef struct {
    evio_t    io_watcher;
    evtimer_t timeout_timer;
    evloop_t *evloop;
    int       server_idx;
    ev_tstamp start_ts;
    int       sockfd;

    ss2022_udp_client_session udp_session;
    uint16_t dns_txid;
} ss_udp_probe_t;

static ss_udp_probe_t g_udp_probes[SS_MAX_SERVERS];

static const ss2022_addr UDP_PROBE_TARGET = {
    .type   = SS2022_ADDR_IPV4,
    .port   = 53,
    .u.ipv4 = {8, 8, 4, 4},
};

static uint16_t g_dns_txid_seq = 0;

static size_t build_dns_query(uint8_t *buf, size_t cap, uint16_t txid) {
    static const uint8_t qname_and_type[] = {
        0x06, 'g','o','o','g','l','e',
        0x03, 'c','o','m', 0x00,
        0x00, 0x01,  /* QTYPE  A  */
        0x00, 0x01,  /* QCLASS IN */
    };
    if (cap < 12 + sizeof(qname_and_type))
        return 0;
    buf[0] = (uint8_t)(txid >> 8);
    buf[1] = (uint8_t)(txid);
    buf[2] = 0x01;
    buf[3] = 0x00;  /* flags: RD=1 */
    buf[4] = 0x00;
    buf[5] = 0x01;  /* QDCOUNT=1 */
    buf[6] = 0x00;
    buf[7] = 0x00;
    buf[8] = 0x00;
    buf[9] = 0x00;
    buf[10]= 0x00;
    buf[11]= 0x00;
    memcpy(buf + 12, qname_and_type, sizeof(qname_and_type));
    return 12 + sizeof(qname_and_type);
}

static void udp_probe_finish(ss_udp_probe_t *p, uint32_t latency_ms, bool errored) {
    ev_io_stop(p->evloop, &p->io_watcher);
    ev_timer_stop(p->evloop, &p->timeout_timer);
    close(p->sockfd);
    p->sockfd = -1;
    ss2022_udp_client_session_free(&p->udp_session);

    ss_server_t *srv = &g_ss_servers[p->server_idx];
    ss_push_udp_sample(srv, latency_ms, errored, ev_now(p->evloop));

    LOGINF("[server_selector] udp [%d] %s:%u: %s %ums score=%u",
           p->server_idx, srv->ipstr, (unsigned)srv->portno,
           errored ? "error" : "ok", latency_ms,
           atomic_load_explicit(&srv->udp_score, memory_order_relaxed));

    if (!errored)
        ss_update_best();
    probe_maybe_update_best();
}

static void udp_probe_on_recv(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    (void)evloop;
    ss_udp_probe_t *p = watcher->data;

    uint8_t pkt[4096];
    ssize_t nr = recv(p->sockfd, pkt, sizeof(pkt), 0);
    if (nr < 0) {
        if (errno == EINTR)
            return;
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        udp_probe_finish(p, (uint32_t)((ev_now(p->evloop) - p->start_ts) * 1000.0), true);
        return;
    }

    uint8_t payload[4096];
    ss2022_addr source_addr;
    size_t payload_len = 0;
    if (ss2022_udp_client_open(&p->udp_session,
                               pkt, (size_t)nr,
                               &source_addr,
                               payload, sizeof(payload),
                               &payload_len) != SS2022_OK) {
        LOGINF("[server_selector] udp [%d]: unpack failed", p->server_idx);
        return;
    }

    uint32_t elapsed = (uint32_t)((ev_now(p->evloop) - p->start_ts) * 1000.0);

    bool ok = (payload_len >= 4 &&
               (uint16_t)((payload[0] << 8) | payload[1]) == p->dns_txid &&
               (payload[2] & 0x80) != 0 &&
               (payload[3] & 0x0f) == 0);
    if (!ok)
        LOGINF("[server_selector] udp [%d]: invalid DNS response", p->server_idx);
    udp_probe_finish(p, elapsed, !ok);
}

static void udp_probe_on_timeout(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    (void)evloop;
    ss_udp_probe_t *p = watcher->data;
    udp_probe_finish(p, SS_MAX_RTT_MS, true);
}

static void udp_probe_start(evloop_t *evloop, int idx) {
    ss_server_t    *srv = &g_ss_servers[idx];
    ss_udp_probe_t *p   = &g_udp_probes[idx];

    ss2022_client_ctx *ctx = ss_ctx_get(idx);
    if (!ctx || ss2022_udp_client_session_init(&p->udp_session, ctx) != SS2022_OK) {
        ss_push_udp_sample(srv, SS_MAX_RTT_MS, true, ev_now(evloop));
        probe_maybe_update_best();
        return;
    }

    int family = (srv->skaddr.sin6_family == AF_INET6) ? AF_INET6 : AF_INET;
    int fd = new_udp_normal_sockfd(family);
    if (fd < 0) {
        LOGERR("[server_selector] udp [%d]: new_udp_normal_sockfd: %s", idx, strerror(errno));
        ss2022_udp_client_session_free(&p->udp_session);
        ss_push_udp_sample(srv, SS_MAX_RTT_MS, true, ev_now(evloop));
        probe_maybe_update_best();
        return;
    }

    p->dns_txid = ++g_dns_txid_seq ? g_dns_txid_seq : ++g_dns_txid_seq; /* skip 0 */

    uint8_t dns_buf[64];
    size_t  dns_len = build_dns_query(dns_buf, sizeof(dns_buf), p->dns_txid);

    uint8_t sealed[4096];
    size_t  sealed_len = 0;
    if (ss2022_udp_client_seal(&p->udp_session,
                               &UDP_PROBE_TARGET,
                               dns_buf, dns_len,
                               sealed, sizeof(sealed),
                               &sealed_len) != SS2022_OK) {
        LOGERR("[server_selector] udp [%d]: seal failed", idx);
        close(fd);
        ss2022_udp_client_session_free(&p->udp_session);
        ss_push_udp_sample(srv, SS_MAX_RTT_MS, true, ev_now(evloop));
        probe_maybe_update_best();
        return;
    }

    socklen_t sklen = (srv->skaddr.sin6_family == AF_INET6)
                      ? (socklen_t)sizeof(struct sockaddr_in6)
                      : (socklen_t)sizeof(struct sockaddr_in);
    if (sendto(fd, sealed, sealed_len, 0,
               (const struct sockaddr *)&srv->skaddr, sklen) < 0) {
        LOGERR("[server_selector] udp [%d]: sendto: %s", idx, strerror(errno));
        close(fd);
        ss2022_udp_client_session_free(&p->udp_session);
        ss_push_udp_sample(srv, SS_MAX_RTT_MS, true, ev_now(evloop));
        probe_maybe_update_best();
        return;
    }

    p->evloop     = evloop;
    p->server_idx = idx;
    p->sockfd     = fd;
    p->start_ts   = ev_now(evloop);
    p->io_watcher.data    = p;
    p->timeout_timer.data = p;

    ev_io_init(&p->io_watcher, udp_probe_on_recv, fd, EV_READ);
    ev_timer_init(&p->timeout_timer, udp_probe_on_timeout, SS_CHECK_TIMEOUT, 0.0);
    ev_io_start(evloop, &p->io_watcher);
    ev_timer_start(evloop, &p->timeout_timer);
}

static void selector_start_probe_round(evloop_t *evloop) {
    int probes_per_server = 0;
    if (g_options & OPT_ENABLE_TCP)
        probes_per_server++;
    if (g_options & OPT_ENABLE_UDP)
        probes_per_server++;

    g_probes_remaining = g_ss_server_count * probes_per_server;
    for (int i = 0; i < g_ss_server_count; i++) {
        if (g_options & OPT_ENABLE_TCP)
            tcp_probe_start(evloop, i);
        if (g_options & OPT_ENABLE_UDP)
            udp_probe_start(evloop, i);
    }
}

static void check_timer_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    (void)watcher;
    if (g_probes_remaining > 0)
        return;

    selector_start_probe_round(evloop);
}

void server_selector_start(evloop_t *evloop) {
    memset(g_ss_ctx_ready, 0, sizeof(g_ss_ctx_ready));

    for (int i = 0; i < g_ss_server_count; i++) {
        atomic_store_explicit(&g_ss_servers[i].tcp_score, UINT32_MAX, memory_order_relaxed);
        atomic_store_explicit(&g_ss_servers[i].udp_score, UINT32_MAX, memory_order_relaxed);
        g_ss_servers[i].tcp_window_head  = 0;
        g_ss_servers[i].tcp_window_count = 0;
        g_ss_servers[i].udp_window_head  = 0;
        g_ss_servers[i].udp_window_count = 0;
        g_tcp_probes[i].sockfd = -1;
        g_udp_probes[i].sockfd = -1;
    }

    atomic_store_explicit(&g_ss_best_tcp_idx, 0, memory_order_release);
    atomic_store_explicit(&g_ss_best_udp_idx, 0, memory_order_release);

    selector_start_probe_round(evloop);

    g_check_timer.data = NULL;
    ev_timer_init(&g_check_timer, check_timer_cb, SS_CHECK_INTERVAL, SS_CHECK_INTERVAL);
    ev_timer_start(evloop, &g_check_timer);

    LOG_ALWAYS_INF("[server_selector] started, %d server(s), interval=%.0fs timeout=%.0fs",
                   g_ss_server_count, SS_CHECK_INTERVAL, SS_CHECK_TIMEOUT);
}

void server_selector_stop(evloop_t *evloop) {
    ev_timer_stop(evloop, &g_check_timer);

    for (int i = 0; i < g_ss_server_count; i++) {
        ss_tcp_probe_t *tp = &g_tcp_probes[i];
        if (tp->sockfd >= 0) {
            ev_io_stop(evloop, &tp->io_watcher);
            ev_timer_stop(evloop, &tp->timeout_timer);
            close(tp->sockfd);
            tp->sockfd = -1;
            ss2022_tcp_client_free(&tp->tcp_client);
        }
        ss_udp_probe_t *up = &g_udp_probes[i];
        if (up->sockfd >= 0) {
            ev_io_stop(evloop, &up->io_watcher);
            ev_timer_stop(evloop, &up->timeout_timer);
            close(up->sockfd);
            up->sockfd = -1;
            ss2022_udp_client_session_free(&up->udp_session);
        }
    }
    for (int i = 0; i < g_ss_server_count; i++) {
        if (g_ss_ctx_ready[i]) {
            ss2022_client_ctx_free(&g_ss_ctx[i]);
            g_ss_ctx_ready[i] = false;
        }
    }
    LOG_ALWAYS_INF("[server_selector] stopped");
}
