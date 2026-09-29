#include <errno.h>
#include <pthread.h>
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

typedef enum {
    SS_HEALTH_UNKNOWN,
    SS_HEALTH_OK,
    SS_HEALTH_FAILED,
} ss_health_t;

typedef struct {
    pthread_mutex_t lock;
    const char *name;
    bool is_tcp;
    _Atomic int *best_idx;
    ss_health_t health[SS_MAX_SERVERS];
    uint64_t failure_epoch[SS_MAX_SERVERS];
    /* Timer, outstanding probes and crypto contexts belong to this protocol.
     * Only the main event loop accesses these fields. */
    int probes_remaining;
    evtimer_t check_timer;
    ss2022_client_ctx ctx[SS_MAX_SERVERS];
    bool ctx_ready[SS_MAX_SERVERS];
} ss_selector_t;

static ss_selector_t g_tcp_selector = {
    .lock = PTHREAD_MUTEX_INITIALIZER, .name = "TCP", .is_tcp = true,
    .best_idx = &g_ss_best_tcp_idx,
};
static ss_selector_t g_udp_selector = {
    .lock = PTHREAD_MUTEX_INITIALIZER, .name = "UDP", .is_tcp = false,
    .best_idx = &g_ss_best_udp_idx,
};

static ss2022_client_ctx *ss_ctx_get(ss_selector_t *selector, int idx) {
    if (!selector->ctx_ready[idx]) {
        if (ss2022_client_ctx_init(&selector->ctx[idx],
                                   g_ss_servers[idx].method,
                                   g_ss_servers[idx].psk) != SS2022_OK) {
            LOGERR("[server_selector] %s ctx init failed for server [%d]", selector->name, idx);
            return NULL;
        }
        selector->ctx_ready[idx] = true;
    }
    return &selector->ctx[idx];
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

#define SS_SWITCH_THRESHOLD 6u

static const char *ss_health_name(ss_health_t health) {
    return health == SS_HEALTH_OK ? "healthy" :
           health == SS_HEALTH_FAILED ? "failed" : "unknown";
}

static int ss_health_rank(ss_health_t health) {
    return health == SS_HEALTH_OK ? 0 : health == SS_HEALTH_UNKNOWN ? 1 : 2;
}

static _Atomic uint32_t *ss_score_ptr(ss_selector_t *selector, int idx) {
    return selector->is_tcp ? &g_ss_servers[idx].tcp_score : &g_ss_servers[idx].udp_score;
}

/* All ranking and publication use the same per-protocol lock. Readers of the
 * selected index remain lock-free. Unknown nodes rank ahead of failed nodes. */
static bool ss_better_locked(ss_selector_t *selector, int a, int b) {
    int ar = ss_health_rank(selector->health[a]);
    int br = ss_health_rank(selector->health[b]);
    return ar < br || (ar == br &&
                       atomic_load_explicit(ss_score_ptr(selector, a), memory_order_relaxed) <
                       atomic_load_explicit(ss_score_ptr(selector, b), memory_order_relaxed));
}

static int ss_candidate_locked(ss_selector_t *selector, uint32_t tried_mask) {
    int best = atomic_load_explicit(selector->best_idx, memory_order_relaxed);
    if (best < 0 || best >= g_ss_server_count || (tried_mask & (1u << best)))
        best = -1;
    for (int i = 0; i < g_ss_server_count; i++) {
        if (tried_mask & (1u << i)) continue;
        if (best < 0 || ss_better_locked(selector, i, best)) best = i;
    }
    return best;
}

static void ss_update_best_locked(ss_selector_t *selector, const char *reason, int failed_idx,
                                  bool allow_score_switch) {
    int prev = atomic_load_explicit(selector->best_idx, memory_order_relaxed);
    int best = ss_candidate_locked(selector, 0);
    if (best < 0) return;
    /* With every node failed, keep trying alternatives instead of pinning all
     * new connections to the formerly fastest dead node. */
    bool force = failed_idx == prev && g_ss_server_count > 1;
    if (force && best == prev)
        best = ss_candidate_locked(selector, 1u << prev);
    if (best == prev) return;
    /* During a round, scores contain a mix of old and new samples. Only
     * health improvements and failure failover may switch immediately.
     * Business feedback uses this gate too, without reading loop-owned
     * probes_remaining from a worker thread. */
    if (!force && !allow_score_switch && selector->health[best] == selector->health[prev])
        return;
    uint32_t score = atomic_load_explicit(ss_score_ptr(selector, best), memory_order_relaxed);
    uint32_t prev_score = atomic_load_explicit(ss_score_ptr(selector, prev), memory_order_relaxed);
    if (!force && selector->health[best] == selector->health[prev] &&
            (score >= prev_score || prev_score - score <= SS_SWITCH_THRESHOLD))
        return;
    atomic_store_explicit(selector->best_idx, best, memory_order_release);
    LOG_ALWAYS_INF("[server_selector] %s best changed (%s): [%d] %s:%u -> [%d] %s:%u "
                   "(score=%u health=%s)", selector->name, reason,
                   prev, g_ss_servers[prev].ipstr, (unsigned)g_ss_servers[prev].portno,
                   best, g_ss_servers[best].ipstr, (unsigned)g_ss_servers[best].portno,
                   score, ss_health_name(selector->health[best]));
}

static uint64_t ss_attempt_epoch(ss_selector_t *selector, int idx) {
    pthread_mutex_lock(&selector->lock);
    uint64_t epoch = selector->failure_epoch[idx];
    pthread_mutex_unlock(&selector->lock);
    return epoch;
}

uint64_t server_selector_tcp_attempt(int server_idx) {
    return ss_attempt_epoch(&g_tcp_selector, server_idx);
}

int server_selector_next_best_tcp(uint32_t tried_mask) {
    pthread_mutex_lock(&g_tcp_selector.lock);
    int best = ss_candidate_locked(&g_tcp_selector, tried_mask);
    pthread_mutex_unlock(&g_tcp_selector.lock);
    return best;
}

int server_selector_udp_replacement(int server_idx) {
    ss_selector_t *selector = &g_udp_selector;
    pthread_mutex_lock(&selector->lock);
    int best = atomic_load_explicit(selector->best_idx, memory_order_relaxed);
    int replacement = -1;
    if (server_idx >= 0 && server_idx < g_ss_server_count &&
            best >= 0 && best < g_ss_server_count && best != server_idx &&
            selector->health[server_idx] == SS_HEALTH_FAILED &&
            selector->health[best] == SS_HEALTH_OK)
        replacement = best;
    pthread_mutex_unlock(&selector->lock);
    return replacement;
}

void server_selector_report_tcp_failure(int server_idx) {
    if (server_idx < 0 || server_idx >= g_ss_server_count) return;
    ss_selector_t *selector = &g_tcp_selector;
    pthread_mutex_lock(&selector->lock);
    selector->failure_epoch[server_idx]++;
    selector->health[server_idx] = SS_HEALTH_FAILED;
    LOGINF("[server_selector] TCP [%d] business handshake failed: score=%u health=failed",
           server_idx, atomic_load_explicit(&g_ss_servers[server_idx].tcp_score, memory_order_relaxed));
    ss_update_best_locked(selector, "business handshake failure", server_idx, false);
    pthread_mutex_unlock(&selector->lock);
}

void server_selector_report_tcp_success(int server_idx, uint64_t attempt_epoch) {
    if (server_idx < 0 || server_idx >= g_ss_server_count) return;
    ss_selector_t *selector = &g_tcp_selector;
    pthread_mutex_lock(&selector->lock);
    /* A response from an older connection must not erase a newer failure. */
    if (attempt_epoch == selector->failure_epoch[server_idx]) {
        selector->health[server_idx] = SS_HEALTH_OK;
        ss_update_best_locked(selector, "authenticated business response", -1, false);
    }
    pthread_mutex_unlock(&selector->lock);
}

static void ss_record_probe(ss_selector_t *selector, int idx, uint32_t latency_ms,
                            bool errored, uint64_t attempt_epoch, ev_tstamp now,
                            const char *stage) {
    ss_server_t *srv = &g_ss_servers[idx];
    ss_sample_t *window = selector->is_tcp ? srv->tcp_window : srv->udp_window;
    int *head = selector->is_tcp ? &srv->tcp_window_head : &srv->udp_window_head;
    int *count = selector->is_tcp ? &srv->tcp_window_count : &srv->udp_window_count;
    window[*head] = (ss_sample_t) {
        latency_ms, errored, now
    };
    *head = (*head + 1) % SS_WINDOW_SLOTS;
    if (*count < SS_WINDOW_SLOTS) (*count)++;
    uint32_t score = ss_compute_score(window, *count, *head, now);

    pthread_mutex_lock(&selector->lock);
    atomic_store_explicit(ss_score_ptr(selector, idx), score, memory_order_release);
    if (errored) {
        selector->failure_epoch[idx]++;
        selector->health[idx] = SS_HEALTH_FAILED;
    } else if (attempt_epoch == selector->failure_epoch[idx]) {
        selector->health[idx] = SS_HEALTH_OK;
    }
    LOGINF("[server_selector] %s [%d] %s:%u: %s %ums score=%u health=%s stage=%s",
           selector->name, idx, srv->ipstr, (unsigned)srv->portno,
           errored ? "error" : "ok", latency_ms, score,
           ss_health_name(selector->health[idx]), stage);
    ss_update_best_locked(selector, errored ? "probe failure" : "probe success", errored ? idx : -1, false);
    pthread_mutex_unlock(&selector->lock);
}

static void ss_probe_done(ss_selector_t *selector) {
    if (--selector->probes_remaining == 0) {
        pthread_mutex_lock(&selector->lock);
        ss_update_best_locked(selector, "probe round complete", -1, true);
        pthread_mutex_unlock(&selector->lock);
    }
}

static void ss_probe_skip(ss_selector_t *selector, int idx, const char *reason) {
    LOGERR("[server_selector] %s [%d] probe skipped: local %s; health unchanged",
           selector->name, idx, reason);
    ss_probe_done(selector);
}

#define TCP_PROBE_SEND_BUF_SIZE 1024
#define TCP_PROBE_RECV_BUF_SIZE ((size_t)UINT16_MAX + 2u + 16u)
#define TCP_PROBE_STATUS_LEN    12u
#define TCP_PROBE_LENGTH_LEN    (2u + 16u)

static const char TCP_PROBE_REQUEST[] =
    "GET /generate_204 HTTP/1.1\r\nHost: google.com\r\nConnection: close\r\n\r\n";

typedef enum {
    TCP_PROBE_CONNECTING,
    TCP_PROBE_SENDING,
    TCP_PROBE_RECV_RESP_HDR,
    TCP_PROBE_RECV_PAYLOAD,
    TCP_PROBE_RECV_LENGTH,
} tcp_probe_state_t;

typedef struct {
    ss2022_tcp_client tcp_client;
    evloop_t *evloop;
    ev_tstamp start_ts;
    uint64_t attempt_epoch;

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

    static const char *stages[] = {"connect", "send", "response-header", "payload", "length"};
    ss_record_probe(&g_tcp_selector, p->server_idx, latency_ms, errored,
                    p->attempt_epoch, ev_now(p->evloop), stages[p->state]);
    ss_probe_done(&g_tcp_selector);
}

static void tcp_probe_socket_error(ss_tcp_probe_t *p, int err) {
    if (!socket_error_is_local(err)) {
        tcp_probe_finish(p, (uint32_t)((ev_now(p->evloop) - p->start_ts) * 1000.0), true);
        return;
    }
    ev_io_stop(p->evloop, &p->io_watcher);
    ev_timer_stop(p->evloop, &p->timeout_timer);
    close(p->sockfd);
    p->sockfd = -1;
    ss2022_tcp_client_free(&p->tcp_client);
    ss_probe_skip(&g_tcp_selector, p->server_idx, strerror(err));
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
        tcp_probe_socket_error(p, errno);
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
            int saved_errno = errno;
            LOGERR("[server_selector] tcp [%d]: send: %s", p->server_idx, strerror(saved_errno));
            tcp_probe_socket_error(p, saved_errno);
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
        tcp_probe_socket_error(p, errno);
        return;
    }

    p->state = TCP_PROBE_SENDING;
    ev_set_cb(&p->io_watcher, tcp_probe_on_send);
    ev_invoke(evloop, watcher, EV_WRITE);
}

static void tcp_probe_on_timeout(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    (void)evloop;
    ss_tcp_probe_t *p = watcher->data;
    tcp_probe_finish(p, SS_MAX_RTT_MS, true);
}

static void tcp_probe_start(evloop_t *evloop, int idx) {
    ss_server_t *srv = &g_ss_servers[idx];
    ss_tcp_probe_t *p = &g_tcp_probes[idx];
    p->attempt_epoch = ss_attempt_epoch(&g_tcp_selector, idx);

    ss2022_client_ctx *ctx = ss_ctx_get(&g_tcp_selector, idx);
    if (!ctx || ss2022_tcp_client_init(&p->tcp_client, ctx) != SS2022_OK) {
        ss_probe_skip(&g_tcp_selector, idx, "crypto initialization failure");
        return;
    }
    ss2022_addr target = {.type = SS2022_ADDR_DOMAIN, .port = 80, .u.domain.len = 10};
    memcpy(target.u.domain.name, "google.com", 10);
    if (ss2022_tcp_client_build_request_header(&p->tcp_client, &target,
            (const uint8_t *)TCP_PROBE_REQUEST, sizeof(TCP_PROBE_REQUEST) - 1,
            p->send_buf, sizeof(p->send_buf), &p->send_len) != SS2022_OK) {
        ss2022_tcp_client_free(&p->tcp_client);
        ss_probe_skip(&g_tcp_selector, idx, "request construction failure");
        return;
    }
    p->send_off = 0;
    int family = srv->skaddr.sin6_family == AF_INET6 ? AF_INET6 : AF_INET;
    int fd = new_tcp_connect_sockfd(family, g_tcp_syncnt_max);
    if (fd < 0) {
        ss2022_tcp_client_free(&p->tcp_client);
        ss_probe_skip(&g_tcp_selector, idx, "socket creation failure");
        return;
    }
    p->evloop = evloop;
    p->server_idx = idx;
    p->sockfd = fd;
    p->start_ts = ev_now(evloop);
    p->state = TCP_PROBE_CONNECTING;
    p->io_watcher.data = p;
    p->timeout_timer.data = p;
    ev_io_init(&p->io_watcher, tcp_probe_on_connected, fd, EV_WRITE);
    ev_timer_init(&p->timeout_timer, tcp_probe_on_timeout, SS_CHECK_TIMEOUT, 0.0);
    ev_timer_start(evloop, &p->timeout_timer);

    ssize_t nsend = -1;
    bool tfo = (g_options & OPT_ENABLE_TFO_CONNECT) != 0;
    tcp_connect_result_t conn = tcp_connect(fd, &srv->skaddr,
                                            tfo ? p->send_buf : NULL,
                                            tfo ? p->send_len : 0, &nsend);
    if (conn == TCP_CONNECT_FAILED) {
        tcp_probe_socket_error(p, errno);
        return;
    }
    if (nsend > 0) p->send_off = (size_t)nsend;
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
    uint64_t attempt_epoch;
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

    ss_record_probe(&g_udp_selector, p->server_idx, latency_ms, errored,
                    p->attempt_epoch, ev_now(p->evloop), "dns-response");
    ss_probe_done(&g_udp_selector);
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

    p->attempt_epoch = ss_attempt_epoch(&g_udp_selector, idx);
    ss2022_client_ctx *ctx = ss_ctx_get(&g_udp_selector, idx);
    if (!ctx || ss2022_udp_client_session_init(&p->udp_session, ctx) != SS2022_OK) {
        ss_probe_skip(&g_udp_selector, idx, "probe setup failure");
        return;
    }

    int family = (srv->skaddr.sin6_family == AF_INET6) ? AF_INET6 : AF_INET;
    int fd = new_udp_normal_sockfd(family);
    if (fd < 0) {
        LOGERR("[server_selector] udp [%d]: new_udp_normal_sockfd: %s", idx, strerror(errno));
        ss2022_udp_client_session_free(&p->udp_session);
        ss_probe_skip(&g_udp_selector, idx, "probe setup failure");
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
        ss_probe_skip(&g_udp_selector, idx, "probe setup failure");
        return;
    }

    socklen_t sklen = (srv->skaddr.sin6_family == AF_INET6)
                      ? (socklen_t)sizeof(struct sockaddr_in6)
                      : (socklen_t)sizeof(struct sockaddr_in);
    if (sendto(fd, sealed, sealed_len, 0,
               (const struct sockaddr *)&srv->skaddr, sklen) < 0) {
        int saved_errno = errno;
        LOGERR("[server_selector] udp [%d]: sendto: %s", idx, strerror(saved_errno));
        close(fd);
        ss2022_udp_client_session_free(&p->udp_session);
        if (socket_error_is_local(saved_errno)) {
            ss_probe_skip(&g_udp_selector, idx, "send failure");
        } else {
            ss_record_probe(&g_udp_selector, idx, 0, true, p->attempt_epoch, ev_now(evloop), "dns-send");
            ss_probe_done(&g_udp_selector);
        }
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

static void selector_start_probe_round(evloop_t *evloop, ss_selector_t *selector) {
    if (selector->probes_remaining > 0) return;
    selector->probes_remaining = g_ss_server_count;
    for (int i = 0; i < g_ss_server_count; i++) {
        if (selector->is_tcp) tcp_probe_start(evloop, i);
        else udp_probe_start(evloop, i);
    }
}

static void check_timer_cb(evloop_t *evloop, struct ev_watcher *watcher,
                           int revents __attribute__((unused))) {
    selector_start_probe_round(evloop, watcher->data);
}

void server_selector_init(void) {
    /* Called before worker creation, never while business reports can arrive. */
    ss_selector_t *selectors[] = {&g_tcp_selector, &g_udp_selector};
    for (size_t n = 0; n < sizeof(selectors) / sizeof(selectors[0]); n++) {
        ss_selector_t *selector = selectors[n];
        selector->probes_remaining = 0;
        memset(selector->health, 0, sizeof(selector->health));
        memset(selector->failure_epoch, 0, sizeof(selector->failure_epoch));
        for (int i = 0; i < g_ss_server_count; i++)
            atomic_store_explicit(ss_score_ptr(selector, i), UINT32_MAX, memory_order_relaxed);
        atomic_store_explicit(selector->best_idx, 0, memory_order_release);
    }
    for (int i = 0; i < g_ss_server_count; i++) {
        g_ss_servers[i].tcp_window_head = g_ss_servers[i].tcp_window_count = 0;
        g_ss_servers[i].udp_window_head = g_ss_servers[i].udp_window_count = 0;
        g_tcp_probes[i].sockfd = g_udp_probes[i].sockfd = -1;
    }
}

static void selector_start(evloop_t *evloop, ss_selector_t *selector) {
    selector->check_timer.data = selector;
    ev_timer_init(&selector->check_timer, check_timer_cb, SS_CHECK_INTERVAL, SS_CHECK_INTERVAL);
    ev_timer_start(evloop, &selector->check_timer);
    selector_start_probe_round(evloop, selector);
    LOG_ALWAYS_INF("[server_selector] %s started, %d server(s), interval=%.0fs timeout=%.0fs",
                   selector->name, g_ss_server_count, SS_CHECK_INTERVAL, SS_CHECK_TIMEOUT);
}

void server_selector_start(evloop_t *evloop) {
    if (g_options & OPT_ENABLE_TCP) selector_start(evloop, &g_tcp_selector);
    if (g_options & OPT_ENABLE_UDP) selector_start(evloop, &g_udp_selector);
}

void server_selector_stop(evloop_t *evloop) {
    ev_timer_stop(evloop, &g_tcp_selector.check_timer);
    ev_timer_stop(evloop, &g_udp_selector.check_timer);
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
        ss_selector_t *selectors[] = {&g_tcp_selector, &g_udp_selector};
        for (size_t n = 0; n < sizeof(selectors) / sizeof(selectors[0]); n++) {
            if (selectors[n]->ctx_ready[i]) {
                ss2022_client_ctx_free(&selectors[n]->ctx[i]);
                selectors[n]->ctx_ready[i] = false;
            }
        }
    }
    g_tcp_selector.probes_remaining = g_udp_selector.probes_remaining = 0;
    LOG_ALWAYS_INF("[server_selector] stopped");
}
