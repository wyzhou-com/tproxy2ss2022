#ifndef TPROXY2SS2022_SERVER_SELECTOR_H
#define TPROXY2SS2022_SERVER_SELECTOR_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "ss2022_client.h"
#include "ev_types.h"
#include "netutils.h"

#define SS_MAX_SERVERS    8
#define SS_WINDOW_SLOTS   67
#define SS_CHECK_INTERVAL 60.0
#define SS_CHECK_TIMEOUT  5.0
#define SS_MAX_RTT_MS     ((uint32_t)(SS_CHECK_TIMEOUT * 1000))
#define SS_WINDOW_SEC     (SS_CHECK_INTERVAL * SS_WINDOW_SLOTS)

typedef struct {
    uint32_t  latency_ms;
    bool      errored;
    ev_tstamp ts;        /* ev_now() when the probe completed */
} ss_sample_t;

typedef struct {
    char            ipstr[IP6STRLEN];
    portno_t        portno;
    skaddr6_t       skaddr;
    ss2022_method_t method;
    char            psk[128];
    uint8_t         salt_len;

    ss_sample_t      tcp_window[SS_WINDOW_SLOTS];
    int              tcp_window_head;
    int              tcp_window_count;

    ss_sample_t      udp_window[SS_WINDOW_SLOTS];
    int              udp_window_head;
    int              udp_window_count;

    _Atomic uint32_t tcp_score;
    _Atomic uint32_t udp_score;
} ss_server_t;

extern ss_server_t g_ss_servers[SS_MAX_SERVERS];
extern int         g_ss_server_count;
extern _Atomic int g_ss_best_tcp_idx;
extern _Atomic int g_ss_best_udp_idx;

/* Initialize before worker threads can accept connections. */
void server_selector_init(void);
void server_selector_start(evloop_t *evloop);
void server_selector_stop(evloop_t *evloop);
int  server_selector_next_best_tcp(uint32_t tried_mask);
/* Snapshot of the healthy UDP best replacing a failed node, or -1. */
int  server_selector_udp_replacement(int server_idx);
void server_selector_report_tcp_failure(int server_idx);
uint64_t server_selector_tcp_attempt(int server_idx);
void server_selector_report_tcp_success(int server_idx, uint64_t attempt_epoch);

static inline ss_server_t *server_selector_best_tcp(void) {
    int idx = atomic_load_explicit(&g_ss_best_tcp_idx, memory_order_acquire);
    return &g_ss_servers[idx];
}

static inline ss_server_t *server_selector_best_udp(void) {
    int idx = atomic_load_explicit(&g_ss_best_udp_idx, memory_order_acquire);
    return &g_ss_servers[idx];
}

#endif /* TPROXY2SS2022_SERVER_SELECTOR_H */
