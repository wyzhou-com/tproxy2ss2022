#ifndef TPROXY2SS2022_CTX_H
#define TPROXY2SS2022_CTX_H

#include <pthread.h>
#include <stdint.h>

#include "ev_types.h"

#include "mempool.h"
#include "netutils.h"
#include "tcp_proxy.h"
#include "udp_proxy.h"

#define MAX_THREADS 64

typedef struct {
    pthread_t thread_id;
    evloop_t *evloop;
    ev_async  exit_watcher;
    int thread_index;       /* thread index: main=0, workers=1..N-1 */
    int running;
} thread_info_t;

/* Global thread management */
extern thread_info_t g_threads[MAX_THREADS];
extern int g_thread_count;  /* excluding main thread */

enum {
    OPT_ENABLE_TCP         = 0x01 << 0, /* enable tcp proxy */
    OPT_ENABLE_UDP         = 0x01 << 1, /* enable udp proxy */
    OPT_ENABLE_IPV4        = 0x01 << 2, /* enable ipv4 proxy */
    OPT_ENABLE_IPV6        = 0x01 << 3, /* enable ipv6 proxy */
    OPT_ENABLE_TFO_ACCEPT  = 0x01 << 4, /* enable tcp_fastopen for listen socket (server tfo) */
    OPT_ENABLE_TFO_CONNECT = 0x01 << 5, /* enable tcp_fastopen for connect socket (client tfo) */
    OPT_ENABLE_FAKEDNS     = 0x01 << 6, /* enable fakedns feature */
};

extern uint16_t g_options;
extern uint8_t  g_nthreads;
extern uint8_t  g_udp_nthreads;

extern char      g_bind_ipstr4[IP4STRLEN];
extern char      g_bind_ipstr6[IP6STRLEN];
extern portno_t  g_bind_portno;
extern skaddr4_t g_bind_skaddr4;
extern skaddr6_t g_bind_skaddr6;

extern uint8_t g_tcp_syncnt_max;

extern uint16_t g_udp_idletimeout_sec;
extern __thread udp_fullcone_node_t  *g_udp_fullcone_table;
extern __thread udp_symmetric_node_t *g_udp_symmetric_table;
extern __thread udp_tproxy_entry_t   *g_udp_tproxy_table;
extern __thread char    g_udp_batch_buffer[UDP_BATCH_SIZE][UDP_DATAGRAM_MAXSIZ];
extern __thread memory_pool_t *g_udp_session_pool;
extern __thread memory_pool_t *g_udp_fullcone_node_pool;
extern __thread memory_pool_t *g_udp_symmetric_node_pool;
extern __thread memory_pool_t *g_udp_tproxy_pool;
extern __thread memory_pool_t *g_tcp_session_pool;
extern __thread memory_pool_t *g_tcp_relay_in_pool;
extern __thread tcp_session_t *g_tcp_session_head;

extern char      g_fakedns_ipstr[IP4STRLEN];
extern portno_t  g_fakedns_portno;
extern char      g_fakedns_cidr[64];
extern char      g_fakedns_cache_path[256];
extern skaddr4_t g_fakedns_skaddr;

#endif /* TPROXY2SS2022_CTX_H */
