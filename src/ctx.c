#include "ctx.h"

bool     g_verbose  = false;
uint16_t g_options  = OPT_ENABLE_TCP | OPT_ENABLE_UDP | OPT_ENABLE_IPV4 | OPT_ENABLE_IPV6;
uint8_t  g_nthreads = 1;
uint8_t  g_udp_nthreads = 1;

thread_info_t g_threads[MAX_THREADS] = {0};
int g_thread_count = 0;

char      g_bind_ipstr4[IP4STRLEN] = IP4STR_LOOPBACK;
char      g_bind_ipstr6[IP6STRLEN] = IP6STR_LOOPBACK;
portno_t  g_bind_portno            = 54321;
skaddr4_t g_bind_skaddr4           = {0};
skaddr6_t g_bind_skaddr6           = {0};

uint8_t g_tcp_syncnt_max = 0; /* 0: use default syncnt */

uint16_t g_udp_idletimeout_sec                           = UDP_IDLE_TIMEOUT_DEFAULT_SEC;
__thread udp_fullcone_node_t  *g_udp_fullcone_table      = NULL;
__thread udp_symmetric_node_t *g_udp_symmetric_table     = NULL;
__thread udp_tproxy_entry_t   *g_udp_tproxy_table        = NULL;
__thread char    g_udp_batch_buffer[UDP_BATCH_SIZE][UDP_DATAGRAM_MAXSIZ];
__thread memory_pool_t *g_udp_session_pool               = NULL;
__thread memory_pool_t *g_udp_fullcone_node_pool         = NULL;
__thread memory_pool_t *g_udp_symmetric_node_pool        = NULL;
__thread memory_pool_t *g_udp_tproxy_pool                = NULL;
__thread memory_pool_t *g_tcp_session_pool               = NULL;
__thread memory_pool_t *g_tcp_relay_in_pool              = NULL;
__thread tcp_session_t *g_tcp_session_head               = NULL;

char      g_fakedns_ipstr[IP4STRLEN] = "127.0.0.1";
portno_t  g_fakedns_portno           = 5353;
char      g_fakedns_cidr[64]         = "198.18.0.0/15";
char      g_fakedns_cache_path[256]  = {0};
skaddr4_t g_fakedns_skaddr           = {0};
