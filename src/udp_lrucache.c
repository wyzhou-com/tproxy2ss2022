#include "lrucache.h"
#include "udp_proxy.h"

/* Capacity configuration. */

#define SYMMETRIC_SIZE_MULTIPLIER 2
#define TPROXY_SIZE_MULTIPLIER    4

static uint16_t g_fullcone_cache_maxsize = 256;
static uint16_t g_symmetric_cache_maxsize = 256 * SYMMETRIC_SIZE_MULTIPLIER;
static uint16_t g_tproxy_cache_maxsize    = 256 * TPROXY_SIZE_MULTIPLIER;

uint16_t udp_lrucache_get_fullcone_maxsize(void)   {
    return g_fullcone_cache_maxsize;
}
uint16_t udp_lrucache_get_symmetric_maxsize(void)   {
    return g_symmetric_cache_maxsize;
}
uint16_t udp_lrucache_get_tproxy_maxsize(void) {
    return g_tproxy_cache_maxsize;
}

void udp_lrucache_set_maxsize(uint16_t base_size) {
    g_fullcone_cache_maxsize = base_size;

    unsigned int symmetric_size = (unsigned int)base_size * SYMMETRIC_SIZE_MULTIPLIER;
    unsigned int tproxy_size    = (unsigned int)base_size * TPROXY_SIZE_MULTIPLIER;

    g_symmetric_cache_maxsize   = (symmetric_size   > 65535u) ? 65535u : (uint16_t)symmetric_size;
    g_tproxy_cache_maxsize      = (tproxy_size      > 65535u) ? 65535u : (uint16_t)tproxy_size;
}

/* Full-cone table: client endpoint -> session. */

LRU_DEFINE_ADD(udp_fullcone_node_add,
               udp_fullcone_node_t, key,
               g_fullcone_cache_maxsize, last_active)

LRU_DEFINE_FIND(udp_fullcone_node_find,
                udp_fullcone_node_t, udp_endpoint_key_t)

LRU_DEFINE_DEL(udp_fullcone_node_del,
               udp_fullcone_node_t)

/* Symmetric table: (client endpoint, target endpoint) -> session. */

LRU_DEFINE_ADD(udp_symmetric_node_add,
               udp_symmetric_node_t, key,
               g_symmetric_cache_maxsize, last_active)

LRU_DEFINE_FIND(udp_symmetric_node_find,
                udp_symmetric_node_t, udp_symmetric_key_t)

LRU_DEFINE_DEL(udp_symmetric_node_del,
               udp_symmetric_node_t)

/* TProxy table: remote source endpoint -> bound tproxy socket. */

LRU_DEFINE_ADD(udp_tproxy_entry_add,
               udp_tproxy_entry_t, key,
               g_tproxy_cache_maxsize, last_active)

LRU_DEFINE_FIND(udp_tproxy_entry_find,
                udp_tproxy_entry_t, udp_tproxy_key_t)

LRU_DEFINE_DEL(udp_tproxy_entry_del,
               udp_tproxy_entry_t)

/* Clear helpers. */

LRU_DEFINE_CLEAR(udp_fullcone_node_clear, udp_fullcone_node_t)
LRU_DEFINE_CLEAR(udp_symmetric_node_clear, udp_symmetric_node_t)
LRU_DEFINE_CLEAR(udp_tproxy_entry_clear, udp_tproxy_entry_t)
