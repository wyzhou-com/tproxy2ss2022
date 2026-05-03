#include "mempool.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "logutils.h"

#define MEMPOOL_MAGIC_POOL   0xDEADBEEF
#define MEMPOOL_MAGIC_FREE   0x00000000
#define CACHELINE_SIZE       64
#define EXPAND_BATCH_SIZE    32

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

/* ----------------------------------------------------------------------------
 * Memory Topologies & Headers
 * ---------------------------------------------------------------------------- */

/* 1. Inline Slab Metadata (64 bytes) */
typedef struct mempool_slab {
    struct mempool_slab *next;
    size_t block_count;
    char padding[CACHELINE_SIZE - sizeof(struct mempool_slab *) - sizeof(size_t)];
} mempool_slab_t;

_Static_assert(sizeof(mempool_slab_t) == CACHELINE_SIZE, "mempool_slab_t alignment broken");

/* 2. Pool Block Header (64 bytes) */
typedef struct block_header {
    uint32_t magic;
    uint32_t _pad0;               /* Explicit padding to align next_free to 8 bytes */
    struct block_header *next_free;
    char padding[CACHELINE_SIZE - (sizeof(uint32_t) * 2 + sizeof(void *))];
} block_header_t;

_Static_assert(sizeof(block_header_t) == CACHELINE_SIZE, "block_header_t alignment broken");

struct memory_pool {
    mempool_slab_t  *slab_list;
    mempool_slab_t  *last_freed_slab; /* Amortized O(1) temporal locality cache */

    block_header_t  *free_list;

    size_t block_size;
    size_t total_size;

    size_t pool_blocks;
    size_t max_blocks;
    size_t free_count;

    size_t pool_allocs;
    size_t pool_frees;
    size_t warn_counter;
};

static inline void* block_to_data(void *header) {
    return (char *)header + CACHELINE_SIZE;
}

static inline void* data_to_header(void *ptr) {
    return (char *)ptr - CACHELINE_SIZE;
}

static size_t mempool_physical_size(memory_pool_t *pool) {
    if (!pool) {
        return 0;
    }
    size_t total = sizeof(memory_pool_t);
    mempool_slab_t *slab = pool->slab_list;
    while (slab) {
        total += sizeof(mempool_slab_t) + slab->block_count * pool->total_size;
        slab = slab->next;
    }
    return total;
}

/* ----------------------------------------------------------------------------
 * Internal: Slab Expansion
 * ---------------------------------------------------------------------------- */

static size_t expand_pool_batch(memory_pool_t *pool, size_t batch_count) {
    if (batch_count == 0) {
        return 0;
    }

    if (batch_count > (SIZE_MAX - sizeof(mempool_slab_t)) / pool->total_size) {
        LOGERR("[mempool] batch_count=%zu overflows slab_size calculation", batch_count);
        return 0;
    }

    size_t slab_size = sizeof(mempool_slab_t) + batch_count * pool->total_size;

    void *slab_raw = NULL;
    if (posix_memalign(&slab_raw, CACHELINE_SIZE, slab_size) != 0) {
        LOGERR("[mempool] posix_memalign failed for slab size=%zu", slab_size);
        return 0;
    }

    mempool_slab_t *slab_hdr = (mempool_slab_t *)slab_raw;
    slab_hdr->block_count = batch_count;
    slab_hdr->next = pool->slab_list;
    pool->slab_list = slab_hdr;

    char *block_start = (char *)slab_raw + sizeof(mempool_slab_t);
    block_header_t *first_block = (block_header_t *)block_start;
    block_header_t *curr = first_block;

    for (size_t i = 0; i < batch_count; i++) {
        curr->magic = MEMPOOL_MAGIC_FREE;

        block_header_t *next_block = (block_header_t *)((char *)curr + pool->total_size);

        if (i < batch_count - 1) {
            curr->next_free = next_block;
        } else {
            curr->next_free = pool->free_list;
        }

        curr = next_block;
    }

    pool->free_list = first_block;
    pool->pool_blocks += batch_count;
    pool->free_count += batch_count;

    return batch_count;
}

/* ----------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------------- */

memory_pool_t* mempool_create(size_t block_size, size_t initial_blocks, size_t max_blocks) {
    memory_pool_t *pool = calloc(1, sizeof(memory_pool_t));
    if (!pool) {
        return NULL;
    }

    pool->block_size = block_size;
    size_t base_total = sizeof(block_header_t) + block_size;
    pool->total_size = (base_total + (size_t)CACHELINE_SIZE - 1) & ~((size_t)CACHELINE_SIZE - 1);
    pool->max_blocks = (max_blocks == 0) ? SIZE_MAX : max_blocks;

    if (initial_blocks > 0) {
        size_t want = MIN(initial_blocks, pool->max_blocks);
        size_t got  = expand_pool_batch(pool, want);
        if (got < want) {
            LOGERR("[mempool] create: initial reservation failed (requested=%zu, got=%zu)",
                   want, got);
            mempool_slab_t *s = pool->slab_list;
            while (s) {
                mempool_slab_t *n = s->next;
                free(s);
                s = n;
            }
            free(pool);
            return NULL;
        }
    }

    size_t phys_mem_kb = mempool_physical_size(pool) / 1024;
    LOGINF("[mempool] create: payload=%-4zu stride=%-4zu | blocks=%zu, max=%zu | memory: %zuKB",
           pool->block_size, pool->total_size, pool->pool_blocks, pool->max_blocks, phys_mem_kb);

    return pool;
}

void* mempool_alloc_sized(memory_pool_t *pool, size_t size) {
    if (!pool) {
        return NULL;
    }

    if (size > pool->block_size) {
        LOGERR("[mempool] BUG: alloc size=%zu exceeds block_size=%zu", size, pool->block_size);
        return NULL;
    }

    if (!pool->free_list && pool->pool_blocks < pool->max_blocks) {
        expand_pool_batch(pool, MIN(EXPAND_BATCH_SIZE, pool->max_blocks - pool->pool_blocks));
    }

    if (pool->free_list) {
        block_header_t *header = pool->free_list;
        pool->free_list = header->next_free;

        header->magic = MEMPOOL_MAGIC_POOL;
        header->next_free = NULL;

        pool->free_count--;
        pool->pool_allocs++;
        return block_to_data(header);
    }

    if (pool->warn_counter++ % 1000 == 0) {
        LOGWAR("[mempool] pool exhausted (%zu/%zu)", pool->pool_blocks, pool->max_blocks);
    }
    return NULL;
}

void* mempool_calloc_sized(memory_pool_t *pool, size_t size) {
    void *ptr = mempool_alloc_sized(pool, size);
    if (ptr) {
        memset(ptr, 0, pool->block_size);
    }
    return ptr;
}

static inline bool verify_boundary(memory_pool_t *pool, mempool_slab_t *slab, char *hdr_ptr) {
    if (!slab) {
        return false;
    }
    /* Use uintptr_t arithmetic: relational comparison / subtraction between
     * pointers from different objects is UB in C, and this path is designed
     * to reject arbitrary foreign pointers. */
    uintptr_t addr       = (uintptr_t)hdr_ptr;
    uintptr_t slab_start = (uintptr_t)slab + sizeof(mempool_slab_t);
    uintptr_t slab_end   = slab_start + slab->block_count * pool->total_size;

    if (addr >= slab_start && addr < slab_end) {
        return ((addr - slab_start) % pool->total_size == 0);
    }
    return false;
}

static void internal_free(memory_pool_t *pool, void *ptr) {
    if (!pool || !ptr) {
        return;
    }

    char *hdr_ptr = (char *)data_to_header(ptr);
    block_header_t *valid_header = NULL;

    /* Axiom 1: Fast Path via Temporal Locality Cache */
    if (verify_boundary(pool, pool->last_freed_slab, hdr_ptr)) {
        valid_header = (block_header_t *)hdr_ptr;
    } else {
        /* Axiom 2: Full Topological Boundary Verification (Slow Path) */
        mempool_slab_t *slab = pool->slab_list;
        while (slab) {
            if (verify_boundary(pool, slab, hdr_ptr)) {
                valid_header = (block_header_t *)hdr_ptr;
                pool->last_freed_slab = slab; /* Update locality cache */
                break;
            }
            slab = slab->next;
        }
    }

    if (!valid_header) {
        LOGERR("[mempool] FATAL: Boundary verification failed. Interior/Invalid pointer %p", ptr);
        return; /* Eradicates arbitrary free-list injection */
    }

    block_header_t *header = valid_header;

    /* Axiom 3: Strict State Integrity */
    if (header->magic == MEMPOOL_MAGIC_FREE) {
        LOGERR("[mempool] FATAL: Double free detected! ptr=%p", ptr);
        return;
    }

    if (header->magic != MEMPOOL_MAGIC_POOL) {
        LOGERR("[mempool] FATAL: Invalid magic=0x%08X, ptr=%p (Memory Corruption)", header->magic, ptr);
        return;
    }

    header->magic     = MEMPOOL_MAGIC_FREE;
    header->next_free = pool->free_list;
    pool->free_list   = header;

    pool->free_count++;
    pool->pool_frees++;
}

void mempool_free_sized(memory_pool_t *pool, void *ptr, size_t size) {
    (void)size;
    internal_free(pool, ptr);
}

size_t mempool_destroy(memory_pool_t *pool) {
    if (!pool) {
        return 0;
    }

    /* Axiom 4: Underflow Guard for Leak Calculation */
    if (pool->free_count > pool->pool_blocks) {
        LOGERR("[mempool] FATAL: free_count (%zu) > pool_blocks (%zu). Tracking state corrupted.",
               pool->free_count, pool->pool_blocks);
    }

    size_t total_leaks = (pool->free_count <= pool->pool_blocks)
                         ? (pool->pool_blocks - pool->free_count) : 0;

    size_t phys_mem_kb = mempool_physical_size(pool) / 1024;

    LOGINF("[mempool] destroy: payload=%-4zu stride=%-4zu | blocks=%zu, free=%zu | "
           "alloc=%zu, free=%zu | leaks=%zu | memory: %zuKB",
           pool->block_size, pool->total_size, pool->pool_blocks, pool->free_count,
           pool->pool_allocs, pool->pool_frees, total_leaks, phys_mem_kb);

    if (total_leaks > 0) {
        LOGWAR("[mempool] detected leaks: %zu", total_leaks);
    }

    mempool_slab_t *s_curr = pool->slab_list;
    while (s_curr) {
        mempool_slab_t *s_next = s_curr->next;
        free(s_curr);
        s_curr = s_next;
    }

    free(pool);
    return total_leaks;
}
