#ifndef TPROXY2SS2022_MEMPOOL_H
#define TPROXY2SS2022_MEMPOOL_H

#include <stddef.h>
#include <stdint.h>

typedef struct memory_pool memory_pool_t;

memory_pool_t* mempool_create(size_t block_size, size_t initial_blocks, size_t max_blocks);
void* mempool_alloc_sized(memory_pool_t *pool, size_t size);
void* mempool_calloc_sized(memory_pool_t *pool, size_t size);
void mempool_free_sized(memory_pool_t *pool, void *ptr, size_t size);
size_t mempool_destroy(memory_pool_t *pool);

#endif /* TPROXY2SS2022_MEMPOOL_H */
