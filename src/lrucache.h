#ifndef TPROXY2SS2022_LRUCACHE_H
#define TPROXY2SS2022_LRUCACHE_H

/* ── lrucache.h ────────────────────────────────────────────────────────────
 * Generic LRU-eviction layer.
 *
 * It provides:
 *   1. MYLRU_HASH_* wrappers around uthash (ADD / GET / DEL / CNT / FOR).
 *   2. Four macro templates that callers instantiate once, in exactly
 *      one translation unit, to generate typed cache functions:
 *        LRU_DEFINE_ADD    — insert; evict least-recently-active if over capacity
 *        LRU_DEFINE_FIND   — pure lookup
 *        LRU_DEFINE_DEL    — unconditional removal
 *        LRU_DEFINE_CLEAR  — iterate and invoke a callback on all entries
 * Requirements on the caller's struct:
 *   - must contain a field  `myhash_hh hh`  (the uthash bookkeeping handle)
 *   - must contain a timestamp field for LRU_DEFINE_ADD eviction
 *   - key field(s) must be plain value types (no pointers-into-struct needed)
 * ──────────────────────────────────────────────────────────────────────── */

#include <stddef.h>
#include <stdint.h>

#include "xxhash.h"
#define HASH_FUNCTION(key, len, hashv) { (hashv) = (unsigned)XXH3_64bits((key), (len)); }
#include "uthash.h"

/* ── uthash handle typedef (keeps domain structs clean) ── */
typedef UT_hash_handle myhash_hh;

/* ── Thin uthash wrappers ── */
#define MYLRU_HASH_ADD(head, entry, keyptr, keylen) \
    HASH_ADD_KEYPTR(hh, (head), (keyptr), (keylen), (entry))

#define MYLRU_HASH_GET(head, out, keyptr, keylen) \
    HASH_FIND(hh, (head), (keyptr), (keylen), (out))

#define MYLRU_HASH_DEL(head, entry) \
    HASH_DELETE(hh, (head), (entry))

#define MYLRU_HASH_CNT(head) \
    HASH_COUNT(head)

/* Iterates in insertion order (oldest → newest) — used to find the LRU victim */
#define MYLRU_HASH_FOR(head, cur, tmp) \
    HASH_ITER(hh, (head), (cur), (tmp))

/* ════════════════════════════════════════════════════════════════════════
 * Generic cache macro templates
 *
 * Instantiate each macro exactly once per (func_name, type) pair,
 * in a single .c file. Multiple inclusions of these macros in different
 * translation units will produce duplicate-symbol linker errors.
 *
 * LRU_DEFINE_ADD   — insert entry; if over capacity, removes the entry
 *                    with the smallest ts_field (least recently active)
 *                    from the hash table and returns it.  The caller is
 *                    responsible only for resource teardown + free on
 *                    that returned pointer (do NOT call _del again).
 *
 * LRU_DEFINE_FIND  — pure lookup; returns NULL on miss.
 *
 * LRU_DEFINE_DEL   — unconditional removal from the hash table.
 *
 * LRU_DEFINE_CLEAR — iterate over all entries and invoke a caller-supplied
 *                    teardown callback on each.
 *
 *   The callback MAY call the corresponding _del function on the current
 *   entry; doing so is safe because the iterator saves the next pointer
 *   before entering the loop body (HASH_ITER guarantee).
 *
 *   The callback MUST eventually remove each entry from the table (via _del
 *   or equivalent), either synchronously inside the callback or via a
 *   guaranteed-synchronous mechanism such as ev_invoke with EV_CUSTOM.
 *   Leaving entries in the table after clear completes is a bug.
 *
 *   Motivation: Abstract away `HASH_ITER` and `hh` so that business logic
 *   files never need to interact with uthash macros directly.
 *
 * Design note — no per-packet LRU reordering:
 *   Hot-path callers only update the entry's ts_field (a plain timestamp
 *   write).  Eviction and GC pay O(n) scans over small bounded tables
 *   (n ≤ UINT16_MAX) instead of forcing a hash DEL+ADD on every packet.
 * ════════════════════════════════════════════════════════════════════════ */

#define LRU_DEFINE_ADD(func_name, type, key_field, maxsize_expr, ts_field)   \
type* func_name(type **cache, type *entry) {                                 \
    MYLRU_HASH_ADD(*cache, entry, &entry->key_field, sizeof(entry->key_field));  \
    if (MYLRU_HASH_CNT(*cache) > (maxsize_expr)) {                               \
        type *cur_ = NULL, *tmp_ = NULL, *victim_ = NULL;                   \
        MYLRU_HASH_FOR(*cache, cur_, tmp_) {                                     \
            if (cur_ == entry) continue; /* never evict the just-added entry */ \
            if (!victim_ || cur_->ts_field < victim_->ts_field)             \
                victim_ = cur_;                                              \
        }                                                                    \
        if (victim_) MYLRU_HASH_DEL(*cache, victim_);                       \
        return victim_;                                                      \
    }                                                                        \
    return NULL;                                                             \
}

#define LRU_DEFINE_FIND(func_name, type, key_type)                           \
type* func_name(type **cache, const key_type *keyptr) {                      \
    type *entry = NULL;                                                      \
    MYLRU_HASH_GET(*cache, entry, keyptr, sizeof(key_type));                 \
    return entry;                                                            \
}

#define LRU_DEFINE_DEL(func_name, type)                                      \
void func_name(type **cache, type *entry) {                                  \
    MYLRU_HASH_DEL(*cache, entry);                                               \
}

#define LRU_DEFINE_CLEAR(func_name, type)                                    \
void func_name(type **cache, void (*cb)(void *, type *), void *ctx) {        \
    type *curr, *tmp;                                                        \
    MYLRU_HASH_FOR(*cache, curr, tmp) {                                      \
        cb(ctx, curr);                                                       \
    }                                                                        \
}

#endif /* TPROXY2SS2022_LRUCACHE_H */
