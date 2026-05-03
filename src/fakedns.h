#ifndef TPROXY2SS2022_FAKEDNS_H
#define TPROXY2SS2022_FAKEDNS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define FAKEDNS_MAX_DOMAIN_LEN 244

void fakedns_init(const char *cidr_str);

bool fakedns_reverse_lookup(uint32_t ip, char *buffer, size_t buf_len);

size_t fakedns_process_query(const uint8_t *query, size_t qlen, uint8_t *buffer, size_t buflen);

bool fakedns_is_fakeip(uint32_t ip_net);

/* Combined fakeip check + reverse lookup.
 * Returns domain string (thread-local, valid until next call) on hit,
 * NULL on skip (not enabled / not fakeip).  Sets *is_miss = true on
 * fakeip that has no mapping (caller should drop the packet). */
const char *fakedns_try_resolve(uint32_t ip_net, bool *is_miss);

void fakedns_save(const char *path);
void fakedns_load(const char *path);

#endif /* TPROXY2SS2022_FAKEDNS_H */
