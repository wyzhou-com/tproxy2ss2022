#ifndef TPROXY2SS2022_FAKEDNS_SERVER_H
#define TPROXY2SS2022_FAKEDNS_SERVER_H

#include "ev_types.h"

void fakedns_server_recv_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents);

#endif /* TPROXY2SS2022_FAKEDNS_SERVER_H */
