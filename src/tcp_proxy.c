#include "tcp_proxy.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ctx.h"
#include "fakedns.h"
#include "logutils.h"
#include "server_selector.h"

static __thread ss2022_client_ctx g_tcp_ss_ctx[SS_MAX_SERVERS];
static __thread bool              g_tcp_ss_ctx_ready[SS_MAX_SERVERS];

static ss2022_client_ctx *tcp_ctx_get(int server_idx) {
    if (!g_tcp_ss_ctx_ready[server_idx]) {
        ss_server_t *srv = &g_ss_servers[server_idx];
        if (ss2022_client_ctx_init(&g_tcp_ss_ctx[server_idx],
                                   srv->method, srv->psk) != SS2022_OK) {
            return NULL;
        }
        g_tcp_ss_ctx_ready[server_idx] = true;
    }
    return &g_tcp_ss_ctx[server_idx];
}

static inline tcp_session_t *tcp_session_from_watcher(evio_t *watcher) {
    return (tcp_session_t *)watcher->data;
}

static inline void tcp_session_close(evloop_t *evloop, tcp_session_t *session, bool is_tcp_reset) {
    evio_t *client_watcher = &session->client_watcher;
    evio_t *server_watcher = &session->server_watcher;

    if (client_watcher->fd >= 0) {
        ev_io_stop(evloop, client_watcher);
    }
    if (server_watcher->fd >= 0) {
        ev_io_stop(evloop, server_watcher);
    }
    ev_timer_stop(evloop, &session->phase_timer);
    if (is_tcp_reset) {
        if (client_watcher->fd >= 0) {
            tcp_close_by_rst(client_watcher->fd);
        }
        if (server_watcher->fd >= 0) {
            tcp_close_by_rst(server_watcher->fd);
        }
    } else {
        if (client_watcher->fd >= 0) {
            close(client_watcher->fd);
        }
        if (server_watcher->fd >= 0) {
            close(server_watcher->fd);
        }
    }

    if (session->relay_in_allocated) {
        mempool_free_sized(g_tcp_relay_in_pool, session->relay.server_to_client_in, TCP_SS_RESP_IN_BUFSIZ);
        session->relay_in_allocated = false;
    }
    ss2022_tcp_client_free(&session->ss_client);

    if (session->next) session->next->prev = session->prev;
    if (session->prev) {
        session->prev->next = session->next;
    } else {
        g_tcp_session_head = session->next;
    }

    mempool_free_sized(g_tcp_session_pool, session, sizeof(*session));
}

static void tcp_handshake_on_timeout(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    tcp_session_t *session = (tcp_session_t *)watcher->data;
    LOGERR("[tcp_handshake] connect/header-send timed out (%gs), closing", TCP_CONNECT_TIMEOUT_SEC);
    tcp_session_close(evloop, session, true);
}

static bool tcp_proxy_resolve_target(int client_sockfd, bool isipv4, ss2022_addr *target) {
    skaddr6_t skaddr;
    char ipstr[IP6STRLEN];
    portno_t portno;

    if (!get_tcp_orig_dstaddr(isipv4 ? AF_INET : AF_INET6, client_sockfd, &skaddr)) {
        return false;
    }
    IF_VERBOSE {
        parse_socket_addr(&skaddr, ipstr, &portno);
        LOGINF_RAW("[tcp_proxy] target socket address: %s#%hu", ipstr, portno);
    }

    const char *fake_domain = NULL;
    if ((g_options & OPT_ENABLE_FAKEDNS) && isipv4) {
        uint32_t target_ip = ((skaddr4_t *)&skaddr)->sin_addr.s_addr;
        bool is_miss;
        fake_domain = fakedns_try_resolve(target_ip, &is_miss);
        if (is_miss) {
            LOGERR("[tcp_fakedns] miss for FakeIP: %u.%u.%u.%u, dropping connection",
                   ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                   ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3]);
            return false;
        }
        IF_VERBOSE if (fake_domain) {
            LOGINF_RAW("[tcp_fakedns] fakedns hit: %u.%u.%u.%u -> %s",
                       ((uint8_t *)&target_ip)[0], ((uint8_t *)&target_ip)[1],
                       ((uint8_t *)&target_ip)[2], ((uint8_t *)&target_ip)[3],
                       fake_domain);
        }
    }

    memset(target, 0, sizeof(*target));
    if (fake_domain) {
        size_t domain_len = strlen(fake_domain);
        if (domain_len == 0 || domain_len > sizeof(target->u.domain.name)) {
            LOGERR("[tcp_proxy] invalid fakedns domain length: %zu", domain_len);
            return false;
        }
        target->type = SS2022_ADDR_DOMAIN;
        target->port = ntohs(((skaddr4_t *)&skaddr)->sin_port);
        target->u.domain.len = (uint8_t)domain_len;
        memcpy(target->u.domain.name, fake_domain, domain_len);
    } else if (((skaddr4_t *)&skaddr)->sin_family == AF_INET) {
        skaddr4_t *addr4 = (skaddr4_t *)&skaddr;
        target->type = SS2022_ADDR_IPV4;
        target->port = ntohs(addr4->sin_port);
        memcpy(target->u.ipv4, &addr4->sin_addr.s_addr, sizeof(target->u.ipv4));
    } else {
        skaddr6_t *addr6 = &skaddr;
        target->type = SS2022_ADDR_IPV6;
        target->port = ntohs(addr6->sin6_port);
        memcpy(target->u.ipv6, &addr6->sin6_addr.s6_addr, sizeof(target->u.ipv6));
    }
    return true;
}

static int tcp_handshake_connect_server(const ss_server_t *srv, const uint8_t *request_header,
                                        size_t request_header_len, ssize_t *tfo_nsend,
                                        tcp_connect_result_t *conn) {
    int server_sockfd = new_tcp_connect_sockfd(srv->skaddr.sin6_family, g_tcp_syncnt_max);
    if (server_sockfd < 0) {
        LOGERR("[tcp_handshake] new_tcp_connect_sockfd: %s", strerror(errno));
        return -1;
    }

    const void *tfo_data = NULL;
    size_t tfo_datalen = 0;
    if ((g_options & OPT_ENABLE_TFO_CONNECT) && request_header && request_header_len) {
        tfo_data = request_header;
        tfo_datalen = request_header_len;
    }

    *tfo_nsend = -1;
    *conn = tcp_connect(server_sockfd, &srv->skaddr, tfo_data, tfo_datalen, tfo_nsend);
    if (*conn == TCP_CONNECT_FAILED) {
        LOGERR("[tcp_handshake] connect to %s#%hu: %s", srv->ipstr, srv->portno, strerror(errno));
        close(server_sockfd);
        return -1;
    }
    if (*tfo_nsend >= 0) {
        LOGINF("[tcp_handshake] tfo connecting to %s#%hu, nsend:%zd", srv->ipstr, srv->portno, *tfo_nsend);
    } else if (*conn == TCP_CONNECT_IN_PROGRESS) {
        LOGINF("[tcp_handshake] connecting to %s#%hu ...", srv->ipstr, srv->portno);
    }

    return server_sockfd;
}

static void tcp_buf_consume(size_t *head, size_t *len, size_t n) {
    if (n >= *len) {
        *head = 0;
        *len = 0;
        return;
    }
    *head += n;
    *len  -= n;
}

static bool tcp_relay_drain(evloop_t *evloop, tcp_session_t *session,
                            evio_t *watcher, uint8_t *buf,
                            size_t *off, size_t *len,
                            const char *name) {
    while (*len > 0) {
        ssize_t nsend = send(watcher->fd, buf + *off, *len, 0);
        if (nsend < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return true;
            }
            if (errno == EPIPE || errno == ECONNRESET) {
                IF_VERBOSE {
                    LOGINF_RAW("[tcp_relay] send to %s: %s, cascade RST", name, strerror(errno));
                }
            } else {
                LOGERR("[tcp_relay] send to %s: %s", name, strerror(errno));
            }
            tcp_session_close(evloop, session, true);
            return false;
        }
        if (nsend == 0) {
            LOGERR("[tcp_relay] send to %s returned 0", name);
            tcp_session_close(evloop, session, true);
            return false;
        }
        *off += (size_t)nsend;
        *len -= (size_t)nsend;
    }
    *off = 0;
    return true;
}

static bool tcp_relay_process_server_data(evloop_t *evloop, tcp_session_t *session) {
    while (session->relay.server_to_client_out_len == 0) {
        uint8_t *base = session->relay.server_to_client_in + session->relay.server_to_client_in_head;

        if (!session->relay.response_header_done) {
            if (session->relay.server_to_client_in_len < session->relay.response_header_len) {
                return true;
            }
            int ret = ss2022_tcp_client_open_response_header(
                          &session->ss_client,
                          base,
                          session->relay.response_header_len,
                          &session->relay.response_payload_len);
            if (ret != SS2022_OK) {
                LOGERR("[tcp_relay] open ss2022 response header failed: %d", ret);
                tcp_session_close(evloop, session, true);
                return false;
            }
            tcp_buf_consume(&session->relay.server_to_client_in_head, &session->relay.server_to_client_in_len,
                            session->relay.response_header_len);
            base = session->relay.server_to_client_in + session->relay.server_to_client_in_head;
            session->relay.response_header_done = true;
            session->relay.server_to_client_need_len = false;
        }

        if (session->relay.server_to_client_need_len) {
            if (session->relay.server_to_client_in_len < SS2022_LENGTH_CHUNK_LEN) {
                return true;
            }
            int ret = ss2022_tcp_client_open_length(
                          &session->ss_client,
                          base,
                          SS2022_LENGTH_CHUNK_LEN,
                          &session->relay.response_payload_len);
            if (ret != SS2022_OK) {
                LOGERR("[tcp_relay] open ss2022 length chunk failed: %d", ret);
                tcp_session_close(evloop, session, true);
                return false;
            }
            tcp_buf_consume(&session->relay.server_to_client_in_head, &session->relay.server_to_client_in_len, SS2022_LENGTH_CHUNK_LEN);
            base = session->relay.server_to_client_in + session->relay.server_to_client_in_head;
            session->relay.server_to_client_need_len = false;
        }

        size_t need = (size_t)session->relay.response_payload_len + TCP_SS2022_TAG_LEN;
        if (session->relay.server_to_client_in_len < need) {
            return true;
        }
        size_t plain_len = 0;
        int ret = ss2022_tcp_client_open_payload(
                      &session->ss_client,
                      base,
                      need,
                      base,
                      need - TCP_SS2022_TAG_LEN,
                      &plain_len);
        if (ret != SS2022_OK) {
            LOGERR("[tcp_relay] open ss2022 payload chunk failed: %d", ret);
            tcp_session_close(evloop, session, true);
            return false;
        }
        if (plain_len == 0) {
            tcp_buf_consume(&session->relay.server_to_client_in_head, &session->relay.server_to_client_in_len, need);
            session->relay.server_to_client_in_consume = 0;
        } else {
            session->relay.server_to_client_in_consume = need;
        }
        session->relay.server_to_client_out_off = 0;
        session->relay.server_to_client_out_len = plain_len;
        session->relay.server_to_client_need_len = true;
    }
    return true;
}

static bool tcp_relay_server_eof_is_clean(const tcp_session_t *session) {
    if (session->relay.server_to_client_in_len != 0) {
        return false;
    }
    if (!session->relay.response_header_done) {
        return false;
    }
    return session->relay.server_to_client_need_len;
}

static void tcp_relay_get_client_endpoint(const tcp_session_t *session,
        char ipstr[IP6STRLEN], portno_t *portno) {
    skaddr6_t client_peer_addr;
    socklen_t client_peer_addrlen = sizeof(client_peer_addr);

    if (getpeername(session->client_watcher.fd, (struct sockaddr *)&client_peer_addr,
                    &client_peer_addrlen) != 0) {
        parse_socket_addr(&session->client_peer_addr, ipstr, portno);
        return;
    }
    parse_socket_addr(&client_peer_addr, ipstr, portno);
}

static void tcp_log_relay_client_eof(const tcp_session_t *session) {
    ss_server_t *srv = &g_ss_servers[session->server_idx];
    char client_ipstr[IP6STRLEN];
    portno_t client_portno;

    tcp_relay_get_client_endpoint(session, client_ipstr, &client_portno);
    LOGINF_RAW("[tcp_relay] %s#%hu EOF <-> %s#%hu",
               client_ipstr, client_portno, srv->ipstr, srv->portno);
}

static void tcp_log_relay_server_eof(const tcp_session_t *session) {
    ss_server_t *srv = &g_ss_servers[session->server_idx];
    char client_ipstr[IP6STRLEN];
    portno_t client_portno;

    tcp_relay_get_client_endpoint(session, client_ipstr, &client_portno);
    LOGINF_RAW("[tcp_relay] %s#%hu <-> EOF %s#%hu",
               client_ipstr, client_portno, srv->ipstr, srv->portno);
}

static void tcp_log_relay_established(const tcp_session_t *session) {
    ss_server_t *srv = &g_ss_servers[session->server_idx];
    char client_ipstr[IP6STRLEN];
    portno_t client_portno;

    tcp_relay_get_client_endpoint(session, client_ipstr, &client_portno);
    LOGINF_RAW("[tcp_relay] tcp tunnel established %s#%hu <-> %s#%hu",
               client_ipstr, client_portno, srv->ipstr, srv->portno);
}

static void tcp_log_relay_done(const tcp_session_t *session) {
    ss_server_t *srv = &g_ss_servers[session->server_idx];
    char client_ipstr[IP6STRLEN];
    portno_t client_portno;

    tcp_relay_get_client_endpoint(session, client_ipstr, &client_portno);
    LOGINF_RAW("[tcp_relay] proxy done %s#%hu <-> %s#%hu",
               client_ipstr, client_portno, srv->ipstr, srv->portno);
}

static void tcp_relay_update_watchers(evloop_t *evloop, tcp_session_t *session) {
    if (session->relay.client_eof && session->relay.client_to_server_len == 0 && !session->relay.server_shutdown_sent) {
        shutdown(session->server_watcher.fd, SHUT_WR);
        session->relay.server_shutdown_sent = true;
    }
    if (session->relay.server_eof && session->relay.server_to_client_out_len == 0 && session->relay.server_to_client_in_len == 0 &&
            !session->relay.client_shutdown_sent) {
        shutdown(session->client_watcher.fd, SHUT_WR);
        session->relay.client_shutdown_sent = true;
    }

    if (session->relay.client_eof && session->relay.server_eof &&
            session->relay.client_to_server_len == 0 && session->relay.server_to_client_out_len == 0 && session->relay.server_to_client_in_len == 0) {
        IF_VERBOSE {
            tcp_log_relay_done(session);
        }
        tcp_session_close(evloop, session, false);
        return;
    }

    int client_events = 0;
    int server_events = 0;
    if (!session->relay.client_eof && session->relay.client_to_server_len == 0) {
        client_events |= EV_READ;
    }
    if (session->relay.server_to_client_out_len > 0) {
        client_events |= EV_WRITE;
    }
    if (!session->relay.server_eof && session->relay.server_to_client_out_len == 0 &&
            session->relay.server_to_client_in_len < TCP_SS_RESP_IN_BUFSIZ) {
        server_events |= EV_READ;
    }
    if (session->relay.client_to_server_len > 0) {
        server_events |= EV_WRITE;
    }

    ev_io_stop(evloop, &session->client_watcher);
    if (client_events) {
        ev_io_set(&session->client_watcher, session->client_watcher.fd, client_events);
        ev_io_start(evloop, &session->client_watcher);
    }
    ev_io_stop(evloop, &session->server_watcher);
    if (server_events) {
        ev_io_set(&session->server_watcher, session->server_watcher.fd, server_events);
        ev_io_start(evloop, &session->server_watcher);
    }
}

static bool tcp_relay_write_to_client(evloop_t *evloop, tcp_session_t *session) {
    uint8_t *out = session->relay.server_to_client_in + session->relay.server_to_client_in_head;

    if (!tcp_relay_drain(evloop, session, &session->client_watcher,
                         out, &session->relay.server_to_client_out_off,
                         &session->relay.server_to_client_out_len, "client")) {
        return false;
    }
    if (session->relay.server_to_client_out_len == 0 &&
            session->relay.server_to_client_in_consume > 0) {
        tcp_buf_consume(&session->relay.server_to_client_in_head,
                        &session->relay.server_to_client_in_len,
                        session->relay.server_to_client_in_consume);
        session->relay.server_to_client_in_consume = 0;
    }
    return true;
}

static bool tcp_relay_write_to_server(evloop_t *evloop, tcp_session_t *session) {
    return tcp_relay_drain(evloop, session, &session->server_watcher,
                           session->relay.client_to_server_buf,
                           &session->relay.client_to_server_off,
                           &session->relay.client_to_server_len, "server");
}

static bool tcp_relay_process_pending_server_data(evloop_t *evloop, tcp_session_t *session) {
    if (session->relay.server_to_client_out_len != 0 ||
            session->relay.server_to_client_in_len == 0) {
        return true;
    }
    return tcp_relay_process_server_data(evloop, session);
}

static bool tcp_relay_read_from_client(evloop_t *evloop, tcp_session_t *session) {
    uint8_t *plain = session->relay.client_to_server_buf + SS2022_TCP_PAYLOAD_CHUNK_PREFIX_LEN;
    ssize_t nrecv;

    do {
        nrecv = recv(session->client_watcher.fd, plain, TCP_SS_PLAIN_BUFSIZ, 0);
    } while (nrecv < 0 && errno == EINTR);

    if (nrecv < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            IF_VERBOSE {
                LOGERR("[tcp_relay] recv from client: %s", strerror(errno));
            }
            tcp_session_close(evloop, session, true);
            return false;
        }
        return true;
    }
    if (nrecv == 0) {
        IF_VERBOSE {
            tcp_log_relay_client_eof(session);
        }
        session->relay.client_eof = true;
        return true;
    }

    size_t cipher_len = 0;
    int ret = ss2022_tcp_client_seal_payload(
                  &session->ss_client,
                  plain,
                  (size_t)nrecv,
                  session->relay.client_to_server_buf,
                  sizeof(session->relay.client_to_server_buf),
                  &cipher_len);
    if (ret != SS2022_OK) {
        LOGERR("[tcp_relay] seal payload failed: %d", ret);
        tcp_session_close(evloop, session, true);
        return false;
    }
    session->relay.client_to_server_off = 0;
    session->relay.client_to_server_len = cipher_len;
    return true;
}

static void tcp_relay_compact_server_input(tcp_session_t *session) {
    if (session->relay.server_to_client_in_head == 0) {
        return;
    }
    if (TCP_SS_RESP_IN_BUFSIZ - session->relay.server_to_client_in_head -
            session->relay.server_to_client_in_len != 0) {
        return;
    }
    memmove(session->relay.server_to_client_in,
            session->relay.server_to_client_in + session->relay.server_to_client_in_head,
            session->relay.server_to_client_in_len);
    session->relay.server_to_client_in_head = 0;
}

static bool tcp_relay_handle_server_eof(evloop_t *evloop, tcp_session_t *session) {
    IF_VERBOSE {
        tcp_log_relay_server_eof(session);
    }
    if (!tcp_relay_server_eof_is_clean(session)) {
        if (!session->relay.response_header_done) {
            IF_VERBOSE {
                LOGINF_RAW("[tcp_relay] server closed before ss2022 response header");
            }
        } else {
            LOGERR("[tcp_relay] server closed mid-chunk");
        }
        tcp_session_close(evloop, session, true);
        return false;
    }
    session->relay.server_eof = true;
    return true;
}

static bool tcp_relay_read_from_server(evloop_t *evloop, tcp_session_t *session) {
    tcp_relay_compact_server_input(session);

    size_t cap = TCP_SS_RESP_IN_BUFSIZ - session->relay.server_to_client_in_head -
                 session->relay.server_to_client_in_len;
    ssize_t nrecv;
    do {
        nrecv = recv(session->server_watcher.fd,
                     session->relay.server_to_client_in +
                     session->relay.server_to_client_in_head +
                     session->relay.server_to_client_in_len,
                     cap, 0);
    } while (nrecv < 0 && errno == EINTR);

    if (nrecv < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[tcp_relay] recv from server: %s", strerror(errno));
            tcp_session_close(evloop, session, true);
            return false;
        }
        return true;
    }
    if (nrecv == 0) {
        return tcp_relay_handle_server_eof(evloop, session);
    }

    session->relay.server_to_client_in_len += (size_t)nrecv;
    return tcp_relay_process_server_data(evloop, session);
}

static bool tcp_relay_handle_write(evloop_t *evloop, tcp_session_t *session,
                                   bool is_client, int revents) {
    if (!(revents & EV_WRITE)) {
        return true;
    }
    if (is_client) {
        return tcp_relay_write_to_client(evloop, session);
    }
    return tcp_relay_write_to_server(evloop, session);
}

static bool tcp_relay_handle_read(evloop_t *evloop, tcp_session_t *session,
                                  bool is_client, int revents) {
    if (!(revents & EV_READ)) {
        return true;
    }
    if (is_client) {
        if (session->relay.client_to_server_len != 0) {
            return true;
        }
        return tcp_relay_read_from_client(evloop, session);
    }
    if (session->relay.server_to_client_out_len != 0) {
        return true;
    }
    return tcp_relay_read_from_server(evloop, session);
}

static void tcp_relay_on_event(evloop_t *evloop, struct ev_watcher *watcher, int revents) {
    evio_t *self_watcher = (evio_t *)watcher;
    tcp_session_t *session = tcp_session_from_watcher(self_watcher);
    bool is_client = (self_watcher == &session->client_watcher);

    if (!tcp_relay_handle_write(evloop, session, is_client, revents)) {
        return;
    }
    if (!tcp_relay_process_pending_server_data(evloop, session)) {
        return;
    }
    if (!tcp_relay_handle_read(evloop, session, is_client, revents)) {
        return;
    }

    tcp_relay_update_watchers(evloop, session);
}

static void tcp_session_enter_relay(evloop_t *evloop, tcp_session_t *session) {
    ev_timer_stop(evloop, &session->phase_timer);
    bool client_eof = session->handshake.client_eof;
    memset(&session->relay, 0, sizeof(session->relay));
    session->relay.client_eof = client_eof;
    session->relay.server_to_client_in = mempool_alloc_sized(g_tcp_relay_in_pool, TCP_SS_RESP_IN_BUFSIZ);
    if (!session->relay.server_to_client_in) {
        LOGERR("[tcp_relay] alloc server input buffer failed");
        tcp_session_close(evloop, session, true);
        return;
    }
    session->relay_in_allocated = true;
    session->relay.response_header_len = ss2022_tcp_client_response_header_size(&session->ss_client);
    if (session->relay.response_header_len == 0 ||
            session->relay.response_header_len > TCP_SS_RESP_IN_BUFSIZ) {
        LOGERR("[tcp_relay] invalid ss2022 response header length: %zu",
               session->relay.response_header_len);
        tcp_session_close(evloop, session, true);
        return;
    }

    ev_io_stop(evloop, &session->client_watcher);
    ev_io_stop(evloop, &session->server_watcher);
    ev_io_init(&session->client_watcher, tcp_relay_on_event, session->client_watcher.fd, EV_READ);
    ev_io_init(&session->server_watcher, tcp_relay_on_event, session->server_watcher.fd, EV_READ);
    session->client_watcher.data = session;
    session->server_watcher.data = session;
    IF_VERBOSE {
        tcp_log_relay_established(session);
    }
    tcp_relay_update_watchers(evloop, session);
}

static int tcp_handshake_send_request_header(evloop_t *evloop, tcp_session_t *session) {
    evio_t *server_watcher = &session->server_watcher;
    const uint8_t *request_header = session->handshake.request_header;
    size_t request_header_len = session->handshake.request_header_len;
    uint16_t *request_header_sent = &session->handshake.request_header_sent;
    ss_server_t *srv = &g_ss_servers[session->server_idx];
    if (*request_header_sent > request_header_len) {
        LOGERR("[tcp_handshake] invalid request_header_sent %hu/%zu", *request_header_sent, request_header_len);
        tcp_session_close(evloop, session, true);
        return -1;
    }
    if (*request_header_sent == request_header_len) {
        return 1;
    }

    ssize_t nsend = send(server_watcher->fd,
                         request_header + *request_header_sent,
                         request_header_len - *request_header_sent, 0);
    if (nsend < 0) {
        if (errno == EINTR) {
            return 0;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[tcp_handshake] send to %s#%hu: %s", srv->ipstr, srv->portno, strerror(errno));
            tcp_session_close(evloop, session, true);
            return -1;
        }
        return 0;
    }
    if (nsend == 0) {
        LOGERR("[tcp_handshake] send returned 0");
        tcp_session_close(evloop, session, true);
        return -1;
    }
    size_t new_offset = (size_t)*request_header_sent + (size_t)nsend;
    if (new_offset > request_header_len) {
        LOGERR("[tcp_handshake] header send overflow: %zu/%zu", new_offset, request_header_len);
        tcp_session_close(evloop, session, true);
        return -1;
    }
    *request_header_sent = (uint16_t)new_offset;
    return *request_header_sent == request_header_len ? 1 : 0;
}

static void tcp_handshake_on_server_writable(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *server_watcher = (evio_t *)watcher;
    tcp_session_t *session = tcp_session_from_watcher(server_watcher);
    if (tcp_handshake_send_request_header(evloop, session) != 1) {
        return;
    }
    tcp_session_enter_relay(evloop, session);
}

static void tcp_handshake_on_server_connected(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *server_watcher = (evio_t *)watcher;
    tcp_session_t *session = tcp_session_from_watcher(server_watcher);
    ss_server_t *srv = &g_ss_servers[session->server_idx];
    if (tcp_has_error(server_watcher->fd)) {
        LOGERR("[tcp_handshake] connect to %s#%hu: %s", srv->ipstr, srv->portno, strerror(errno));
        tcp_session_close(evloop, session, true);
        return;
    }
    LOGINF("[tcp_handshake] connected to %s#%hu", srv->ipstr, srv->portno);

    if (session->handshake.request_header_sent >= session->handshake.request_header_len) {
        tcp_session_enter_relay(evloop, session);
        return;
    }

    ev_set_cb(server_watcher, tcp_handshake_on_server_writable);
    ev_invoke(evloop, server_watcher, EV_WRITE);
}

static void tcp_session_attach_server(tcp_session_t *session, int server_sockfd,
                                      ssize_t tfo_nsend) {
    session->server_watcher.data = session;
    ev_io_init(&session->server_watcher, tcp_handshake_on_server_connected, server_sockfd, EV_WRITE);

    if (tfo_nsend > 0) {
        size_t sent = (size_t)tfo_nsend;
        if (sent > session->handshake.request_header_len) {
            sent = session->handshake.request_header_len;
        }
        session->handshake.request_header_sent = (uint16_t)sent;
    }
}

static bool tcp_handshake_build_request_header(tcp_session_t *session) {
    size_t request_header_len = 0;
    int ret = ss2022_tcp_client_build_request_header(
                  &session->ss_client,
                  &session->handshake.target,
                  session->handshake.initial_payload,
                  session->handshake.initial_payload_len,
                  session->handshake.request_header,
                  sizeof(session->handshake.request_header),
                  &request_header_len);
    if (ret != SS2022_OK || request_header_len > UINT16_MAX) {
        LOGERR("[tcp_handshake] build request header failed: %d", ret);
        return false;
    }

    session->handshake.request_header_len = (uint16_t)request_header_len;
    session->handshake.request_header_sent = 0;
    return true;
}

static bool tcp_handshake_start(evloop_t *evloop, tcp_session_t *session) {
    ev_timer_stop(evloop, &session->phase_timer);
    ev_io_stop(evloop, &session->client_watcher);

    if (!tcp_handshake_build_request_header(session)) {
        tcp_session_close(evloop, session, true);
        return false;
    }

    ssize_t tfo_nsend = -1;
    tcp_connect_result_t conn;
    ss_server_t *srv = &g_ss_servers[session->server_idx];
    int server_sockfd = tcp_handshake_connect_server(srv, session->handshake.request_header,
                        session->handshake.request_header_len,
                        &tfo_nsend, &conn);
    if (server_sockfd < 0) {
        tcp_session_close(evloop, session, true);
        return false;
    }

    tcp_session_attach_server(session, server_sockfd, tfo_nsend);
    ev_io_start(evloop, &session->server_watcher);
    ev_timer_init(&session->phase_timer, tcp_handshake_on_timeout, TCP_CONNECT_TIMEOUT_SEC, 0.);
    session->phase_timer.data = session;
    ev_timer_start(evloop, &session->phase_timer);
    if (conn == TCP_CONNECT_CONNECTED) {
        tcp_handshake_on_server_connected(evloop, (struct ev_watcher *)&session->server_watcher, EV_WRITE);
    }
    return true;
}

static bool tcp_handshake_read_initial_payload(evloop_t *evloop, tcp_session_t *session, bool *need_wait) {
    *need_wait = false;

    size_t initial_payload_cap = sizeof(session->handshake.initial_payload);
    while (session->handshake.initial_payload_len < initial_payload_cap) {
        ssize_t nr = recv(session->client_watcher.fd,
                          session->handshake.initial_payload + session->handshake.initial_payload_len,
                          initial_payload_cap - session->handshake.initial_payload_len, 0);
        if (nr < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                *need_wait = (session->handshake.initial_payload_len == 0);
                return true;
            }
            LOGERR("[tcp_handshake] recv initial client payload: %s", strerror(errno));
            tcp_session_close(evloop, session, true);
            return false;
        }
        if (nr == 0) {
            session->handshake.client_eof = true;
            return true;
        }
        session->handshake.initial_payload_len += (size_t)nr;
    }

    return true;
}

static void tcp_log_handshake_initial_payload(const tcp_session_t *session) {
    LOGINF_RAW("[tcp_handshake] initial client payload: %zu bytes%s",
               session->handshake.initial_payload_len,
               session->handshake.client_eof ? ", client EOF" : "");
}

static void tcp_handshake_start_after_initial_payload(evloop_t *evloop, tcp_session_t *session) {
    ev_timer_stop(evloop, &session->phase_timer);
    ev_io_stop(evloop, &session->client_watcher);

    if (session->handshake.initial_payload_len == 0 && session->handshake.client_eof) {
        tcp_session_close(evloop, session, false);
        return;
    }

    IF_VERBOSE if (session->handshake.initial_payload_len > 0) {
        tcp_log_handshake_initial_payload(session);
    }
    (void)tcp_handshake_start(evloop, session);
}

static void tcp_handshake_on_initial_payload_read(evloop_t *evloop, struct ev_watcher *watcher,
        int revents __attribute__((unused))) {
    evio_t *client_watcher = (evio_t *)watcher;
    tcp_session_t *session = tcp_session_from_watcher(client_watcher);
    bool need_wait = false;
    if (!tcp_handshake_read_initial_payload(evloop, session, &need_wait)) {
        return;
    }
    if (need_wait) {
        return;
    }
    tcp_handshake_start_after_initial_payload(evloop, session);
}

static void tcp_handshake_on_initial_payload_timeout(evloop_t *evloop, struct ev_watcher *watcher,
        int revents __attribute__((unused))) {
    tcp_session_t *session = (tcp_session_t *)watcher->data;
    bool need_wait = false;
    if (!tcp_handshake_read_initial_payload(evloop, session, &need_wait)) {
        return;
    }
    IF_VERBOSE if (need_wait) {
        LOGINF_RAW("[tcp_handshake] first client payload wait timed out (%gs), sending handshake without data",
                   TCP_FIRST_PAYLOAD_TIMEOUT_SEC);
    }
    tcp_handshake_start_after_initial_payload(evloop, session);
}

static void tcp_handshake_wait_initial_payload(evloop_t *evloop, tcp_session_t *session) {
    bool need_wait = false;
    if (!tcp_handshake_read_initial_payload(evloop, session, &need_wait)) {
        return;
    }
    if (!need_wait) {
        tcp_handshake_start_after_initial_payload(evloop, session);
        return;
    }

    ev_io_stop(evloop, &session->client_watcher);
    ev_io_init(&session->client_watcher, tcp_handshake_on_initial_payload_read,
               session->client_watcher.fd, EV_READ);
    session->client_watcher.data = session;
    ev_io_start(evloop, &session->client_watcher);

    ev_timer_init(&session->phase_timer, tcp_handshake_on_initial_payload_timeout,
                  TCP_FIRST_PAYLOAD_TIMEOUT_SEC, 0.);
    session->phase_timer.data = session;
    ev_timer_start(evloop, &session->phase_timer);
}

static tcp_session_t *tcp_session_create(int client_sockfd, const ss2022_addr *target,
        const skaddr6_t *client_peer_addr) {
    tcp_session_t *session = mempool_alloc_sized(g_tcp_session_pool, sizeof(*session));
    if (!session) {
        LOGERR("[tcp_session] mempool alloc failed");
        return NULL;
    }
    memset(session, 0, sizeof(*session));
    session->client_watcher.fd = -1;
    session->server_watcher.fd = -1;
    session->handshake.target = *target;
    session->client_peer_addr = *client_peer_addr;

    ss_server_t *srv = server_selector_best_tcp();
    int server_idx = (int)(srv - g_ss_servers);
    session->server_idx = (uint8_t)server_idx;

    ss2022_client_ctx *ctx = tcp_ctx_get(server_idx);
    if (!ctx) {
        LOGERR("[tcp_session] ss2022 ctx init failed");
        mempool_free_sized(g_tcp_session_pool, session, sizeof(*session));
        return NULL;
    }
    int ret = ss2022_tcp_client_init(&session->ss_client, ctx);
    if (ret != SS2022_OK) {
        LOGERR("[tcp_session] ss2022 tcp init failed: %d", ret);
        mempool_free_sized(g_tcp_session_pool, session, sizeof(*session));
        return NULL;
    }

    session->client_watcher.data = session;
    ev_io_init(&session->client_watcher, tcp_relay_on_event, client_sockfd, EV_READ);

    session->prev = NULL;
    session->next = g_tcp_session_head;
    if (session->next) session->next->prev = session;
    g_tcp_session_head = session;
    return session;
}

void tcp_proxy_on_accept(evloop_t *evloop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *accept_watcher = (evio_t *)watcher;
    bool isipv4 = (intptr_t)accept_watcher->data;

    for (int accepted = 0; accepted < TCP_ACCEPT_BATCH; accepted++) {
        skaddr6_t skaddr;
        int client_sockfd = tcp_accept(accept_watcher->fd, (void *)&skaddr, &(socklen_t) {
            sizeof(skaddr)
        });
        if (client_sockfd < 0) {
            if (errno == EINTR) {
                accepted--;
                continue;
            }
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOGERR("[tcp_proxy] accept tcp%s socket: %s", isipv4 ? "4" : "6", strerror(errno));
            }
            break;
        }
        IF_VERBOSE {
            char ipstr[IP6STRLEN];
            portno_t portno;
            parse_socket_addr(&skaddr, ipstr, &portno);
            LOGINF_RAW("[tcp_proxy] source socket address: %s#%hu", ipstr, portno);
        }

        ss2022_addr target;
        if (!tcp_proxy_resolve_target(client_sockfd, isipv4, &target)) {
            tcp_close_by_rst(client_sockfd);
            continue;
        }

        tcp_session_t *session = tcp_session_create(client_sockfd, &target, &skaddr);
        if (!session) {
            tcp_close_by_rst(client_sockfd);
            continue;
        }

        tcp_handshake_wait_initial_payload(evloop, session);
    }
}

void tcp_proxy_close_all_sessions(evloop_t *evloop) {
    LOGINF("[tcp_proxy] cleaning up remaining sessions...");
    tcp_session_t *curr = g_tcp_session_head;
    while (curr) {
        tcp_session_t *next = curr->next;
        tcp_session_close(evloop, curr, false);
        curr = next;
    }
}

void tcp_proxy_ctx_cleanup(void) {
    for (int i = 0; i < SS_MAX_SERVERS; i++) {
        if (g_tcp_ss_ctx_ready[i]) {
            ss2022_client_ctx_free(&g_tcp_ss_ctx[i]);
            g_tcp_ss_ctx_ready[i] = false;
        }
    }
}
