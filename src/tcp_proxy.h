#ifndef TPROXY2SS2022_TCP_PROXY_H
#define TPROXY2SS2022_TCP_PROXY_H

#include <stdbool.h>
#include <stdint.h>

#include "ev_types.h"
#include "netutils.h"
#include "ss2022_client.h"

#define TCP_CONNECT_TIMEOUT_SEC       5.0
#define TCP_FIRST_PAYLOAD_TIMEOUT_SEC 0.5
#define TCP_ACCEPT_BATCH              16

#define TCP_SS2022_SALT_MAX_LEN          32u
#define TCP_SS2022_FIXED_REQ_LEN         11u
#define TCP_SS2022_ATYP_LEN              1u
#define TCP_SS2022_DOMAIN_LEN_FIELD_LEN  1u
#define TCP_SS2022_MAX_DOMAIN_LEN        255u
#define TCP_SS2022_PORT_LEN              2u
#define TCP_SS2022_MAX_ADDR_LEN          (TCP_SS2022_ATYP_LEN + TCP_SS2022_DOMAIN_LEN_FIELD_LEN + \
                                          TCP_SS2022_MAX_DOMAIN_LEN + TCP_SS2022_PORT_LEN)
#define TCP_SS2022_LEN_FIELD_LEN        2u
#define TCP_SS2022_TAG_LEN              16u
#define TCP_SS2022_MAX_PADDING_LEN      900u
#define TCP_SS2022_MAX_PAYLOAD_LEN      65535u
#define TCP_SS2022_RESP_READ_SLACK      64u
#define TCP_SS_PLAIN_BUFSIZ             16384
#define TCP_SS2022_REQ_VAR_DATA_MAX     ((TCP_SS2022_MAX_PADDING_LEN > TCP_SS_PLAIN_BUFSIZ) ? \
                                         TCP_SS2022_MAX_PADDING_LEN : TCP_SS_PLAIN_BUFSIZ)

#define TCP_SS2022_REQ_HDR_OVERHEAD  (TCP_SS2022_SALT_MAX_LEN + TCP_SS2022_FIXED_REQ_LEN + \
                                      TCP_SS2022_TAG_LEN + TCP_SS2022_MAX_ADDR_LEN + \
                                      TCP_SS2022_LEN_FIELD_LEN + TCP_SS2022_TAG_LEN)
#define TCP_SS2022_REQ_HDR_BUFSIZ    (TCP_SS2022_REQ_HDR_OVERHEAD + TCP_SS2022_REQ_VAR_DATA_MAX)
#define TCP_SS_CIPHER_BUFSIZ         (TCP_SS_PLAIN_BUFSIZ + TCP_SS2022_LEN_FIELD_LEN + \
                                      TCP_SS2022_TAG_LEN + TCP_SS2022_TAG_LEN)
#define TCP_SS_RESP_IN_BUFSIZ        (TCP_SS2022_MAX_PAYLOAD_LEN + TCP_SS2022_LEN_FIELD_LEN + \
                                      TCP_SS2022_TAG_LEN + TCP_SS2022_RESP_READ_SLACK)

#define SS2022_LENGTH_CHUNK_LEN      (TCP_SS2022_LEN_FIELD_LEN + TCP_SS2022_TAG_LEN)

typedef struct tcp_session_t {
    evio_t    client_watcher;
    evio_t    server_watcher;
    evtimer_t phase_timer;
    uint8_t   server_idx;
    bool      relay_in_allocated;
    skaddr6_t client_peer_addr;

    union {
        struct {
            uint8_t  request_header[TCP_SS2022_REQ_HDR_BUFSIZ];
            uint8_t  initial_payload[TCP_SS_PLAIN_BUFSIZ];
            ss2022_addr target;
            uint16_t request_header_len;
            uint16_t request_header_sent;
            size_t   initial_payload_len;
            bool     client_eof;
        } handshake;
        struct {
            bool     client_eof;
            bool     server_eof;
            bool     client_shutdown_sent;
            bool     server_shutdown_sent;
            bool     response_header_done;
            uint16_t response_payload_len;
            size_t   response_header_len;

            uint8_t  client_to_server_buf[TCP_SS_CIPHER_BUFSIZ];
            size_t   client_to_server_off;
            size_t   client_to_server_len;

            uint8_t *server_to_client_in;
            size_t   server_to_client_in_head;
            size_t   server_to_client_in_len;
            bool     server_to_client_need_len;

            size_t   server_to_client_out_off;
            size_t   server_to_client_out_len;
            size_t   server_to_client_in_consume;
        } relay;
    };

    ss2022_tcp_client ss_client;

    struct tcp_session_t *prev;
    struct tcp_session_t *next;
} tcp_session_t;

void tcp_proxy_on_accept(evloop_t *evloop, struct ev_watcher *watcher, int revents);
void tcp_proxy_close_all_sessions(evloop_t *evloop);
void tcp_proxy_ctx_cleanup(void);

#endif /* TPROXY2SS2022_TCP_PROXY_H */
