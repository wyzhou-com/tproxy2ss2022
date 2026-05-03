#include "fakedns_server.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>

#include "fakedns.h"
#include "logutils.h"

#define FAKEDNS_BATCH_SIZE 16
#define FAKEDNS_MAX_UDP_SIZE 512

typedef struct {
    uint8_t buffer[FAKEDNS_MAX_UDP_SIZE];
} fakedns_packet_t;

static fakedns_packet_t g_fakedns_batch_packets[FAKEDNS_BATCH_SIZE];

/* Static buffers and headers — initialized once, reused across callbacks */
static struct mmsghdr s_msgs[FAKEDNS_BATCH_SIZE];
static struct iovec   s_iovecs[FAKEDNS_BATCH_SIZE];
static struct sockaddr_storage s_addrs[FAKEDNS_BATCH_SIZE];
static bool s_initialized = false;

void fakedns_server_recv_cb(evloop_t *evloop, struct ev_watcher *watcher, int revents) {
    evio_t *io_watcher = (evio_t *)watcher;
    (void)evloop;
    (void)revents;

    if (!s_initialized) {
        for (int i = 0; i < FAKEDNS_BATCH_SIZE; ++i) {
            s_iovecs[i].iov_base = g_fakedns_batch_packets[i].buffer;
            s_iovecs[i].iov_len = FAKEDNS_MAX_UDP_SIZE;
            s_msgs[i].msg_hdr.msg_name = &s_addrs[i];
            s_msgs[i].msg_hdr.msg_iov = &s_iovecs[i];
            s_msgs[i].msg_hdr.msg_iovlen = 1;
            s_msgs[i].msg_hdr.msg_control = NULL;
            s_msgs[i].msg_hdr.msg_controllen = 0;
            s_msgs[i].msg_hdr.msg_flags = 0;
        }
        s_initialized = true;
    }

    /* Reset fields modified by the previous send/recv cycle */
    for (int i = 0; i < FAKEDNS_BATCH_SIZE; ++i) {
        s_msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
        s_iovecs[i].iov_len = FAKEDNS_MAX_UDP_SIZE; /* send path sets this to nresp */
    }

    int nrecv = recvmmsg(io_watcher->fd, s_msgs, FAKEDNS_BATCH_SIZE, 0, NULL);
    if (nrecv < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOGERR("[fakedns_server_recv_cb] recvmmsg: %s", strerror(errno));
        }
        return;
    }

    struct mmsghdr send_msgs[FAKEDNS_BATCH_SIZE];
    int send_count = 0;

    for (int i = 0; i < nrecv; ++i) {
        size_t len = s_msgs[i].msg_len;
        uint8_t *buf = g_fakedns_batch_packets[i].buffer;

        // Process query IN-PLACE
        size_t nresp = fakedns_process_query(buf, len, buf, FAKEDNS_MAX_UDP_SIZE);

        if (nresp > 0) {
            send_msgs[send_count].msg_hdr.msg_name = s_msgs[i].msg_hdr.msg_name;
            send_msgs[send_count].msg_hdr.msg_namelen = s_msgs[i].msg_hdr.msg_namelen;
            send_msgs[send_count].msg_hdr.msg_iov = s_msgs[i].msg_hdr.msg_iov;

            // Adjust length for the response
            send_msgs[send_count].msg_hdr.msg_iov[0].iov_len = nresp;

            send_msgs[send_count].msg_hdr.msg_iovlen = 1;
            send_msgs[send_count].msg_hdr.msg_control = NULL;
            send_msgs[send_count].msg_hdr.msg_controllen = 0;
            send_msgs[send_count].msg_hdr.msg_flags = 0;

            send_count++;
        }
    }

    if (send_count > 0) {
        int sent = sendmmsg(io_watcher->fd, send_msgs, (unsigned int)send_count, 0);
        if (sent < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                LOGERR("[fakedns_server_recv_cb] sendmmsg: %s", strerror(errno));
            }
        } else if (sent < send_count) {
            LOGWAR("[fakedns_server_recv_cb] partial send %d/%d, %d responses dropped",
                   sent, send_count, send_count - sent);
        }
    }
}
