#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ctx.h"
#include "fakedns.h"
#include "fakedns_server.h"
#include "logutils.h"
#include "lrucache.h"
#include "server_selector.h"
#include "tcp_proxy.h"

#define TPROXY2SS2022_VERSION "tproxy2ss2022 v0.1.0 <https://github.com/wyzhou-com/tproxy2ss2022>"

static void* run_event_loop(void *arg);
static void on_async_exit(evloop_t *loop, struct ev_watcher *watcher __attribute__((unused)), int revents __attribute__((unused)));
static void request_worker_exits(void);
static int join_worker_threads(void);

static pthread_mutex_t g_thread_state_lock = PTHREAD_MUTEX_INITIALIZER;

static void print_command_help(void) {
    printf("usage: tproxy2ss2022 <options...>. the existing options are as follows:\n"
           " -g, --server-group <spec>          add a server (repeatable)\n"
           "                                    format: addr:port:method:psk  (IPv6: [addr]:port:method:psk)\n"
           " -b, --listen-addr4 <addr>          listen ipv4 address, default: 127.0.0.1\n"
           " -B, --listen-addr6 <addr>          listen ipv6 address, default: ::1\n"
           " -l, --listen-port <port>           listen port number, default: 54321\n"
           " -S, --tcp-syncnt <cnt>             change the number of tcp syn retransmits\n"
           " -c, --cache-size <size>            udp context cache maxsize, default: 256\n"
           " -o, --udp-timeout <sec>            udp context idle timeout, default/min: 60\n"
           " -j, --thread-nums <num>            number of the worker threads, default: 1\n"
           " -J, --udp-thread-nums <num>        number of udp threads, default: 1\n"
           " -n, --nofile-limit <num>           set nofile limit, may need root privilege\n"
           " -T, --tcp-only                     listen tcp only, aka: disable udp proxy\n"
           " -U, --udp-only                     listen udp only, aka: disable tcp proxy\n"
           " -4, --ipv4-only                    listen ipv4 only, aka: disable ipv6 proxy\n"
           " -6, --ipv6-only                    listen ipv6 only, aka: disable ipv4 proxy\n"
           " -w, --tfo-accept                   enable tcp_fastopen for server socket\n"
           " -W, --tfo-connect                  enable tcp_fastopen for client socket\n"
           " -v, --verbose                      print verbose log, affect performance\n"
           " -V, --version                      print version number and exit\n"
           " -h, --help                         print help information and exit\n"
           "     --enable-fakedns               enable fakedns feature\n"
           "     --fakedns-addr <addr>          fakedns listen address, default: 127.0.0.1\n"
           "     --fakedns-port <port>          fakedns listen port, default: 5353\n"
           "     --fakedns-ip-range <cidr>      fakedns ip range, default: 198.18.0.0/15\n"
           "     --fakedns-cache <path>         fakedns cache file path, support persistence\n"
          );
}

static bool validate_ip_address(const char *ipstr, size_t max_len, int required_family, const char *opt_name) {
    if (strlen(ipstr) + 1 > max_len) {
        printf("[parse_command_args] %s address max length is %zu: %s\n", opt_name, max_len - 1, ipstr);
        return false;
    }
    int family = get_ipstr_family(ipstr);
    if (required_family == -1) {
        if (family == -1) {
            printf("[parse_command_args] invalid %s ip address: %s\n", opt_name, ipstr);
            return false;
        }
    } else if (family != required_family) {
        printf("[parse_command_args] invalid %s %s address: %s\n", opt_name,
               required_family == AF_INET ? "ipv4" : "ipv6", ipstr);
        return false;
    }
    return true;
}

static bool validate_port_number(const char *portstr, portno_t *out_port, const char *opt_name) {
    char *endptr;
    unsigned long port = strtoul(portstr, &endptr, 10);
    if (*endptr != '\0' || port == 0 || port > 65535) {
        printf("[parse_command_args] invalid %s port number: %s\n", opt_name, portstr);
        return false;
    }
    *out_port = (portno_t)port;
    return true;
}

static bool validate_uint_range(const char *valstr, unsigned long max_val, unsigned long *out_val, const char *opt_name) {
    char *endptr;
    unsigned long val = strtoul(valstr, &endptr, 10);
    if (*endptr != '\0' || val == 0 || val > max_val) {
        printf("[parse_command_args] invalid %s: %s\n", opt_name, valstr);
        return false;
    }
    *out_val = val;
    return true;
}

static bool parse_server_group_arg(const char *str) {
    if (g_ss_server_count >= SS_MAX_SERVERS) {
        printf("[parse_command_args] too many -g servers (max %d)\n", SS_MAX_SERVERS);
        return false;
    }
    ss_server_t *out = &g_ss_servers[g_ss_server_count];
    const char *p = str;
    char ipstr[IP6STRLEN];

    if (*p == '[') {
        const char *rb = strchr(p + 1, ']');
        if (!rb || rb[1] != ':') {
            printf("[parse_command_args] invalid -g format (expected [ipv6]:port:method:psk)\n");
            return false;
        }
        size_t len = (size_t)(rb - p - 1);
        if (len == 0 || len >= IP6STRLEN) {
            printf("[parse_command_args] invalid -g IPv6 address length\n");
            return false;
        }
        memcpy(ipstr, p + 1, len);
        ipstr[len] = '\0';
        if (get_ipstr_family(ipstr) != AF_INET6) {
            printf("[parse_command_args] invalid -g IPv6 address: %s\n", ipstr);
            return false;
        }
        p = rb + 2;
    } else {
        int colon_count = 0;
        for (const char *q = p; *q; q++) {
            if (*q == ':')
                colon_count++;
        }
        const char *colon = strchr(p, ':');
        if (!colon) {
            printf("[parse_command_args] invalid -g format (expected addr:port:method:psk)\n");
            return false;
        }
        size_t len = (size_t)(colon - p);
        if (len == 0 || len >= IP6STRLEN) {
            printf("[parse_command_args] invalid -g address length\n");
            return false;
        }
        memcpy(ipstr, p, len);
        ipstr[len] = '\0';
        if (get_ipstr_family(ipstr) == -1) {
            if (colon_count > 3) {
                printf("[parse_command_args] invalid -g IPv6 format (expected [ipv6]:port:method:psk)\n");
                return false;
            }
            printf("[parse_command_args] invalid -g IP address: %s\n", ipstr);
            return false;
        }
        p = colon + 1;
    }

    char *next;
    if (!isdigit((unsigned char)*p)) {
        printf("[parse_command_args] invalid -g port number\n");
        return false;
    }
    unsigned long port = strtoul(p, &next, 10);
    if (*next != ':' || port == 0 || port > 65535) {
        printf("[parse_command_args] invalid -g port number\n");
        return false;
    }
    p = next + 1;

    ss2022_method_t method;
    const char *m128 = "2022-blake3-aes-128-gcm:";
    const char *m256 = "2022-blake3-aes-256-gcm:";
    if (strncmp(p, m128, strlen(m128)) == 0) {
        method = SS2022_AES_128_GCM;
        p += strlen(m128);
    } else if (strncmp(p, m256, strlen(m256)) == 0) {
        method = SS2022_AES_256_GCM;
        p += strlen(m256);
    } else {
        printf("[parse_command_args] invalid -g method\n");
        return false;
    }

    size_t psklen = strlen(p);
    if (psklen == 0 || psklen >= sizeof(out->psk)) {
        printf("[parse_command_args] invalid -g PSK length\n");
        return false;
    }
    ss2022_client_ctx test_ctx;
    if (ss2022_client_ctx_init(&test_ctx, method, p) != SS2022_OK) {
        printf("[parse_command_args] invalid -g PSK for method\n");
        return false;
    }
    ss2022_client_ctx_free(&test_ctx);

    memcpy(out->ipstr, ipstr, strlen(ipstr) + 1);
    out->portno   = (portno_t)port;
    out->method   = method;
    out->salt_len = (method == SS2022_AES_256_GCM) ? 32u : 16u;
    memcpy(out->psk, p, psklen + 1);
    build_socket_addr(get_ipstr_family(ipstr), &out->skaddr, ipstr, out->portno);

    g_ss_server_count++;
    return true;
}

static unsigned long parse_command_args(int argc, char* argv[]) {
    opterr = 0;
    const char *optstr = ":g:b:B:l:S:c:o:j:J:n:TU46wWvVh";
    const struct option options[] = {
        {"server-group",  required_argument,    NULL, 'g'},
        {"listen-addr4",  required_argument,    NULL, 'b'},
        {"listen-addr6",  required_argument,    NULL, 'B'},
        {"listen-port",   required_argument,    NULL, 'l'},
        {"tcp-syncnt",    required_argument,    NULL, 'S'},
        {"cache-size",    required_argument,    NULL, 'c'},
        {"udp-timeout",   required_argument,    NULL, 'o'},
        {"thread-nums",   required_argument,    NULL, 'j'},
        {"udp-thread-nums", required_argument,  NULL, 'J'},
        {"nofile-limit",  required_argument,    NULL, 'n'},
        {"tcp-only",      no_argument,          NULL, 'T'},
        {"udp-only",      no_argument,          NULL, 'U'},
        {"ipv4-only",     no_argument,          NULL, '4'},
        {"ipv6-only",     no_argument,          NULL, '6'},
        {"tfo-accept",    no_argument,          NULL, 'w'},
        {"tfo-connect",   no_argument,          NULL, 'W'},
        {"verbose",       no_argument,          NULL, 'v'},
        {"version",       no_argument,          NULL, 'V'},
        {"help",          no_argument,          NULL, 'h'},
        {"enable-fakedns", no_argument,         NULL, 1001},
        {"fakedns-addr",  required_argument,    NULL, 1002},
        {"fakedns-port",  required_argument,    NULL, 1003},
        {"fakedns-ip-range", required_argument, NULL, 1004},
        {"fakedns-cache", required_argument,    NULL, 1005},
        {NULL,            0,                    NULL,   0},
    };

    int shortopt = -1;
    unsigned long nofile_limit = 0;
    while ((shortopt = getopt_long(argc, argv, optstr, options, NULL)) != -1) {
        switch (shortopt) {
            case 'g':
                if (!parse_server_group_arg(optarg))
                    goto PRINT_HELP_AND_EXIT;
                break;
            case 'b':
                if (!validate_ip_address(optarg, IP4STRLEN, AF_INET, "listen")) {
                    goto PRINT_HELP_AND_EXIT;
                }
                strcpy(g_bind_ipstr4, optarg);
                break;
            case 'B':
                if (!validate_ip_address(optarg, IP6STRLEN, AF_INET6, "listen")) {
                    goto PRINT_HELP_AND_EXIT;
                }
                strcpy(g_bind_ipstr6, optarg);
                break;
            case 'l':
                if (!validate_port_number(optarg, &g_bind_portno, "listen")) {
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 'S': {
                    unsigned long val;
                    if (!validate_uint_range(optarg, 255, &val, "number of syn retransmits")) {
                        goto PRINT_HELP_AND_EXIT;
                    }
                    g_tcp_syncnt_max = (uint8_t)val;
                    break;
                }
            case 'c': {
                    unsigned long val;
                    if (!validate_uint_range(optarg, 65535, &val, "maxsize of udp lrucache")) {
                        goto PRINT_HELP_AND_EXIT;
                    }
                    udp_lrucache_set_maxsize((uint16_t)val);
                    break;
                }
            case 'o': {
                    unsigned long val;
                    if (!validate_uint_range(optarg, 65535, &val, "udp socket idle timeout")) {
                        goto PRINT_HELP_AND_EXIT;
                    }
                    if (val < UDP_IDLE_TIMEOUT_DEFAULT_SEC) {
                        val = UDP_IDLE_TIMEOUT_DEFAULT_SEC;
                    }
                    g_udp_idletimeout_sec = (uint16_t)val;
                    break;
                }
            case 'j': {
                    unsigned long val;
                    if (!validate_uint_range(optarg, MAX_THREADS + 1, &val, "number of worker threads")) {
                        goto PRINT_HELP_AND_EXIT;
                    }
                    g_nthreads = (uint8_t)val;
                    break;
                }
            case 'J': {
                    unsigned long val;
                    if (!validate_uint_range(optarg, MAX_THREADS + 1, &val, "number of udp threads")) {
                        goto PRINT_HELP_AND_EXIT;
                    }
                    g_udp_nthreads = (uint8_t)val;
                    break;
                }
            case 'n': {
                    unsigned long val;
                    if (!validate_uint_range(optarg, ULONG_MAX, &val, "nofile limit")) {
                        goto PRINT_HELP_AND_EXIT;
                    }
                    nofile_limit = val;
                    break;
                }
            case 'T':
                g_options &= (uint16_t)~OPT_ENABLE_UDP;
                break;
            case 'U':
                g_options &= (uint16_t)~OPT_ENABLE_TCP;
                break;
            case '4':
                g_options &= (uint16_t)~OPT_ENABLE_IPV6;
                break;
            case '6':
                g_options &= (uint16_t)~OPT_ENABLE_IPV4;
                break;
            case 'w':
                g_options |= OPT_ENABLE_TFO_ACCEPT;
                break;
            case 'W':
                g_options |= OPT_ENABLE_TFO_CONNECT;
                break;
            case 'v':
                g_verbose = true;
                break;
            case 'V':
                printf(TPROXY2SS2022_VERSION"\n");
                exit(0);
            case 'h':
                print_command_help();
                exit(0);
            case ':':
                printf("[parse_command_args] missing optarg: '%s'\n", argv[optind - 1]);
                goto PRINT_HELP_AND_EXIT;
            case '?':
                if (optopt) {
                    printf("[parse_command_args] unknown option: '-%c'\n", optopt);
                } else {
                    char *longopt = argv[optind - 1];
                    char *equalsign = strchr(longopt, '=');
                    if (equalsign) {
                        *equalsign = 0;
                    }
                    printf("[parse_command_args] unknown option: '%s'\n", longopt);
                }
                goto PRINT_HELP_AND_EXIT;
            case 1001:
                g_options |= OPT_ENABLE_FAKEDNS;
                break;
            case 1002:
                if (!validate_ip_address(optarg, IP4STRLEN, AF_INET, "fakedns")) {
                    goto PRINT_HELP_AND_EXIT;
                }
                strcpy(g_fakedns_ipstr, optarg);
                break;
            case 1003:
                if (!validate_port_number(optarg, &g_fakedns_portno, "fakedns")) {
                    goto PRINT_HELP_AND_EXIT;
                }
                break;
            case 1004:
                strncpy(g_fakedns_cidr, optarg, sizeof(g_fakedns_cidr) - 1);
                g_fakedns_cidr[sizeof(g_fakedns_cidr) - 1] = '\0';
                break;
            case 1005:
                strncpy(g_fakedns_cache_path, optarg, sizeof(g_fakedns_cache_path) - 1);
                g_fakedns_cache_path[sizeof(g_fakedns_cache_path) - 1] = '\0';
                break;
        }
    }

    if (!(g_options & (OPT_ENABLE_TCP | OPT_ENABLE_UDP))) {
        printf("[parse_command_args] both tcp and udp are disabled, nothing to do\n");
        goto PRINT_HELP_AND_EXIT;
    }
    if (!(g_options & (OPT_ENABLE_IPV4 | OPT_ENABLE_IPV6))) {
        printf("[parse_command_args] both ipv4 and ipv6 are disabled, nothing to do\n");
        goto PRINT_HELP_AND_EXIT;
    }

    if (g_ss_server_count == 0) {
        printf("[parse_command_args] at least one -g/--server-group is required\n");
        goto PRINT_HELP_AND_EXIT;
    }

    /* Clamp udp thread count to total thread count */
    if (g_udp_nthreads > g_nthreads) {
        g_udp_nthreads = g_nthreads;
    }
    return nofile_limit;

PRINT_HELP_AND_EXIT:
    print_command_help();
    exit(1);
}

int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN);

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &mask, NULL);

    setvbuf(stdout, NULL, _IOLBF, 256);

    unsigned long nofile_limit = parse_command_args(argc, argv);

    if (nofile_limit) {
        set_nofile_limit(nofile_limit);
    }

    build_socket_addr(AF_INET,  &g_bind_skaddr4, g_bind_ipstr4, g_bind_portno);
    build_socket_addr(AF_INET6, &g_bind_skaddr6, g_bind_ipstr6, g_bind_portno);
    if (g_options & OPT_ENABLE_FAKEDNS) {
        build_socket_addr(AF_INET, &g_fakedns_skaddr, g_fakedns_ipstr, g_fakedns_portno);
    }

    if (g_ss_server_count > 1) {
        for (int i = 0; i < g_ss_server_count; i++) {
            LOGINF("[main] server[%d]: %s#%hu method: %s", i,
                   g_ss_servers[i].ipstr, g_ss_servers[i].portno,
                   g_ss_servers[i].method == SS2022_AES_256_GCM
                   ? "2022-blake3-aes-256-gcm" : "2022-blake3-aes-128-gcm");
        }
    } else {
        LOGINF("[main] server address: %s#%hu", g_ss_servers[0].ipstr, g_ss_servers[0].portno);
        LOGINF("[main] method: %s",
               g_ss_servers[0].method == SS2022_AES_256_GCM ? "2022-blake3-aes-256-gcm" : "2022-blake3-aes-128-gcm");
    }
    if (g_options & OPT_ENABLE_IPV4) {
        LOG_ALWAYS_INF("[main] listen address: %s#%hu", g_bind_ipstr4, g_bind_portno);
    }
    if (g_options & OPT_ENABLE_IPV6) {
        LOG_ALWAYS_INF("[main] listen address: %s#%hu", g_bind_ipstr6, g_bind_portno);
    }
    if (g_tcp_syncnt_max) {
        LOGINF("[main] max number of syn retries: %hhu", g_tcp_syncnt_max);
    }
    if (g_options & OPT_ENABLE_UDP) {
        if (g_options & OPT_ENABLE_FAKEDNS) {
            LOGINF("[main] udp cache capacity: fullcone=%hu symmetric=%hu tproxy=%hu",
                   udp_lrucache_get_fullcone_maxsize(), udp_lrucache_get_symmetric_maxsize(), udp_lrucache_get_tproxy_maxsize());
        } else {
            LOGINF("[main] udp cache capacity: fullcone=%hu tproxy=%hu",
                   udp_lrucache_get_fullcone_maxsize(), udp_lrucache_get_tproxy_maxsize());
        }
        LOGINF("[main] udp session idle timeout: %hu", g_udp_idletimeout_sec);
    }
    LOGINF("[main] number of worker threads: %hhu", g_nthreads);
    if (g_options & OPT_ENABLE_UDP) {
        LOGINF("[main] number of udp threads: %hhu", g_udp_nthreads);
    }
    LOGINF("[main] max file descriptor limit: %zu", get_nofile_limit());
    if (g_options & OPT_ENABLE_TCP) {
        LOGINF("[main] enable tcp transparent proxy");
    }
    if (g_options & OPT_ENABLE_UDP) {
        LOGINF("[main] enable udp transparent proxy");
    }
    if (g_options & OPT_ENABLE_TFO_ACCEPT) {
        LOGINF("[main] enable tfo for tcp server socket");
    }
    if (g_options & OPT_ENABLE_TFO_CONNECT) {
        LOGINF("[main] enable tfo for tcp client socket");
    }
    if (g_options & OPT_ENABLE_FAKEDNS) {
        LOGINF("[main] enable fakedns feature");
        LOG_ALWAYS_INF("[main] fakedns listen address: %s#%hu", g_fakedns_ipstr, g_fakedns_portno);
        fakedns_init(g_fakedns_cidr);
        if (g_fakedns_cache_path[0]) {
            LOGINF("[main] fakedns cache path: %s", g_fakedns_cache_path);
            fakedns_load(g_fakedns_cache_path);
        }
    }
    LOGINF("[main] verbose mode enabled (affects performance)");

    int started_threads = 0;
    int exit_code = 0;
    g_thread_count = g_nthreads - 1;
    for (int i = 0; i < g_thread_count; ++i) {
        g_threads[i].thread_index = i + 1;
        g_threads[i].running = 0;
        g_threads[i].evloop = ev_loop_new(0);
        if (!g_threads[i].evloop) {
            LOGERR("[main] ev_loop_new failed for thread %d", i);
            goto THREAD_INIT_FAIL;
        }
        ev_async_init(&g_threads[i].exit_watcher, on_async_exit);
        ev_async_start(g_threads[i].evloop, &g_threads[i].exit_watcher);

        pthread_mutex_lock(&g_thread_state_lock);
        g_threads[i].running = 1;
        pthread_mutex_unlock(&g_thread_state_lock);
        int ret = pthread_create(&g_threads[i].thread_id, NULL, run_event_loop, &g_threads[i]);
        if (ret != 0) {
            LOGERR("[main] create worker thread: %s", strerror(ret));
            pthread_mutex_lock(&g_thread_state_lock);
            g_threads[i].running = 0;
            pthread_mutex_unlock(&g_thread_state_lock);
            ev_async_stop(g_threads[i].evloop, &g_threads[i].exit_watcher);
            ev_loop_destroy(g_threads[i].evloop);
            g_threads[i].evloop = NULL;
            goto THREAD_INIT_FAIL;
        }
        started_threads++;
    }
    goto THREAD_INIT_OK;

THREAD_INIT_FAIL:
    g_thread_count = started_threads;
    request_worker_exits();
    (void)join_worker_threads();
    exit_code = 1;
    goto MAIN_EXIT;

THREAD_INIT_OK:
    exit_code = (int)(intptr_t)run_event_loop(NULL);  /* main thread passes NULL */
    if (exit_code != 0) {
        request_worker_exits();
    }

    int worker_exit_code = join_worker_threads();
    if (exit_code == 0 && worker_exit_code != 0) {
        exit_code = worker_exit_code;
    }
    LOG_ALWAYS_INF("[main] all worker threads exited");

MAIN_EXIT:
    LOG_ALWAYS_INF("[main] exiting...");
    if ((g_options & OPT_ENABLE_FAKEDNS) && g_fakedns_cache_path[0]) {
        fakedns_save(g_fakedns_cache_path);
    }

    return exit_code;
}

static void on_signal_read(evloop_t *loop, struct ev_watcher *watcher, int revents __attribute__((unused))) {
    evio_t *io_watcher = (evio_t *)watcher;
    struct signalfd_siginfo fdsi;
    ssize_t s = read(io_watcher->fd, &fdsi, sizeof(struct signalfd_siginfo));
    if (s != sizeof(struct signalfd_siginfo)) {
        return;
    }

    LOG_ALWAYS_INF("[on_signal_read] caught signal %d, stopping...", fdsi.ssi_signo);

    request_worker_exits();
    ev_break(loop, EVBREAK_ALL);
}

static void on_async_exit(evloop_t *loop, struct ev_watcher *watcher __attribute__((unused)), int revents __attribute__((unused))) {
    ev_break(loop, EVBREAK_ALL);
}

static void request_worker_exits(void) {
    pthread_mutex_lock(&g_thread_state_lock);
    for (int i = 0; i < g_thread_count; i++) {
        if (g_threads[i].running && g_threads[i].evloop) {
            ev_async_send(g_threads[i].evloop, &g_threads[i].exit_watcher);
        }
    }
    pthread_mutex_unlock(&g_thread_state_lock);
}

static int join_worker_threads(void) {
    int exit_code = 0;
    for (int i = 0; i < g_thread_count; ++i) {
        void *thread_ret = NULL;
        int ret = pthread_join(g_threads[i].thread_id, &thread_ret);
        if (ret != 0) {
            LOGERR("[main] join worker thread %d: %s", i + 1, strerror(ret));
            if (exit_code == 0) exit_code = ret;
        } else if (thread_ret && exit_code == 0) {
            exit_code = (int)(intptr_t)thread_ret;
        }

        if (g_threads[i].evloop) {
            ev_loop_destroy(g_threads[i].evloop);
            g_threads[i].evloop = NULL;
        }
        g_threads[i].running = 0;
    }
    return exit_code;
}

/* Listen endpoint descriptor for unified socket setup/cleanup */
typedef struct {
    int         *sockfd;
    evio_t     **watcher;
    int          family;
    bool         is_tcp;
    const void  *bind_addr;
    socklen_t    bind_len;
    void (*callback)(evloop_t *, struct ev_watcher *, int);
    const char  *tag;
} listen_endpoint_t;

static int setup_listen_endpoint(evloop_t *evloop, const listen_endpoint_t *ep,
                                 bool is_reuse_port, bool is_tfo_accept) {
    int sockfd;
    if (ep->is_tcp) {
        sockfd = new_tcp_listen_sockfd(ep->family, is_reuse_port, is_tfo_accept);
    } else {
        sockfd = new_udp_tprecv_sockfd(ep->family, is_reuse_port);
    }
    if (sockfd < 0) {
        LOGERR("[run_event_loop] create %s socket: %s", ep->tag, strerror(errno));
        return errno;
    }

    if (bind(sockfd, ep->bind_addr, ep->bind_len) < 0) {
        int saved_errno = errno;
        LOGERR("[run_event_loop] bind %s address: %s", ep->tag, strerror(saved_errno));
        close(sockfd);
        return saved_errno;
    }
    if (ep->is_tcp && listen(sockfd, SOMAXCONN) < 0) {
        int saved_errno = errno;
        LOGERR("[run_event_loop] listen %s socket: %s", ep->tag, strerror(saved_errno));
        close(sockfd);
        return saved_errno;
    }

    evio_t *watcher = malloc(sizeof(*watcher));
    if (!watcher) {
        LOGERR("[run_event_loop] malloc %s_watcher failed", ep->tag);
        close(sockfd);
        return ENOMEM;
    }
    watcher->data = (ep->family == AF_INET) ? (void *)(intptr_t)1 : NULL;
    ev_io_init(watcher, ep->callback, sockfd, EV_READ);
    ev_io_start(evloop, watcher);

    *ep->sockfd = sockfd;
    *ep->watcher = watcher;
    return 0;
}

static void cleanup_endpoint(evloop_t *evloop, evio_t **watcher, int *sockfd) {
    if (*watcher) {
        ev_io_stop(evloop, *watcher);
        free(*watcher);
        *watcher = NULL;
    }
    if (*sockfd >= 0) {
        close(*sockfd);
        *sockfd = -1;
    }
}

static void* run_event_loop(void *arg) {
    thread_info_t *thread_info = (thread_info_t *)arg;
    bool is_main_thread = (thread_info == NULL);

    evloop_t *evloop = is_main_thread ? ev_loop_new(0) : thread_info->evloop;

    int exit_code = 0;
    int signalfd_fd = -1;
    evio_t  signal_watcher;
    bool    signal_watcher_started = false;
    evio_t *watchers[4] = {NULL, NULL, NULL, NULL};
    int     sockfds[4]  = {-1, -1, -1, -1};
    evio_t *fakedns_watcher  = NULL;
    int     fakedns_sockfd   = -1;
    bool    selector_started = false;

    /* Initialize memory pools (thread-local) */
    bool fakedns_enabled = (g_options & OPT_ENABLE_FAKEDNS) != 0;
    size_t fullcone_max_blocks = udp_lrucache_get_fullcone_maxsize();
    size_t symmetric_max_blocks = fakedns_enabled ? udp_lrucache_get_symmetric_maxsize() : 0;
    /* LRU add inserts first, then evicts. Pools need one spare block so a full
     * cache can allocate the incoming entry before freeing the victim. */
    size_t session_max_blocks = fullcone_max_blocks + symmetric_max_blocks + 1;
    size_t fullcone_node_max_blocks = fullcone_max_blocks + 1;
    size_t symmetric_node_max_blocks = fakedns_enabled ? symmetric_max_blocks + 1 : 0;

    size_t session_initial_blocks = MEMPOOL_INITIAL_SIZE;
    if (session_initial_blocks > session_max_blocks) {
        session_initial_blocks = session_max_blocks;
    }
    size_t fullcone_node_initial_blocks = MEMPOOL_INITIAL_SIZE;
    if (fullcone_node_initial_blocks > fullcone_node_max_blocks) {
        fullcone_node_initial_blocks = fullcone_node_max_blocks;
    }
    size_t symmetric_node_initial_blocks = fakedns_enabled ? MEMPOOL_INITIAL_SIZE : 0;
    if (symmetric_node_initial_blocks > symmetric_node_max_blocks) {
        symmetric_node_initial_blocks = symmetric_node_max_blocks;
    }

    size_t tproxy_max_blocks = udp_lrucache_get_tproxy_maxsize();
    size_t tproxy_pool_max_blocks = tproxy_max_blocks + UDP_BATCH_SIZE;
    size_t tproxy_initial_blocks = MEMPOOL_INITIAL_SIZE;
    if (tproxy_initial_blocks > tproxy_pool_max_blocks) {
        tproxy_initial_blocks = tproxy_pool_max_blocks;
    }

    int my_thread_index = is_main_thread ? 0 : thread_info->thread_index;
    bool should_handle_udp = (my_thread_index < g_udp_nthreads) && (g_options & OPT_ENABLE_UDP);

    /* All cleanup-state is now initialized; only here is it safe to goto cleanup. */
    if (!evloop) {
        LOGERR("[run_event_loop] ev_loop_new failed for main thread");
        exit_code = 1;
        goto cleanup;
    }

    /* 1. UDP Context Pools */
    if (should_handle_udp) {
        g_udp_session_pool = mempool_create(
                                 sizeof(udp_session_t),
                                 session_initial_blocks,
                                 session_max_blocks
                             );
        if (!g_udp_session_pool) {
            LOGERR("[run_event_loop] failed to create udp session memory pool");
            exit_code = 1;
            goto cleanup;
        }

        g_udp_fullcone_node_pool = mempool_create(
                                       sizeof(udp_fullcone_node_t),
                                       fullcone_node_initial_blocks,
                                       fullcone_node_max_blocks
                                   );
        if (!g_udp_fullcone_node_pool) {
            LOGERR("[run_event_loop] failed to create udp fullcone-node memory pool");
            exit_code = 1;
            goto cleanup;
        }

        if (fakedns_enabled) {
            g_udp_symmetric_node_pool = mempool_create(
                                            sizeof(udp_symmetric_node_t),
                                            symmetric_node_initial_blocks,
                                            symmetric_node_max_blocks
                                        );
            if (!g_udp_symmetric_node_pool) {
                LOGERR("[run_event_loop] failed to create udp symmetric-node memory pool");
                exit_code = 1;
                goto cleanup;
            }
        }

        g_udp_tproxy_pool = mempool_create(
                                sizeof(udp_tproxy_entry_t),
                                tproxy_initial_blocks,
                                tproxy_pool_max_blocks
                            );
        if (!g_udp_tproxy_pool) {
            LOGERR("[run_event_loop] failed to create udp tproxy memory pool");
            exit_code = 1;
            goto cleanup;
        }
    }

    /* 2. TCP Session Pool */
    if (g_options & OPT_ENABLE_TCP) {
        g_tcp_session_pool = mempool_create(
                                 sizeof(tcp_session_t),
                                 64,
                                 65535
                             );
        if (!g_tcp_session_pool) {
            LOGERR("[run_event_loop] failed to create tcp session memory pool");
            exit_code = 1;
            goto cleanup;
        }

        g_tcp_relay_in_pool = mempool_create(
                                  TCP_SS_RESP_IN_BUFSIZ,
                                  0,
                                  65535
                              );
        if (!g_tcp_relay_in_pool) {
            LOGERR("[run_event_loop] failed to create tcp relay input memory pool");
            exit_code = 1;
            goto cleanup;
        }
    }

    if (is_main_thread) {
        sigset_t sig_mask;
        sigemptyset(&sig_mask);
        sigaddset(&sig_mask, SIGINT);
        sigaddset(&sig_mask, SIGTERM);
        signalfd_fd = signalfd(-1, &sig_mask, SFD_NONBLOCK | SFD_CLOEXEC);
        if (signalfd_fd < 0) {
            LOGERR("[run_event_loop] signalfd: %s", strerror(errno));
            exit_code = errno;
            goto cleanup;
        }

        ev_io_init(&signal_watcher, on_signal_read, signalfd_fd, EV_READ);
        ev_io_start(evloop, &signal_watcher);
        signal_watcher_started = true;
    }

    enum { EP_TCP4 = 0, EP_TCP6, EP_UDP4, EP_UDP6, EP_COUNT };

    listen_endpoint_t endpoints[EP_COUNT] = {
        [EP_TCP4] = { &sockfds[0], &watchers[0], AF_INET,  true,  &g_bind_skaddr4, sizeof(skaddr4_t), tcp_proxy_on_accept,  "tcp4" },
        [EP_TCP6] = { &sockfds[1], &watchers[1], AF_INET6, true,  &g_bind_skaddr6, sizeof(skaddr6_t), tcp_proxy_on_accept,  "tcp6" },
        [EP_UDP4] = { &sockfds[2], &watchers[2], AF_INET,  false, &g_bind_skaddr4, sizeof(skaddr4_t), udp_proxy_on_recvmsg, "udp4" },
        [EP_UDP6] = { &sockfds[3], &watchers[3], AF_INET6, false, &g_bind_skaddr6, sizeof(skaddr6_t), udp_proxy_on_recvmsg, "udp6" },
    };

    bool ep_enabled[EP_COUNT] = {
        [EP_TCP4] = (g_options & OPT_ENABLE_TCP) && (g_options & OPT_ENABLE_IPV4),
        [EP_TCP6] = (g_options & OPT_ENABLE_TCP) && (g_options & OPT_ENABLE_IPV6),
        [EP_UDP4] = should_handle_udp && (g_options & OPT_ENABLE_IPV4),
        [EP_UDP6] = should_handle_udp && (g_options & OPT_ENABLE_IPV6),
    };

    bool is_tfo_accept = g_options & OPT_ENABLE_TFO_ACCEPT;
    bool is_tcp_reuse_port = g_nthreads > 1;
    bool is_udp_reuse_port = g_udp_nthreads > 1;

    for (int i = 0; i < EP_COUNT; i++) {
        if (!ep_enabled[i]) continue;
        bool reuse = endpoints[i].is_tcp ? is_tcp_reuse_port : is_udp_reuse_port;
        exit_code = setup_listen_endpoint(evloop, &endpoints[i], reuse, is_tfo_accept);
        if (exit_code) goto cleanup;
    }

    if ((g_options & OPT_ENABLE_FAKEDNS) && is_main_thread) {
        fakedns_sockfd = new_udp_normal_sockfd(AF_INET);
        if (fakedns_sockfd < 0) {
            exit_code = errno;
            goto cleanup;
        }
        if (bind(fakedns_sockfd, (void *)&g_fakedns_skaddr, sizeof(skaddr4_t)) < 0) {
            LOGERR("[run_event_loop] bind fakedns address: %s", strerror(errno));
            exit_code = errno;
            goto cleanup;
        }
        fakedns_watcher = malloc(sizeof(*fakedns_watcher));
        if (!fakedns_watcher) {
            LOGERR("[run_event_loop] malloc fakedns_watcher failed");
            exit_code = ENOMEM;
            goto cleanup;
        }
        ev_io_init(fakedns_watcher, fakedns_server_recv_cb, fakedns_sockfd, EV_READ);
        ev_io_start(evloop, fakedns_watcher);
    }

    if (should_handle_udp) {
        udp_proxy_thread_init();
        udp_proxy_gc_start(evloop);
    }

    if (is_main_thread && g_ss_server_count > 1) {
        server_selector_start(evloop);
        selector_started = true;
    }

    ev_run(evloop, 0);

cleanup:
    if (selector_started)
        server_selector_stop(evloop);
    for (int i = 0; i < EP_COUNT; i++) {
        cleanup_endpoint(evloop, &watchers[i], &sockfds[i]);
    }
    cleanup_endpoint(evloop, &fakedns_watcher, &fakedns_sockfd);
    if (signal_watcher_started) {
        ev_io_stop(evloop, &signal_watcher);
    }
    if (signalfd_fd >= 0) {
        close(signalfd_fd);
    }
    if (!is_main_thread) {
        ev_async_stop(evloop, &thread_info->exit_watcher);
    }

    if (evloop && should_handle_udp) {
        udp_proxy_close_all_sessions(evloop);
        udp_proxy_ctx_cleanup();
    }
    if (evloop && (g_options & OPT_ENABLE_TCP)) {
        tcp_proxy_close_all_sessions(evloop);
        tcp_proxy_ctx_cleanup();
    }

    if (g_udp_session_pool) {
        size_t leaks = mempool_destroy(g_udp_session_pool);
        if (leaks > 0) {
            LOGERR("[run_event_loop] udp session pool leaks: %zu", leaks);
        }
        g_udp_session_pool = NULL;
    }
    if (g_udp_fullcone_node_pool) {
        size_t leaks = mempool_destroy(g_udp_fullcone_node_pool);
        if (leaks > 0) {
            LOGERR("[run_event_loop] udp fullcone-node pool leaks: %zu", leaks);
        }
        g_udp_fullcone_node_pool = NULL;
    }
    if (g_udp_symmetric_node_pool) {
        size_t leaks = mempool_destroy(g_udp_symmetric_node_pool);
        if (leaks > 0) {
            LOGERR("[run_event_loop] udp symmetric-node pool leaks: %zu", leaks);
        }
        g_udp_symmetric_node_pool = NULL;
    }
    if (g_udp_tproxy_pool) {
        size_t leaks = mempool_destroy(g_udp_tproxy_pool);
        if (leaks > 0) {
            LOGERR("[run_event_loop] udp tproxy pool leaks: %zu", leaks);
        }
        g_udp_tproxy_pool = NULL;
    }
    if (g_tcp_session_pool) {
        size_t leaks = mempool_destroy(g_tcp_session_pool);
        if (leaks > 0) {
            LOGERR("[run_event_loop] tcp session pool leaks: %zu", leaks);
        }
        g_tcp_session_pool = NULL;
    }
    if (g_tcp_relay_in_pool) {
        size_t leaks = mempool_destroy(g_tcp_relay_in_pool);
        if (leaks > 0) {
            LOGERR("[run_event_loop] tcp relay input pool leaks: %zu", leaks);
        }
        g_tcp_relay_in_pool = NULL;
    }

    if (evloop && is_main_thread) {
        ev_loop_destroy(evloop);
    }

    if (!is_main_thread) {
        pthread_mutex_lock(&g_thread_state_lock);
        thread_info->running = 0;
        pthread_mutex_unlock(&g_thread_state_lock);
    }

    if (exit_code != 0) {
        if (!is_main_thread) {
            LOGERR("[run_event_loop] worker thread failed (code=%d), requesting shutdown", exit_code);
            kill(getpid(), SIGTERM);
        }
    }
    return (void *)(intptr_t)exit_code;
}
