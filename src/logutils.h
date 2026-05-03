#ifndef TPROXY2SS2022_LOGUTILS_H
#define TPROXY2SS2022_LOGUTILS_H

#include <stdbool.h>

extern bool g_verbose;
#define IF_VERBOSE if (unlikely(g_verbose))

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif /* unlikely */

typedef enum {
    LOG_LEVEL_INF,
    LOG_LEVEL_ERR,
    LOG_LEVEL_WAR,
    LOG_LEVEL_ALWAYS_INF  /* Always output, behaves like old LOG_ALWAYS_INF */
} log_level_t;

void log_print(log_level_t level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

/* Optimized logging macros */
/* Normal INFO logs: Checked against g_verbose with unlikely hint to minimize impact on hot paths */
#define LOGINF(fmt, ...) \
    do { \
        if (unlikely(g_verbose)) { \
            log_print(LOG_LEVEL_INF, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

/* No verbose guard — use ONLY inside IF_VERBOSE { } blocks to avoid double-checking g_verbose */
#define LOGINF_RAW(fmt, ...) log_print(LOG_LEVEL_INF, fmt, ##__VA_ARGS__)

#define LOGERR(fmt, ...) log_print(LOG_LEVEL_ERR, fmt, ##__VA_ARGS__)
#define LOGWAR(fmt, ...) log_print(LOG_LEVEL_WAR, fmt, ##__VA_ARGS__)
#define LOG_ALWAYS_INF(fmt, ...) log_print(LOG_LEVEL_ALWAYS_INF, fmt, ##__VA_ARGS__)

#endif /* TPROXY2SS2022_LOGUTILS_H */
