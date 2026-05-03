/* src/ev_types.h — libev configuration overrides and application-layer type aliases.
 *
 * This header MUST be included before any direct use of libev types.
 * It pre-defines macros that ev.h honors via #ifndef guards, ensuring
 * all watcher structs use a uniform callback signature and layout.
 */
#ifndef TPROXY2SS2022_EV_TYPES_H
#define TPROXY2SS2022_EV_TYPES_H

/* Forward declarations required by EV_CB_DECLARE below */
struct ev_loop;
struct ev_watcher;

/*
 * Override the per-watcher callback field type BEFORE ev.h is included.
 * Default libev declares:  void (*cb)(loop, struct <watcher_type> *w, revents)
 * Our override unifies to: void (*cb)(loop, struct ev_watcher     *w, revents)
 *
 * This eliminates undefined behavior from calling a function through a
 * pointer whose declared parameter type differs from the actual definition.
 * ev.h guards this with #ifndef, so our definition takes precedence.
 */
#ifndef EV_CB_DECLARE
#   define EV_CB_DECLARE(type) void (*cb)(struct ev_loop *loop, struct ev_watcher *w, int revents);
#endif /* EV_CB_DECLARE */

/*
 * Collapse the priority range to a single level (0).
 * This removes the `int priority` field from every watcher struct,
 * saving 4 bytes per watcher and simplifying the pending-queue to a
 * single tier.  ev.h guards these with #ifndef.
 *
 * IMPORTANT: libev_config.h (used only for libev/ev.o via -include)
 * must define identical values to maintain ABI consistency.
 */
#ifndef EV_MINPRI
#define EV_MINPRI 0
#endif /* EV_MINPRI */
#ifndef EV_MAXPRI
#define EV_MAXPRI 0
#endif /* EV_MAXPRI */

#include "../libev/ev.h"

/* Suppress -Wunused-value from libev's priority-collapse no-op macros.
 * When EV_MINPRI == EV_MAXPRI, ev.h defines ev_set_priority as a comma
 * expression ((ev), (pri)) that discards both operands; casting to void
 * silences the warning without changing semantics. */
#if EV_MINPRI == EV_MAXPRI
# undef ev_set_priority
# define ev_set_priority(ev,pri) ((void)(ev), (void)(pri))
# undef ev_priority
# define ev_priority(ev)         ((void)(ev), EV_MINPRI)
#endif /* EV_MINPRI == EV_MAXPRI */

/* --- Application-layer type aliases for libev --- */
typedef struct ev_loop  evloop_t;
typedef struct ev_io    evio_t;
typedef struct ev_timer evtimer_t;

/* Unified callback signatures matching the overridden EV_CB_DECLARE */
typedef void (*evio_cb_t)(evloop_t *evloop, struct ev_watcher *watcher, int revents);
typedef void (*evtimer_cb_t)(evloop_t *evloop, struct ev_watcher *watcher, int revents);

#endif /* TPROXY2SS2022_EV_TYPES_H */
