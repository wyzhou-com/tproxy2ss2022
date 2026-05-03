#pragma once

/* =========================================================================
 * System Environment Facts (Linux/POSIX Strict Explicit Injection)
 * Bypassing Autotools completely.
 * ========================================================================= */
#define HAVE_SYS_EPOLL_H 1
#define HAVE_SYS_EVENTFD_H 1
#define HAVE_SYS_TIMERFD_H 1
#define HAVE_SYS_SELECT_H 1
#define HAVE_POLL_H 1
#define HAVE_UNISTD_H 1
#define HAVE_SYS_STAT_H 1
#define HAVE_SYS_TIME_H 1

#define HAVE_CLOCK_SYSCALL 1
#define HAVE_CLOCK_GETTIME 1
#define HAVE_NANOSLEEP 1
#define HAVE_EPOLL_CTL 1
#define HAVE_EVENTFD 1
#define HAVE_TIMERFD_CREATE 1
#define HAVE_INOTIFY_INIT 1

#define HAVE_STDINT_H 1
#define HAVE_INTTYPES_H 1

/* =========================================================================
 * libev Micro-Architecture Configuration
 * ========================================================================= */
#define EV_STANDALONE 1         /* manual configuration */
#define EV_COMPAT3 0            /* strip backwards compatibility */
#define EV_VERIFY 0             /* disable internal assertions */
#define EV_USE_FLOOR 1          /* use native math floor */

/* --- Concurrency & Locks Elision (Shared-Nothing Architecture) --- */
#define EV_NO_SMP 1
#define EV_NO_THREADS 1

/* --- Watcher Subsystem Pruning --- */
#define EV_PERIODIC_ENABLE 0
#define EV_SIGNAL_ENABLE 0      /* Handled natively by signalfd in main.c */
#define EV_CHILD_ENABLE 0
#define EV_STAT_ENABLE 0
#define EV_IDLE_ENABLE 0
#define EV_PREPARE_ENABLE 0
#define EV_CHECK_ENABLE 0
#define EV_EMBED_ENABLE 0
#define EV_FORK_ENABLE 0
#define EV_CLEANUP_ENABLE 0
#define EV_ASYNC_ENABLE 1       /* Required for worker thread exit notification */

/* --- High-Performance Epoll Backend Enforcement --- */
#define EV_USE_SELECT 0
#define EV_USE_POLL 0
#define EV_USE_EPOLL 1
#define EV_USE_LINUXAIO 0
#define EV_USE_IOURING 0
#define EV_USE_KQUEUE 0
#define EV_USE_PORT 0
#define EV_USE_INOTIFY 0

/* --- Hardware Offloading for Async & Timers --- */
#define EV_USE_EVENTFD 1
#define EV_USE_TIMERFD 1

/* --- Scheduler Priority Collapse O(1) --- */
#define EV_MINPRI 0
#define EV_MAXPRI 0
