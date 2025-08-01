/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief Top level header file for BBS
 *
 */

/* BBS compiler options */
#ifndef BBS_TEST_FRAMEWORK
#define DEBUG_FD_LEAKS 1
#define REDIRECT_LIBC_ALLOC 1
#endif

/* Compiler directives */

/* asprintf, etc. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#ifndef BBS_TEST_FRAMEWORK
#include "include/lock.h"
#endif

/* Universal includes */
#include <errno.h>
#include <assert.h>
#include <stddef.h> /* use NULL */
#include <unistd.h>
#include <time.h> /* time_t cannot be forward declared, since it's a typedef */

#include <stdlib.h>
#include <string.h>
#include <stdio.h> /* FILE* cannot be forward declared, since it's a typedef */

#include <sys/stat.h>

#if defined(DEBUG_FD_LEAKS) && DEBUG_FD_LEAKS == 1
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#else
#include <stdarg.h>
#endif /* DEBUG_FD_LEAKS */

#include "include/logger.h"

/* Global definitions */
#include "include/definitions.h"

#define BBS_COPYRIGHT STRCAT("Copyright 2023 ", BBS_AUTHOR)
#define BBS_COPYRIGHT_SHORT STRCAT("(C) 2023 ", BBS_AUTHOR)
#define BBS_VERSION XSTR(BBS_MAJOR_VERSION) "." XSTR(BBS_MINOR_VERSION) "." XSTR(BBS_PATCH_VERSION)

#define SEMVER_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))

/* Needed (only) by bbs.c and logger.c */
#define BBS_LOG_DIR DIRCAT("/var/log", BBS_NAME)
#define MAX_VERBOSE 10
#define MAX_DEBUG 10

/* Used only by config.c */
#define BBS_CONFIG_DIR "/etc/lbbs"

/* Used only by bbs.c and test/test.c */
#if defined(BBS_IN_CORE) || defined(TEST_IN_CORE)
#define BBS_RUN_DIR DIRCAT("/var/run", BBS_NAME)
#define BBS_PID_FILE DIRCAT(BBS_RUN_DIR, "bbs.pid")
#endif

/* Used by mod_sysop and test_sysop */
#define BBS_SYSOP_SOCKET DIRCAT(DIRCAT("/var/run", BBS_NAME), "sysop.sock")

/* Global undeclarations */
/* Forbid usage of unsafe functions */
#if defined(BBS_IN_CORE)
#define gets(s) Do_not_use_gets__use_fgets
#define strcat(dst, src) Do_not_use_strcat__use_strncat
#define strncat Do_not_use_strncat__use_bbs_append_string
#define strlcat Do_not_use_strlcat__use_bbs_append_string
#define sprintf(fmt, ...) Do_not_use_sprintf__use_snprintf
#define vsprintf(s, fmt, arg) Do_not_use_vsprintf__use_vsnprintf
/* Force usage of poll instead of the deprecated and unsafe select */
#ifdef __GLIBC__
#define select(nfds, readfds, writefds, exceptfds, timeout) Do_not_use_select__use_poll
#endif
/* Force usage of thread-safe functions */
#define localtime(a) Do_not_use_localtime__use_localtime_r
#define gmtime(a) Do_not_use_gmtime__use_gmtime_r
#define ctime(a) Do_not_use_ctime__use_ctime_r
#define ptsname(fd) Do_not_use_ptsname__use_ptsname_r
#define strncpy(dest, src, size) Do_not_use_strncpy__use_safe_strncpy
/* Prohibit direct usage of dangerous functions */
#define pthread_cancel(t) Do_not_use_pthread_cancel__use_bbs_pthread_cancel_kill

#ifndef BBS_MAIN_FILE
/* Allow printf only in bbs.c */
#define printf(...) Do_not_use_printf__use_bbs_printf
#endif
#define dprintf(fd, ...) Do_not_use_dprintf__use_bbs_dprintf
#ifndef BBS_PTHREAD_WRAPPER_FILE
/* Force nonusage of insufficiently portable functions */
#define gettid() Do_not_use_gettid__use_bbs_gettid
/* Force usage of BBS thread wrappers */
#ifdef __linux__
#define pthread_create(a, b, c, d) Do_not_use_pthread_create__use_bbs_pthread_create
#define pthread_create_detached(a, b, c, d) Do_not_use_pthread_create__use_bbs_pthread_create_detached->fail(a, b, c, d)
#define pthread_join(a, b) Do_not_use_pthread_join__use_bbs_pthread_join
#endif /* __linux__ */
#endif /* BBS_MAIN_FILE */
#endif /* BBS_IN_CORE */

/* BUGBUG FIXME XXX ^^^ For some reason adding ->fail(a, b, c, d) etc. on the end
 * (which does force an undeclared function warning) causes an expected = , ; asm or __attribute__ before -> token ???
 *
 * Without forcing a compilation fail using ->fail, the "function defined but not used" will kick in first,
 * which does stop compilation but is confusing because the error is not quite sensible
 * In fact this can end up being an unresolved symbol for core files and shared object modules alike, so this needs to be fixed!!!
 */

#ifndef BBS_TEST_FRAMEWORK
#include "include/fd.h"
#endif

/*!
 * \brief Release as much free memory from the top of the heap as possible
 * \return Number of bytes released by the kernel
 */
size_t bbs_malloc_trim(void);

#if defined(REDIRECT_LIBC_ALLOC) && REDIRECT_LIBC_ALLOC == 1
#define malloc(size) __bbs_malloc(size, __FILE__, __LINE__, __func__)
#define calloc(nmemb, size) __bbs_calloc(nmemb, size, __FILE__, __LINE__, __func__)
#define realloc(ptr, size) __bbs_realloc(ptr, size, __FILE__, __LINE__, __func__)
#define strdup(s) __bbs_strdup(s, __FILE__, __LINE__, __func__)
#define strndup(s, n) __bbs_strndup(s, n, __FILE__, __LINE__, __func__)
#define vasprintf(strp, format, ap) __bbs_vasprintf(strp, format, ap, __FILE__, __LINE__, __func__)
#define asprintf(strp, format, ...) __bbs_asprintf(__FILE__, __LINE__, __func__, strp, format, ## __VA_ARGS__)

/*!
 * \brief Helper function to malloc + memcpy
 * \param ptr Buffer to copy to newly allocated memory
 * \param size Number of bytes to copy.
 * \return NULL on failure
 * \return Allocated buffer which contains size bytes starting at ptr, followed by a terminating NUL byte (useful for strings)
 */
#define memdup(ptr, size) __bbs_memdup(ptr, size, __FILE__, __LINE__, __func__)

void *__bbs_malloc(size_t size, const char *file, int line, const char *func) __attribute__((malloc));
void *__bbs_calloc(size_t nmemb, size_t size, const char *file, int line, const char *func) __attribute__((malloc));
void *__bbs_realloc(void *ptr, size_t size, const char *file, int line, const char *func) __attribute__((malloc));
void *__bbs_strdup(const char *s, const char *file, int line, const char *func) __attribute__((malloc));
void *__bbs_strndup(const char *s, size_t n, const char *file, int line, const char *func) __attribute__((malloc));
void *__bbs_memdup(void *ptr, size_t size, const char *file, int line, const char *func) __attribute__((malloc));
int __attribute__ ((format (gnu_printf, 2, 0))) __bbs_vasprintf(char **strp, const char *fmt, va_list ap, const char *file, int line, const char *func);
int __attribute__ ((format (gnu_printf, 5, 6))) __bbs_asprintf(const char *file, int line, const char *func, char **strp, const char *fmt, ...);
#endif /* REDIRECT_LIBC_ALLOC */

#define ALLOC_FAILURE(x) (unlikely(x == NULL))
#define ALLOC_SUCCESS(x) (likely(x != NULL))

/* Convenience macros */
#define QUOTE(...) #__VA_ARGS__
#define STR(s) #s
#define XSTR(s) STR(s)
#define DIRCAT(a, b) a "/" b
#define STRCAT(a, b) a b
#define ARRAY_LEN(a) (size_t) (sizeof(a) / sizeof(a[0]))

#define likely(x) __builtin_expect((x),1)
#define unlikely(x) __builtin_expect((x),0)

/*!
 * \brief strlen for constant strings
 * \note sizeof is resolved at compile time, that's why it works
 * \see https://stackoverflow.com/a/5022113
 */
#define STRLEN(s) ( (sizeof(s)/sizeof(s[0])) - sizeof(s[0]) )

#define ENSURE_STRLEN(s) if (strlen_zero(s)) { return -1; }

/*! \brief Faster than strncat, since we store our position between calls, but maintain its safety */
#define SAFE_FAST_COND_APPEND(bufstart, bufsize, bufpos, buflen, cond, fmt, ...) \
	if (buflen > 0 && (cond)) { \
		int _bytes = snprintf(bufpos, (size_t) buflen, bufpos == bufstart ? fmt : " " fmt, ## __VA_ARGS__); \
		bufpos += (typeof((buflen))) _bytes; \
		buflen -= (typeof((buflen))) _bytes; \
		if ((int) buflen <= 0) { \
			bbs_warning("Buffer truncation (%lu)\n", (size_t) buflen); \
			*(bufstart + bufsize - 1) = '\0';  \
			buflen = 0; \
		} \
	}

/*! \brief Same as SAFE_FAST_COND_APPEND, but don't automatically append a space first */
#define SAFE_FAST_COND_APPEND_NOSPACE(bufstart, bufsize, bufpos, buflen, cond, fmt, ...) \
	if (buflen > 0 && (cond)) { \
		int _bytes = snprintf(bufpos, (size_t) buflen, fmt, ## __VA_ARGS__); \
		bufpos += (typeof((buflen))) _bytes; \
		buflen -= (typeof((buflen))) _bytes; \
		if ((int) buflen <= 0) { \
			bbs_warning("Buffer truncation (%lu)\n", (size_t) buflen); \
			*(bufstart + bufsize - 1) = '\0';  \
			buflen = 0; \
		} \
	}

#define SAFE_FAST_BUF_INIT(buf, size, bufvar, lenvar) \
	bufvar = buf; \
	lenvar = size; \
	buf[0] = '\0';

#define SAFE_FAST_APPEND(bufstart, bufsize, bufpos, buflen, fmt, ...) SAFE_FAST_COND_APPEND(bufstart, bufsize, bufpos, buflen, 1, fmt, ## __VA_ARGS__)

#define SAFE_FAST_APPEND_NOSPACE(bufstart, bufsize, bufpos, buflen, fmt, ...) SAFE_FAST_COND_APPEND_NOSPACE(bufstart, bufsize, bufpos, buflen, 1, fmt, ## __VA_ARGS__)

#undef MIN
#define MIN(a, b) ({ typeof(a) __a = (a); typeof(b) __b = (b); ((__a > __b) ? __b : __a);})
#undef MAX
#define MAX(a, b) ({ typeof(a) __a = (a); typeof(b) __b = (b); ((__a < __b) ? __b : __a);})

#define bbs_rand(min, max) (min + rand() % (max + 1 - min))
#define bbs_maxrand(max) bbs_rand(0, max)

#define SET_BITFIELD(field, value) field = (unsigned) (value & 0x1)
#define SET_BITFIELD2(field, value) field = (unsigned) (value & 0x3)

/*!
 * \brief Fill in the appropriate bytes of a flexible struct member for a constant string
 * \param var struct
 * \param dataptr A pointer that is initialized (before any calls to this macro) to the flexible struct member
 * \param field The name of the struct field to set.
 * \param name The name of the field and the name of the variable to copy (must be named the same). Variable must not be uninitialized.
 * \param len The number of bytes required to store this variable (strlen + 1)
 */
#define SET_FSM_STRING_VAR(var, dataptr, field, name, len) \
		if (!strlen_zero(name)) { \
			strcpy(dataptr, name); \
			var->field = dataptr; \
			dataptr += len; \
		}

/*! \brief Get number of bytes needed to store a string */
#define STRING_ALLOC_SIZE(s) (!strlen_zero(s) ? strlen(s) + 1 : 0)

#define STARTS_WITH(s, start) (!strncasecmp(s, start, STRLEN(start)))

/*! \brief printf format specifier for time_t variables */
#define TIME_T_FMT "ld"

/*!
 * \brief Check if an argument is within bounds
 * \param x Argument
 * \param min
 * \param max
 */
#define IN_BOUNDS(x, min, max) (x >= min && x <= max)

#define ARRAY_IN_BOUNDS(x, arr) (x >= 0 && x <= (int) (ARRAY_LEN(arr) - 1))

#define SIZE_MB(bytes) (bytes * 1024 * 1024)
#define SIZE_KB(bytes) (bytes * 1024)

/*! \brief Number of ms in given seconds */
#define SEC_MS(x) (1000 * (x))

/*! \brief Number of ms in given minutes */
#define MIN_MS(x) (60000 * (x))

/*! \brief Used to discard unused arguments, since we compile with -Wunused-args */
#define UNUSED(x) (void)(x)

/*! \brief Return -1 if a function returns a negative value */
#define NEG_RETURN(x) if ((x) < 0) { return -1; }

/*! \brief Break if a function returns a negative value */
#define NEG_BREAK(x) if ((x) < 0) { break; }

/*! \brief Break if a function returns a non-positive value */
#define NONPOS_BREAK(x) if ((x) <= 0) { break; }

/*! \brief Return -1 if a value is NULL */
#define NULL_RETURN(x) if (!(x)) { return -1; }

/*! \brief Return -1 if a function returns a non-positive value */
#define NONPOS_RETURN(x) if ((x) <= 0) { return -1; }

/*! \brief Return -1 if a function returns a non-zero value */
#define NONZERO_NEGRETURN(x) if ((x) != 0) { return -1; }

/*!
 * \brief Return x if a function returns a non-zero value
 * \warning Do not directly call this with a function call, since this a macro.
 *          That will result in running the function twice!
 *          Instead, you must save the return value locally and then
 *          call this macro with that return value.
 */
#define NONZERO_RETURN(x) if ((x) != 0) { return x; }

/*! \brief Whether currently running as root */
#define is_root() (geteuid() == 0)

#define strdup_if(x) (x ? strdup(x) : NULL)

#define REPLACE(var, val) free_if(var); var = strdup(val);

#define FREE(x) free(x); x = NULL;

/*! \note In theory, free(NULL) is okay, but using this macro also documents that x could be NULL */
#define free_if(x) if (x) { FREE(x); }

#define CLOSE(x) close(x); x = -1;

#define close_if(x) if (x != -1) { CLOSE(x); }

#define PIPE_CLOSE(x) close_if(x[0]); close_if(x[1]);

/*! \brief If char * is NULL or empty string */
#define strlen_zero(s) ((!s || *s == '\0'))

/*! \brief If stack char buffer is empty */
#define s_strlen_zero(s) ((*s == '\0'))

#define swrite(fd, s) write(fd, s, strlen(s))
#define SWRITE(fd, s) write(fd, s, STRLEN(s))

#define NODE_SWRITE(node, fd, s) bbs_node_fd_write(node, fd, s, STRLEN(s))

/*! \brief Terminate str at first occurence of c, if it exists */
#define bbs_strterm(str, c) { \
	char *strterm_str = strchr(str, c); \
	if (strterm_str) { \
		*strterm_str = '\0'; \
	} \
}

/*! \brief Terminate str at last occurence of c, if it exists */
#define bbs_strrterm(str, c) { \
	char *strrterm_str = strrchr(str, c); \
	if (strrterm_str) { \
		*strrterm_str = '\0'; \
	} \
}

/*!
 * \brief Guaranteed safe way of clearing the contents of a buffer,
 *        since memset(buf, 0, len) is likely to be optimized away
 *        when destroyed values are never used afterwards.
 * \note This is implemented as a macro for now, so we can easily
 *       change the implementation later without updating calling code.
 *       bzero is deprecated and not used in this codebase (memset is always used),
 *       but of explicit_bzero, memset_s, and explicit_memset,
 *       only explicit_bzero is available with the current header files and options,
 *       so I think this is the most portable way of doing this.
 *       A more portable way would be a function that checks several options,
 *       with a suitable fallback, but for now this is fine.
 */
#define bbs_memzero(buf, len) explicit_bzero(buf, len)

/*! \brief returns the equivalent of logic or for strings: first one if not empty, otherwise second one. */
#define S_OR(a, b) ({typeof(&((a)[0])) __x = (a); strlen_zero(__x) ? (b) : __x;})

/*! \brief returns the equivalent of logic or for strings, with an additional boolean check: second one if not empty and first one is true, otherwise third one.
 */
#define S_COR(a, b, c) ({typeof(&((b)[0])) __x = (b); (a) && !strlen_zero(__x) ? (__x) : (c);})

/*! \brief Print a string if it isn't NULL */
#define S_IF(a) S_OR(a, "")

/*! \brief Print singular or plural ending */
#define ESS(x) ((x) == 1 ? "" : "s")

/*! \brief Print Yes or No */
#define BBS_YESNO(x) (x ? "Yes" : "No")

/*! \brief Print Y or N */
#define BBS_YN(x) (x ? "Y" : "N")

/*! \brief Return TRUE/FALSE from string value */
#define S_TRUE(x) (!strcasecmp(x, "y") || !strcasecmp(x, "yes") || !strcasecmp(x, "true") || !strcasecmp(x, "on"))

/*! Atomic += */
#define bbs_atomic_fetch_add(ptr, val, memorder)  __atomic_fetch_add((ptr), (val), (memorder))
#define bbs_atomic_add_fetch(ptr, val, memorder)  __atomic_add_fetch((ptr), (val), (memorder))

/*! Atomic -= */
#define bbs_atomic_fetch_sub(ptr, val, memorder)  __atomic_fetch_sub((ptr), (val), (memorder))
#define bbs_atomic_sub_fetch(ptr, val, memorder)  __atomic_sub_fetch((ptr), (val), (memorder))

#define bbs_atomic_fetchadd_int(p, v) bbs_atomic_fetch_add(p, v, __ATOMIC_RELAXED)

/* BBS macros */

/*! \brief revents that should result in terminating the poll */
#define BBS_POLL_QUIT (POLLERR | POLLHUP | POLLNVAL)

#ifndef BBS_TEST_FRAMEWORK
#define BBS_ASSERT
#endif

#define bbs_assert_exists(x) bbs_assert(x != NULL)

#ifdef BBS_ASSERT
#ifdef BBS_MAIN_FILE
extern int option_dumpcore; /* Actually, this functions as a forward declaration for the real declaration in bbs.c */
#else
extern int option_dumpcore;
#endif /* BBS_MAIN_FILE */
#define bbs_assert(x) __bbs_assert(x, #x, __FILE__, __LINE__, __func__)
#define bbs_soft_assert(x) __bbs_soft_assert(x, #x, __FILE__, __LINE__, __func__)

/*! \brief Same as bbs_soft_assert, but useful as part of an if condition to execute additional logic if the soft assertion fails.
 * This avoids the need to do something like if (badcondition) { bbs_soft_assert(0); dosomething; } */
#define bbs_assertion_failed(x) __bbs_soft_assertion_failed(x, #x, __FILE__, __LINE__, __func__)

void __bbs_assert_nonfatal(const char *condition_str, const char *file, int line, const char *function);
void __attribute__((noreturn)) __bbs_assert_fatal(const char *condition_str, const char *file, int line, const char *function);

static inline void __attribute__((always_inline)) __bbs_assert(int condition, const char *condition_str, const char *file, int line, const char *function)
{
	if (__builtin_expect(!condition, 1)) {
		/* If we're not set to dump core, then what's the point of aborting? We won't get a core dump, so just continue. */
		option_dumpcore ? __bbs_assert_fatal(condition_str, file, line, function) : __bbs_assert_nonfatal(condition_str, file, line, function);
	}
}

static inline void __attribute__((always_inline)) __bbs_soft_assert(int condition, const char *condition_str, const char *file, int line, const char *function)
{
	if (__builtin_expect(!condition, 1)) {
		__bbs_assert_nonfatal(condition_str, file, line, function);
	}
}

static inline int __attribute__((always_inline)) __bbs_soft_assertion_failed(int condition, const char *condition_str, const char *file, int line, const char *function)
{
	if (__builtin_expect(!condition, 1)) {
		__bbs_assert_nonfatal(condition_str, file, line, function);
		return 1;
	}
	return 0;
}

#else
/* Use builtin assert */
#define bbs_assert(x) assert(x)
#endif /* BBS_ASSERT */

/*! \brief Get the name of a signal as a string */
#if defined(__GLIBC__) && __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 32
#define bbs_signal_name(sig) sigdescr_np(sig)
#elif defined(__GLIBC__)
#define bbs_signal_name(sig) sys_siglist[sig]
#else
#define bbs_signal_name(sig) strsignal(sig)
#endif

/*! \brief Dump a backtrace of the current thread to the logs */
void bbs_log_backtrace(void);

/*! \brief Remove all leading whitespace from a string */
#define ltrim(s) while (isspace(*s)) s++;

/*! \brief Remove all trailing whitespace from a string */
#define rtrim(s) { \
	if (s) { \
		char *back = s + strlen(s); \
		while (back != s && isspace(*--back)); \
		if (*s) { \
			*(back + 1) = '\0'; \
		} \
	} \
}

/*! \brief Remove all leading and trailing whitespace from a string */
#define trim(s) ltrim(s); rtrim(s);

/*! \brief Strip begin/end quotes from a string */
#define STRIP_QUOTES(s) { \
	if (*s == '"') { \
		char *tmps; \
		s++; \
		tmps = strrchr(s, '"'); \
		if (tmps && !*(tmps + 1)) { \
			*tmps = '\0'; \
		} \
	} \
}

/*! \brief Whether a number is a valid port number */
/*! \note Technically 0 is valid, but we exclude it here since it would never be used, and atoi returns 0 on failure */
#define PORT_VALID(p) (p > 0 && p < 65535)

/* BBS modules */
#if !defined(TEST_IN_CORE) && !defined(TEST_MODULE_SELF_SYM)
#if defined(BBS_IN_CORE) || (!defined(BBS_MODULE_SELF_SYM) && (defined(STANDALONE) || defined(STANDALONE2) || defined(BBS_NOT_MODULE)))
#define BBS_MODULE_SELF NULL
#elif defined(BBS_MODULE_SELF_SYM)
/*! Retrieve the 'struct bbs_module *' for the current module. */
#define BBS_MODULE_SELF BBS_MODULE_SELF_SYM()
struct bbs_module;
/* Internal/forward declaration, BBS_MODULE_SELF should be used instead. */
struct bbs_module *BBS_MODULE_SELF_SYM(void);
#elif defined(BBS_MODULE_SUBFILE)
/* This is part of a module but not the main module file. Do nothing. */
#else
#error "Externally compiled modules must declare BBS_MODULE_SELF_SYM."
#endif
#endif /* TEST_IN_CORE / TEST_MODULE_SELF_SYM */

#if defined(BBS_IN_CORE) || defined(BBS_MODULE_SELF) || defined(BBS_MODULE_SUBFILE)
#define BBS_MAIN_PROCESS
#endif

/*! \brief Whether the BBS is fully started */
int bbs_is_fully_started(void);

/*! \brief Whether startup is being aborted */
int bbs_abort_startup(void);

/*! \brief Whether the BBS is currently shutting down */
int bbs_is_shutting_down(void);

/*! \brief Get BBS startup time */
time_t bbs_starttime(void);

/*! \brief Get BBS config directory */
const char *bbs_config_dir(void);

/*! \brief Print current BBS settings */
int bbs_view_settings(int fd);

/*!
 * \brief Request async module unload or reload
 * \param name
 * \param reload 1 to load module again after unloading, 0 to just unload it
 * \note You must use this function to trigger an unload/reload of a module from itself.
 */
void bbs_request_module_unload(const char *name, int reload);

/*!
 * \brief Suspend execution of a BBS thread for a given amount of time or until BBS shutdown occurs
 * \param ms Number of milliseconds
 * \retval 0 if sleep returned uneventfully
 * \retval -1 if error occured
 * \retval 1 if activity occured (e.g. BBS shutdown)
 * \note If unloading a module outside of shutdown, you may want to use bbs_safe_sleep_interrupt instead
 */
int bbs_safe_sleep(int ms);

/*!
 * \brief Same as bbs_safe_sleep, but also return immediately if interrupted by a signal
 * \note You will also need to signal the thread, e.g. using bbs_pthread_interrupt, in order to interrupt this function
 */
int bbs_safe_sleep_interrupt(int ms);

/*!
 * \brief Subscribe SIGINT alertpipe
 * \param p alert pipe
 * \note This temporarily overrides normal default SIGINT handling (shutdown the BBS) while active
 */
void bbs_sigint_set_alertpipe(int p[2]);

/*!
 * \brief Wait for a SIGCHLD, with a timer
 * \param ms Maximum number of ms for which to wait
 * \retval Same as bbs_poll
 */
int bbs_sigchld_poll(int ms);
