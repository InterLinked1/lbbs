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

/* Universal includes */
#include <errno.h>
#include <assert.h>
#include <stddef.h> /* use NULL */
#include <unistd.h>
#if defined(DEBUG_FD_LEAKS) && DEBUG_FD_LEAKS == 1
#include <stdlib.h>
#include <string.h>
#endif
#if defined(DEBUG_FD_LEAKS) && DEBUG_FD_LEAKS == 1
	#include <stdio.h> /* FILE* cannot be forward declared, since it's a typedef */
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#endif

#include "include/logger.h"

/* Global definitions */
#include "include/definitions.h"

#define BBS_COPYRIGHT STRCAT("Copyright 2023 ", BBS_AUTHOR)
#define BBS_COPYRIGHT_SHORT STRCAT("(C) 2023 ", BBS_AUTHOR)
#define BBS_VERSION XSTR(BBS_MAJOR_VERSION) "." XSTR(BBS_MINOR_VERSION) "." XSTR(BBS_PATCH_VERSION)

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

/* Global undeclarations */
/* Forbid usage of unsafe functions */
#define gets(s) Do_not_use_gets__use_fgets
#define strcat(dst, src) Do_not_use_strcat__use_strncat
#define sprintf(fmt, ...) Do_not_use_sprintf__use_snprintf
#define vsprintf(s, fmt, arg) Do_not_use_vsprintf__use_vsnprintf
/* Force usage of poll instead of the deprecated and unsafe select */
#define select(nfds, readfds, writefds, exceptfds, timeout) Do_not_use_select__use_poll
/* Force usage of thread-safe functions */
#define localtime(a) Do_not_use_localtime__use_localtime_r
#define gmtime(a) Do_not_use_gmtime__use_gmtime_r
#define ctime(a) Do_not_use_ctime__use_ctime_r
#define ptsname(fd) Do_not_use_ptsname__use_ptsname_r
#define strncpy(dest, src, size) Do_not_use_strncpy__use_safe_strncpy
#ifndef BBS_MAIN_FILE
/* Allow printf only in bbs.c */
#define printf(...) Do_not_use_printf__use_bbs_printf
#endif
#define dprintf(fd, ...) Do_not_use_dprintf__use_bbs_dprintf
#ifndef BBS_PTHREAD_WRAPPER_FILE
/* Force nonusage of insufficiently portable functions */
#define gettid() Do_not_use_gettid__use_bbs_gettid
/* Force usage of BBS thread wrappers */
#define pthread_create(a, b, c, d) Do_not_use_pthread_create__use_bbs_pthread_create
#define pthread_create_detached(a, b, c, d) Do_not_use_pthread_create__use_bbs_pthread_create_detached->fail(a, b, c, d)
#define pthread_join(a, b) Do_not_use_pthread_join__use_bbs_pthread_join
#endif
/* BUGBUG FIXME XXX ^^^ For some reason adding ->fail(a, b, c, d) etc. on the end
 * (which does force an undeclared function warning) causes an expected = , ; asm or __attribute__ before -> token ???
 *
 * Without forcing a compilation fail using ->fail, the "function defined but not used" will kick in first,
 * which does stop compilation but is confusing because the error is not quite sensible
 * In fact this can end up being an unresolved symbol for core files and shared object modules alike, so this needs to be fixed!!!
 */

#if defined(DEBUG_FD_LEAKS) && DEBUG_FD_LEAKS == 1
#define	open(a,...)	__fdleak_open(__FILE__,__LINE__,__func__, a, __VA_ARGS__)
#define pipe(a)		__fdleak_pipe(a, __FILE__,__LINE__,__func__)
#define socketpair(a,b,c,d)	__fdleak_socketpair(a, b, c, d, __FILE__,__LINE__,__func__)
#define socket(a,b,c)	__fdleak_socket(a, b, c, __FILE__,__LINE__,__func__)
#define accept(a,b,c)	__fdleak_accept(a, b, c, __FILE__,__LINE__,__func__)
#define close(a)	__fdleak_close(a, __FILE__,__LINE__,__func__)
#define	fopen(a,b)	__fdleak_fopen(a, b, __FILE__,__LINE__,__func__)
#define	fclose(a)	__fdleak_fclose(a)
#define	dup2(a,b)	__fdleak_dup2(a, b, __FILE__,__LINE__,__func__)
#define dup(a)		__fdleak_dup(a, __FILE__,__LINE__,__func__)
#define eventfd(a,b)	__fdleak_eventfd(a,b, __FILE__,__LINE__,__func__)

int __fdleak_open(const char *file, int line, const char *func, const char *path, int flags, ...);
int __fdleak_pipe(int *fds, const char *file, int line, const char *func);
int __fdleak_socketpair(int domain, int type, int protocol, int sv[2], const char *file, int line, const char *func);
int __fdleak_socket(int domain, int type, int protocol, const char *file, int line, const char *func);
int __fdleak_accept(int socket, struct sockaddr *address, socklen_t *address_len, const char *file, int line, const char *func);
int __fdleak_eventfd(unsigned int initval, int flags, const char *file, int line, const char *func);
int __fdleak_close(int fd, const char *file, int line, const char *func);
FILE *__fdleak_fopen(const char *path, const char *mode, const char *file, int line, const char *func);
int __fdleak_fclose(FILE *ptr);
int __fdleak_dup2(int oldfd, int newfd, const char *file, int line, const char *func);
int __fdleak_dup(int oldfd, const char *file, int line, const char *func);

int bbs_fd_dump(int fd);
#endif /* DEBUG_FD_LEAKS */

#if defined(REDIRECT_LIBC_ALLOC) && REDIRECT_LIBC_ALLOC == 1
#define malloc(size) __bbs_malloc(size, __FILE__, __LINE__, __func__)
#define calloc(nmemb, size) __bbs_calloc(nmemb, size, __FILE__, __LINE__, __func__)
#define realloc(ptr, size) __bbs_realloc(ptr, size, __FILE__, __LINE__, __func__)
#define strdup(s) __bbs_strdup(s, __FILE__, __LINE__, __func__)
#define strndup(s, n) __bbs_strndup(s, n, __FILE__, __LINE__, __func__)
#define vasprintf(strp, format, ap) __bbs_vasprintf(strp, format, ap, __FILE__, __LINE__, __func__)
#define asprintf(strp, format, ...) __bbs_asprintf(__FILE__, __LINE__, __func__, strp, format, ## __VA_ARGS__)

void *__bbs_malloc(size_t size, const char *file, int line, const char *func) __attribute__((malloc));
void *__bbs_calloc(size_t nmemb, size_t size, const char *file, int line, const char *func) __attribute__((malloc));
void *__bbs_realloc(void *ptr, size_t size, const char *file, int line, const char *func) __attribute__((malloc));
void *__bbs_strdup(const char *s, const char *file, int line, const char *func) __attribute__((malloc));
void *__bbs_strndup(const char *s, size_t n, const char *file, int line, const char *func) __attribute__((malloc));
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

#undef MIN
#define MIN(a, b) ({ typeof(a) __a = (a); typeof(b) __b = (b); ((__a > __b) ? __b : __a);})
#undef MAX
#define MAX(a, b) ({ typeof(a) __a = (a); typeof(b) __b = (b); ((__a < __b) ? __b : __a);})

#define bbs_rand(min, max) (min + rand() % (max + 1 - min))
#define bbs_maxrand(max) bbs_rand(0, max)

#define SET_BITFIELD(field, value) field = (unsigned) (value & 0x1)
#define SET_BITFIELD2(field, value) field = (unsigned) (value & 0x3)

#define STARTS_WITH(s, start) (!strncasecmp(s, start, STRLEN(start)))

/*!
 * \brief Check if an argument is within bounds
 * \param x Argument
 * \param min
 * \param max
 */
#define IN_BOUNDS(x, min, max) (x >= min && x <= max)

#define SIZE_MB(bytes) (bytes * 1024 * 1024)
#define SIZE_KB(bytes) (bytes * 1024)

/*! \brief Number of ms in given seconds */
#define SEC_MS(x) (1000 * x)

/*! \brief Number of ms in given minutes */
#define MIN_MS(x) (60000 * x)

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

/*! \brief If char * is NULL or empty string */
#define strlen_zero(s) ((!s || *s == '\0'))

/*! \brief If stack char buffer is empty */
#define s_strlen_zero(s) ((*s == '\0'))

#define swrite(fd, s) write(fd, s, strlen(s))
#define SWRITE(fd, s) write(fd, s, STRLEN(s))

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
 * \brief Size-limited null-terminating string copy.
 * \param dst The destination buffer.
 * \param src The source string
 * \param size The size of the destination buffer
 * This is similar to \a strncpy, with two important differences:
 * - the destination buffer will \b always be null-terminated
 * - the destination buffer is not filled with zeros past the copied string length
 * These differences make it slightly more efficient, and safer to use since it will
 * not leave the destination buffer unterminated. There is no need to pass an artificially
 * reduced buffer size to this function (unlike \a strncpy), and the buffer does not need
 * to be initialized to zeroes prior to calling this function.
 */
static inline void safe_strncpy(char *dst, const char *src, size_t size)
{
	while (*src && size) {
		*dst++ = *src++;
		size--;
	}
	if (__builtin_expect(!size, 0)) {
		dst--;
	}
	*dst = '\0';
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

/*! \brief Print a string if it isn't NULL */
#define S_IF(a) S_OR(a, "")

/*! \brief Print singular or plural ending */
#define ESS(x) ((x) == 1 ? "" : "s")

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
#endif
#define bbs_assert(x) __bbs_assert(x, #x, __FILE__, __LINE__, __func__)
void __bbs_assert_nonfatal(const char *condition_str, const char *file, int line, const char *function);
void __attribute__((noreturn)) __bbs_assert_fatal(const char *condition_str, const char *file, int line, const char *function);

static inline void __attribute__((always_inline)) __bbs_assert(int condition, const char *condition_str, const char *file, int line, const char *function)
{
	if (__builtin_expect(!condition, 1)) {
		/* If we're not set to dump core, then what's the point of aborting? We won't get a core dump, so just continue. */
		option_dumpcore ? __bbs_assert_fatal(condition_str, file, line, function) : __bbs_assert_nonfatal(condition_str, file, line, function);
	}
}

#else
/* Use builtin assert */
#define bbs_assert(x) assert(x)
#endif

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
#else
#error "Externally compiled modules must declare BBS_MODULE_SELF_SYM."
#endif
#endif /* TEST_IN_CORE / TEST_MODULE_SELF_SYM */

/*! \brief Whether the BBS is fully started */
int bbs_is_fully_started(void);

/*! \brief Whether the BBS is currently shutting down */
int bbs_is_shutting_down(void);

/*! \brief Get BBS startup time */
int bbs_starttime(void);

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
 * \brief Subscribe SIGINT alertpipe
 * \param p alert pipe
 * \note This temporarily overrides normal default SIGINT handling (shutdown the BBS) while active
 */
void bbs_sigint_set_alertpipe(int p[2]);

/*!
 * \brief Request BBS shutdown
 * \param restart 1 to restart the BBS after shutdown, 0 for normal shutdown, -1 for immediate halt
 */
void bbs_request_shutdown(int restart);
