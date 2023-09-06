/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Memory allocation wrapper
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#if defined(REDIRECT_LIBC_ALLOC) && REDIRECT_LIBC_ALLOC == 1
/* Undefine the overrides in bbs.h to expose the real functions */
#undef malloc
#undef calloc
#undef realloc
#undef strdup
#undef strndup
#undef asprintf
#undef vasprintf

/* Redefine the real libc alloc functions */
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

extern int option_rand_alloc_failures;
static unsigned int alloc_count = 0;

/* Prevent recursion with logging */
static __thread int alloc_fail_count = 0;

/*! \note option_rand_alloc_failures is always true or false, so the branch predictor should pick up on this quickly, even without likely/unlikely */
/*! \note Since the logging routines also allocate memory, if we have already failed to allocate in the current thread,
 *        we must not log subsequent failures or we would recurse indefinitely.
 *        Furthermore, we must never log without incrementing alloc_fail_count first, and we must never log if this is > 0.
 *
 * As far as making this random, we use powers of 2 so the compiler can optimize these to bit shifts instead of expensive math operations.
 */
#define RAND_MEMORY_FAIL(op, val) \
	alloc_count++; \
	if (!alloc_fail_count && option_rand_alloc_failures && !(alloc_count % 32) && !(rand() % 16)) { \
		alloc_fail_count++; \
		bbs_warning("Simulated allocation failure (" #op ") in %s() at %s:%d\n", func, file, line); \
		alloc_fail_count--; \
		return val; \
	} \

#define LOG_ALLOC_FAILURE(ptr, funcname, fmt, ...) \
	if (unlikely(!ptr)) { \
		alloc_fail_count++; \
		if (alloc_fail_count == 1) { \
			bbs_error(#funcname "(" fmt ") failed in %s() at %s:%d\n", ## __VA_ARGS__, func, file, line); \
		} else { \
			fprintf(stderr, #funcname "(" fmt ") failed in %s() at %s:%d\n", ## __VA_ARGS__, func, file, line); \
		} \
		alloc_fail_count--; \
	}

void *__bbs_malloc(size_t size, const char *file, int line, const char *func)
{
	void *ptr;
	RAND_MEMORY_FAIL(malloc, NULL);
	ptr = malloc(size);
	LOG_ALLOC_FAILURE(ptr, malloc, "%lu", size);
	return ptr;
}

void *__bbs_calloc(size_t nmemb, size_t size, const char *file, int line, const char *func)
{
	void *ptr;
	RAND_MEMORY_FAIL(calloc, NULL);
	ptr = calloc(nmemb, size);
	LOG_ALLOC_FAILURE(ptr, calloc, "%lu,%lu", nmemb, size);
	return ptr;
}

void *__bbs_realloc(void *ptr, size_t size, const char *file, int line, const char *func)
{
	void *newptr;
	RAND_MEMORY_FAIL(realloc, NULL);
	newptr = realloc(ptr, size);
	LOG_ALLOC_FAILURE(newptr, realloc, "%lu", size);
	return newptr;
}

void *__bbs_strdup(const char *s, const char *file, int line, const char *func)
{
	void *ptr;
	RAND_MEMORY_FAIL(strdup, NULL);
	ptr = strdup(s);
	LOG_ALLOC_FAILURE(ptr, strdup, "");
	return ptr;
}

void *__bbs_strndup(const char *s, size_t n, const char *file, int line, const char *func)
{
	void *ptr;
	RAND_MEMORY_FAIL(strndup, NULL);
	ptr = strndup(s, n);
	LOG_ALLOC_FAILURE(ptr, strndup, "%lu", n);
	return ptr;
}

void *__bbs_memdup(void *ptr, size_t size, const char *file, int line, const char *func)
{
	void *newptr;
	RAND_MEMORY_FAIL(realloc, NULL);
	newptr = malloc(size + 1); /* +1 in case it's a string */
	LOG_ALLOC_FAILURE(newptr, realloc, "%lu", size);
	if (ALLOC_SUCCESS(newptr)) {
		char *end = newptr + size;
		memcpy(newptr, ptr, size);
		*end = '\0'; /* Null terminate, in case it's a string */
	}
	return newptr;
}

int __attribute__ ((format (gnu_printf, 2, 0))) __bbs_vasprintf(char **strp, const char *fmt, va_list ap, const char *file, int line, const char *func)
{
	int size;
	va_list ap2;
	char s;
	void *ptr;

	RAND_MEMORY_FAIL(vasprintf, -1);

	va_copy(ap2, ap);
	size = vsnprintf(&s, 1, fmt, ap2);
	va_end(ap2);
	ptr = malloc((unsigned int) size + 1);
	if (!ptr) {
		LOG_ALLOC_FAILURE(ptr, vasprintf, "%d", size);
		va_end(ap);
		return -1;
	}
	vsnprintf(ptr, (unsigned int) size + 1, fmt, ap);
	*strp = ptr;

	return size;
}

int __attribute__ ((format (gnu_printf, 5, 6))) __bbs_asprintf(const char *file, int line, const char *func, char **strp, const char *fmt, ...)
{
	int size;
	va_list ap, ap2;
	char s;
	void *ptr;

	RAND_MEMORY_FAIL(asprintf, -1);

	va_start(ap, fmt);
	va_copy(ap2, ap);
	size = vsnprintf(&s, 1, fmt, ap2);
	va_end(ap2);
	ptr = malloc((unsigned int) size + 1);
	if (!ptr) {
		LOG_ALLOC_FAILURE(ptr, asprintf, "%d", size);
		va_end(ap);
		return -1;
	}
	vsnprintf(ptr, (unsigned int) size + 1, fmt, ap);
	va_end(ap);
	*strp = ptr;

	return size;
}
#endif

#include <malloc.h> /* use malloc_trim */
#include <unistd.h> /* use sbrk */

size_t bbs_malloc_trim(void)
{
	int res;
	size_t diff;
	void *before, *after;

	before = sbrk(0); /* Find current location of program break */
	res = malloc_trim(0); /* Release as much free memory from the top of the heap as possible */
	after = sbrk(0); /* Get new location of program break */

	diff = (size_t) (before - after); /* Number of bytes released (which should be based on the page size) */
	bbs_debug(2, "malloc_trim: %d, before: %p, after: %p, bytes released: %lu\n", res, before, after, diff);
	return diff;
}
