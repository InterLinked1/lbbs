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
 * \brief Numeric lists and ranges
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "include/utils.h"
#include "include/range.h"

int in_range_allocated(const char *s, int num, char *sequences)
{
	char *sequence;

	strcpy(sequences, s); /* This is safe, as it is assumed that sequences itself was strdup'd or malloc'd from s / strlen(s) + 1 previously */

	/*! \todo since atoi would stop on a , anyways, strsep isn't really necessary.
	 * We could parse the string in place, avoiding the need to allocate and copy in the first place. */

	while ((sequence = strsep(&sequences, ","))) {
		int min, max;
		char *begin = strsep(&sequence, ":");
		if (strlen_zero(begin)) {
			bbs_warning("Malformed range: %s\n", s);
			continue;
		}
		if (!strcmp(begin, "*")) {
			/* Something like just *, everything matches */
			return 1;
		}
		min = atoi(begin);
		if (num < min) {
			continue;
		}
		if (sequence) {
			if (!strcmp(sequence, "*")) { /* Something like 1:* */
				max = INT_MAX;
			} else {
				max = atoi(sequence);
			}
		} else {
			max = min;
		}
		if (num > max) {
			continue;
		}
		return 1; /* Matches */
	}
	return 0;
}

int in_range(const char *s, int num)
{
	int res = 0;
	char *dup;

	dup = strdup(s);
	if (ALLOC_FAILURE(dup)) {
		return 0;
	}

	res = in_range_allocated(s, num, dup);

	free(dup);
	return res;
}

#define UINTLIST_CHUNK_SIZE 32

int uintlist_append(unsigned int **a, int *lengths, int *allocsizes, unsigned int vala)
{
	int curlen;

	if (!*a) {
		*a = malloc(UINTLIST_CHUNK_SIZE * sizeof(unsigned int));
		if (ALLOC_FAILURE(*a)) {
			return -1;
		}
		*allocsizes = UINTLIST_CHUNK_SIZE;
	} else {
		if (*lengths >= *allocsizes) {
			unsigned int *newa;
			int newallocsize = *allocsizes += UINTLIST_CHUNK_SIZE; /* Don't multiply by sizeof(unsigned int), so we can directly compare with lengths */
			newa = realloc(*a, (size_t) newallocsize * sizeof(unsigned int)); /* Increase by 32 each chunk */
			if (ALLOC_FAILURE(newa)) {
				return -1;
			}
			*a = newa;
			*allocsizes = newallocsize;
		}
	}

	curlen = *lengths;
#ifdef DEBUG_UINTLIST
	bbs_debug(10, "Writing to index %d/%d\n", curlen, *allocsizes);
#endif
	(*a)[curlen] = vala;
	*lengths = curlen + 1;
	return 0;
}

int uintlist_append2(unsigned int **a, unsigned int **b, int *lengths, int *allocsizes, unsigned int vala, unsigned int valb)
{
	int curlen;

	if (!*a) {
		*a = malloc(UINTLIST_CHUNK_SIZE * sizeof(unsigned int));
		if (ALLOC_FAILURE(*a)) {
			return -1;
		}
		*b = malloc(UINTLIST_CHUNK_SIZE * sizeof(unsigned int));
		if (ALLOC_FAILURE(*b)) {
			free_if(*a);
			return -1;
		}
		*allocsizes = UINTLIST_CHUNK_SIZE;
	} else {
		if (*lengths >= *allocsizes) {
			unsigned int *newb, *newa;
			int newallocsize = *allocsizes += UINTLIST_CHUNK_SIZE; /* Don't multiply by sizeof(unsigned int), so we can directly compare with lengths */
			newa = realloc(*a, (size_t) newallocsize * sizeof(unsigned int)); /* Increase by 32 each chunk */
			if (ALLOC_FAILURE(newa)) {
				return -1;
			}
			newb = realloc(*b, (size_t) newallocsize * sizeof(unsigned int));
			if (ALLOC_FAILURE(newb)) {
				/* This is tricky. We expanded a but failed to expand b. Keep the smaller size for our records. */
				return -1;
			}
			*allocsizes = newallocsize;
			*a = newa;
			*b = newb;
		}
	}

	curlen = *lengths;
#ifdef DEBUG_UINTLIST
	bbs_debug(10, "Writing to index %d/%d\n", curlen, *allocsizes);
#endif
	(*a)[curlen] = vala;
	(*b)[curlen] = valb;
	*lengths = curlen + 1;
	return 0;
}
#undef UINTLIST_CHUNK_SIZE

static int copyuid_str_append(struct dyn_str *dynstr, unsigned int a, unsigned int b)
{
	char range[32];
	int len;
	if (a == b) {
		len = snprintf(range, sizeof(range), "%s%u", dynstr->used ? "," : "", a);
	} else {
		len = snprintf(range, sizeof(range), "%s%u:%u", dynstr->used ? "," : "", a, b);
	}
	return dyn_str_append(dynstr, range, (size_t) len);
}

char *gen_uintlist(unsigned int *l, int lengths)
{
	int i;
	unsigned int begin, last;
	struct dyn_str dynstr;

	if (!lengths) {
		return NULL;
	}

	memset(&dynstr, 0, sizeof(dynstr));

	last = begin = l[0];
	for (i = 1; i < lengths; i++) {
		if (l[i] != last + 1) {
			/* Last one ended a range */
			copyuid_str_append(&dynstr, begin, last);
			begin = l[i]; /* Start of next range */
		}
		last = l[i];
	}
	/* Last one */
	copyuid_str_append(&dynstr, begin, last);
	return dynstr.buf; /* This is dynamically allocated, so okay */
}

char *uintlist_to_str(unsigned int *a, int length)
{
	int i;
	struct dyn_str dynstr;

	memset(&dynstr, 0, sizeof(dynstr));
	for (i = 0; i < length; i++) {
		char buf[15];
		int len = snprintf(buf, sizeof(buf), "%s%u", i ? " " : "", a[i]);
		dyn_str_append(&dynstr, buf, (size_t) len);
	}
	return dynstr.buf;
}

char *uintlist_to_ranges(unsigned int *a, int length)
{
	int i;
	struct dyn_str dynstr;
	unsigned int start = 0, last, len;
	const char *prefix = "";
	char buf[15];

	memset(&dynstr, 0, sizeof(dynstr));
	if (length) {
		start = last = a[0]; /* Instead of putting an if i == 0 branch inside the loop, that will only run once, just do it beforehand */
	}
	for (i = 1; i < length; i++) {
		if (!start) {
			start = last = a[i];
		} else if (a[i] == last + 1) {
			last = a[i];
		} else {
			if (start == last) {
				len = (unsigned int) snprintf(buf, sizeof(buf), "%s%u", prefix, last);
			} else {
				len = (unsigned int) snprintf(buf, sizeof(buf), "%s%u:%u", prefix, start, last);
			}
			dyn_str_append(&dynstr, buf, len);
			prefix = ",";
			start = last = a[i];
		}
	}
	if (start) {
		/* last one */
		if (start == last) {
			len = (unsigned int) snprintf(buf, sizeof(buf), "%s%u", prefix, last);
		} else {
			len = (unsigned int) snprintf(buf, sizeof(buf), "%s%u:%u", prefix, start, last);
		}
		dyn_str_append(&dynstr, buf, len);
	}
	return dynstr.buf;
}

int range_to_uintlist(char *s, unsigned int **list, int *length)
{
	char *seq;
	int alloc_sizes = 0;

	while ((seq = strsep(&s, ","))) {
		unsigned int a, b;
		char *start, *end = seq;
		start = strsep(&end, ":");
		if (strlen_zero(start)) {
			bbs_warning("Invalid range\n");
			continue;
		}
		a = (unsigned int) atoi(start);
		if (!end) {
			uintlist_append(list, length, &alloc_sizes, a);
			continue;
		}
		b = (unsigned int) atoi(end);
		if (b - a > 100000) {
			bbs_warning("Declining to process range %u:%u (too large)\n", a, b);
			return -1; /* Don't malloc into oblivion */
		}
		for (; a <= b; a++) {
			uintlist_append(list, length, &alloc_sizes, a);
		}
	}
	return 0;
}