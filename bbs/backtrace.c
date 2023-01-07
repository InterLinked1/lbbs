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
 * \brief Backtraces
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 *
 * \note process_section and bt_get_symbols based on corresponding functions from Asterisk's backtrace.c (GPLv2)
 */

#include "include/bbs.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <execinfo.h>
#include <dlfcn.h>
#include <bfd.h>

#define BT_MAX_STACK_FRAMES 20
#define BT_MSG_BUFF_LEN 1024

/* Should have one or the other
 * Debian 11 has the shorter ones e.g. bfd_section_vma
 * Debian 10 has the longer ones e.g. bfd_get_section_vma
 */
#ifndef bfd_get_section_size
#define bfd_get_section_size(x) bfd_section_size(x)
#endif
#ifndef bfd_get_section_vma
#define bfd_get_section_vma(x, y)	bfd_section_vma(y)
#endif
#ifndef bfd_get_section_flags
#define bfd_get_section_flags(x, y) bfd_section_flags(y)
#endif

#ifdef BBS_ASSERT
struct bfd_data {
	bfd_vma pc;            /* bfd.h */
	asymbol **syms;        /* bfd.h */
	Dl_info dli;           /* dlfcn.h */
	const char *libname;
	int dynamic;
	int has_syms;
	char *msg;
	int found;
	long unsigned int frame;
	char **retstrings;
};

static void process_section(bfd *bfdobj, asection *section, void *obj)
{
	struct bfd_data *data = obj;
	const char *file, *func;
	unsigned int line;
	bfd_vma offset;
	bfd_vma vma;
	bfd_size_type size;
	bfd_boolean line_found = 0;
	char *fn;
	int inlined = 0;

	offset = data->pc - (data->dynamic ? (bfd_vma)(uintptr_t) data->dli.dli_fbase : 0);

	if (!(bfd_get_section_flags(bfdobj, section) & SEC_ALLOC)) {
		return;
	}

	vma = bfd_get_section_vma(bfdobj, section);
	size = bfd_get_section_size(section);

	if (offset < vma || offset >= vma + size) {
		/* Not in this section */
		return;
	}

	/*! \todo BUGBUG
	 * Memory leak in bfd_find_nearest_line.
	 * Not sure whose fault it is (but there have been known leaks in this function before).
	 * This needs to be fixed (somehow) because we irrecoverably leak memory with every backtrace.
	 * If __bbs_assert_fatal was called (we're dumping a core), so it really doesn't matter,
	 * but if we're not aborting on assertions the leaks will accumulate.
	 *
	 * ==98132== 777 bytes in 31 blocks are definitely lost in loss record 4 of 4
	 * ==98132==    at 0x483877F: malloc (vg_replace_malloc.c:307)
	 * ==98132==    by 0x4C91F3A: strdup (strdup.c:42)
	 * ==98132==    by 0x4A58C78: ??? (in /usr/lib/x86_64-linux-gnu/libbfd-2.35.2-system.so)
	 * ==98132==    by 0x4A58FA4: ??? (in /usr/lib/x86_64-linux-gnu/libbfd-2.35.2-system.so)
	 * ==98132==    by 0x4A5C22A: ??? (in /usr/lib/x86_64-linux-gnu/libbfd-2.35.2-system.so)
	 * ==98132==    by 0x4A27C70: _bfd_elf_find_nearest_line (in /usr/lib/x86_64-linux-gnu/libbfd-2.35.2-system.so)
	 * ==98132==    by 0x10E991: process_section (backtrace.c:74)
	 *
	 */

	line_found = bfd_find_nearest_line(bfdobj, section, data->syms, offset - vma, &file, &func, &line);
	if (!line_found) {
		return;
	}

	/* If we find a line, we will want to continue calling bfd_find_inliner_info
	 * to capture any inlined functions that don't have their own stack frames. */
	do {
		data->found++;
		/* file can possibly be null even with a success result from bfd_find_nearest_line */
		file = file ? file : "";
		fn = strrchr(file, '/');
#define FMT_INLINED     "[%10s] %-17s %24s:%-5u %s()"
#define FMT_NOT_INLINED "[%10p] %-17s %24s:%-5u %s()"

		snprintf(data->msg, BT_MSG_BUFF_LEN, inlined ? FMT_INLINED : FMT_NOT_INLINED,
			inlined ? "inlined" : (char *)(uintptr_t) data->pc,
			data->libname,
			fn ? fn + 1 : file,
			line, S_OR(func, "???"));

		if (inlined) {
			int origlen = strlen(data->retstrings[data->frame]);
			char *s = realloc(data->retstrings[data->frame], origlen + strlen(data->msg) + 2); /* 1 for NUL, 1 for LF */
			if (!s) {
				return; /* Stop on realloc failure */
			}
			data->retstrings[data->frame] = s;
			s[origlen] = '\n';
			strcpy(s + origlen + 1, data->msg); /* Safe */
			data->retstrings[data->frame] = s;
		} else {
			data->retstrings[data->frame] = strdup(data->msg);
		}
		if (!data->retstrings[data->frame]) {
			return; /* Stop on strdup failure */
		}

		inlined++;
		/* Let's see if there are any inlined functions */
	} while (bfd_find_inliner_info(bfdobj, &file, &func, &line));
}

static void bt_get_symbols(void **addresses, int num_frames, char *retstrings[])
{
	int stackfr;
	bfd *bfdobj;
	long allocsize;
	char msg[BT_MSG_BUFF_LEN];
	static pthread_mutex_t bfd_mutex = PTHREAD_MUTEX_INITIALIZER;

	for (stackfr = 0; stackfr < num_frames; stackfr++) {
		int symbolcount;
		struct bfd_data data = {
			.retstrings = retstrings,
			.msg = msg,
			.pc = (bfd_vma)(uintptr_t) addresses[stackfr],
			.found = 0,
			.dynamic = 0,
			.frame = stackfr,
		};

		msg[0] = '\0';

		if (!dladdr((void *)(uintptr_t) data.pc, &data.dli)) {
			continue;
		}
		data.libname = strrchr(data.dli.dli_fname, '/');
		if (!data.libname) {
			data.libname = data.dli.dli_fname;
		} else {
			data.libname++;
		}

		pthread_mutex_lock(&bfd_mutex);
		/* Using do while(0) here makes it easier to escape and clean up */
		do {
			bfdobj = bfd_openr(data.dli.dli_fname, NULL);
			if (!bfdobj) {
				break;
			}

			/* bfd_check_format does more than check. It HAS to be called */
			if (!bfd_check_format(bfdobj, bfd_object)) {
				break;
			}

			data.has_syms = !!(bfd_get_file_flags(bfdobj) & HAS_SYMS);
			data.dynamic = !!(bfd_get_file_flags(bfdobj) & DYNAMIC);

			if (!data.has_syms) {
				break;
			}

			allocsize = data.dynamic ? bfd_get_dynamic_symtab_upper_bound(bfdobj) : bfd_get_symtab_upper_bound(bfdobj);
			if (allocsize < 0) {
				break;
			}

			data.syms = malloc(allocsize);
			if (!data.syms) {
				break;
			}

			symbolcount = data.dynamic ? bfd_canonicalize_dynamic_symtab(bfdobj, data.syms) : bfd_canonicalize_symtab(bfdobj, data.syms);
			if (symbolcount < 0) {
				break;
			}

			bfd_map_over_sections(bfdobj, process_section, &data);
		} while(0);

		if (bfdobj) {
			bfd_close(bfdobj);
			free(data.syms);
			data.syms = NULL;
		}
		pthread_mutex_unlock(&bfd_mutex);

		/* Default output, if we cannot find the information within BFD */
		if (!data.found) {
			snprintf(msg, sizeof(msg), "%s %s()", data.libname, S_OR(data.dli.dli_sname, "<unknown>"));
			retstrings[stackfr] = strdup(msg);
		}
	}
}

/* retstrings takes a variable, which makes gcc unhappy with this option */
#pragma GCC diagnostic ignored "-Wstack-protector"
static void bbs_log_backtrace(void)
{
	char **bt_syms;
	void *array[BT_MAX_STACK_FRAMES]; /* Maximum number of stack frames to dump. */
	size_t size;
	unsigned long i;

	size = backtrace(array, BT_MAX_STACK_FRAMES);
	bt_syms = backtrace_symbols(array, size);

	bbs_error("Got %lu backtrace records\n", size);

	{
		/* Scope for retstrings, since size is not known at beginning of function */
		char *retstrings[size];
#pragma GCC diagnostic pop
		memset(retstrings, 0, sizeof(*retstrings));
		bt_get_symbols(array, size, retstrings); /* Get backtraces with friendly symbols */
		for (i = 0; i < size; i++) {
			if (retstrings[i]) {
				if (strchr(retstrings[i], '\n')) {
					/* More than one in here (inlined frames) */
					char *frame = NULL, *s = retstrings[i]; /* Dup pointer so we can free() on original pointer */
					/* Align each frame onto its own log line so things are aligned visually in logging output */
					/* More efficient than strsep */
					do {
						frame = strchr(s, '\n');
						if (frame) {
							*frame++ = '\0';
						}
						bbs_error("%2lu: %s\n", i, s);
						s = frame;
					} while (frame);
				} else {
					bbs_error("%2lu: %s\n", i, retstrings[i]);
				}
				free(retstrings[i]); /* Free symbols as we're done using them */
			} else {
				/* Fallback to backtrace_symbols output */
				bbs_error("%2lu: %s\n", i, bt_syms[i]);
			}
		}
		free(bt_syms);
	}
}

void __bbs_assert_nonfatal(const char *condition_str, const char *file, int line, const char *function)
{
	__bbs_log(LOG_ERROR, 0, file, line, function, "Failed assertion %s\n", condition_str);
	bbs_log_backtrace(); /* Get a backtrace for the assertion */
}

void __attribute__((noreturn)) __bbs_assert_fatal(const char *condition_str, const char *file, int line, const char *function)
{
	__bbs_log(LOG_ERROR, 0, file, line, function, "Failed assertion %s\n", condition_str);
	/* If, for some reason, we don't dump core or it gets lost, get a backtrace now and log it */
	bbs_log_backtrace(); /* Get a backtrace for the assertion. Do not call __bbs_assert_nonfatal, to minimize the stack size here. */
	usleep(100); /* Give logging a chance to do its thing, before we abort() */
	abort(); /* Abort so we can dump core */
}
#endif /* BBS_ASSERT */
