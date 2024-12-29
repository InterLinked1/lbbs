/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Lock management wrappers
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/* Tunable settings */
#define DETECT_DEADLOCKS
#define STRICT_LOCKING
#define ALWAYS_INITIALIZE 1

/* In general, there should not be *that* many readers for a lock.
 * However, tls.c currently requires a read lock for every TLS
 * connection, so this should be at least as high as maxnodes in nodes.conf,
 * for worst case scenario of every node using TLS encryption. */
#define MAX_READERS 128

/* Start code */
#define BBS_LOCK_WRAPPER_FILE

#include "include/bbs.h"

#include <string.h>

#include "include/utils.h" /* use safe_strncpy, bbs_gettid */

/* Logging would recurse indefinitely, so skip logger.c. strcmp isn't the most efficient, but
 * it's fine here since this is an off-nominal path anyways.
 *
 * Also, do not enable REALLY_STRICT_LOCKING on a production system, it can cause assertions even when nothing is wrong with the BBS. */
#ifdef REALLY_STRICT_LOCKING
#define lock_warning(fmt, ...) if (strcmp(filename, "logger.c")) { __bbs_log(LOG_WARNING, 0, filename, lineno, func, fmt, ## __VA_ARGS__); bbs_assert(0); } else { fprintf(stderr, fmt, ## __VA_ARGS__); }
#define lock_error(fmt, ...) if (strcmp(filename, "logger.c")) { __bbs_log(LOG_ERROR, 0, filename, lineno, func, fmt, ## __VA_ARGS__); bbs_assert(0); } else { fprintf(stderr, fmt, ## __VA_ARGS__); }
#elif defined(STRICT_LOCKING)
#define lock_warning(fmt, ...) if (strcmp(filename, "logger.c")) { __bbs_log(LOG_WARNING, 0, filename, lineno, func, fmt, ## __VA_ARGS__); } else { fprintf(stderr, fmt, ## __VA_ARGS__); }
#define lock_error(fmt, ...) if (strcmp(filename, "logger.c")) { __bbs_log(LOG_ERROR, 0, filename, lineno, func, fmt, ## __VA_ARGS__); bbs_assert(0); } else { fprintf(stderr, fmt, ## __VA_ARGS__); }
#else
#define lock_warning(fmt, ...) if (strcmp(filename, "logger.c")) { __bbs_log(LOG_WARNING, 0, filename, lineno, func, fmt, ## __VA_ARGS__); } else { fprintf(stderr, fmt, ## __VA_ARGS__); }
#define lock_error(fmt, ...) if (strcmp(filename, "logger.c")) { __bbs_log(LOG_ERROR, 0, filename, lineno, func, fmt, ## __VA_ARGS__); bbs_log_backtrace(); } else { fprintf(stderr, fmt, ## __VA_ARGS__); }
#endif

#define lock_notice(fmt, ...) if (strcmp(filename, "logger.c")) { __bbs_log(LOG_WARNING, 0, filename, lineno, func, fmt, ## __VA_ARGS__); bbs_log_backtrace(); } else { fprintf(stderr, fmt, ## __VA_ARGS__); }

#define lock_debug(fmt, ...) if (strcmp(filename, "logger.c")) { __bbs_log(LOG_DEBUG, 8, filename, lineno, func, fmt, ## __VA_ARGS__); } else { fprintf(stderr, fmt, ## __VA_ARGS__); }

#define STORE_CALLER_INFO() \
	safe_strncpy(t->info.filename, filename, sizeof(t->info.filename)); \
	t->info.lineno = lineno; \
	t->info.lwp = bbs_gettid(); 

static int was_statically_initialized(struct bbs_lock_info *info)
{
	/* This could have false positives but can't have false negatives.
	 * There's no way to be 100% sure this isn't a false postive, but
	 * check various fields that should tell us if this was statically initialized or not. */
	return info->initialized && info->staticinit && !info->destroyed && !info->owners && info->filename[0] == '\0' && info->lineno == 0;
}

int __bbs_mutex_init(bbs_mutex_t *t, const char *filename, int lineno, const char *func, const char *name)
{
	int res;
	int staticinit;

	/* If the lock is not static, we explicitly have to zero it out first,
	 * since there's currently garbage here, so we can't check if it
	 * was already initialized already. */
	staticinit = was_statically_initialized(&t->info);

	if (ALWAYS_INITIALIZE || !staticinit) {
		memset(t, 0, sizeof(struct bbs_mutex));
		memset(&t->info, 0, sizeof(struct bbs_lock_info)); /* This seems to be necessary, for some reason */
	} else if (unlikely(t->info.initialized)) {
		lock_warning("Mutex %s already %s initialized at %s:%d\n", name, t->info.staticinit ? "statically" : "dynamically",  t->info.filename, t->info.lineno);
		return -1;
	} else if (unlikely(t->info.destroyed)) {
		lock_error("Attempt to initialize mutex %s previously destroyed at %s:%d\n", name, t->info.filename, t->info.lineno);
	}

	res = pthread_mutex_init(&t->mutex, NULL);
	if (!res) {
		t->info.initialized = 1;
		STORE_CALLER_INFO();
	}
	bbs_assert(t->info.owners == 0);
	return res;
}

int __bbs_mutex_destroy(bbs_mutex_t *t, const char *filename, int lineno, const char *func, const char *name)
{
	int res;

	if (unlikely(!t->info.initialized)) {
		lock_warning("Attempt to destroy uninitialized mutex %s\n", name);
	} else if (unlikely(t->info.destroyed)) {
		lock_error("Attempt to destroy mutex %s previously destroyed at %s:%d\n", name, t->info.filename, t->info.lineno);
	} else if (unlikely(t->info.owners > 0)) {
		lock_error("Attempt to destroy mutex %s locked at %s:%d\n", name, t->info.filename, t->info.lineno);
	}

	res = pthread_mutex_destroy(&t->mutex);
	if (!res) {
		t->info.destroyed = 1;
		STORE_CALLER_INFO();
	}
	return res;
}

int __bbs_mutex_lock(bbs_mutex_t *t, const char *filename, int lineno, const char *func, const char *name)
{
	int res;
#ifdef DETECT_DEADLOCKS
	int c = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized" /* now cannot be used uninitialized since c % 1000 is 0 the first loop */
	time_t now, elapsed, start = 0;
#endif

	if (unlikely(!t->info.initialized)) {
		lock_warning("Attempt to lock uninitialized mutex %s\n", name);
	} else if (unlikely(t->info.destroyed)) {
		lock_error("Attempt to lock mutex %s previously destroyed at %s:%d\n", name, t->info.filename, t->info.lineno);
	}

#ifdef DETECT_DEADLOCKS
	res = pthread_mutex_trylock(&t->mutex);
	while (res == EBUSY) {
		time_t diff;
		/* We sleep for 1 ms between attempts,
		 * so if 10 seconds pass, it's *probably* a deadlock... */
		if (c++ % 1000 == 0) {
			now = time(NULL); /* Only record time once a second */
			if (!start) {
				start = now;
			}
			elapsed = now - start; /* Amount of time we've been waiting for this lock */
			diff = now - t->info.lastlocked; /* Amount of time this lock has been held */
#pragma GCC diagnostic pop
			if (diff < elapsed) {
				/* When we started, the mutex wasn't available, so t->info.lastlocked must
				 * have been at least as older as start. If it suddenly happens that
				 * t->info.lastlocked is newer than start, that means that the mutex was released
				 * and acquired by some other thread (not us, unfortunately).
				 * In this case, the lock is making progress, so it's probably not a deadlock.
				 * Reset the start time and keep retrying. */
				lock_debug("Spent %ld seconds so far waiting for mutex %s (Mutex acquired at %s:%d %ld s ago by LWP %d)\n",
					diff, name, t->info.filename, t->info.lineno, elapsed, t->info.lwp);
				start = now;
			} else if (elapsed == 10) {
				/* Preliminary warning if we think we've encountered a deadlock. */
				lock_notice("Spent %ld seconds so far waiting for mutex %s, possible deadlock? (Mutex acquired at %s:%d %ld s ago by LWP %d)\n",
					diff, name, t->info.filename, t->info.lineno, elapsed, t->info.lwp);
#ifndef STRICT_LOCKING
				/* We always log a backtrace when we think a deadlock has occured, for debugging purposes.
				 * lock_notice already does this with STRICT_LOCKING, so we only need to do this explicitly here
				 * if that wasn't defined. */
				bbs_log_backtrace();
#endif
			} else if (elapsed == 300) {
				/* Okay, this is ridiculous. It should never take 5 minutes to acquire a lock.
				 * In theory, it could, but there shouldn't be anything that actually does in the BBS. */
				lock_warning("Spent %ld seconds so far waiting for mutex %s, probable deadlock? (Mutex acquired at %s:%d %ld s ago by LWP %d)\n",
					diff, name, t->info.filename, t->info.lineno, elapsed, t->info.lwp);
			}
		}
		usleep(1000);
		res = pthread_mutex_trylock(&t->mutex);
	}
#else
	res = pthread_mutex_lock(&t->mutex);
#endif /* DETECT_DEADLOCKS */
	if (unlikely(res)) {
		lock_warning("Failed to obtain mutex %s: %s\n", name, strerror(res));
	} else {
		t->info.lastlocked = time(NULL);
		if (unlikely(++t->info.owners != 1)) {
			lock_error("Mutex %s locked more than once?\n", name);
		}
		STORE_CALLER_INFO();
	}

	return res;
}

int __bbs_mutex_trylock(bbs_mutex_t *t, const char *filename, int lineno, const char *func, const char *name)
{
	int res;

	if (unlikely(!t->info.initialized)) {
		lock_warning("Attempt to lock uninitialized mutex %s\n", name);
	} else if (unlikely(t->info.destroyed)) {
		lock_error("Attempt to lock mutex %s previously destroyed at %s:%d\n", name, t->info.filename, t->info.lineno);
	}

	res = pthread_mutex_trylock(&t->mutex);
	if (!res) {
		t->info.lastlocked = time(NULL);
		if (unlikely(++t->info.owners != 1)) {
			lock_error("Mutex %s locked more than once?\n", name);
		}
		STORE_CALLER_INFO();
	}

	return res;
}

int __bbs_mutex_unlock(bbs_mutex_t *t, const char *filename, int lineno, const char *func, const char *name)
{
	int res;

	if (unlikely(!t->info.initialized)) {
		lock_warning("Attempt to unlock uninitialized mutex %s\n", name);
	} else if (unlikely(t->info.destroyed)) {
		lock_error("Attempt to unlock mutex %s previously destroyed at %s:%d\n", name, t->info.filename, t->info.lineno);
	} else if (unlikely(t->info.owners < 1)) {
		lock_error("Attempt to unlock unheld mutex %s\n", name);
	}

	if (unlikely(--t->info.owners < 0)) {
		lock_error("Mutex %s unlocked more times than it was locked\n", name);
	}

	res = pthread_mutex_unlock(&t->mutex);
	if (unlikely(res)) {
		lock_warning("Failed to unlock mutex %s\n", name);
	}

	return res;
}

int __bbs_rwlock_init(bbs_rwlock_t *t, const char *filename, int lineno, const char *func, const char *name)
{
	int res;
	int staticinit;

	/* If the lock is not static, we explicitly have to zero it out first,
	 * since there's currently garbage here, so we can't check if it
	 * was already initialized already. */
	staticinit = was_statically_initialized(&t->info);

	if (ALWAYS_INITIALIZE || !staticinit) {
		memset(t, 0, sizeof(struct bbs_mutex));
		memset(&t->info, 0, sizeof(struct bbs_lock_info)); /* This seems to be necessary, for some reason */
	} else if (unlikely(t->info.initialized)) {
		lock_warning("Lock %s already %s initialized at %s:%d\n", name, t->info.staticinit ? "statically" : "dynamically", t->info.filename, t->info.lineno);
		return -1;
	} else if (unlikely(t->info.destroyed)) {
		lock_error("Attempt to initialize mutex %s previously destroyed at %s:%d\n", name, t->info.filename, t->info.lineno);
	}

	pthread_mutex_init(&t->intlock, NULL);
	res = pthread_rwlock_init(&t->lock, NULL);
	if (!res) {
		t->info.initialized = 1;
		STORE_CALLER_INFO();
	}
	bbs_assert(t->info.owners == 0);
	return res;
}

int __bbs_rwlock_destroy(bbs_rwlock_t *t, const char *filename, int lineno, const char *func, const char *name)
{
	int res;

	if (unlikely(!t->info.initialized)) {
		lock_warning("Attempt to destroy uninitialized lock %s\n", name);
	} else if (unlikely(t->info.destroyed)) {
		lock_error("Attempt to destroy lock %s previously destroyed at %s:%d\n", name, t->info.filename, t->info.lineno);
	} else if (unlikely(t->info.owners > 0)) {
		lock_error("Attempt to destroy lock %s with %d owner%s, last locked at %s:%d\n", name, t->info.owners, ESS(t->info.owners), t->info.filename, t->info.lineno);
	}

	pthread_mutex_destroy(&t->intlock);
	res = pthread_rwlock_destroy(&t->lock);
	if (!res) {
		t->info.destroyed = 1;
		STORE_CALLER_INFO();
	}
	return res;
}

int __bbs_rwlock_rdlock(bbs_rwlock_t *t, const char *filename, int lineno, const char *func, const char *name)
{
	int res;
#ifdef DETECT_DEADLOCKS
	int c = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized" /* now cannot be used uninitialized since c % 1000 is 0 the first loop */
	time_t now, elapsed, start = 0;
#endif

	if (unlikely(!t->info.initialized)) {
		lock_warning("Attempt to rdlock uninitialized lock %s\n", name);
	} else if (unlikely(t->info.destroyed)) {
		lock_error("Attempt to rdlock lock %s previously destroyed at %s:%d\n", name, t->info.filename, t->info.lineno);
	}

#ifdef DETECT_DEADLOCKS
	/* Similar lock as in bbs_mutex_lock for DETECT_DEADLOCKS */
	res = pthread_rwlock_tryrdlock(&t->lock);
	while (res == EBUSY) {
		time_t diff;
		if (c++ % 1000 == 0) {
			now = time(NULL);
			if (!start) {
				start = now;
			}
			elapsed = now - start;
			diff = now - t->info.lastlocked;
#pragma GCC diagnostic pop
			if (diff < elapsed) {
				lock_debug("Spent %ld seconds so far waiting to rdlock %s (rwlock acquired at %s:%d %ld s ago by LWP %d)\n",
					diff, name, t->info.filename, t->info.lineno, elapsed, t->info.lwp);
				start = now;
			} else if (elapsed == 30) { /* Use a higher threshold for rwlocks than mutexes, since there could be multiple readers */
				/* Preliminary warning if we think we've encountered a deadlock. */
				lock_notice("Spent %ld seconds so far waiting to rdlock %s, possible deadlock? (rwlock acquired at %s:%d %ld s ago by LWP %d)\n",
					diff, name, t->info.filename, t->info.lineno, elapsed, t->info.lwp);
#ifndef STRICT_LOCKING
				bbs_log_backtrace();
#endif
			} else if (elapsed == 300) {
				/* Okay, this is ridiculous. It should never take 5 minutes to acquire a lock.
				 * In theory, it could, but there shouldn't be anything that actually does in the BBS. */
				lock_warning("Spent %ld seconds so far waiting to rdlock %s, probable deadlock? (rwlock acquired at %s:%d %ld s ago by LWP %d)\n",
					diff, name, t->info.filename, t->info.lineno, elapsed, t->info.lwp);
			}
		}
		usleep(1000);
		res = pthread_rwlock_tryrdlock(&t->lock);
	}
#else
	res = pthread_rwlock_rdlock(&t->lock);
#endif /* DETECT_DEADLOCKS */
	if (unlikely(res)) {
		lock_warning("Failed to obtain rdlock %s: %s\n", name, strerror(res));
	} else {
		pthread_mutex_lock(&t->intlock);
		t->info.lastlocked = time(NULL);
		if (unlikely(++t->info.owners > MAX_READERS)) {
			lock_warning("Lock %s has %d readers?\n", name, t->info.owners);
		}
		STORE_CALLER_INFO();
		pthread_mutex_unlock(&t->intlock);
	}

	return res;
}

int __bbs_rwlock_wrlock(bbs_rwlock_t *t, const char *filename, int lineno, const char *func, const char *name)
{
	int res;
#ifdef DETECT_DEADLOCKS
	int c = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized" /* now cannot be used uninitialized since c % 1000 is 0 the first loop */
	time_t now, elapsed, start = 0;
#endif

	if (unlikely(!t->info.initialized)) {
		lock_warning("Attempt to wrlock uninitialized lock %s\n", name);
	} else if (unlikely(t->info.destroyed)) {
		lock_error("Attempt to wrlock lock %s previously destroyed at %s:%d\n", name, t->info.filename, t->info.lineno);
	}

#ifdef DETECT_DEADLOCKS
	/* Similar lock as in bbs_mutex_lock for DETECT_DEADLOCKS */
	res = pthread_rwlock_trywrlock(&t->lock);
	while (res == EBUSY) {
		time_t diff;
		if (c++ % 1000 == 0) {
			now = time(NULL);
			if (!start) {
				start = now;
			}
			elapsed = now - start;
			diff = now - t->info.lastlocked;
#pragma GCC diagnostic pop
			if (diff < elapsed) {
				lock_debug("Spent %ld seconds so far waiting to wrlock %s (rwlock acquired at %s:%d %ld s ago by LWP %d)\n",
					diff, name, t->info.filename, t->info.lineno, elapsed, t->info.lwp);
				start = now;
			} else if (elapsed == 30) { /* Use a higher threshold for rwlocks than mutexes, since there could be multiple readers */
				/* Preliminary warning if we think we've encountered a deadlock. */
				lock_notice("Spent %ld seconds so far waiting to wrlock %s, possible deadlock? (rwlock acquired at %s:%d %ld s ago by LWP %d)\n",
					diff, name, t->info.filename, t->info.lineno, elapsed, t->info.lwp);
#ifndef STRICT_LOCKING
				bbs_log_backtrace();
#endif
			} else if (elapsed == 300) {
				/* Okay, this is ridiculous. It should never take 5 minutes to acquire a lock.
				 * In theory, it could, but there shouldn't be anything that actually does in the BBS. */
				lock_warning("Spent %ld seconds so far waiting to wrlock %s, probable deadlock? (rwlock acquired at %s:%d %ld s ago by LWP %d)\n",
					diff, name, t->info.filename, t->info.lineno, elapsed, t->info.lwp);
			}
		}
		usleep(1000);
		res = pthread_rwlock_trywrlock(&t->lock);
	}
#else
	res = pthread_rwlock_wrlock(&t->lock);
#endif /* DETECT_DEADLOCKS */
	if (unlikely(res)) {
		lock_warning("Failed to obtain wrlock %s: %s\n", name, strerror(res));
	} else {
		/* If wrlock succeeded, we don't need to lock the internal mutex, since there can't be any readers right now */
		t->info.lastlocked = time(NULL);
		if (++t->info.owners != 1) {
			lock_error("Lock %s locked more than once?\n", name);
		}
		STORE_CALLER_INFO();
	}

	return res;
}

int __bbs_rwlock_tryrdlock(bbs_rwlock_t *t, const char *filename, int lineno, const char *func, const char *name)
{
	int res;

	if (unlikely(!t->info.initialized)) {
		lock_warning("Attempt to rdlock uninitialized lock %s\n", name);
	} else if (unlikely(t->info.destroyed)) {
		lock_error("Attempt to rdlock lock at %s previously destroyed at %s:%d\n", name, t->info.filename, t->info.lineno);
	}

	res = pthread_rwlock_tryrdlock(&t->lock);
	if (!res) {
		pthread_mutex_lock(&t->intlock);
		t->info.lastlocked = time(NULL);
		if (unlikely(++t->info.owners > MAX_READERS)) {
			lock_warning("Lock %s has %d readers?\n", name, t->info.owners);
		}
		STORE_CALLER_INFO();
		pthread_mutex_unlock(&t->intlock);
	}

	return res;
}

int __bbs_rwlock_trywrlock(bbs_rwlock_t *t, const char *filename, int lineno, const char *func, const char *name)
{
	int res;

	if (unlikely(!t->info.initialized)) {
		lock_warning("Attempt to wrlock uninitialized lock %s\n", name);
	} else if (unlikely(t->info.destroyed)) {
		lock_error("Attempt to wrlock lock %s previously destroyed at %s:%d\n", name, t->info.filename, t->info.lineno);
	}

	res = pthread_rwlock_trywrlock(&t->lock);
	if (!res) {
		/* If wrlock succeeded, we don't need to lock the internal mutex, since there can't be any readers right now */
		t->info.lastlocked = time(NULL);
		t->info.owners++;
		STORE_CALLER_INFO();
	}

	return res;
}

int __bbs_rwlock_unlock(bbs_rwlock_t *t, const char *filename, int lineno, const char *func, const char *name)
{
	int res;

	if (unlikely(!t->info.initialized)) {
		lock_warning("Attempt to unlock uninitialized lock %s\n", name);
	} else if (unlikely(t->info.destroyed)) {
		lock_error("Attempt to unlock lock %s previously destroyed at %s:%d\n", name, t->info.filename, t->info.lineno);
	} else if (unlikely(t->info.owners < 1)) {
		lock_error("Attempt to unlock unheld lock %s\n", name);
	}

	/* Technically, if we had a wrlock, we don't need to use the internal mutex,
	 * but we don't keep track of that. */
	pthread_mutex_lock(&t->intlock);
	if (unlikely(--t->info.owners < 0)) {
		lock_error("Lock %s unlocked more times than it was locked\n", name);
	}
	pthread_mutex_unlock(&t->intlock);

	res = pthread_rwlock_unlock(&t->lock);
	if (unlikely(res)) {
		lock_warning("Failed to unlock lock %s\n", name);
	}

	return res;
}
