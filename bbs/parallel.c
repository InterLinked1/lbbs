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
 * \brief Parallel Task Framework
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include "include/alertpipe.h"
#include "include/parallel.h"
#include "include/utils.h"

/* Yes, this kind of looks like a threadpool.
 * No, it's not a threadpool. */

/*! \note This code was originally written specifically for and embedded in net_imap.
 * While the code is completely generic, there are still some net_imap specific comments
 * that have been left here. */

/* imap/imap_client_list.c: Unlike normal non-parallel operations, we need to carefully coordinate
 * use of the different imap_client's, because we can't have 2 threads
 * trying to use the same client at once.
 * Naturally won't happen for LIST, where we do one per account,
 * but could happen for STATUS if we do potentially multiple folders/acct at once. */

#define DEBUG_PARALLEL_TASKS

void bbs_parallel_init(struct bbs_parallel *p, unsigned int min, unsigned int max)
{
	memset(p, 0, sizeof(struct bbs_parallel));
	RWLIST_HEAD_INIT(&p->tasks);
	p->min_parallel_tasks = min;
	p->max_parallel_tasks = max;
#ifdef DEBUG_PARALLEL_TASKS
	bbs_debug(7, "Initializing parallel task set (parallelism range: %u-%u)\n", min, max);
#endif
}

static int task_match(struct bbs_parallel *p, int started, int completed, struct bbs_parallel_task *task, unsigned long hash)
{
	struct bbs_parallel_task *t;
	RWLIST_TRAVERSE(&p->tasks, t, entry) {
		if (t == task) {
			continue;
		}
		if (t->started != started) {
			continue;
		}
		if (t->completed != completed) {
			continue;
		}
		if (t->hash == hash) {
			return 1;
		}
	}
	return 0;
}

/*! \note Must be called locked */
static struct bbs_parallel_task *next_task(struct bbs_parallel *p, unsigned int maxconcurrent, int *throttled)
{
	unsigned int total_running = 0;
	struct bbs_parallel_task *t;
	RWLIST_TRAVERSE(&p->tasks, t, entry) {
		if (t->started) { /* t->started implies t->completed, no need to check that as well */
			if (!t->completed) {
				total_running++;
			}
			continue;
		}
		/* We can't execute this task if another task is currently running with the same hash. */
		/* imap/imap_client_list.c: This absolutely MUST be enforced. imap_client's are not thread safe,
		 * we cannot have two different tasks using the same underlying imap_client at ANY time. */
		if (task_match(p, 1, 0, t, t->hash)) {
#ifdef DEBUG_PARALLEL_TASKS
			bbs_debug(8, "Can't execute task %p, currently executing task with same hash (%lu)\n", t, t->hash);
#endif
			continue;
		}
		break;
	}
	if (maxconcurrent && total_running >= maxconcurrent) { /* Reached concurrent thread limit */
		*throttled = 1;
		bbs_debug(6, "Delaying subsequent task execution (currently at %u concurrent)\n", total_running);
		return NULL;
	} else if (!t && total_running) { /* Couldn't find a suitable task */
		bbs_debug(6, "Unable to find suitable task for immediate execution (%u running)\n", total_running);
		*throttled = 1;
		return NULL;
	}
	return t;
}

static void *run_task(void *varg)
{
	int throttled = 0;
	struct bbs_parallel_task *t = varg;
	struct bbs_parallel *p = t->p;

	bbs_debug(6, "Spawned thread for task %p\n", t);
	for (;;) {
		struct bbs_parallel_task *t2;
		t->res = t->cb(t->data);
		t->completed = 1;

		/* To make this "threadpool like",
		 * we can easily reuse this thread to execute a different task. */
		RWLIST_WRLOCK(&p->tasks);
		/* No need to be concerned here with concurrent execution limits.
		 * If it was fine that this task was already running, it's fine
		 * if we replace it with another task. */
		t2 = next_task(p, 0, &throttled); /* throttled is not used since we don't throttle */
		if (!t2) {
			RWLIST_UNLOCK(&p->tasks);
			break;
		}
		t2->started = 1;
		t2->thread = t->thread;
		/* Don't join the current thread for this task, since it now belongs to another task */
		t->thread = 0; /* XXX If pthread_t can ever be 0, this is a problem, since 0 is used as an initializer throughout the BBS */
		t = t2;
		RWLIST_UNLOCK(&p->tasks);
		bbs_debug(6, "Reusing thread for task %p\n", t);
	}

	/* Can't just return, there could be multiple task threads still running that haven't finished yet. */
	if (!throttled) {
		/* This means there were no suitable tasks to execute (but there are still further tasks to execute).
		 * There's no point in notifying the parent now, because we just found out there's no suitable tasks.
		 * Nothing will change that until another task finishes, so that thread can notify the parent instead. */
		bbs_alertpipe_write(p->alertpipe);
	}
	return NULL;
}

/* \retval 0 if a task was scheduled, -1 if tasks could not be scheduled, 1 if there are no further tasks to schedule */
static int run_scheduler(struct bbs_parallel *p)
{
	int remaining = 0;
	int throttled = 0;
	struct bbs_parallel_task *t;

	/* Look through the list for a suitable task to schedule */
	RWLIST_WRLOCK(&p->tasks);
	t = next_task(p, p->max_parallel_tasks, &throttled);
	if (!t) {
		/* Perhaps we've reached the concurrent execution limit */
		RWLIST_UNLOCK(&p->tasks);
		return throttled ? 0 : 1; /* If throttled, pretend we scheduled successfully, there will be more to schedule later */
	}
	t->started = 1;

	/* Probably more efficient to have a threadpool rather than creating and joining threads
	 * for each task. But the whole optimization of tasks is intended to save hundreds of milliseconds
	 * to many seconds, so a few ms of overhead is perfectly fine for the simplicity of this interface. */
	if (bbs_pthread_create(&t->thread, NULL, run_task, t)) {
		t->started = 0;
		RWLIST_UNLOCK(&p->tasks);
		return 0; /* We still need to run this task */
	}
	/* Successfully scheduled something */
	RWLIST_UNLOCK(&p->tasks);
	/* We couldn't schedule anything! That probably means we're all done. */
	return remaining ? -1 : 1;
}

/*!
 * \brief Fast hashing function for strings
 * \note See: http://www.cse.yorku.ca/~oz/hash.html
 */
static unsigned long fast_hash(unsigned const char *restrict s)
{
	unsigned long hash = 5381;
	int c;

	while ((c = *s++)) {
		hash = ((hash << 5) + hash) + (long unsigned) c; /* hash * 33 + c */
	}
	return hash;
}

int bbs_parallel_schedule_task(struct bbs_parallel *p, const char *restrict prefix, void *data, int (*cb)(void *data), void *(*duplicate)(void *data), void (*cleanup)(void *data))
{
	struct bbs_parallel_task *t;
	void *datadup;

	/* XXX Or if we know there won't be any more tasks coming (either only 1, or this is the last one),
	 * we might as well just do it directly as well */
	if (p->max_parallel_tasks <= 1) {
		/* Use the stack allocated version directly, since we won't be able to take advantage of concurrency anyways. */
		/* imap/imap_client_list.c: XXX Problem is this MIGHT not be safe if one is already in use, in a parallel task?
		 * imap_client_get should create a new client if we already have one but it's in use for a parallel job.
		 * That'll take care of the case where a static job like this requests it,
		 * or if we accidentally request it for a parallel job (which shouldn't happen,
		 * since we shouldn't be scheduling tasks for the same IMAP client at the same time). */
#ifdef DEBUG_PARALLEL_TASKS
		bbs_debug(7, "Parallelism inhibited (max parallel tasks: %u), running task serially\n", p->max_parallel_tasks);
#endif
		return cb(data);
	}

	/* Set up a parallel task instead */
	if (duplicate) {
		datadup = duplicate(data); /* Allocate a heap allocated version of the stack structure since we can't execute this in the current thread */
		if (!datadup) {
			/* If duplicate function returns NULL, then we must execute in serial.
			 * imap/imap_client_list.c: This might not always indicate failure. Maybe for this task, it's been determined that it's better to do it this way
			 * (e.g. the remote server supports LIST-STATUS, so this will be a fast operation) */
			return cb(data);
		}
	} else {
		datadup = data; /* Just use the data directly, if we don't need to duplicate it */
	}
	t = calloc(1, sizeof(*t));
	if (ALLOC_FAILURE(t)) {
		if (cleanup) {
			cleanup(datadup);
		}
		return cb(data);
	}

	if (!p->initialized) {
		/* Set up an alertpipe for signaling.
		 * We want to be able to be notified whenever any of the child threads finishes executing.
		 * Basically, something like waitpid(-1, &wstatus, 0);
		 * However, pthreads has no equivalent to "wait for any thread", you have to specify a particular thread. */
		if (bbs_alertpipe_create(p->alertpipe)) {
			if (cleanup) {
				cleanup(datadup);
			}
			free(t);
			return cb(data);
		}
		p->initialized = 1;
	}

	t->data = datadup;
	/* Keep track of functions we'll need to execute (whether now or later) in a different thread */
	t->cb = cb;
	t->cleanup = cleanup;
	t->p = p;
	t->hash = fast_hash((unsigned const char *restrict) prefix); /* Use a fast hash for constant time comparisons */

	bbs_debug(7, "Scheduled task with prefix %s (hash %lu) for delayed, parallel execution\n", prefix, t->hash);

	/* Actually push the task onto p. Don't explicitly schedule the task now, it might not be appropriate to start it immediately. */
	RWLIST_WRLOCK(&p->tasks);
	RWLIST_INSERT_TAIL(&p->tasks, t, entry);
	RWLIST_UNLOCK(&p->tasks);

	return run_scheduler(p);
}

int bbs_parallel_join(struct bbs_parallel *p)
{
	struct bbs_parallel_task *t;
	int res; /* Maybe there are no tasks (everything was executed serially), assume success by default */

	if (!p->initialized) {
#ifdef DEBUG_PARALLEL_TASKS
		bbs_debug(3, "No parallel tasks initialized, nothing to join\n");
#endif
		return 0;
	}

	/* At this point, all tasks have already been created.
	 * Keep joining threads and scheduling tasks until there are no tasks left */
	for (;;) {
		/* We're interested in threads for tasks that have been started, but aren't yet completed.
		 * If there aren't any, then everything has finished executing. */
		res = bbs_alertpipe_poll(p->alertpipe, -1);
		/* A thread exited. */
		bbs_alertpipe_read(p->alertpipe);
		res = run_scheduler(p);
		if (res == 1) {
			/* No more tasks left to execute. We can go ahead and join any remaining threads. */
			res = 0;
			break;
		} else if (res) {
			bbs_warning("Parallel job scheduling failure\n");
			break;
		}
		/* Scheduled another task. Go round for another loop. */
	}

	/* Join all threads (and clean up the tasks) */
	RWLIST_WRLOCK(&p->tasks);
	while ((t = RWLIST_REMOVE_HEAD(&p->tasks, entry))) {
		/* Release the lock before we call pthread_join, and acquire it again before continuing.
		 * Since we've removed t at this point, there's no need to keep it locked.
		 * If we do, it is possible for deadlock to occur, if the thread we try to join here
		 * needs to acquire the list lock before it can finish. */
		RWLIST_UNLOCK(&p->tasks);
		if (!t->started) {
			bbs_error("In join phase, but task %p hasn't been started?\n", t); /* Shouldn't happen */
		} else if (!t->completed) {
			bbs_debug(6, "Waiting for task %p to finish executing...\n", t);
			/* Proceed, bbs_pthread_join will block for a bit though */
		}
		if (t->thread) { /* If this task was/is the last user of this thread, clean it up */
			bbs_pthread_join(t->thread, NULL);
		}
		if (t->cleanup) {
			t->cleanup(t->data);
		}
		free(t);
		RWLIST_WRLOCK(&p->tasks);
	}
	RWLIST_UNLOCK(&p->tasks);

	RWLIST_HEAD_DESTROY(&p->tasks);

	bbs_alertpipe_close(p->alertpipe);
	bbs_debug(6, "Parallel task set has finished\n");
	return res;
}
