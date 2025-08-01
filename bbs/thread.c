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
 * \brief Thread management
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#define BBS_PTHREAD_WRAPPER_FILE

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <signal.h> /* use pthread_kill */

#ifdef __FreeBSD__
#include <sys/thr.h>
#endif

#include "include/utils.h"
#include "include/linkedlists.h"
#include "include/cli.h"

static __thread int my_tid = 0;

int bbs_gettid(void)
{
	int tid;

	/* If we've called this before, return the cached value to avoid a system call.
	 * Since every call to __bbs_log calls bbs_gettid, this is an important optimization. */
	if (likely(my_tid)) {
		return my_tid;
	}

	/* We cannot merely have a macro defining gettid if it's not defined,
	 * because the native return types of gettid and SYS_gettid differ.
	 * Here, we implicitly cast to int before returning.
	 */
#ifdef gettid
	/* gettid() is not very portable at all.
	 * It works on Debian 11 but not on Debian 10 for me. */
	tid = gettid();
#elif defined(__linux__)
	tid = (int) syscall(SYS_gettid);
#elif defined(__FreeBSD__)
	{
		long lwpid;
		thr_self(&lwpid);
		tid = (int) lwpid;
	}
#else
#error "gettid not implemented for this platform"
#endif
	my_tid = tid; /* Save the value for future reference, so we don't need to do this again. */
	return tid;
}

struct thread_list_t {
	RWLIST_ENTRY(thread_list_t) list;
	char *name;
	pthread_t id;
	int lwp;
	time_t start;
	time_t end;
	unsigned int detached:1;
	unsigned int waitingjoin:1;
};

static RWLIST_HEAD_STATIC(thread_list, thread_list_t);

static int lifetime_threads = 0;

static void thread_register(char *name, int detached)
{
	struct thread_list_t *new = calloc(1, sizeof(*new));

	if (ALLOC_FAILURE(new)) {
		return;
	}

	new->start = time(NULL);
	new->id = pthread_self();
	new->lwp = bbs_gettid();
	new->name = name; /* steal the allocated memory for the thread name */
	SET_BITFIELD(new->detached, detached);
	RWLIST_WRLOCK(&thread_list);
	RWLIST_INSERT_TAIL(&thread_list, new, list);
	lifetime_threads++;
	RWLIST_UNLOCK(&thread_list);
	bbs_debug(3, "Thread %d spawned from %s\n", new->lwp, new->name);
}

static int __thread_unregister(pthread_t id, const char *file, int line, const char *func)
{
	struct thread_list_t *x;
	int remove = 0;
	int lwp = -1;

#if defined(__linux__) && defined(__GLIBC__)
	/* For some reason, when detached threads exit on ARM (as opposed to x86),
	 * the thread id is 1, rather than an actual thread.
	 * However, since it's being run in the context of the exiting thread,
	 * we can use pthread_self() to get the actual thread and then everything else works as expected. */
	if (id == 1) {
		id = pthread_self();
	}
#endif

	RWLIST_WRLOCK(&thread_list);
	RWLIST_TRAVERSE_SAFE_BEGIN(&thread_list, x, list) {
#ifdef __FreeBSD__
		/* Need both checks and it works */
		if ((unsigned long) x->id == (unsigned long) id || (unsigned long) x->lwp == (unsigned long) id) {
#else
		if (x->id == id) { /* pthread_t isn't numeric on FreeBSD, so this check only works on Linux. */
#endif
			if (x->detached || x->waitingjoin) {
				RWLIST_REMOVE_CURRENT(list);
				remove = 1;
			} else {
				x->waitingjoin = 1;
				x->end = time(NULL);
			}
			lwp = x->lwp;
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	if (x) {
		if (remove) {
			if (x->detached) {
				bbs_debug(3, "Thread %d is exiting (detached)\n", x->lwp);
			} else {
				bbs_debug(3, "Thread %d has been joined by thread %d at %s:%d %s()\n", x->lwp, bbs_gettid(), file, line, func);
			}
			free_if(x->name);
			free(x);
		} else {
			bbs_debug(3, "Thread %d is exiting (%s)\n", lwp, "must be joined");
		}
	} else {
		bbs_error("Thread %lu not found?\n", (unsigned long) id);
	}
	/* On shutdown, bbs_thread_cleanup will occur right after all modules have unloaded, i.e. all child threads have exited.
	 * If we release the lock right after the traversal ends, bbs_thread_cleanup will find the list empty and return, and
	 * then bbs_log_close is called not long afterwards, i.e. the logger could proceed to shut down before we finish logging above. */
	RWLIST_UNLOCK(&thread_list);
	return lwp;
}

static const char *thread_state_name(struct thread_list_t *cur)
{
	return cur->detached ? "detached" : cur->waitingjoin ? "waitjoin" : "joinable";
}

/*!
 * \brief Print list of active BBS threads
 * \warning This may not include all threads, such as those that do not use the BBS pthread creation wrappers (external libraries, etc.)
 */
static int cli_threads(struct bbs_cli_args *a)
{
	char elapsed[24];
	int threads = 0;
	struct thread_list_t *cur;
	time_t now = time(NULL);

	bbs_dprintf(a->fdout, "%3d %6d (%s)\n", 0, getpid(), "PID / main thread");
	RWLIST_RDLOCK(&thread_list);
	RWLIST_TRAVERSE(&thread_list, cur, list) {
		threads++;
		print_time_elapsed(cur->waitingjoin ? cur->end : cur->start, now, elapsed, sizeof(elapsed));
		bbs_dprintf(a->fdout, "%3d %6d (%9lu) [%12p] (%s %10s) %s\n", threads, cur->lwp, (unsigned long) cur->id, (void *) cur->id, thread_state_name(cur), elapsed, cur->name);
	}
	RWLIST_UNLOCK(&thread_list);
	bbs_dprintf(a->fdout, "%d active threads registered, %d lifetime threads (may be incomplete).\n", threads, lifetime_threads);
	return 0;
}

static struct bbs_cli_entry cli_commands_threads[] = {
	BBS_CLI_COMMAND(cli_threads, "threads", 1, "List registered threads", NULL),
};

int bbs_init_threads(void)
{
	return bbs_cli_register_multiple(cli_commands_threads);
}

void bbs_thread_cleanup(void)
{
	char elapsed[24];
	struct thread_list_t *x;
	time_t now = time(NULL);

	/* All spawned threads should have exited by now. Let's see if that's the case. */
	RWLIST_WRLOCK(&thread_list);
	while ((x = RWLIST_REMOVE_HEAD(&thread_list, list))) {
		/* In theory, all registered threads should have exited / been joined by this phase of shutdown.
		 * If not, then it's probably a bug, a thread we forgot to exit, join, etc.
		 * especially if it's a thread that has been in the waitjoin state for some time (more than a couple seconds).
		 * Be nice and free the memory anyways. */
		print_time_elapsed(x->waitingjoin ? x->end : x->start, now, elapsed, sizeof(elapsed));
#ifdef __linux__
		bbs_warning("Thread still registered at shutdown: %d [%lu] (%s %s) %s\n", x->lwp, (unsigned long) x->id, thread_state_name(x), elapsed, x->name);
#else
		bbs_warning("Thread still registered at shutdown: %d (%s %s) %s\n", x->lwp, thread_state_name(x), elapsed, x->name);
#endif
		free_if(x->name);
		free(x);
	}
	RWLIST_UNLOCK(&thread_list);
}

static void thread_unregister(void *id)
{
	pthread_t *thread = id;
	__thread_unregister(*thread, NULL, 0, NULL);
}

int bbs_pthread_tid(pthread_t thread)
{
	struct thread_list_t *x;
	int lwp = -1;

	RWLIST_RDLOCK(&thread_list);
	RWLIST_TRAVERSE(&thread_list, x, list) {
		if (thread == x->id) {
			lwp = x->lwp;
			break;
		}
	}
	RWLIST_UNLOCK(&thread_list);

	return lwp;
}

void bbs_pthread_disable_cancel(void)
{
	int oldstate;
	/* In LINUX, it's okay to pass NULL for the 2nd argument, but this is not portable. */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldstate);
}

void bbs_pthread_enable_cancel(void)
{
	int oldstate;
	/* In LINUX, it's okay to pass NULL for the 2nd argument, but this is not portable. */
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldstate);
}

int bbs_pthread_cancel_kill(pthread_t thread)
{
	int res;

	/* Log a message before calling pthread_cancel, since this is dangerous.
	 * In the unlikely event that a thread is cancelled while in a critical section,
	 * deadlock could ensue. I've suspected this might have been responsible for
	 * some issues in the past but few clues have been available to such activity,
	 * so this log message is an important clue if that happens (see [LBBS-86]). */
	bbs_debug(1, "Attempting to cancel thread %lu\n", (unsigned long) thread);

#undef pthread_cancel
	res = pthread_cancel(thread);
	if (res) {
		if (res == ESRCH) {
			bbs_debug(3, "Thread %lu no longer exists\n", (unsigned long) thread);
		} else {
			bbs_warning("Could not cancel thread %lu: %s\n", (unsigned long) thread, strerror(res));
		}
	}

	res = pthread_kill(thread, SIGURG);
	if (res) {
		if (res == ESRCH) {
			bbs_debug(3, "Thread %lu no longer exists\n", (unsigned long) thread);
		} else {
			bbs_warning("Could not kill thread %lu: %s\n", (unsigned long) thread, strerror(res));
		}
	} else {
		bbs_debug(3, "Killed thread %lu\n", (unsigned long) thread);
	}
	return res;
}

int bbs_pthread_interrupt(pthread_t thread)
{
	int res;
	bbs_debug(3, "Signaling thread %lu with SIGURG\n", (unsigned long) thread);
	res = pthread_kill(thread, SIGURG);
	if (res) {
		if (res == ESRCH) {
			bbs_debug(3, "Thread %lu no longer exists\n", (unsigned long) thread);
		} else {
			bbs_warning("Could not signal thread %lu: %s\n", (unsigned long) thread, strerror(res));
		}
	}
	return res;
}

static struct thread_list_t *find_thread(pthread_t thread, int *restrict lwp, int *restrict waiting_join, const char *file, const char *func, int line)
{
	struct thread_list_t *x;

	RWLIST_RDLOCK(&thread_list);
	RWLIST_TRAVERSE(&thread_list, x, list) {
		if (thread == x->id) {
			*lwp = x->lwp;
			if (x->detached) {
				bbs_error("Can't join detached LWP %d at %s:%d %s()\n", *lwp, file, line, func);
				*lwp = 0;
			}
			*waiting_join = x->waitingjoin;
			break;
		}
	}
	RWLIST_UNLOCK(&thread_list);

	return x;
}

int __bbs_pthread_join(pthread_t thread, void **retval, const char *file, const char *func, int line)
{
	void *tmp;
	int res;
	struct thread_list_t *x;
	int lwp;
	int waiting_join;

	bbs_soft_assert(thread != 0); /* Somebody tried to join the thread 0? (often used as NIL thread) */

	x = find_thread(thread, &lwp, &waiting_join, file, func, line);

	if (!x) {
		/* If we try joining a thread right after we created it, it's possible it hasn't actually begun running (and registered itself) yet.
		 * Wait a moment, then try again, since this shouldn't generally happen anyways.
		 * If we don't do this, this can cause a segfault for some reason,
		 * so it's good to be a bit generous with the timing here. */
		bbs_debug(3, "Thread %lu not registered, checking again momentarily\n", (unsigned long) thread);
		usleep(10000);
		x = find_thread(thread, &lwp, &waiting_join, file, func, line);
	}
	if (!x) {
		bbs_error("Thread %lu not registered\n", (unsigned long) thread);
		return -1;
	} else if (!lwp) {
		return -1;
	}

	bbs_debug(6, "Attempting to join thread %lu (LWP %d) at %s:%d %s()\n", (unsigned long) thread, lwp, file, line, func);

	if (!waiting_join) {
#ifdef __linux__
		struct timespec ts;
#if defined(__GLIBC__)
		time_t start = time(NULL);
#endif /* __GLIBC__ */
		/* This is suspicious... we may end up hanging if the thread doesn't exit imminently */
		/* Don't immediately emit a warning, because the thread may be just about to exit
		 * and thus wasn't waitingjoin when we checked. This prevents superflous warnings,
		 * by waiting to join for a brief moment and only warning if the thread doesn't join in that time. */
		if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
			bbs_error("clock_gettime failed: %s\n", strerror(errno));
		}
		ts.tv_sec += 2; /* Wait up to 2 seconds to start */
		res = pthread_timedjoin_np(thread, retval ? retval : &tmp, &ts); /* This is not POSIX portable */
		if (res == ETIMEDOUT) {
			/* The thread hasn't exited yet. At this point, it's more likely that something is actually wrong.
			 * This isn't always the case, for threads that might take a long time to clean up and exit,
			 * but most of the time, it shouldn't take more than a second. */
			__bbs_log(LOG_WARNING, 0, file, line, func, "Thread %d is not currently waiting to be joined\n", lwp);
			/* Now, proceed as normal and do a ~blocking pthread_join */
			/* Seems that after using pthread_timedjoin_np, you can't do a blocking pthread_join anymore? So loop */
			while (res && res == ETIMEDOUT) {
#if defined(__GLIBC__)
				bbs_debug(9, "Thread %lu not yet joined after %lus\n", thread, ts.tv_sec - start);
#endif /* __GLIBC__ */
				clock_gettime(CLOCK_REALTIME, &ts); /* Get time again, in case a lot of delayed has occured since the last pthread_timedjoin_np */
				ts.tv_sec += 5;
				res = pthread_timedjoin_np(thread, retval ? retval : &tmp, &ts);
			}
		}
#else
		__bbs_log(LOG_DEBUG, 1, file, line, func, "Thread %d is not currently waiting to be joined\n", lwp);
		/* This is bad, as we could block indefinitely */
		res = pthread_join(thread, retval ? retval : &tmp);
#endif /* __linux__ */
	} else {
		res = pthread_join(thread, retval ? retval : &tmp);
	}

	if (res) {
		bbs_error("pthread_join(%lu) at %s:%d %s(): %s\n", (unsigned long) thread, file, line, func, strerror(res));
		return res;
	}
	res = __thread_unregister(thread, file, line, func);
	if (res == -1) {
		bbs_error("Thread %d attempted to join nonjoinable thread %lu at %s:%d %s()\n", bbs_gettid(), (unsigned long) thread, file, line, func);
		return -1; /* pthread_join may have returned 0, but if the thread was detached (though it can't be here!), we probably can't trust its return value */
	}
	return 0;
}

int __bbs_pthread_timedjoin(pthread_t thread, void **retval, const char *file, const char *func, int line, int waitms)
{
	int res;
	struct thread_list_t *x;
	int lwp;
	int waiting_join;
#ifdef __linux__
	void *tmp;
	int nsec;
	struct timespec ts;
#else
	/* Just pretend the timer expired, to avoid hanging */
	UNUSED(retval);
	UNUSED(waitms);
	bbs_debug(1, "pthread_timedjoin_np is not supported on this platform\n");
	return -1;
#endif

	bbs_soft_assert(thread != 0); /* Somebody tried to join the thread 0? (often used as NIL thread) */

	x = find_thread(thread, &lwp, &waiting_join, file, func, line);

	if (!x) {
		/* If we try joining a thread right after we created it, it's possible it hasn't actually begun running (and registered itself) yet.
		 * Wait a moment, then try again, since this shouldn't generally happen anyways.
		 * If we don't do this, this can cause a segfault for some reason,
		 * so it's good to be a bit generous with the timing here. */
		bbs_debug(3, "Thread %lu not registered, checking again momentarily\n", (unsigned long) thread);
		usleep(10000);
		x = find_thread(thread, &lwp, &waiting_join, file, func, line);
	}
	if (!x) {
		bbs_error("Thread %lu not registered\n", (unsigned long) thread);
		return -1;
	} else if (!lwp) {
		return -1;
	}

	bbs_debug(6, "Attempting to join thread %lu (LWP %d) with timeout %d at %s:%d %s()\n", (unsigned long) thread, lwp, waitms, file, line, func);

#ifdef __linux__
	if (clock_gettime(CLOCK_REALTIME, &ts) == -1) {
		bbs_error("clock_gettime failed: %s\n", strerror(errno));
	}
	nsec = 1000000 * (waitms % 1000);
	ts.tv_nsec += nsec;
	if (ts.tv_nsec < nsec) {
		ts.tv_sec++;
	}
	ts.tv_sec += waitms / 1000;
	res = pthread_timedjoin_np(thread, retval ? retval : &tmp, &ts);
#endif

	if (res) {
		bbs_error("pthread_timedjoin_np(%lu) at %s:%d %s(): %s\n", (unsigned long) thread, file, line, func, strerror(res));
		return res;
	}
	res = __thread_unregister(thread, file, line, func);
	if (res == -1) {
		bbs_error("Thread %d attempted to join nonjoinable thread %lu at %s:%d %s()\n", bbs_gettid(), (unsigned long) thread, file, line, func);
		return -1; /* pthread_join may have returned 0, but if the thread was detached (though it can't be here!), we probably can't trust its return value */
	}
	return 0;
}

/*!
 * \brief support for thread inventory. The start routine is wrapped by
 * thread_run(), so that thread_register() and
 * thread_unregister() know the thread identifier.
 */
struct thr_arg {
	void *(*start_routine)(void *);
	void *data;
	char *name;
	unsigned int detached:1;
};

static void *thread_run(void *data)
{
	void *ret;
	struct thr_arg a = *((struct thr_arg *) data);	/* make a local copy */

	/* Note that even though data->name is a pointer to allocated memory,
	 * we are not freeing it here because thread_register is going to
	 * keep a copy of the pointer and then thread_unregister will
	 * free the memory */
	free(data);
	thread_register(a.name, a.detached);
	pthread_cleanup_push(thread_unregister, (void *) pthread_self());

	ret = a.start_routine(a.data);

	pthread_cleanup_pop(1);
	return ret;
}

static int create_thread(pthread_t *thread, pthread_attr_t *attr, void *(*start_routine)(void *), void *data, int detached, const char *file, const char *func, int line, const char *start_fn)
{
	int res;
	struct thr_arg *a;

	a = malloc(sizeof(*a));
	if (ALLOC_FAILURE(a)) {
		/* If we can't malloc, what makes us think thread creation will succeed?
		 * Just abort now. */
		return -1;
	}

	/* Start thread execution at thread_run so we can push the cleanup function */
	a->start_routine = start_routine;
	a->data = data;
	a->detached = detached ? 1 : 0;
	start_routine = thread_run;
	res = asprintf(&a->name, "%-21s started by thread %d at %s:%d %s()", start_fn, bbs_gettid(), file, line, func);
	if (unlikely(res < 0)) {
		free(a);
		return -1;
	}
	data = a;

	res = pthread_create(thread, attr, start_routine, data);
	if (unlikely(res)) {
		bbs_error("Failed to spawn thread to execute %s(): %s\n", start_fn, strerror(errno));
		/* The thread never spawned, so cleanup the mess we made */
		free_if(a->name); /* We continued on failure, so this could be NULL. */
		free(a);
	}
	return res;
}

static int __bbs_pthread_create_detached_full(pthread_t *thread, pthread_attr_t *attr, void *(*start_routine)(void *), void *data, const char *file, const char *func, int line, const char *start_fn, int detached)
{
	int res;
	pthread_attr_t attrlocal;
	pthread_attr_t *attrptr = attr ? attr : &attrlocal;

	if (!attr) {
		pthread_attr_init(&attrlocal);
	}
	res = pthread_attr_setdetachstate(attrptr, PTHREAD_CREATE_DETACHED);
	if (unlikely(res)) {
		bbs_error("pthread_attr_setdetachstate: %s\n", strerror(res));
		return -1;
	}
	return create_thread(thread, attrptr, start_routine, data, detached, file, func, line, start_fn);
}

int __bbs_pthread_create_detached(pthread_t *thread, pthread_attr_t *attr, void *(*start_routine)(void *), void *data, const char *file, const char *func, int line, const char *start_fn)
{
	return __bbs_pthread_create_detached_full(thread, attr, start_routine, data, file, func, line, start_fn, 1);
}

int __bbs_pthread_create(pthread_t *thread, pthread_attr_t *attr, void *(*start_routine)(void *), void *data, const char *file, const char *func, int line, const char *start_fn)
{
	return create_thread(thread, attr, start_routine, data, 0, file, func, line, start_fn);
}
