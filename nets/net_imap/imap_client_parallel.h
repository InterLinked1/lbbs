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
 * \brief IMAP Client Parallel Operation Framework
 *
 */

#include "include/linkedlists.h"

struct imap_parallel_task {
	struct imap_parallel *p;		/* Parent to which this task belongs */
	unsigned long hash;				/* Prefix hash value */
	int (*cb)(void *data);			/* Callback to execute the task */
	void (*cleanup)(void *data);	/* Cleanup function */
	void *data;						/* Callback data for the task */
	pthread_t thread;				/* Thread responsible for the task */
	int res;						/* Return code of task */
	RWLIST_ENTRY(imap_parallel_task) entry;
	unsigned int started:1;			/* Task has been started (i.e. is either running or completed) */
	unsigned int completed:1;		/* Task has been completed */
};

RWLIST_HEAD(parallel_tasks, imap_parallel_task);

struct imap_parallel {
	struct parallel_tasks tasks;
	int alertpipe[2];
	unsigned int waiting:1;			/* In the "waiting" phase, i.e. there are no more tasks to schedule */
	unsigned int initialized:1;
};

/*!
 * \brief Schedule a task for execution. The task may be executed immediately or delayed, in a separate thread
 * \param p Parallel job series structure
 * \param prefix Prefix unique for concurrency restrictions. No tasks with the same prefix will be concurrently scheduled.
 * \param data Callback data to pass to callback functions
 * \param cb Callback function to execute task
 * \param duplicate Function that duplicates data and returns a heap allocated version of it
 * \param cleanup Function to destroy a heap allocated callback data structure
 * \return Task return code, if executed immediately
 * \return Scheduler return code, if not being executed immediately.
 * \note You must call imap_client_parallel_join to ensure all tasks finish execeution, at some point before p goes out of scope
 * \note This function should only be called from the (same) parent thread
 */
int imap_client_parallel_schedule_task(struct imap_parallel *p, const char *restrict prefix, void *data, int (*cb)(void *data), void *(*duplicate)(void *data), void (*cleanup)(void *data));

/*!
 * \brief Wait for all pending tasks to finish execution
 * \retval Bitwise OR of all task return values, ORed with the status of this function (0 on success, nonzero on failure)
 */
int imap_client_parallel_join(struct imap_parallel *p);
