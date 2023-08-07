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
 * \brief Thread management
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/*! \brief Get thread ID of current thread */
int bbs_gettid(void);

/*!
 * \brief Disable cancellability of a thread
 * \warning This function should be avoided if possible, but must be used if it is needed
 */
void bbs_pthread_disable_cancel(void);

/*!
 * \brief Restore cancellability of a thread
 */
void bbs_pthread_enable_cancel(void);

/*!
 * \brief Cancel and kill a thread
 * \deprecated
 * \warning Avoid this function if possible, as threads may not clean up properly if cancelled/killed in the wrong place
 */
int bbs_pthread_cancel_kill(pthread_t thread);

int __bbs_pthread_join(pthread_t thread, void **retval, const char *file, const char *func, int line);

/*! \brief Join a non-detached thread */
#define bbs_pthread_join(thread, retval) __bbs_pthread_join(thread, retval, __FILE__, __func__, __LINE__)

int __bbs_pthread_create_detached(pthread_t *thread, pthread_attr_t *attr, void *(*start_routine)(void *), void *data, const char *file, const char *func, int line, const char *start_fn);

/*!
 * \brief Create a detached pthread
 * \retval 0 on success, -1 on failure
 */
#define bbs_pthread_create_detached(thread, attr, start_routine, data) __bbs_pthread_create_detached(thread, attr, start_routine, data, __FILE__, __func__, __LINE__, #start_routine)

int __bbs_pthread_create(pthread_t *thread, pthread_attr_t *attr, void *(*start_routine)(void *), void *data, const char *file, const char *func, int line, const char *start_fn);

/*!
 * \brief Create a non-detached pthread
 * \retval 0 on success, -1 on failure
 */
#define bbs_pthread_create(thread, attr, start_routine, data) __bbs_pthread_create(thread, attr, start_routine, data, __FILE__, __func__, __LINE__, #start_routine)

/*! \brief Destroy thread registrations (on shutdown) */
void bbs_thread_cleanup(void);

/*!
 * \brief Get the thread ID (LWP) of a registered thread
 * \param thread pthread_t handle
 * \retval -1 if thread not currently registered, LWP/thread ID otherwise
 */
int bbs_pthread_tid(pthread_t thread);

/*!
 * \brief Print list of active BBS threads
 * \param fd File descriptor to which to print thread listing
 * \warning This may not include all threads, such as those that do not use the BBS pthread creation wrappers (external libraries, etc.)
 */
int bbs_dump_threads(int fd);
