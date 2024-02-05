/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief Lock management wrappers
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include <pthread.h>

struct bbs_lock_info {
	unsigned int initialized:1;	/*!< Initialized */
	unsigned int staticinit:1;	/*!< Initialized statically */
	unsigned int destroyed:1;	/*!< Destroyed, no longer valid */
	int owners;					/*!< Current number of locks held (only 1 or 0 for mutex) */
	/* Mutex owner, write lock owner, or last read lock obtainer, using constant O(1) storage */
	/* We only store the filename and line number since that's sufficient for debugging purposes.
	 * Locks are a very common data structure, and storing the function name is superflous. */
	time_t lastlocked;			/*!< Time of last lock */
	int lwp;					/*!< Thread performing last logged operation */
	int lineno;					/*!< Source line of last lock */
	char filename[24];			/*!< Source filename of last lock */
};

struct bbs_mutex {
	pthread_mutex_t mutex;
	struct bbs_lock_info info;
};

struct bbs_rwlock {
	pthread_rwlock_t lock;
	pthread_mutex_t intlock;	/*!< Internal mutex for rwlock */
	struct bbs_lock_info info;
};

typedef struct bbs_mutex bbs_mutex_t;
typedef struct bbs_rwlock bbs_rwlock_t;

#define BBS_MUTEX_INITIALIZER { \
	.mutex = PTHREAD_MUTEX_INITIALIZER, \
	.info = { \
		.initialized = 1, \
		.staticinit = 1, \
		.destroyed = 0, \
		.owners = 0, \
		.lastlocked = 0, \
		.lwp = 0, \
		.filename = "", \
		.lineno = 0 \
	} \
}

#define BBS_RWLOCK_INITIALIZER { \
	.lock = PTHREAD_RWLOCK_INITIALIZER, \
	.intlock = PTHREAD_MUTEX_INITIALIZER, \
	.info = { \
		.initialized = 1, \
		.staticinit = 1, \
		.destroyed = 0, \
		.owners = 0, \
		.lastlocked = 0, \
		.lwp = 0, \
		.filename = "", \
		.lineno = 0 \
	} \
}

/* Note the _init APIs take an attr argument, but this should be NULL.
 * The argument is only present for paramter compatibility with the pthread APIs. */

#define bbs_mutex_init(lock, attr) __bbs_mutex_init(lock, __FILE__, __LINE__, __func__, #lock)
#define bbs_mutex_destroy(lock) __bbs_mutex_destroy(lock, __FILE__, __LINE__, __func__, #lock)
#define bbs_mutex_lock(lock) __bbs_mutex_lock(lock, __FILE__, __LINE__, __func__, #lock)
#define bbs_mutex_trylock(lock) __bbs_mutex_trylock(lock, __FILE__, __LINE__, __func__, #lock)
#define bbs_mutex_unlock(lock) __bbs_mutex_unlock(lock, __FILE__, __LINE__, __func__, #lock)

#define bbs_rwlock_init(lock, attr) __bbs_rwlock_init(lock, __FILE__, __LINE__, __func__, #lock)
#define bbs_rwlock_destroy(lock) __bbs_rwlock_destroy(lock, __FILE__, __LINE__, __func__, #lock)
#define bbs_rwlock_rdlock(lock) __bbs_rwlock_rdlock(lock, __FILE__, __LINE__, __func__, #lock)
#define bbs_rwlock_wrlock(lock) __bbs_rwlock_wrlock(lock, __FILE__, __LINE__, __func__, #lock)
#define bbs_rwlock_tryrdlock(lock) __bbs_rwlock_tryrdlock(lock, __FILE__, __LINE__, __func__, #lock)
#define bbs_rwlock_trywrlock(lock) __bbs_rwlock_trywrlock(lock, __FILE__, __LINE__, __func__, #lock)
#define bbs_rwlock_unlock(lock) __bbs_rwlock_unlock(lock, __FILE__, __LINE__, __func__, #lock)

int __bbs_mutex_init(bbs_mutex_t *t, const char *filename, int lineno, const char *func, const char *name);
int __bbs_mutex_destroy(bbs_mutex_t *t, const char *filename, int lineno, const char *func, const char *name);
int __bbs_mutex_lock(bbs_mutex_t *t, const char *filename, int lineno, const char *func, const char *name);
int __bbs_mutex_trylock(bbs_mutex_t *t, const char *filename, int lineno, const char *func, const char *name);
int __bbs_mutex_unlock(bbs_mutex_t *t, const char *filename, int lineno, const char *func, const char *name);

int __bbs_rwlock_init(bbs_rwlock_t *t, const char *filename, int lineno, const char *func, const char *name);
int __bbs_rwlock_destroy(bbs_rwlock_t *t, const char *filename, int lineno, const char *func, const char *name);
int __bbs_rwlock_rdlock(bbs_rwlock_t *t, const char *filename, int lineno, const char *func, const char *name);
int __bbs_rwlock_wrlock(bbs_rwlock_t *t, const char *filename, int lineno, const char *func, const char *name);
int __bbs_rwlock_tryrdlock(bbs_rwlock_t *t, const char *filename, int lineno, const char *func, const char *name);
int __bbs_rwlock_trywrlock(bbs_rwlock_t *t, const char *filename, int lineno, const char *func, const char *name);
int __bbs_rwlock_unlock(bbs_rwlock_t *t, const char *filename, int lineno, const char *func, const char *name);

#ifndef BBS_LOCK_WRAPPER_FILE

#ifndef BBS_LOCK_WRAPPERS_NOWARN
#define pthread_mutex_t				use_bbs_mutex_t_instead_of_pthread_mutex_t
#define pthread_mutex_init			use_bbs_mutex_init_instead_of_pthread_mutex_init
#define pthread_mutex_destroy		use_bbs_mutex_destroy_instead_of_pthread_mutex_destroy
#define pthread_mutex_lock			use_bbs_mutex_lock_instead_of_pthread_mutex_lock
#define pthread_mutex_trylock		use_bbs_mutex_trylock_instead_of_pthread_mutex_trylock
#define pthread_mutex_unlock		use_bbs_mutex_unlock_instead_of_pthread_mutex_unlock

#define pthread_rwlock_t			use_bbs_rwlock_t_instead_of_pthread_rwlock_t
#define pthread_rwlock_init			use_bbs_rwlock_init_instead_of_pthread_rwlock_init
#define pthread_rwlock_destroy		use_bbs_rwlock_destroy_instead_of_pthread_rwlock_destroy
#define pthread_rwlock_rdlock		use_bbs_rwlock_rdlock_instead_of_pthread_rwlock_rdlock
#define pthread_rwlock_wrlock		use_bbs_rwlock_wrlock_instead_of_pthread_rwlock_wrlock
#define pthread_rwlock_tryrdlock	use_bbs_rwlock_tryrdlock_instead_of_pthread_rwlock_tryrdlock
#define pthread_rwlock_trywrlock	use_bbs_rwlock_trywrlock_instead_of_pthread_rwlock_trywrlock
#define pthread_rwlock_unlock		use_bbs_rwlock_unlock_instead_of_pthread_rwlock_unlock
#endif /* BBS_LOCK_WRAPPERS_NOWARN */

#endif /* BBS_LOCK_WRAPPER_FILE */
