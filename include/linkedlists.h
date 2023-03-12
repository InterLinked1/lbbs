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
 * \brief Read and write lock singly (forward) linked lists
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 *
 * \note Parts of this linked list implementation based on code in Asterisk's linkedlists.h (also GPLv2)
 */

#ifndef _LINKEDLISTS_H
#define _LINKEDLISTS_H

#include <pthread.h>

/*!
 * \brief Write locks a list.
 * \param head This is a pointer to the list head structure
 *
 * This macro attempts to place an exclusive write lock in the
 * list head structure pointed to by head.
 * \retval 0 on success
 * \retval non-zero on failure
 */
#define RWLIST_WRLOCK(head) pthread_rwlock_wrlock(&(head)->lock)

/*!
 * \brief Read locks a list.
 * \param head This is a pointer to the list head structure
 *
 * This macro attempts to place a read lock in the
 * list head structure pointed to by head.
 * \retval 0 on success
 * \retval non-zero on failure
 */
#define RWLIST_RDLOCK(head) pthread_rwlock_rdlock(&(head)->lock)

/*!
 * \brief Write locks a list, without blocking if the list is locked.
 * \param head This is a pointer to the list head structure
 *
 * This macro attempts to place an exclusive write lock in the
 * list head structure pointed to by head.
 * \retval 0 on success
 * \retval non-zero on failure
 */
#define RWLIST_TRYWRLOCK(head) pthread_rwlock_trywrlock(&(head)->lock)

/*!
 * \brief Attempts to unlock a read/write based list.
 * \param head This is a pointer to the list head structure
 *
 * This macro attempts to remove a read or write lock from the
 * list head structure pointed to by head. If the list
 * was not locked by this thread, this macro has no effect.
 */
#define RWLIST_UNLOCK(head) pthread_rwlock_unlock(&(head)->lock)

/*!
 * \brief Defines a structure to be used to hold a read/write list of specified type.
 * \param name This will be the name of the defined structure.
 * \param type This is the type of each list entry.
 *
 * This macro creates a structure definition that can be used
 * to hold a list of the entries of type \a type. It does not actually
 * declare (allocate) a structure; to do that, either follow this
 * macro with the desired name of the instance you wish to declare,
 * or use the specified \a name to declare instances elsewhere.
 */
#define RWLIST_HEAD(name, type)                                     \
struct name {                                                           \
        struct type *first;                                             \
        struct type *last;                                              \
        pthread_rwlock_t lock;                                          \
}

/*!
 * \brief Defines initial values for a declaration of RWLIST_HEAD
 */
#define RWLIST_HEAD_INIT_VALUE      {               \
	.first = NULL,                                  \
	.last = NULL,                                   \
	.lock = PTHREAD_RWLOCK_INITIALIZER,             \
}

/*!
 * \brief Defines a structure to be used to hold a read/write list of specified type, statically initialized.
 * \param name This will be the name of the defined structure.
 * \param type This is the type of each list entry.
 */
#define RWLIST_HEAD_STATIC(name, type)                          \
struct name {                                                   \
	struct type *first;                                         \
	struct type *last;                                          \
	pthread_rwlock_t lock;                                      \
} name = RWLIST_HEAD_INIT_VALUE

/*!
 * \brief Declare a forward link structure inside a list entry.
 * \param type This is the type of each list entry.
 *
 * This macro declares a structure to be used to link list entries together.
 * It must be used inside the definition of the structure named in
 * \a type
 *
 * The field name \a list here is arbitrary, and can be anything you wish.
 */
#define RWLIST_ENTRY(type)						\
struct {								\
	struct type *next;						\
}

/*!
 * \brief Returns the first entry contained in a list.
 * \param head This is a pointer to the list head structure
 */
#define RWLIST_FIRST(head)	((head)->first)

/*!
 * \brief Returns the last entry contained in a list.
 * \param head This is a pointer to the list head structure
 */
#define RWLIST_LAST(head)	((head)->last)

/*!
 * \brief Returns the next entry in the list after the given entry.
 * \param elm This is a pointer to the current entry.
 * \param field This is the name of the field (declared using RWLIST_ENTRY())
 * used to link entries of this list together.
 */
#define RWLIST_NEXT(elm, field)	((elm)->field.next)

/*!
 * \brief Checks whether the specified list contains any entries.
 * \param head This is a pointer to the list head structure
 *
 * \return zero if the list has entries
 * \return non-zero if not.
 */
#define RWLIST_EMPTY(head)	(RWLIST_FIRST(head) == NULL)

/*!
 * \brief Returns the number of elements in the list
 * \param head This is a pointer to the list head structure
 * \param var This is the name of the variable that will hold a pointer to the
 * current list entry on each iteration. It must be declared before calling
 * this macro.
 * \param field This is the name of the field (declared using RWLIST_ENTRY())
 * used to link entries of this list together.
 *
 * \return Number of elements in list
 */
#define RWLIST_SIZE(head,var,field) ({ \
	int __rwlist_count = 0; \
	for((var) = (head)->first; (var); (var) = (var)->field.next, __rwlist_count++); \
	__rwlist_count; \
})

/*!
 * \brief Loops over (traverses) the entries in a list.
 * \param head This is a pointer to the list head structure
 * \param var This is the name of the variable that will hold a pointer to the
 * current list entry on each iteration. It must be declared before calling
 * this macro.
 * \param field This is the name of the field (declared using RWLIST_ENTRY())
 * used to link entries of this list together.
 *
 * This macro is use to loop over (traverse) the entries in a list. It uses a
 * \a for loop, and supplies the enclosed code with a pointer to each list
 * entry as it loops.
 */
#define RWLIST_TRAVERSE(head,var,field) for((var) = (head)->first; (var); (var) = (var)->field.next)

/*!
 * \brief Loops safely over (traverses) the entries in a list.
 * \param head This is a pointer to the list head structure
 * \param var This is the name of the variable that will hold a pointer to the
 * current list entry on each iteration. It must be declared before calling
 * this macro.
 * \param field This is the name of the field (declared using RWLIST_ENTRY())
 * used to link entries of this list together.
 *
 * This macro is used to safely loop over (traverse) the entries in a list. It
 * uses a \a for loop, and supplies the enclosed code with a pointer to each list
 * entry as it loops.
 *
 * It differs from RWLIST_TRAVERSE() in that the code inside the loop can modify
 * (or even free, after calling RWLIST_REMOVE_CURRENT()) the entry pointed to by
 * the \a current pointer without affecting the loop traversal.
 */
#define RWLIST_TRAVERSE_SAFE_BEGIN(head, var, field) {				\
	typeof((head)) __list_head = head;									\
	typeof(__list_head->first) __list_next;								\
	typeof(__list_head->first) __list_prev = NULL;						\
	typeof(__list_head->first) __list_current;							\
	for ((var) = __list_head->first,									\
		__list_current = (var),											\
		__list_next = (var) ? (var)->field.next : NULL;					\
		(var);															\
		__list_prev = __list_current,									\
		(var) = __list_next,											\
		__list_current = (var),											\
		__list_next = (var) ? (var)->field.next : NULL,					\
		(void) __list_prev /* To quiet compiler? */						\
		)

/*!
 * \brief Removes the \a current entry from a list during a traversal.
 * \param field This is the name of the field (declared using RWLIST_ENTRY())
 * used to link entries of this list together.
 *
 * \note This macro can \b only be used inside an RWLIST_TRAVERSE_SAFE_BEGIN()
 * block; it is used to unlink the current entry from the list without affecting
 * the list traversal (and without having to re-traverse the list to modify the
 * previous entry, if any).
 */
#define RWLIST_REMOVE_CURRENT(field) do { 							\
		__list_current->field.next = NULL;								\
		__list_current = __list_prev;									\
		if (__list_prev) {												\
			__list_prev->field.next = __list_next;						\
		} else {														\
			__list_head->first = __list_next;							\
		}																\
		if (!__list_next) {												\
			__list_head->last = __list_prev;							\
		}																\
	} while (0)

/*!
 * \brief Closes a safe loop traversal block.
 */
#define RWLIST_TRAVERSE_SAFE_END  }

/*!
 * \brief Inserts a list entry after a given entry.
 * \param head This is a pointer to the list head structure
 * \param listelm This is a pointer to the entry after which the new entry should
 * be inserted.
 * \param elm This is a pointer to the entry to be inserted.
 * \param field This is the name of the field (declared using RWLIST_ENTRY())
 * used to link entries of this list together.
 */
#define RWLIST_INSERT_AFTER(head, listelm, elm, field) do {		\
	(elm)->field.next = (listelm)->field.next;			\
	(listelm)->field.next = (elm);					\
	if ((head)->last == (listelm))					\
		(head)->last = (elm);					\
} while (0)

/*!
 * \brief Inserts a list entry at the head of a list.
 * \param head This is a pointer to the list head structure
 * \param elm This is a pointer to the entry to be inserted.
 * \param field This is the name of the field (declared using RWLIST_ENTRY())
 * used to link entries of this list together.
 */
#define RWLIST_INSERT_HEAD(head, elm, field) do {			\
		(elm)->field.next = (head)->first;			\
		(head)->first = (elm);					\
		if (!(head)->last)					\
			(head)->last = (elm);				\
} while (0)

/*!
 * \brief Appends a list entry to the tail of a list.
 * \param head This is a pointer to the list head structure
 * \param elm This is a pointer to the entry to be appended.
 * \param field This is the name of the field (declared using RWLIST_ENTRY())
 * used to link entries of this list together.
 *
 * Note: The link field in the appended entry is \b not modified, so if it is
 * actually the head of a list itself, the entire list will be appended
 * temporarily (until the next RWLIST_INSERT_TAIL is performed).
 */
#define RWLIST_INSERT_TAIL(head, elm, field) do {			\
      if (!(head)->first) {						\
		(head)->first = (elm);					\
		(head)->last = (elm);					\
      } else {								\
		(head)->last->field.next = (elm);			\
		(head)->last = (elm);					\
      }									\
} while (0)

/*!
 * \brief Removes and returns the head entry from a list.
 * \param head This is a pointer to the list head structure
 * \param field This is the name of the field (declared using RWLIST_ENTRY())
 * used to link entries of this list together.
 *
 * Removes the head entry from the list, and returns a pointer to it.
 * This macro is safe to call on an empty list.
 */
#define RWLIST_REMOVE_HEAD(head, field) ({				\
		typeof((head)->first) __cur = (head)->first;		\
		if (__cur) {						\
			(head)->first = __cur->field.next;		\
			__cur->field.next = NULL;			\
			if ((head)->last == __cur)			\
				(head)->last = NULL;			\
		}							\
		__cur;							\
	})

/*!
 * \brief Removes a specific entry from a list.
 * \param head This is a pointer to the list head structure
 * \param elm This is a pointer to the entry to be removed.
 * \param field This is the name of the field (declared using RWLIST_ENTRY())
 * used to link entries of this list together.
 * \retval elm if elm was in the list.
 * \retval NULL if elm was not in the list or elm was NULL.
 * \warning The removed entry is \b not freed.
 */
#define RWLIST_REMOVE(head, elm, field)						\
	({															\
		typeof(elm) __elm = (elm);								\
		if (__elm) {											\
			if ((head)->first == __elm) {						\
				(head)->first = __elm->field.next;				\
				__elm->field.next = NULL;						\
				if ((head)->last == __elm) {					\
					(head)->last = NULL;						\
				}												\
			} else {											\
				typeof(elm) __prev = (head)->first;				\
				while (__prev && __prev->field.next != __elm) {	\
					__prev = __prev->field.next;				\
				}												\
				if (__prev) {									\
					__prev->field.next = __elm->field.next;		\
					__elm->field.next = NULL;					\
					if ((head)->last == __elm) {				\
						(head)->last = __prev;					\
					}											\
				} else {										\
					__elm = NULL;								\
				}												\
			}													\
		}														\
		__elm;													\
	})

/*!
 * \brief Removes all the entries from a list and invokes a destructor on each entry
 * \param head This is a pointer to the list head structure
 * \param field This is the name of the field (declared using RWLIST_ENTRY())
 * used to link entries of this list together.
 * \param destructor A destructor function to call on each element (e.g. free)
 *
 * This macro is safe to call on an empty list.
 */
#define RWLIST_REMOVE_ALL(head, field, destructor) { \
	typeof((head)) __list_head = head; \
	typeof(__list_head->first) __list_current; \
	while ((__list_current = RWLIST_REMOVE_HEAD(head, field))) { \
		destructor(__list_current); \
	} \
}

/*! \brief Same as RWLIST_REMOVE_ALL, but WRLOCK list beforehand and UNLOCK afterwards */
#define RWLIST_WRLOCK_REMOVE_ALL(head, field, destructor) \
	RWLIST_WRLOCK(head); \
	RWLIST_REMOVE_ALL(head, field, destructor); \
	RWLIST_UNLOCK(head);

#endif /* _LINKEDLISTS_H */
