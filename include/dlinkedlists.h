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
 * \brief Read and write lock doubly linked lists
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 *
 * \note Parts of this doubly linked list implementation based on code in Asterisk's dlinkedlists.h (also GPLv2)
 */

#ifndef DLINKEDLISTS_H
#define DLINKEDLISTS_H

/*!
 * \brief Locks a list.
 * \param head This is a pointer to the list head structure
 *
 * This macro attempts to place an exclusive lock in the
 * list head structure pointed to by head.
 * \retval 0 on success
 * \retval non-zero on failure
 */
#define DLLIST_LOCK(head) bbs_mutex_lock(&(head)->lock)

/*!
 * \brief Write locks a list.
 * \param head This is a pointer to the list head structure
 *
 * This macro attempts to place an exclusive write lock in the
 * list head structure pointed to by head.
 * \retval 0 on success
 * \retval non-zero on failure
 */
#define RWDLLIST_WRLOCK(head) bbs_rwlock_wrlock(&(head)->lock)

/*!
 * \brief Read locks a list.
 * \param head This is a pointer to the list head structure
 *
 * This macro attempts to place a read lock in the
 * list head structure pointed to by head.
 * \retval 0 on success
 * \retval non-zero on failure
 */
#define RWDLLIST_RDLOCK(head) bbs_rwlock_rdlock(&(head)->lock)

/*!
 * \brief Locks a list, without blocking if the list is locked.
 * \param head This is a pointer to the list head structure
 *
 * This macro attempts to place an exclusive lock in the
 * list head structure pointed to by head.
 * \retval 0 on success
 * \retval non-zero on failure
 */
#define DLLIST_TRYLOCK(head) bbs_mutex_trylock(&(head)->lock)

/*!
 * \brief Write locks a list, without blocking if the list is locked.
 * \param head This is a pointer to the list head structure
 *
 * This macro attempts to place an exclusive write lock in the
 * list head structure pointed to by head.
 * \retval 0 on success
 * \retval non-zero on failure
 */
#define RWDLLIST_TRYWRLOCK(head) bbs_rwlock_trywrlock(&(head)->lock)

/*!
 * \brief Read locks a list, without blocking if the list is locked.
 * \param head This is a pointer to the list head structure
 *
 * This macro attempts to place a read lock in the
 * list head structure pointed to by head.
 * \retval 0 on success
 * \retval non-zero on failure
 */
#define RWDLLIST_TRYRDLOCK(head) bbs_rwlock_tryrdlock(&(head)->lock)

/*!
 * \brief Attempts to unlock a list.
 * \param head This is a pointer to the list head structure
 *
 * This macro attempts to remove an exclusive lock from the
 * list head structure pointed to by head. If the list
 * was not locked by this thread, this macro has no effect.
 */
#define DLLIST_UNLOCK(head) bbs_mutex_unlock(&(head)->lock)

/*!
 * \brief Attempts to unlock a read/write based list.
 * \param head This is a pointer to the list head structure
 *
 * This macro attempts to remove a read or write lock from the
 * list head structure pointed to by head. If the list
 * was not locked by this thread, this macro has no effect.
 */
#define RWDLLIST_UNLOCK(head) bbs_rwlock_unlock(&(head)->lock)

/*!
 * \brief Defines a structure to be used to hold a list of specified type.
 * \param name This will be the name of the defined structure.
 * \param type This is the type of each list entry.
 *
 * This macro creates a structure definition that can be used
 * to hold a list of the entries of type \a type. It does not actually
 * declare (allocate) a structure; to do that, either follow this
 * macro with the desired name of the instance you wish to declare,
 * or use the specified \a name to declare instances elsewhere.
 *
 * Example usage:
 * \code
 * static DLLIST_HEAD(entry_list, entry) entries;
 * \endcode
 *
 * This would define \c struct \c entry_list, and declare an instance of it named
 * \a entries, all intended to hold a list of type \c struct \c entry.
 */
#define DLLIST_HEAD(name, type)					\
	struct name {									\
		struct type *first;							\
		struct type *last;							\
		bbs_mutex_t lock;							\
	}

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
 *
 * Example usage:
 * \code
 * static RWDLLIST_HEAD(entry_list, entry) entries;
 * \endcode
 *
 * This would define \c struct \c entry_list, and declare an instance of it named
 * \a entries, all intended to hold a list of type \c struct \c entry.
 */
#define RWDLLIST_HEAD(name, type)				\
	struct name {									\
		struct type *first;							\
		struct type *last;							\
		bbs_rwlock_t lock;							\
	}

/*!
 * \brief Defines a structure to be used to hold a list of specified type (with no lock).
 * \param name This will be the name of the defined structure.
 * \param type This is the type of each list entry.
 *
 * This macro creates a structure definition that can be used
 * to hold a list of the entries of type \a type. It does not actually
 * declare (allocate) a structure; to do that, either follow this
 * macro with the desired name of the instance you wish to declare,
 * or use the specified \a name to declare instances elsewhere.
 *
 * Example usage:
 * \code
 * static DLLIST_HEAD_NOLOCK(entry_list, entry) entries;
 * \endcode
 *
 * This would define \c struct \c entry_list, and declare an instance of it named
 * \a entries, all intended to hold a list of type \c struct \c entry.
 */
#define DLLIST_HEAD_NOLOCK(name, type)			\
	struct name {									\
		struct type *first;							\
		struct type *last;							\
	}

/*!
 * \brief Defines initial values for a declaration of DLLIST_HEAD
 */
#define DLLIST_HEAD_INIT_VALUE					\
	{												\
		.first = NULL,								\
		.last = NULL,								\
		.lock = BBS_RWLOCK_INITIALIZER,				\
	}

/*!
 * \brief Defines initial values for a declaration of RWDLLIST_HEAD
 */
#define RWDLLIST_HEAD_INIT_VALUE				\
	{												\
		.first = NULL,								\
		.last = NULL,								\
		.lock = BBS_RWLOCK_INITIALIZER,				\
	}

/*!
 * \brief Defines initial values for a declaration of DLLIST_HEAD_NOLOCK
 */
#define DLLIST_HEAD_NOLOCK_INIT_VALUE			\
	{												\
		.first = NULL,								\
		.last = NULL,								\
	}

/*!
 * \brief Defines a structure to be used to hold a list of specified type, statically initialized.
 * \param name This will be the name of the defined structure.
 * \param type This is the type of each list entry.
 *
 * This macro creates a structure definition that can be used
 * to hold a list of the entries of type \a type, and allocates an instance
 * of it, initialized to be empty.
 *
 * Example usage:
 * \code
 * static DLLIST_HEAD_STATIC(entry_list, entry);
 * \endcode
 *
 * This would define \c struct \c entry_list, intended to hold a list of
 * type \c struct \c entry.
 */
#if defined(MUTEX_INIT_W_CONSTRUCTORS)
#define DLLIST_HEAD_STATIC(name, type)							\
	struct name {													\
		struct type *first;											\
		struct type *last;											\
		bbs_mutex_t lock;											\
	} name;															\
	static void  __attribute__((constructor)) __init_##name(void)	\
	{																\
		DLLIST_HEAD_INIT(&name);								\
	}																\
	static void  __attribute__((destructor)) __fini_##name(void)	\
	{																\
		DLLIST_HEAD_DESTROY(&name);								\
	}																\
	struct __dummy_##name
#else
#define DLLIST_HEAD_STATIC(name, type)			\
	struct name {									\
		struct type *first;							\
		struct type *last;							\
		bbs_mutex_t lock;							\
	} name = DLLIST_HEAD_INIT_VALUE
#endif

/*!
 * \brief Defines a structure to be used to hold a read/write list of specified type, statically initialized.
 * \param name This will be the name of the defined structure.
 * \param type This is the type of each list entry.
 *
 * This macro creates a structure definition that can be used
 * to hold a list of the entries of type \a type, and allocates an instance
 * of it, initialized to be empty.
 *
 * Example usage:
 * \code
 * static RWDLLIST_HEAD_STATIC(entry_list, entry);
 * \endcode
 *
 * This would define \c struct \c entry_list, intended to hold a list of
 * type \c struct \c entry.
 */
#define RWDLLIST_HEAD_STATIC(name, type)		\
	struct name {									\
		struct type *first;							\
		struct type *last;							\
		bbs_rwlock_t lock;							\
	} name = RWDLLIST_HEAD_INIT_VALUE

/*!
 * \brief Defines a structure to be used to hold a list of specified type, statically initialized.
 *
 * This is the same as DLLIST_HEAD_STATIC, except without the lock included.
 */
#define DLLIST_HEAD_NOLOCK_STATIC(name, type)	\
	struct name {									\
		struct type *first;							\
		struct type *last;							\
	} name = DLLIST_HEAD_NOLOCK_INIT_VALUE

/*!
 * \brief Initializes a list head structure with a specified first entry.
 * \param head This is a pointer to the list head structure
 * \param entry pointer to the list entry that will become the head of the list
 *
 * This macro initializes a list head structure by setting the head
 * entry to the supplied value and recreating the embedded lock.
 */
#define DLLIST_HEAD_SET(head, entry)			\
	do {											\
		(head)->first = (entry);					\
		(head)->last = (entry);						\
		bbs_mutex_init(&(head)->lock);				\
	} while (0)

/*!
 * \brief Initializes an rwlist head structure with a specified first entry.
 * \param head This is a pointer to the list head structure
 * \param entry pointer to the list entry that will become the head of the list
 *
 * This macro initializes a list head structure by setting the head
 * entry to the supplied value and recreating the embedded lock.
 */
#define RWDLLIST_HEAD_SET(head, entry)			\
	do {											\
		(head)->first = (entry);					\
		(head)->last = (entry);						\
		bbs_rwlock_init(&(head)->lock);				\
	} while (0)

/*!
 * \brief Initializes a list head structure with a specified first entry.
 * \param head This is a pointer to the list head structure
 * \param entry pointer to the list entry that will become the head of the list
 *
 * This macro initializes a list head structure by setting the head
 * entry to the supplied value.
 */
#define DLLIST_HEAD_SET_NOLOCK(head, entry)		\
	do {											\
		(head)->first = (entry);					\
		(head)->last = (entry);						\
	} while (0)

/*!
 * \brief Declare previous/forward links inside a list entry.
 * \param type This is the type of each list entry.
 *
 * This macro declares a structure to be used to doubly link list entries together.
 * It must be used inside the definition of the structure named in
 * \a type, as follows:
 *
 * \code
 * struct list_entry {
 *     ...
 *     DLLIST_ENTRY(list_entry) list;
 * }
 * \endcode
 *
 * The field name \a list here is arbitrary, and can be anything you wish.
 */
#define DLLIST_ENTRY(type)			DLLIST_HEAD_NOLOCK(, type)

#define RWDLLIST_ENTRY DLLIST_ENTRY

/*!
 * \brief Returns the first entry contained in a list.
 * \param head This is a pointer to the list head structure
 */
#define	DLLIST_FIRST(head)	((head)->first)

#define RWDLLIST_FIRST DLLIST_FIRST

/*!
 * \brief Returns the last entry contained in a list.
 * \param head This is a pointer to the list head structure
 */
#define	DLLIST_LAST(head)	((head)->last)

#define RWDLLIST_LAST DLLIST_LAST

#define DLLIST_NEXT_DIRECTION(elm, field, direction)	((elm)->field.direction)

#define RWDLLIST_NEXT_DIRECTION DLLIST_NEXT_DIRECTION

/*!
 * \brief Returns the next entry in the list after the given entry.
 * \param elm This is a pointer to the current entry.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link entries of this list together.
 */
#define DLLIST_NEXT(elm, field)	DLLIST_NEXT_DIRECTION(elm, field, first)

#define RWDLLIST_NEXT DLLIST_NEXT

/*!
 * \brief Returns the previous entry in the list before the given entry.
 * \param elm This is a pointer to the current entry.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link entries of this list together.
 */
#define DLLIST_PREV(elm, field)	DLLIST_NEXT_DIRECTION(elm, field, last)

#define RWDLLIST_PREV DLLIST_PREV

/*!
 * \brief Checks whether the specified list contains any entries.
 * \param head This is a pointer to the list head structure
 *
 * \return non-zero if the list has entries
 * \return zero if not.
 */
#define	DLLIST_EMPTY(head)	(DLLIST_FIRST(head) == NULL)

#define RWDLLIST_EMPTY DLLIST_EMPTY

/*!
 * \brief Checks whether the specified list contains the element.
 * \param head This is a pointer to the list head structure
 * \param elm This is a pointer to the list element to see if in list.
 * \param field List node field for the next node information.
 *
 * \return elm if the list has elm in it.
 * \return NULL if not.
 */
#define DLLIST_IS_MEMBER(head, elm, field)	\
	({												\
		typeof((head)->first) __cur;				\
		typeof((elm)) __elm = (elm);				\
		if (!__elm) {								\
			__cur = NULL;							\
		} else {									\
			__cur = (head)->first;					\
			while (__cur && __cur != __elm) {		\
				__cur = __cur->field.first;			\
			}										\
		}											\
		__cur;										\
	})

#define RWDLLIST_IS_MEMBER	DLLIST_IS_MEMBER

/*!
 * \brief Traverse a doubly linked list using the specified direction list.
 *
 * \param head List head structure pointer.
 * \param var This is the name of the variable that will hold a pointer to the
 * current list node on each iteration. It must be declared before calling
 * this macro.
 * \param field List node field for the next node information. (declared using DLLIST_ENTRY())
 * \param start Specified list node to start traversal: first or last
 *
 * This macro is use to loop over (traverse) the nodes in a list. It uses a
 * \a for loop, and supplies the enclosed code with a pointer to each list
 * node as it loops. It is typically used as follows:
 * \code
 * static DLLIST_HEAD(entry_list, list_entry) entries;
 * ...
 * struct list_entry {
 *     ...
 *     DLLIST_ENTRY(list_entry) list;
 * }
 * ...
 * struct list_entry *current;
 * ...
 * DLLIST_TRAVERSE_DIRECTION(&entries, current, list, first) {
 *    (do something with current here (travers list in forward direction))
 * }
 * ...
 * DLLIST_TRAVERSE_DIRECTION(&entries, current, list, last) {
 *    (do something with current here (travers list in reverse direction))
 * }
 * \endcode
 */
#define DLLIST_TRAVERSE_DIRECTION(head, var, field, start) 				\
	for ((var) = (head)->start; (var); (var) = DLLIST_NEXT_DIRECTION(var, field, start))

#define RWDLLIST_TRAVERSE_DIRECTION DLLIST_TRAVERSE_DIRECTION

/*!
 * \brief Loops over (traverses) the entries in a list.
 * \param head This is a pointer to the list head structure
 * \param var This is the name of the variable that will hold a pointer to the
 * current list entry on each iteration. It must be declared before calling
 * this macro.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link entries of this list together.
 *
 * This macro is use to loop over (traverse) the entries in a list. It uses a
 * \a for loop, and supplies the enclosed code with a pointer to each list
 * entry as it loops. It is typically used as follows:
 * \code
 * static DLLIST_HEAD(entry_list, list_entry) entries;
 * ...
 * struct list_entry {
 *     ...
 *     DLLIST_ENTRY(list_entry) list;
 * }
 * ...
 * struct list_entry *current;
 * ...
 * DLLIST_TRAVERSE(&entries, current, list) {
 *    (do something with current here)
 * }
 * \endcode
 * \warning If you modify the forward-link pointer contained in the \a current entry while
 * inside the loop, the behavior will be unpredictable. At a minimum, the following
 * macros will modify the forward-link pointer, and should not be used inside
 * DLLIST_TRAVERSE() against the entry pointed to by the \a current pointer without
 * careful consideration of their consequences:
 * \li DLLIST_NEXT() (when used as an lvalue)
 * \li DLLIST_INSERT_AFTER()
 * \li DLLIST_INSERT_HEAD()
 * \li DLLIST_INSERT_TAIL()
 */
#define DLLIST_TRAVERSE(head,var,field) 				\
	DLLIST_TRAVERSE_DIRECTION(head, var, field, first)

#define RWDLLIST_TRAVERSE DLLIST_TRAVERSE

/*!
 * \brief Loops over (traverses) the entries in a list in reverse order, starting at the end.
 * \param head This is a pointer to the list head structure
 * \param var This is the name of the variable that will hold a pointer to the
 * current list entry on each iteration. It must be declared before calling
 * this macro.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link entries of this list together.
 *
 * This macro is use to loop over (traverse) the entries in a list in reverse order. It uses a
 * \a for loop, and supplies the enclosed code with a pointer to each list
 * entry as it loops. It is typically used as follows:
 * \code
 * static DLLIST_HEAD(entry_list, list_entry) entries;
 * ...
 * struct list_entry {
 *     ...
 *     DLLIST_ENTRY(list_entry) list;
 * }
 * ...
 * struct list_entry *current;
 * ...
 * DLLIST_TRAVERSE_BACKWARDS(&entries, current, list) {
 *    (do something with current here)
 * }
 * \endcode
 * \warning If you modify the forward-link pointer contained in the \a current entry while
 * inside the loop, the behavior will be unpredictable. At a minimum, the following
 * macros will modify the forward-link pointer, and should not be used inside
 * DLLIST_TRAVERSE() against the entry pointed to by the \a current pointer without
 * careful consideration of their consequences:
 * \li DLLIST_PREV() (when used as an lvalue)
 * \li DLLIST_INSERT_BEFORE()
 * \li DLLIST_INSERT_HEAD()
 * \li DLLIST_INSERT_TAIL()
 */
#define DLLIST_TRAVERSE_BACKWARDS(head,var,field) 				\
	DLLIST_TRAVERSE_DIRECTION(head, var, field, last)

#define RWDLLIST_TRAVERSE_BACKWARDS DLLIST_TRAVERSE_BACKWARDS

/*!
 * \brief Safe traversal of a doubly linked list using the specified direction list.
 *
 * \param head List head structure pointer.
 * \param var This is the name of the variable that will hold a pointer to the
 * current list node on each iteration. It must be declared before calling
 * this macro.
 * \param field List node field for the next node information. (declared using DLLIST_ENTRY())
 * \param start Specified list node to start traversal: first or last
 *
 * This macro is used to safely loop over (traverse) the nodes in a list. It
 * uses a \a for loop, and supplies the enclosed code with a pointer to each list
 * node as it loops. It is typically used as follows:
 *
 * \code
 * static DLLIST_HEAD(entry_list, list_entry) entries;
 * ...
 * struct list_entry {
 *     ...
 *     DLLIST_ENTRY(list_entry) list;
 * }
 * ...
 * struct list_entry *current;
 * ...
 * DLLIST_TRAVERSE_DIRECTION_SAFE_BEGIN(&entries, current, list, first) {
 *    (do something with current here (travers list in forward direction))
 * }
 * ...
 * DLLIST_TRAVERSE_DIRECTION_SAFE_BEGIN(&entries, current, list, last) {
 *    (do something with current here (travers list in reverse direction))
 * }
 * DLLIST_TRAVERSE_DIRECTION_SAFE_END;
 * \endcode
 *
 * It differs from DLLIST_TRAVERSE() in that the code inside the loop can modify
 * (or even free, after calling DLLIST_REMOVE_CURRENT()) the entry pointed to by
 * the \a current pointer without affecting the loop traversal.
 */
#define DLLIST_TRAVERSE_DIRECTION_SAFE_BEGIN(head, var, field, start)	\
	do {																\
		typeof((head)) __list_head = (head);							\
		typeof(__list_head->first) __list_current;						\
		typeof(__list_head->first) __list_first;						\
		typeof(__list_head->first) __list_last;							\
		typeof(__list_head->first) __list_next;							\
		for ((var) = __list_head->start,								\
			__list_current = (var),										\
			__list_first = (var) ? (var)->field.first : NULL,			\
			__list_last = (var) ? (var)->field.last : NULL,				\
			__list_next = (var) ? DLLIST_NEXT_DIRECTION(var, field, start) : NULL;	\
			(var);														\
			(void) __list_current,/* To quiet compiler? */				\
			(void) __list_first,/* To quiet compiler? */				\
			(void) __list_last,/* To quiet compiler? */					\
			(var) = __list_next,										\
			__list_current = (var),										\
			__list_first = (var) ? (var)->field.first : NULL,			\
			__list_last = (var) ? (var)->field.last : NULL,				\
			__list_next = (var) ? DLLIST_NEXT_DIRECTION(var, field, start) : NULL	\
			)

#define RWDLLIST_TRAVERSE_DIRECTION_SAFE_BEGIN	DLLIST_TRAVERSE_DIRECTION_SAFE_BEGIN

/*!
 * \brief Inserts a list node before the current node during a traversal.
 * \param elm This is a pointer to the entry to be inserted.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link nodes of this list together.
 */
#define DLLIST_INSERT_BEFORE_CURRENT(elm, field)					\
		do {															\
			typeof((elm)) __elm = (elm);								\
			__elm->field.last = __list_last;							\
			__elm->field.first = __list_current;						\
			if (__list_head->first == __list_current) {					\
				__list_head->first = __elm;								\
			} else {													\
				__list_last->field.first = __elm;						\
			}															\
			__list_current->field.last = __elm;							\
			if (__list_next == __list_last) {							\
				__list_next = __elm;									\
			}															\
			__list_last = __elm;										\
		} while (0)

#define RWDLLIST_INSERT_BEFORE_CURRENT DLLIST_INSERT_BEFORE_CURRENT

/*!
 * \brief Inserts a list node after the current node during a traversal.
 * \param elm This is a pointer to the node to be inserted.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link nodes of this list together.
 */
#define DLLIST_INSERT_AFTER_CURRENT(elm, field)						\
		do {															\
			typeof((elm)) __elm = (elm);								\
			__elm->field.first = __list_first;							\
			__elm->field.last = __list_current;							\
			if (__list_head->last == __list_current) {					\
				__list_head->last = __elm;								\
			} else {													\
				__list_first->field.last = __elm;						\
			}															\
			__list_current->field.first = __elm;						\
			if (__list_next == __list_first) {							\
				__list_next = __elm;									\
			}															\
			__list_first = __elm;										\
		} while (0)

#define RWDLLIST_INSERT_AFTER_CURRENT DLLIST_INSERT_AFTER_CURRENT

/*!
 * \brief Removes the \a current entry from a list during a traversal.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link entries of this list together.
 *
 * \note This macro can \b only be used inside an DLLIST_TRAVERSE_SAFE_BEGIN()
 * block; it is used to unlink the current entry from the list without affecting
 * the list traversal (and without having to re-traverse the list to modify the
 * previous entry, if any).
 */
#define DLLIST_REMOVE_CURRENT(field)								\
		do {															\
			if (__list_first) {											\
				__list_first->field.last = __list_last;					\
			} else {													\
				__list_head->last = __list_last;						\
			}															\
			if (__list_last) {											\
				__list_last->field.first = __list_first;				\
			} else {													\
				__list_head->first = __list_first;						\
			}															\
			__list_current->field.first = NULL;							\
			__list_current->field.last = NULL;							\
			__list_current = NULL;										\
		} while (0)

#define RWDLLIST_REMOVE_CURRENT DLLIST_REMOVE_CURRENT

/*!
 * \brief Move the current list entry to another list at the tail.
 *
 * \note This is a silly macro.  It should be done explicitly
 * otherwise the field parameter must be the same for the two
 * lists.
 *
 * DLLIST_REMOVE_CURRENT(field);
 * DLLIST_INSERT_TAIL(newhead, var, other_field);
 */
#define DLLIST_MOVE_CURRENT(newhead, field)						\
		do {														\
			typeof ((newhead)->first) __list_cur = __list_current;	\
			DLLIST_REMOVE_CURRENT(field);						\
			DLLIST_INSERT_TAIL((newhead), __list_cur, field);	\
		} while (0)

#define RWDLLIST_MOVE_CURRENT DLLIST_MOVE_CURRENT

/*!
 * \brief Move the current list entry to another list at the head.
 *
 * \note This is a silly macro.  It should be done explicitly
 * otherwise the field parameter must be the same for the two
 * lists.
 *
 * DLLIST_REMOVE_CURRENT(field);
 * DLLIST_INSERT_HEAD(newhead, var, other_field);
 */
#define DLLIST_MOVE_CURRENT_BACKWARDS(newhead, field)			\
		do {														\
			typeof ((newhead)->first) __list_cur = __list_current;	\
			DLLIST_REMOVE_CURRENT(field);						\
			DLLIST_INSERT_HEAD((newhead), __list_cur, field);	\
		} while (0)

#define RWDLLIST_MOVE_CURRENT_BACKWARDS DLLIST_MOVE_CURRENT_BACKWARDS

#define DLLIST_TRAVERSE_DIRECTION_SAFE_END	\
	} while (0)

#define RWDLLIST_TRAVERSE_DIRECTION_SAFE_END	DLLIST_TRAVERSE_DIRECTION_SAFE_END

/*!
 * \brief Loops safely over (traverses) the entries in a list.
 * \param head This is a pointer to the list head structure
 * \param var This is the name of the variable that will hold a pointer to the
 * current list entry on each iteration. It must be declared before calling
 * this macro.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link entries of this list together.
 *
 * This macro is used to safely loop over (traverse) the entries in a list. It
 * uses a \a for loop, and supplies the enclosed code with a pointer to each list
 * entry as it loops. It is typically used as follows:
 *
 * \code
 * static DLLIST_HEAD(entry_list, list_entry) entries;
 * ...
 * struct list_entry {
 *     ...
 *     DLLIST_ENTRY(list_entry) list;
 * }
 * ...
 * struct list_entry *current;
 * ...
 * DLLIST_TRAVERSE_SAFE_BEGIN(&entries, current, list) {
 *    (do something with current here)
 * }
 * DLLIST_TRAVERSE_SAFE_END;
 * \endcode
 *
 * It differs from DLLIST_TRAVERSE() in that the code inside the loop can modify
 * (or even free, after calling DLLIST_REMOVE_CURRENT()) the entry pointed to by
 * the \a current pointer without affecting the loop traversal.
 */
#define DLLIST_TRAVERSE_SAFE_BEGIN(head, var, field)	\
	DLLIST_TRAVERSE_DIRECTION_SAFE_BEGIN(head, var, field, first)

#define RWDLLIST_TRAVERSE_SAFE_BEGIN DLLIST_TRAVERSE_SAFE_BEGIN

/*!
 * \brief Loops safely over (traverses) the entries in a list.
 * \param head This is a pointer to the list head structure
 * \param var This is the name of the variable that will hold a pointer to the
 * current list entry on each iteration. It must be declared before calling
 * this macro.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link entries of this list together.
 *
 * This macro is used to safely loop over (traverse) the entries in a list. It
 * uses a \a for loop, and supplies the enclosed code with a pointer to each list
 * entry as it loops. It is typically used as follows:
 *
 * \code
 * static DLLIST_HEAD(entry_list, list_entry) entries;
 * ...
 * struct list_entry {
 *     ...
 *     DLLIST_ENTRY(list_entry) list;
 * }
 * ...
 * struct list_entry *current;
 * ...
 * DLLIST_TRAVERSE_SAFE_BEGIN(&entries, current, list) {
 *    (do something with current here)
 * }
 * DLLIST_TRAVERSE_SAFE_END;
 * \endcode
 *
 * It differs from DLLIST_TRAVERSE() in that the code inside the loop can modify
 * (or even free, after calling DLLIST_REMOVE_CURRENT()) the entry pointed to by
 * the \a current pointer without affecting the loop traversal.
 */
#define DLLIST_TRAVERSE_BACKWARDS_SAFE_BEGIN(head, var, field)	\
	DLLIST_TRAVERSE_DIRECTION_SAFE_BEGIN(head, var, field, last)

#define RWDLLIST_TRAVERSE_BACKWARDS_SAFE_BEGIN DLLIST_TRAVERSE_BACKWARDS_SAFE_BEGIN

/*!
 * \brief Inserts a list entry after the current entry during a backwards traversal. Since
 *        this is a backwards traversal, this will insert the entry AFTER the current
 *        element. Since this is a backwards traveral, though, this would be BEFORE
 *        the current entry in traversal order. Confusing?
 * \param elm This is a pointer to the entry to be inserted.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link entries of this list together.
 */
#define DLLIST_INSERT_BEFORE_CURRENT_BACKWARDS(elm, field)	\
	DLLIST_INSERT_AFTER_CURRENT(elm, field)

#define RWDLLIST_INSERT_BEFORE_CURRENT_BACKWARDS DLLIST_INSERT_BEFORE_CURRENT_BACKWARDS

/*!
 * \brief Closes a safe loop traversal block.
 */
#define DLLIST_TRAVERSE_SAFE_END DLLIST_TRAVERSE_DIRECTION_SAFE_END

#define RWDLLIST_TRAVERSE_SAFE_END DLLIST_TRAVERSE_SAFE_END

/*!
 * \brief Closes a safe loop traversal block.
 */
#define DLLIST_TRAVERSE_BACKWARDS_SAFE_END DLLIST_TRAVERSE_DIRECTION_SAFE_END

#define RWDLLIST_TRAVERSE_BACKWARDS_SAFE_END DLLIST_TRAVERSE_BACKWARDS_SAFE_END

/*!
 * \brief Initializes a list head structure.
 * \param head This is a pointer to the list head structure
 *
 * This macro initializes a list head structure by setting the head
 * entry to \a NULL (empty list) and recreating the embedded lock.
 */
#define DLLIST_HEAD_INIT(head)			\
	{										\
		(head)->first = NULL;				\
		(head)->last = NULL;				\
		bbs_mutex_init(&(head)->lock);		\
	}

/*!
 * \brief Initializes an rwlist head structure.
 * \param head This is a pointer to the list head structure
 *
 * This macro initializes a list head structure by setting the head
 * entry to \a NULL (empty list) and recreating the embedded lock.
 */
#define RWDLLIST_HEAD_INIT(head)		\
	{										\
		(head)->first = NULL;				\
		(head)->last = NULL;				\
		bbs_rwlock_init(&(head)->lock);		\
	}

/*!
 * \brief Destroys a list head structure.
 * \param head This is a pointer to the list head structure
 *
 * This macro destroys a list head structure by setting the head
 * entry to \a NULL (empty list) and destroying the embedded lock.
 * It does not free the structure from memory.
 */
#define DLLIST_HEAD_DESTROY(head)		\
	{										\
		(head)->first = NULL;				\
		(head)->last = NULL;				\
		bbs_mutex_destroy(&(head)->lock);	\
	}

/*!
 * \brief Destroys an rwlist head structure.
 * \param head This is a pointer to the list head structure
 *
 * This macro destroys a list head structure by setting the head
 * entry to \a NULL (empty list) and destroying the embedded lock.
 * It does not free the structure from memory.
 */
#define RWDLLIST_HEAD_DESTROY(head)		\
	{										\
		(head)->first = NULL;				\
		(head)->last = NULL;				\
		bbs_rwlock_destroy(&(head)->lock);	\
	}

/*!
 * \brief Initializes a list head structure.
 * \param head This is a pointer to the list head structure
 *
 * This macro initializes a list head structure by setting the head
 * entry to \a NULL (empty list). There is no embedded lock handling
 * with this macro.
 */
#define DLLIST_HEAD_INIT_NOLOCK(head)	\
	{										\
		(head)->first = NULL;				\
		(head)->last = NULL;				\
	}

/*!
 * \brief Inserts a list entry after a given entry.
 * \param head This is a pointer to the list head structure
 * \param listelm This is a pointer to the entry after which the new entry should
 * be inserted.
 * \param elm This is a pointer to the entry to be inserted.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link entries of this list together.
 */
#define DLLIST_INSERT_AFTER(head, listelm, elm, field)		\
	do {														\
		typeof((listelm)) __listelm = (listelm);				\
		typeof((elm)) __elm = (elm);							\
		__elm->field.first = __listelm->field.first;			\
		__elm->field.last = __listelm;							\
		if ((head)->last == __listelm) {						\
			(head)->last = __elm;								\
		} else {												\
			__listelm->field.first->field.last = __elm;			\
		}														\
		__listelm->field.first = __elm;							\
	} while (0)

#define RWDLLIST_INSERT_AFTER DLLIST_INSERT_AFTER

/*!
 * \brief Inserts a list entry before a given entry.
 * \param head This is a pointer to the list head structure
 * \param listelm This is a pointer to the entry before which the new entry should
 * be inserted.
 * \param elm This is a pointer to the entry to be inserted.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link entries of this list together.
 */
#define DLLIST_INSERT_BEFORE(head, listelm, elm, field)		\
	do {														\
		typeof((listelm)) __listelm = (listelm);				\
		typeof((elm)) __elm = (elm);							\
		__elm->field.last = __listelm->field.last;				\
		__elm->field.first = __listelm;							\
		if ((head)->first == __listelm) {						\
			(head)->first = __elm;								\
		} else {												\
			__listelm->field.last->field.first = __elm;			\
		}														\
		__listelm->field.last = __elm;							\
	} while (0)

#define RWDLLIST_INSERT_BEFORE DLLIST_INSERT_BEFORE

/*!
 * \brief Inserts a list entry at the head of a list.
 * \param head This is a pointer to the list head structure
 * \param elm This is a pointer to the entry to be inserted.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link entries of this list together.
 */
#define DLLIST_INSERT_HEAD(head, elm, field)	\
	do {											\
		typeof((elm)) __elm = (elm);				\
		__elm->field.last = NULL;					\
		__elm->field.first = (head)->first;			\
		if (!(head)->first) {						\
			(head)->last = __elm;					\
		} else {									\
			(head)->first->field.last = __elm;		\
		}											\
		(head)->first = __elm;						\
	} while (0)

#define RWDLLIST_INSERT_HEAD DLLIST_INSERT_HEAD

/*!
 * \brief Appends a list entry to the tail of a list.
 * \param head This is a pointer to the list head structure
 * \param elm This is a pointer to the entry to be appended.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link entries of this list together.
 *
 * Note: The link field in the appended entry is \b not modified, so if it is
 * actually the head of a list itself, the entire list will be appended
 * temporarily (until the next DLLIST_INSERT_TAIL is performed).
 */
#define DLLIST_INSERT_TAIL(head, elm, field)	\
	do {											\
		typeof((elm)) __elm = (elm);				\
		__elm->field.first = NULL;					\
		if (!(head)->first) {						\
			__elm->field.last = NULL;				\
			(head)->first = __elm;					\
		} else {									\
			__elm->field.last = (head)->last;		\
			(head)->last->field.first = __elm;		\
		}											\
		(head)->last = __elm;						\
	} while (0)

#define RWDLLIST_INSERT_TAIL DLLIST_INSERT_TAIL

/*!
 * \brief Appends a whole list to the tail of a list.
 * \param head This is a pointer to the list head structure
 * \param list This is a pointer to the list to be appended.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link entries of this list together.
 *
 * Note: The source list (the \a list parameter) will be empty after
 * calling this macro (the list entries are \b moved to the target list).
 */
#define DLLIST_APPEND_DLLIST(head, list, field)		\
	do {												\
		if (!(head)->first) {							\
			(head)->first = (list)->first;				\
			(head)->last = (list)->last;				\
		} else {										\
			(head)->last->field.first = (list)->first;	\
			(list)->first->field.last = (head)->last;	\
			(head)->last = (list)->last;				\
		}												\
		(list)->first = NULL;							\
		(list)->last = NULL;							\
	} while (0)

#define RWDLLIST_APPEND_DLLIST DLLIST_APPEND_DLLIST

/*!
 * \brief Removes and returns the head entry from a list.
 * \param head This is a pointer to the list head structure
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link entries of this list together.
 *
 * Removes the head entry from the list, and returns a pointer to it.
 * This macro is safe to call on an empty list.
 */
#define DLLIST_REMOVE_HEAD(head, field)			\
	({												\
		typeof((head)->first) cur = (head)->first;	\
		if (cur) {									\
			(head)->first = cur->field.first;		\
			if ((head)->first) {					\
				(head)->first->field.last = NULL;	\
			}										\
			cur->field.first = NULL;				\
			cur->field.last = NULL;					\
			if ((head)->last == cur) {				\
				(head)->last = NULL;				\
			}										\
		}											\
		cur;										\
	})

#define RWDLLIST_REMOVE_HEAD DLLIST_REMOVE_HEAD

/*!
 * \brief Removes and returns the tail node from a list.
 * \param head This is a pointer to the list head structure
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link nodes of this list together.
 *
 * Removes the tail entry from the list, and returns a pointer to it.
 * This macro is safe to call on an empty list.
 */
#define DLLIST_REMOVE_TAIL(head, field)			\
	({												\
		typeof((head)->last) cur = (head)->last;	\
		if (cur) {									\
			(head)->last = cur->field.last;			\
			if ((head)->last) {						\
				(head)->last->field.first = NULL;	\
			}										\
			cur->field.first = NULL;				\
			cur->field.last = NULL;					\
			if ((head)->first == cur) {				\
				(head)->first = NULL;				\
			}										\
		}											\
		cur;										\
	})

#define RWDLLIST_REMOVE_TAIL DLLIST_REMOVE_TAIL

/*!
 * \brief Removes a specific entry from a list.
 * \param head This is a pointer to the list head structure
 * \param elm This is a pointer to the entry to be removed.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link entries of this list together.
 * \warning The removed entry is \b not freed.
 */
#define DLLIST_REMOVE(head, elm, field)								\
	do {																\
		typeof((elm)) __elm = (elm);									\
	 	if (__elm) {													\
			if (__elm->field.first) {									\
				__elm->field.first->field.last = __elm->field.last;		\
			} else {													\
				(head)->last = __elm->field.last;						\
			}															\
			if (__elm->field.last) {									\
				__elm->field.last->field.first = __elm->field.first;	\
			} else {													\
				(head)->first = __elm->field.first;						\
			}															\
			__elm->field.first = NULL;									\
			__elm->field.last = NULL;									\
		}																\
	} while (0)

#define RWDLLIST_REMOVE DLLIST_REMOVE

/*!
 * \brief Removes a specific node from a list if it is in the list.
 * \param head This is a pointer to the list head structure
 * \param elm This is a pointer to the node to be removed.
 * \param field This is the name of the field (declared using DLLIST_ENTRY())
 * used to link nodes of this list together.
 * \warning The removed node is \b not freed.
 * \return elm if the list had elm in it.
 * \return NULL if not.
 */
#define DLLIST_REMOVE_VERIFY(head, elm, field)						\
	({																	\
		typeof((elm)) __res = DLLIST_IS_MEMBER(head, elm, field);	\
		DLLIST_REMOVE(head, __res, field);							\
		__res;															\
	})

#define RWDLLIST_REMOVE_VERIFY DLLIST_REMOVE_VERIFY

/*!
 * \brief Removes all the entries from a list and invokes a destructor on each entry
 * \param head This is a pointer to the list head structure
 * \param field This is the name of the field (declared using RWLIST_ENTRY())
 * used to link entries of this list together.
 * \param destructor A destructor function to call on each element (e.g. free)
 *
 * This macro is safe to call on an empty list.
 */
#define DLLIST_REMOVE_ALL(head, field, destructor) { \
	typeof((head)) __list_head = head; \
	typeof(__list_head->first) __list_current; \
	while ((__list_current = DLLIST_REMOVE_HEAD(head, field))) { \
		destructor(__list_current); \
	} \
}

#define RWDLLIST_REMOVE_ALL DLLIST_REMOVE_ALL

#endif /* _DLINKEDLISTS_H */
