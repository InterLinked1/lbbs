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

/* No lock variants
 * These are prefixed BBS_LIST instead of simply LIST,
 * as LIST_ENTRY is already defined on FreeBSD in /usr/include/sys/queue.h
 * The RWLIST macros are not prefixed with BBS for brevity */
#define BBS_LIST_HEAD_NOLOCK(name, type)	\
struct name {							\
	struct type *first;					\
	struct type *last;					\
}

#define BBS_LIST_HEAD_NOLOCK_INIT_VALUE	{	\
	.first = NULL,						\
	.last = NULL,						\
}

#define BBS_LIST_HEAD_NOLOCK_STATIC(name, type)	\
struct name {								\
	struct type *first;						\
	struct type *last;						\
} name = BBS_LIST_HEAD_NOLOCK_INIT_VALUE

/*!
 * \brief Write locks a list.
 * \param head This is a pointer to the list head structure
 *
 * This macro attempts to place an exclusive write lock in the
 * list head structure pointed to by head.
 * \retval 0 on success
 * \retval non-zero on failure
 */
#define RWLIST_WRLOCK(head) __bbs_rwlock_wrlock(&(head)->lock, __FILE__, __LINE__, __func__, #head)

/*!
 * \brief Read locks a list.
 * \param head This is a pointer to the list head structure
 *
 * This macro attempts to place a read lock in the
 * list head structure pointed to by head.
 * \retval 0 on success
 * \retval non-zero on failure
 */
#define RWLIST_RDLOCK(head) __bbs_rwlock_rdlock(&(head)->lock, __FILE__, __LINE__, __func__, #head)

/*!
 * \brief Write locks a list, without blocking if the list is locked.
 * \param head This is a pointer to the list head structure
 *
 * This macro attempts to place an exclusive write lock in the
 * list head structure pointed to by head.
 * \retval 0 on success
 * \retval non-zero on failure
 */
#define RWLIST_TRYWRLOCK(head) __bbs_rwlock_trywrlock(&(head)->lock, __FILE__, __LINE__, __func__, #head)

/*!
 * \brief Attempts to unlock a read/write based list.
 * \param head This is a pointer to the list head structure
 *
 * This macro attempts to remove a read or write lock from the
 * list head structure pointed to by head. If the list
 * was not locked by this thread, this macro has no effect.
 */
#define RWLIST_UNLOCK(head) __bbs_rwlock_unlock(&(head)->lock, __FILE__, __LINE__, __func__, #head)

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
struct name {                                                       \
	struct type *first;                                             \
	struct type *last;                                              \
	bbs_rwlock_t lock;                                          \
}

/*!
 * \brief Defines initial values for a declaration of RWLIST_HEAD
 */
#define RWLIST_HEAD_INIT_VALUE      {               \
	.first = NULL,                                  \
	.last = NULL,                                   \
	.lock = BBS_RWLOCK_INITIALIZER,             \
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
	bbs_rwlock_t lock;                                      \
} name = RWLIST_HEAD_INIT_VALUE

/*!
 * \brief Initializes an rwlist head structure.
 * \param head This is a pointer to the list head structure
 *
 * This macro initializes a list head structure by setting the head
 * entry to \a NULL (empty list) and recreating the embedded lock.
 */
#define RWLIST_HEAD_INIT(head) {                                    \
	(head)->first = NULL;                                           \
	(head)->last = NULL;                                            \
	__bbs_rwlock_init(&(head)->lock, __FILE__, __LINE__, __func__, #head); \
}

/*!
 * \brief Destroys an rwlist head structure.
 * \param head This is a pointer to the list head structure
 *
 * This macro destroys a list head structure by setting the head
 * entry to \a NULL (empty list) and destroying the embedded lock.
 * It does not free the structure from memory.
 */
#define RWLIST_HEAD_DESTROY(head) {                                 \
	(head)->first = NULL;                                           \
	(head)->last = NULL;                                            \
	__bbs_rwlock_destroy(&(head)->lock, __FILE__, __LINE__, __func__, #head); \
}

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
#define BBS_LIST_ENTRY(type)						\
struct {								\
	struct type *next;						\
}

#define RWLIST_ENTRY BBS_LIST_ENTRY

/*!
 * \brief Returns the first entry contained in a list.
 * \param head This is a pointer to the list head structure
 */
#define BBS_LIST_FIRST(head) ((head)->first)
#define RWLIST_FIRST BBS_LIST_FIRST

/*!
 * \brief Returns the last entry contained in a list.
 * \param head This is a pointer to the list head structure
 */
#define BBS_LIST_LAST(head) ((head)->last)
#define RWLIST_LAST BBS_LIST_LAST

/*!
 * \brief Returns the next entry in the list after the given entry.
 * \param elm This is a pointer to the current entry.
 * \param field This is the name of the field (declared using BBS_LIST_ENTRY())
 * used to link entries of this list together.
 */
#define BBS_LIST_NEXT(elm, field) ((elm)->field.next)
#define RWLIST_NEXT BBS_LIST_NEXT

/*!
 * \brief Checks whether the specified list contains any entries.
 * \param head This is a pointer to the list head structure
 *
 * \return zero if the list has entries
 * \return non-zero if not.
 */
#define BBS_LIST_EMPTY(head) (BBS_LIST_FIRST(head) == NULL)
#define RWLIST_EMPTY BBS_LIST_EMPTY

/*!
 * \brief Returns the number of elements in the list
 * \param head This is a pointer to the list head structure
 * \param var This is the name of the variable that will hold a pointer to the
 * current list entry on each iteration. It must be declared before calling
 * this macro.
 * \param field This is the name of the field (declared using BBS_LIST_ENTRY())
 * used to link entries of this list together.
 *
 * \return Number of elements in list
 */
#define BBS_LIST_SIZE(head,var,field) ({ \
	int __rwlist_count = 0; \
	for((var) = (head)->first; (var); (var) = (var)->field.next, __rwlist_count++); \
	__rwlist_count; \
})
#define RWLIST_SIZE BBS_LIST_SIZE

/*!
 * \brief Loops over (traverses) the entries in a list.
 * \param head This is a pointer to the list head structure
 * \param var This is the name of the variable that will hold a pointer to the
 * current list entry on each iteration. It must be declared before calling
 * this macro.
 * \param field This is the name of the field (declared using BBS_LIST_ENTRY())
 * used to link entries of this list together.
 *
 * This macro is use to loop over (traverse) the entries in a list. It uses a
 * \a for loop, and supplies the enclosed code with a pointer to each list
 * entry as it loops.
 */
#define BBS_LIST_TRAVERSE(head,var,field) for((var) = (head)->first; (var); (var) = (var)->field.next)
#define RWLIST_TRAVERSE BBS_LIST_TRAVERSE

/*!
 * \brief Loops safely over (traverses) the entries in a list.
 * \param head This is a pointer to the list head structure
 * \param var This is the name of the variable that will hold a pointer to the
 * current list entry on each iteration. It must be declared before calling
 * this macro.
 * \param field This is the name of the field (declared using BBS_LIST_ENTRY())
 * used to link entries of this list together.
 *
 * This macro is used to safely loop over (traverse) the entries in a list. It
 * uses a \a for loop, and supplies the enclosed code with a pointer to each list
 * entry as it loops.
 *
 * It differs from BBS_LIST_TRAVERSE() in that the code inside the loop can modify
 * (or even free, after calling BBS_LIST_REMOVE_CURRENT()) the entry pointed to by
 * the \a current pointer without affecting the loop traversal.
 */
#define BBS_LIST_TRAVERSE_SAFE_BEGIN(head, var, field) {				\
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
#define RWLIST_TRAVERSE_SAFE_BEGIN BBS_LIST_TRAVERSE_SAFE_BEGIN

/*!
 * \brief Removes the \a current entry from a list during a traversal.
 * \param field This is the name of the field (declared using BBS_LIST_ENTRY())
 * used to link entries of this list together.
 *
 * \note This macro can \b only be used inside an BBS_LIST_TRAVERSE_SAFE_BEGIN()
 * block; it is used to unlink the current entry from the list without affecting
 * the list traversal (and without having to re-traverse the list to modify the
 * previous entry, if any).
 */
#define BBS_LIST_REMOVE_CURRENT(field) do { 							\
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
#define RWLIST_REMOVE_CURRENT BBS_LIST_REMOVE_CURRENT

/*!
 * \brief Closes a safe loop traversal block.
 */
#define BBS_LIST_TRAVERSE_SAFE_END }
#define RWLIST_TRAVERSE_SAFE_END BBS_LIST_TRAVERSE_SAFE_END

/*!
 * \brief Inserts a list entry after a given entry.
 * \param head This is a pointer to the list head structure
 * \param listelm This is a pointer to the entry after which the new entry should
 * be inserted.
 * \param elm This is a pointer to the entry to be inserted.
 * \param field This is the name of the field (declared using BBS_LIST_ENTRY())
 * used to link entries of this list together.
 */
#define BBS_LIST_INSERT_AFTER(head, listelm, elm, field) do {		\
	(elm)->field.next = (listelm)->field.next;			\
	(listelm)->field.next = (elm);					\
	if ((head)->last == (listelm))					\
		(head)->last = (elm);					\
} while (0)
#define RWLIST_INSERT_AFTER BBS_LIST_INSERT_AFTER

/*!
 * \brief Inserts a list entry at the head of a list.
 * \param head This is a pointer to the list head structure
 * \param elm This is a pointer to the entry to be inserted.
 * \param field This is the name of the field (declared using BBS_LIST_ENTRY())
 * used to link entries of this list together.
 */
#define BBS_LIST_INSERT_HEAD(head, elm, field) do {			\
		(elm)->field.next = (head)->first;			\
		(head)->first = (elm);					\
		if (!(head)->last)					\
			(head)->last = (elm);				\
} while (0)
#define RWLIST_INSERT_HEAD BBS_LIST_INSERT_HEAD

/*!
 * \brief Appends a list entry to the tail of a list.
 * \param head This is a pointer to the list head structure
 * \param elm This is a pointer to the entry to be appended.
 * \param field This is the name of the field (declared using BBS_LIST_ENTRY())
 * used to link entries of this list together.
 *
 * Note: The link field in the appended entry is \b not modified, so if it is
 * actually the head of a list itself, the entire list will be appended
 * temporarily (until the next BBS_LIST_INSERT_TAIL is performed).
 */
#define BBS_LIST_INSERT_TAIL(head, elm, field) do {			\
	if (!(head)->first) {						\
		(head)->first = (elm);					\
		(head)->last = (elm);					\
	} else {								\
		(head)->last->field.next = (elm);			\
		(head)->last = (elm);					\
	}									\
} while (0)
#define RWLIST_INSERT_TAIL BBS_LIST_INSERT_TAIL

/*!
 * \brief Insert a list entry such that the list remains sorted in ascending order
 * \param head This is a pointer to the list head structure
 * \param elm This is a pointer to the entry to be inserted.
 * \param field This is the name of the field (declared using BBS_LIST_ENTRY())
 * used to link entries of this list together.
 * \param attr This is the name of the struct field that will be compared
 */
#define BBS_LIST_INSERT_SORTED(head, elm, field, attr) {	\
	typeof((head)->first) __prev = NULL, __cur;			\
	BBS_LIST_TRAVERSE(head, __cur, field) { 				\
		if (__cur->attr > elm->attr) { 					\
			break; 										\
		} 												\
		__prev = __cur; 								\
	} 													\
	if (__prev) { 										\
		BBS_LIST_INSERT_AFTER(head, __prev, elm, field); 	\
	} else { 											\
		BBS_LIST_INSERT_HEAD(head, elm, field); /* List was empty, or it should go at beginning. */ \
	}													\
}
#define RWLIST_INSERT_SORTED BBS_LIST_INSERT_SORTED

/*!
 * \brief Inserts a list entry into a alphabetically sorted list
 * \param head Pointer to the list head structure
 * \param elm Pointer to the entry to be inserted
 * \param field Name of the list entry field (declared using BBS_LIST_ENTRY())
 * \param sortfield Name of the field on which the list is sorted
 */
#define BBS_LIST_INSERT_SORTALPHA(head, elm, field, sortfield) {          \
	if (!(head)->first) {                                               \
		(head)->first = (elm);                                          \
		(head)->last = (elm);                                           \
	} else {                                                            \
		typeof((head)->first) __cur = (head)->first, __prev = NULL;     \
		while (__cur && strcmp(__cur->sortfield, elm->sortfield) < 0) { \
			__prev = __cur;                                             \
			__cur = __cur->field.next;                                  \
		}                                                               \
		if (!__prev) {                                                  \
			BBS_LIST_INSERT_HEAD(head, elm, field);                       \
		} else if (!__cur) {                                            \
			BBS_LIST_INSERT_TAIL(head, elm, field);                       \
		} else {                                                        \
			BBS_LIST_INSERT_AFTER(head, __prev, elm, field);              \
		}                                                               \
	}                                                                   \
}
#define RWLIST_INSERT_SORTALPHA BBS_LIST_INSERT_SORTALPHA

/*!
 * \brief Removes and returns the head entry from a list.
 * \param head This is a pointer to the list head structure
 * \param field This is the name of the field (declared using BBS_LIST_ENTRY())
 * used to link entries of this list together.
 *
 * Removes the head entry from the list, and returns a pointer to it.
 * This macro is safe to call on an empty list.
 */
#define BBS_LIST_REMOVE_HEAD(head, field) ({				\
		typeof((head)->first) __cur = (head)->first;		\
		if (__cur) {						\
			(head)->first = __cur->field.next;		\
			__cur->field.next = NULL;			\
			if ((head)->last == __cur)			\
				(head)->last = NULL;			\
		}							\
		__cur;							\
	})
#define RWLIST_REMOVE_HEAD BBS_LIST_REMOVE_HEAD

/*!
 * \brief Removes a specific entry from a list.
 * \param head This is a pointer to the list head structure
 * \param elm This is a pointer to the entry to be removed.
 * \param field This is the name of the field (declared using BBS_LIST_ENTRY())
 * used to link entries of this list together.
 * \retval elm if elm was in the list.
 * \retval NULL if elm was not in the list or elm was NULL.
 * \warning The removed entry is \b not freed.
 */
#define BBS_LIST_REMOVE(head, elm, field)						\
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
#define RWLIST_REMOVE BBS_LIST_REMOVE

/*!
 * \brief Removes a specific entry from a list, by an attribute match.
 * \param head This is a pointer to the list head structure
 * \param attribute The attribute by which to look for a match
 * \param value The value that the attribute must have to match
 * \param field This is the name of the field (declared using BBS_LIST_ENTRY())
 * used to link entries of this list together.
 * \retval Removed element
 * \retval NULL if no matching element was found.
 * \warning The removed entry is \b not freed.
 */
#define BBS_LIST_REMOVE_BY_FIELD(head, attribute, value, field)	\
	({															\
		typeof((head)->first) __elm = NULL;						\
		if ((head)->first && (head)->first->attribute == value) {		\
			__elm = (head)->first;							\
			(head)->first = __elm->field.next;				\
			__elm->field.next = NULL;						\
			if ((head)->last == __elm) {					\
				(head)->last = NULL;						\
			}												\
		} else {											\
			typeof((head)->first) __prev = (head)->first;	\
			while (__prev && __prev->field.next && __prev->field.next->attribute != value) {	\
				__prev = __prev->field.next;				\
			}												\
			if (__prev) {									\
				__elm = (__prev)->field.next;				\
				if (__elm) {								\
					__prev->field.next = __elm->field.next;	\
					__elm->field.next = NULL;				\
				}											\
				if ((head)->last == __elm) {				\
					(head)->last = __prev;					\
				}											\
			} else {										\
				__elm = NULL;								\
			}												\
		}													\
		__elm;												\
	})
#define RWLIST_REMOVE_BY_FIELD BBS_LIST_REMOVE_BY_FIELD

#define RWLIST_WRLOCK_REMOVE_BY_FIELD(head, attribute, value, field) ({ \
	typeof((head)->first) __elm_outer = NULL; \
	RWLIST_WRLOCK(head); \
	__elm_outer = RWLIST_REMOVE_BY_FIELD(head, attribute, value, field); \
	RWLIST_UNLOCK(head); \
	__elm_outer; \
})

/*!
 * \brief Removes a specific entry from a list, by an attribute string comparison match.
 * \param head This is a pointer to the list head structure
 * \param attribute The attribute by which to look for a match via string comparison
 * \param value The value that the attribute must have to match
 * \param field This is the name of the field (declared using BBS_LIST_ENTRY())
 * used to link entries of this list together.
 * \retval Removed element
 * \retval NULL if no matching element was found.
 * \warning The removed entry is \b not freed.
 */
#define BBS_LIST_REMOVE_BY_STRING_FIELD(head, attribute, value, field)	\
	({															\
		typeof((head)->first) __elm = NULL;						\
		if ((head)->first && !strcmp((head)->first->attribute, value)) {		\
			__elm = (head)->first;							\
			(head)->first = __elm->field.next;				\
			__elm->field.next = NULL;						\
			if ((head)->last == __elm) {					\
				(head)->last = NULL;						\
			}												\
		} else {											\
			typeof((head)->first) __prev = (head)->first;	\
			while (__prev && __prev->field.next && strcmp(__prev->field.next->attribute, value)) {	\
				__prev = __prev->field.next;				\
			}												\
			if (__prev) {									\
				__elm = (__prev)->field.next;				\
				if (__elm) {								\
					__prev->field.next = __elm->field.next;	\
					__elm->field.next = NULL;				\
				}											\
				if ((head)->last == __elm) {				\
					(head)->last = __prev;					\
				}											\
			} else {										\
				__elm = NULL;								\
			}												\
		}													\
		__elm;												\
	})
#define RWLIST_REMOVE_BY_STRING_FIELD BBS_LIST_REMOVE_BY_STRING_FIELD

#define RWLIST_WRLOCK_REMOVE_BY_STRING_FIELD(head, attribute, value, field) ({ \
	typeof((head)->first) __elm_outer = NULL; \
	RWLIST_WRLOCK(head); \
	__elm_outer = RWLIST_REMOVE_BY_STRING_FIELD(head, attribute, value, field); \
	RWLIST_UNLOCK(head); \
	__elm_outer; \
})

/*!
 * \brief Removes all the entries from a list and invokes a destructor on each entry
 * \param head This is a pointer to the list head structure
 * \param field This is the name of the field (declared using BBS_LIST_ENTRY())
 * used to link entries of this list together.
 * \param destructor A destructor function to call on each element (e.g. free)
 *
 * This macro is safe to call on an empty list.
 */
#define BBS_LIST_REMOVE_ALL(head, field, destructor) { \
	typeof((head)) __list_head = head; \
	typeof(__list_head->first) __list_current; \
	while ((__list_current = BBS_LIST_REMOVE_HEAD(head, field))) { \
		destructor(__list_current); \
	} \
}
#define RWLIST_REMOVE_ALL BBS_LIST_REMOVE_ALL

/*! \brief Same as RWLIST_REMOVE_ALL, but WRLOCK list beforehand and UNLOCK afterwards */
#define RWLIST_WRLOCK_REMOVE_ALL(head, field, destructor) \
	RWLIST_WRLOCK(head); \
	RWLIST_REMOVE_ALL(head, field, destructor); \
	RWLIST_UNLOCK(head);

#endif /* _LINKEDLISTS_H */
