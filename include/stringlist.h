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
 * \brief Linked list of strings
 *
 */

#include "include/linkedlists.h"

/* Forward declarations */
struct stringitem;
RWLIST_HEAD(stringlist, stringitem);

/*! \brief Init a stringlist */
#define stringlist_init(l) RWLIST_HEAD_INIT(l)

/*! \brief Destroy a stringlist */
#define stringlist_destroy(l) RWLIST_HEAD_DESTROY(l)

/*! \brief Empty and destroy a stringlist */
#define stringlist_empty_destroy(l) stringlist_empty(l); stringlist_destroy(l)

/*!
 * \brief Get the number of items in a stringlist
 * \return Number of items
 */
int stringlist_size(struct stringlist *list);

/*! \brief Whether a stringlist is empty */
int stringlist_is_empty(struct stringlist *list);

/*!
 * \brief Whether a stringlist contains a string
 * \param list
 * \param s Search string. Case sensitive.
 * \retval 1 if contains, 0 if not
 * \note Must not be WRLOCK'd when calling
 */
int stringlist_contains(struct stringlist *list, const char *s);

/*!
 * \brief Whether a stringlist contains a string
 * \param list
 * \param s Search string. Case sensitive.
 * \retval 1 if contains, 0 if not
 * \note Must be locked when calling
 */
int stringlist_contains_locked(struct stringlist *list, const char *s);

/*!
 * \brief Whether a stringlist contains a string, case-insensitively
 * \param list
 * \param s Search string. Case insensitive.
 * \retval 1 if contains, 0 if not
 */
int stringlist_case_contains(struct stringlist *list, const char *s);

/*!
 * \brief Remove the first encountered occurence of a string from a stringlist
 * \param list
 * \param s Search string. Case sensitive.
 * \retval 0 if removed once, -1 if not present
 */
int stringlist_remove(struct stringlist *list, const char *s);

/*! \brief Remove all items from a stringlist */
void stringlist_empty(struct stringlist *list);

/*!
 * \brief Get the next stringlist item in a stringlist without removing it
 * \param list
 * \param i Initialize to NULL. The value will contain the next item so this function can be repeatedly called.
 *        When NULL, this will return NULL again.
 * \returns Next string, or NULL if end of list reached.
 * \note The returned string must not be modified, since it remains in the list.
 */
const char *stringlist_next(const struct stringlist *list, struct stringitem **i);

/*!
 * \brief Pop the most recently added item to a string list
 * \retval string if list is non-empty, NULL if list is empty.
 * \note Assumes list is WRLOCKed
 * \note The returned string must be freed using free()
 */
char *stringlist_pop(struct stringlist *list);

/*!
 * \brief Add an item to the beginning of stringlist
 * \param list
 * \param s String to add
 * \note Assumes list is WRLOCKed
 * \retval 0 on success, -1 on failure
 */
int stringlist_push(struct stringlist *list, const char *s);

/*!
 * \brief Add an item to a stringlist, such that the stringlist remains sorted alphabetically
 * \param list
 * \param s String to add
 * \note Assumes list is WRLOCKed
 * \retval 0 on success, -1 on failure
 */
int stringlist_push_sorted(struct stringlist *list, const char *s);

/*!
 * \brief Add an item to the end of a stringlist
 * \param list
 * \param s String to add
 * \note Assumes list is WRLOCKed
 * \retval 0 on success, -1 on failure
 */
int stringlist_push_tail(struct stringlist *list, const char *s);

/*!
 * \brief Add all the items in a comma-separated list to a stringlist
 * \param list
 * \param s List of items to add
 * \retval 0 on total success, -1 on partial or complete failure
 */
int stringlist_push_list(struct stringlist *list, const char *s);
