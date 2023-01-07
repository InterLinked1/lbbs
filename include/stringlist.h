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

/* Forward declarations */
struct stringitem;
RWLIST_HEAD(stringlist, stringitem);

/*!
 * \brief Whether a stringlist contains a string
 * \param list
 * \param s Search string. Case sensitive.
 * \retval 1 if contains, 0 if not
 */
int stringlist_contains(struct stringlist *list, const char *s);

/*! \brief Remove all items from a stringlist */
void stringlist_empty(struct stringlist *list);

/*!
 * \brief Add an item to a stringlist
 * \param list
 * \param s String to add
 * \note Assumes list is WRLOCKed
 * \retval 0 on success, -1 on failure
 */
int stringlist_push(struct stringlist *list, const char *s);
