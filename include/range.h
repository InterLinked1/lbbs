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
 * \brief Numeric lists and ranges
 *
 * \note These functions are primarily (or exclusively) used by net_imap,
 *       however they are general utility functions,
 *       and given how large net_imap has become they have been moved here.
 *
 */

/*!
 * \brief Determine whether a number is found in a list of ranges (e.g. 1,2,4:7,9:11)
 * \param s List of ranges
 * \param num Number to search for
 * \param sequences Temporary buffer at least as large as s
 * \note Direct use of this function is more efficient than in_range since we can reuse the same allocated buffer for all comparisons
 */
int in_range_allocated(const char *s, int num, char *sequences);

/*!
 * \brief Determine whether a number is found in a list of ranges (e.g. 1,2,4:7,9:11)
 * \param s List of ranges
 * \param num Number to search for
 * \note Memory is allocated for every call, which is not terribly efficient. Prefer using in_range_allocated directly.
 */
int in_range(const char *s, int num);

/*!
 * \brief Add an unsigned int to the end of a list of unsigned integers
 * \param a List of unsigned integers. Must be initialized to NULL when empty.
 * \param lengths Current size of list. Initialize to 0.
 * \param allocsizes. Current allocation size. Initialize to 0.
 * \param vala Value to add to the list
 * \retval 0 on success, -1 on failure
 */
int uintlist_append(unsigned int **a, int *lengths, int *allocsizes, unsigned int vala);

/*!
 * \brief Atomically add 2 unsigned ints to the end of 2 lists of unsigned integers
 * \brief a List of unsigned integers. Must be initialized to NULL when empty.
 * \brief b List of unsigned integers. Must be initialized to NULL when empty.
 * \param lengths Current size of list. Initialize to 0.
 * \param allocsizes. Current allocation size. Initialize to 0.
 * \param vala Value to add to list a
 * \param valb Value to add to list b
 * \retval 0 on success, -1 on failure
 */
int uintlist_append2(unsigned int **a, unsigned int **b, int *lengths, int *allocsizes, unsigned int vala, unsigned int valb);

/*!
 * \brief Generate a string representation of a uintlist as a list of ranges (e.g. 1,2,4:7,9:11)
 * \param l A uintlist
 * \param lengths Number of elements in l
 * \return NULL on failure
 * \return String representation of list. free when done.
 */
char *gen_uintlist(unsigned int *l, int lengths);

/*!
 * \brief Generate a string representation of a uintlist as a list of numbers (e.g. 1 2 4 5 6 7 9 10 11)
 * \param l A uintlist
 * \param lengths Number of elements in l
 * \return NULL on failure
 * \return String representation of list. free when done.
 */
char *uintlist_to_str(unsigned int *a, int length);

/*!
 * \brief Generate a string representation of a uintlist as a list of ranges (e.g. 1,2,4:7,9:11)
 * \param l A uintlist
 * \param lengths Number of elements in l
 * \return NULL on failure
 * \return String representation of list. free when done.
 * \todo How is this different from gen_uintlist? Consolidate the 2?
 */
char *uintlist_to_ranges(unsigned int *a, int length);

/*!
 * \brief Convert a string containing a list of ranges into a uintlist
 * \param s String to convert
 * \param[out] list uintlist
 * \param[out] length Number of elements in list.
 * \retval 0 on success, -1 on failure
 * \warning This function is not safe to use for arbitrary valid IMAP sequences, e.g. *, 1:*, etc.
 */
int range_to_uintlist(char *s, unsigned int **list, int *length);
