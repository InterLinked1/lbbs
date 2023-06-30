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
 * \brief IMAP Server SEARCH, SORT, THREAD
 *
 */

int handle_search(struct imap_session *imap, char *s, int usinguid);

int handle_sort(struct imap_session *imap, char *s, int usinguid);

int test_thread_orderedsubject(void);

int test_thread_references(void);

int handle_thread(struct imap_session *imap, char *s, int usinguid);
