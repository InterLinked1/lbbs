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
 * \brief IMAP Server FETCH
 *
 */

/* There can be multiple of these in a request */
struct fetch_body_request {
	const char *bodyarg;	/*!< BODY arguments */
	int substart;			/*!< For BODY and BODY.PEEK partial fetch, the beginning octet */
	long sublength;			/*!< For BODY and BODY.PEEK partial fetch, number of bytes to fetch */
	unsigned int peek:1;	/*!< Whether this is a BODY.PEEK */
	RWLIST_ENTRY(fetch_body_request) entry;
};

RWLIST_HEAD(body_fetches, fetch_body_request);

struct fetch_request {
	const char *flags;
	unsigned long changedsince;
	unsigned int envelope:1;
	unsigned int body:1;
	unsigned int bodystructure:1;
	unsigned int internaldate:1;
	unsigned int rfc822:1;
	unsigned int rfc822header:1;
	unsigned int rfc822size:1;
	unsigned int rfc822text:1;
	unsigned int uid:1;
	unsigned int modseq:1;
	unsigned int vanished:1;
	unsigned int nopeek:1;	/*!< An operation was requested that will implicitly mark seen */
	struct body_fetches bodyfetches;
};

/*! \brief strsep-like FETCH items tokenizer */
char *fetchitem_sep(char **s);

/*!
 * \brief Retrieve data associated with a message
 * \param imap
 * \param s FETCH command arguments
 * \param usinguid UID FETCH instead of FETCH
 * \param tagged Whether to send a tagged reply at the end of the command
 */
int handle_fetch_full(struct imap_session *imap, char *s, int usinguid, int tagged);
