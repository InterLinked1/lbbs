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
 * \brief RFC6376 DomainKeys Identified Mail (DKIM) Signing and Verification
 * \note Used for both DKIM and ARC signing
 */

#include "include/linkedlists.h"

struct dkim_domain {
	const char *domain;
	const char *selector;
	const char *key;
	size_t keylen;
	RWLIST_ENTRY(dkim_domain) entry;
	unsigned int strictheaders:1;
	unsigned int strictbody:1;
	unsigned int sha256:1;
	char data[];
};

/*!
 * \brief Get a domain that can be signed using DKIM/ARC
 * \param name Domain name
 * \return dkim_domain if found
 * \return NULL if domain not found
 */
struct dkim_domain *smtp_get_dkim_domain(const char *name);
