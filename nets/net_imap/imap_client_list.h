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
 * \brief IMAP Client LIST
 *
 */

/*! \brief Allow a LIST against mailboxes on other mail servers, configured in the .imapremote file in a user's home directory */
/*! \note XXX Virtual mailboxes already have a meaning in some IMAP contexts, so maybe "remote mailboxes" would be a better name? */
int list_virtual(struct imap_session *imap, struct list_command *lcmd);
