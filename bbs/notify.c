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
 * \brief System and User Notifications
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include "include/mail.h"
#include "include/user.h" /* must be included before notify.h */
#include "include/notify.h"

#define MSG_TRAILER "\r\n\r\n\t--" BBS_SHORTNAME

int __attribute__ ((format (gnu_printf, 3, 4))) bbs_sysop_email(struct bbs_user *user, const char *subject, const char *fmt, ...)
{
	int len, res;
	char *buf;
	char frombuf[192];
	const char *to = NULL; /* Go to sysop */
	const char *from = NULL; /* Sent from default noreply */
	const char *replyto = NULL;
	char *buf2;
	va_list ap;

	if (user) {
		if (!strlen_zero(bbs_user_email(user))) {
			/* If logged in as guest, it is certainly possible guestname and guestemail might not be set.
			 * (askinfo=no could be set).
			 * If this is the case, we have no way of getting in touch with the user.
			 */
			snprintf(frombuf, sizeof(frombuf), "%s <%s>", bbs_user_alias(user), bbs_user_email(user));
			replyto = frombuf;
			bbs_debug(5, "Reply-To: %s\n", replyto);
		} else {
			/* if user but no email, it will not have the Reply-To address set */
			bbs_debug(4, "No email address available for user %d\n", user->id);
		}
	} else {
		bbs_debug(5, "No sending user, system message\n");
	}

	/* Skip the usual no-format skip-allocation string check here, since:
	 * a) almost all messages will have *some* dynamic (variadic) arg
	 * b) we want to tack on a trailer afterwards, regardless, so we have to allocate anyways
	 */

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}

	/* Append the customary message trailer */
	buf2 = realloc(buf, len + STRLEN(MSG_TRAILER) + 1);
	if (ALLOC_SUCCESS(buf2)) {
		buf = buf2;
		strcpy(buf + len, MSG_TRAILER); /* Safe */
	}

	res = bbs_mail(1, to, from, replyto, subject, buf);
	free(buf);
	return res;
}
