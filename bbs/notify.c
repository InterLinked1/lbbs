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
#include "include/module.h"
#include "include/linkedlists.h"

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
	buf2 = realloc(buf, (unsigned int) len + STRLEN(MSG_TRAILER) + 1);
	if (ALLOC_SUCCESS(buf2)) {
		buf = buf2;
		strcpy(buf + len, MSG_TRAILER); /* Safe */
	}

	res = bbs_mail(1, to, from, replyto, subject, buf);
	free(buf);
	return res;
}

struct alerter {
	int (*alerter)(unsigned int userid, const char *msg);
	void *module;
	RWLIST_ENTRY(alerter) entry;
	unsigned int priority;
};

static RWLIST_HEAD_STATIC(alerters, alerter);

int __bbs_register_alerter(int (*alerter)(ALERTER_PARAMS), void *mod, int priority)
{
	struct alerter *a;

	RWLIST_WRLOCK(&alerters);
	RWLIST_TRAVERSE(&alerters, a, entry) {
		if (a->alerter == alerter) {
			break;
		}
	}
	if (a) {
		bbs_error("Alerter is already registered\n");
		RWLIST_UNLOCK(&alerters);
		return -1;
	}
	a = calloc(1, sizeof(*a) + 1);
	if (ALLOC_FAILURE(a)) {
		RWLIST_UNLOCK(&alerters);
		return -1;
	}
	a->alerter = alerter;
	a->module = mod;
	a->priority = (unsigned int) priority;
	RWLIST_INSERT_SORTED(&alerters, a, entry, priority); /* Insert in order of priority */
	RWLIST_UNLOCK(&alerters);
	return 0;
}

int bbs_unregister_alerter(int (*alerter)(ALERTER_PARAMS))
{
	struct alerter *a;

	a = RWLIST_WRLOCK_REMOVE_BY_FIELD(&alerters, alerter, alerter, entry);
	if (!a) {
		bbs_error("Failed to unregister alerter: not currently registered\n");
		return -1;
	} else {
		free(a);
	}
	return 0;
}

static int __bbs_alert_user(unsigned int userid, enum notify_delivery_type persistence, const char *msg)
{
	int res = -1;
	struct alerter *a;

	/*! \todo Possible future enhancement: if userid is 0, broadcast the alert to all users.
	 * (could add an /alertall command to mod_sysop)
	 * We'd have to pass 0 to the module and have it deliver the message to as many users as possible,
	 * and inform us of which users, so we don't deliver repeats to the same user using other callbacks. */

	RWLIST_RDLOCK(&alerters);
	RWLIST_TRAVERSE(&alerters, a, entry) {
		bbs_module_ref(a->module);
		res = a->alerter(userid, msg);
		bbs_module_unref(a->module);
		if (!res) {
			break;
		}
	}
	RWLIST_UNLOCK(&alerters);

	/* If everything else failed and we're allowed to, deliver via email instead. */
	if (res && persistence == DELIVERY_GUARANTEED) {
		char username[48];
		if (!bbs_username_from_userid(userid, username, sizeof(username))) {
			res = bbs_mail(1, username, NULL, NULL, "BBS Alert", msg);
		}
	}
	return res;
}

int __attribute__ ((format (gnu_printf, 3, 4))) bbs_alert_user(unsigned int userid, enum notify_delivery_type persistence, const char *fmt, ...)
{
	int len, res;
	char *buf;
	va_list ap;

	if (!strchr(fmt, '%')) {
		return __bbs_alert_user(userid, persistence, fmt);
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}

	res = __bbs_alert_user(userid, persistence, buf);
	free(buf);
	return res;
}
