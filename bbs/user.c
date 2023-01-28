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
 * \brief BBS user
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h> /* use strdup */
#include <time.h> /* use strftime */

#include "include/user.h"
#include "include/auth.h" /* use bbs_user_info_by_username */

const char *bbs_username(struct bbs_user *user)
{
	if (!user || user->priv == -1) {
		return "<Not Logged In>";
	} else if (user->priv == 0) {
		return "Guest";
	} else if (user->username) {
		return user->username;
	} else {
		bbs_error("User has privilege %d but no username?\n", user->priv);
		return "<Unknown>"; /* Shouldn't happen, but this fulfills our contract of the return value never being NULL. */
	}
}

struct bbs_user *bbs_user_request(void)
{
	struct bbs_user *user = calloc(1, sizeof(*user));
	if (!user) {
		bbs_error("calloc failure\n");
		return NULL;
	}
	user->priv = -1; /* Not logged in yet */
	return user;
}

int bbs_user_guest_info_set(struct bbs_user *user, const char *guestname, const char *guestemail, const char *guestlocation)
{
	bbs_assert(bbs_user_is_guest(user)); /* This function is only for guest users */
	user->guestname = strdup(guestname);
	user->guestemail = strdup(guestemail);
	user->guestlocation = strdup(guestlocation);
	/* We don't check for strdup failure here, so we use free_if rather than free in bbs_user_destroy
	 * Not to mention if askguestinfo=no, then these will never get set. */
	bbs_auth("Guest %s (%s) logged in from %s\n", guestname, guestemail, guestlocation);
	return 0;
}

int bbs_user_dump(int fd, const char *username, int verbose)
{
	char timebuf[30];
	struct bbs_user *user = bbs_user_info_by_username(username);

	if (!user) {
		return -1;
	}
	/* Use CR LF instead of just LF in this function, since Finger also uses it */
	bbs_dprintf(fd, "User: %s #%d\r\n", bbs_username(user), user->id);
	if (verbose >= 10) {
		bbs_dprintf(fd, "Full Name: %s\n", S_IF(user->fullname));
	}
	if (verbose >= 2) {
		bbs_dprintf(fd, "From: %s, %s %s\r\n", user->city, user->state, verbose >= 10 ? S_IF(user->zip) : "");
	}
	if (user->gender) {
		bbs_dprintf(fd, "Gender: %c\r\n", user->gender);
	}
	if (verbose >= 8 && user->dob && strftime(timebuf, sizeof(timebuf), "%a %b %e %Y", user->dob) > 0) {
		bbs_dprintf(fd, "DOB: %s\n", timebuf);
	}
	if (verbose >= 10) {
		bbs_dprintf(fd, "Phone Number: %s\r\n", S_IF(user->phone));
		bbs_dprintf(fd, "Address: %s\r\n", S_IF(user->address));
	}
	if (user->registered && strftime(timebuf, sizeof(timebuf), "%a %b %e %Y %I:%M %P %Z", user->registered) > 0) { /* bbs_time_friendly does this internally */
		bbs_dprintf(fd, "Registered: %s\n", timebuf);
	}
	if (user->lastlogin && strftime(timebuf, sizeof(timebuf), "%a %b %e %Y %I:%M %P %Z", user->lastlogin) > 0) { /* bbs_time_friendly does this internally */
		bbs_dprintf(fd, "Last Login: %s\n", timebuf);
	}
	/*! \todo Add more information here */
	bbs_user_destroy(user);
	return 0;
}

void bbs_user_destroy(struct bbs_user *user)
{
	if (bbs_user_is_guest(user)) {
		free_if(user->guestname);
		free_if(user->guestemail);
		free_if(user->guestlocation);
	}

	/* Additional info fields */
	free_if(user->fullname);
	free_if(user->phone);
	free_if(user->address);
	free_if(user->city);
	free_if(user->state);
	free_if(user->zip);

	/* Date/time fields */
	free_if(user->dob);
	free_if(user->registered);
	free_if(user->lastlogin);

	free_if(user->email);
	free_if(user->username);
	free(user);
}
