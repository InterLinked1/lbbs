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

#include "include/user.h"

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

void bbs_user_destroy(struct bbs_user *user)
{
	if (bbs_user_is_guest(user)) {
		free_if(user->guestname);
		free_if(user->guestemail);
		free_if(user->guestlocation);
	}
	free_if(user->email);
	free_if(user->username);
	free(user);
}
