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
#include "include/linkedlists.h"
#include "include/utils.h"

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
	if (ALLOC_FAILURE(user)) {
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
		if (!strlen_zero(user->city) || !strlen_zero(user->state) || !strlen_zero(user->zip)) {
			bbs_dprintf(fd, "From: %s, %s %s\r\n", S_IF(user->city), S_IF(user->state), verbose >= 10 ? S_IF(user->zip) : "");
		}
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

int bbs_users_dump(int fd, int verbose)
{
	int index = 0;
	struct bbs_user *user, **userlist = bbs_user_list();
	if (!userlist) {
		return -1;
	}

	/* Use CR LF instead of just LF since Finger also uses it */
	while ((user = userlist[index++])) {
		char namebuf[26];
		const char *disp_name = user->fullname;
		if (disp_name && strlen(disp_name) > 22) {
			memcpy(namebuf, disp_name, 22);
			strcpy(namebuf + 22, "..."); /* Safe */
			disp_name = namebuf;
		}
		if (index == 1) {
			bbs_dprintf(fd, " %4s %-18s %-25s %3s %s\r\n", "#", "USERNAME", "FULL NAME", "PRV", "LOCATION");
		}
		if (!bbs_str_isprint(bbs_username(user))) {
			bbs_warning("Invalid username:\n");
			bbs_dump_mem((unsigned const char*) bbs_username(user), strlen(bbs_username(user)));
			continue;
		} else if (disp_name && !bbs_str_isprint(disp_name)) {
			bbs_warning("Invalid name:\n");
			bbs_dump_mem((unsigned const char*) disp_name, strlen(disp_name));
			continue;
		}
		if (verbose >= 10) {
			bbs_dprintf(fd, " %4d %-18s %-25s %3d %s%c %s\r\n",
				user->id, bbs_username(user), S_IF(disp_name), user->priv,
				S_IF(user->city), !strlen_zero(user->city) || !strlen_zero(user->state), S_IF(user->state));
		} else {
			bbs_dprintf(fd, " %4d %-18s\r\n", user->id, bbs_username(user));
		}
		if (strchr(bbs_username(user), ' ')) {
			/* mod_auth_mysql doesn't allow registration of usernames with spaces,
			 * but that doesn't guarantee there aren't already usernames with spaces, etc. */
			bbs_warning("Username '%s' contains space (may not be compatible with all services)\n", bbs_username(user)); /* e.g. IRC */
		}
	}

	bbs_user_list_destroy(userlist);
	return 0;
}

/* User ID / username translation caching */
struct username_id_mapping {
	unsigned int userid;
	RWLIST_ENTRY(username_id_mapping) entry;
	char username[0];
};

static RWLIST_HEAD_STATIC(username_mappings, username_id_mapping);

void username_cache_flush(void)
{
	/* In general, this cache can only grow larger over time,
	 * (e.g. new user registration).
	 * It is not currently bounded since most BBS's don't have
	 * an enormoous number of users, so caching everything is fine
	 * to avoid DB calls, since this cache is used for common operations.
	 * We don't really expect to ever edit or delete entries.
	 * However, if we need to invalidate the cache for some reason,
	 * this would allow us to do so.
	 * For now, this is only called on shutdown. */
	RWLIST_WRLOCK_REMOVE_ALL(&username_mappings, entry, free);
}

static void username_mapping_cache_add(unsigned int userid, const char *username)
{
	struct username_id_mapping *m;
	size_t len;

	len = strlen(username);
	m = calloc(1, sizeof(*m) + len + 1); /* Plus NUL */
	if (ALLOC_SUCCESS(m)) {
		m->userid = userid;
		strcpy(m->username, username); /* Safe */
		RWLIST_WRLOCK(&username_mappings);
		RWLIST_INSERT_SORTED(&username_mappings, m, entry, userid); /* Insert in order of user ID */
		RWLIST_UNLOCK(&username_mappings);
	}
}

int bbs_user_exists(const char *username)
{
	struct bbs_user *user;
	struct username_id_mapping *m;

	/* Check the cache first, to avoid a DB call if unnecessary. */
	RWLIST_RDLOCK(&username_mappings);
	RWLIST_TRAVERSE(&username_mappings, m, entry) {
		if (!strcasecmp(username, m->username)) {
			break;
		}
	}
	RWLIST_UNLOCK(&username_mappings);

	if (m) {
		return 1;
	}

	user = bbs_user_info_by_username(username); /* Does this user exist on the BBS? */
	if (user) {
		/* Yup, sure does. */
		username_mapping_cache_add(user->id, bbs_username(user)); /* Cache, so we don't have to do this again. */
		bbs_user_destroy(user);
		return 1;
	}
	return 0;
}

unsigned int bbs_userid_from_username(const char *username)
{
	unsigned int res;
	struct bbs_user *user;
	struct username_id_mapping *m;

	/* Check the cache first */
	RWLIST_RDLOCK(&username_mappings);
	RWLIST_TRAVERSE(&username_mappings, m, entry) {
		if (!strcasecmp(username, m->username)) {
			res = m->userid;
			break;
		}
	}
	RWLIST_UNLOCK(&username_mappings);
	if (m) {
		return res;
	}

	/* Yes, there is a race condition in that we unlock and then WRLOCK to insert,
	 * so a duplicate entry could enter the cache.
	 * This is still relatively unlikely, and if it happened, it wouldn't hurt anything,
	 * it would just be unnecessary.
	 * The overhead in WRLOCKing from the beginning of the search and keeping it locked,
	 * is probably not worth it since that would unnecessarily serialize all calls to this function.
	 */

	/* XXX Rather than fetching an entire user
	 * just to extract the user ID, then destroying it,
	 * it would be more efficient if there was a user callback
	 * that auth providers registered to query user IDs from usernames,
	 * since a single-column SELECT will be more efficient than
	 * doing SELECT * (which is effectively what bbs_user_info_by_username does).
	 *
	 * Even better, it would be more efficient
	 * to cache all the users in memory with a mapping from
	 * usernames to user IDs, and only perform a DB query
	 * in the case of no match (which would actually eliminate
	 * the majority of queries, for most use cases).
	 *
	 * Either of these would be a welcome improvement, and at least
	 * there is one place to change the code in the future.
	 */

	user = bbs_user_info_by_username(username);
	if (!user) {
		return 0;
	}
	res = user->id;
	username_mapping_cache_add(user->id, bbs_username(user)); /* Cache, so we don't have to do this again. */
	bbs_user_destroy(user);
	return res;
}

int bbs_username_from_userid(unsigned int userid, char *buf, size_t len)
{
	struct bbs_user *bbsuser;
	struct username_id_mapping *m;

	/* Check the cache first */
	RWLIST_RDLOCK(&username_mappings);
	RWLIST_TRAVERSE(&username_mappings, m, entry) {
		if (userid == m->userid) {
			safe_strncpy(buf, m->username, len);
			break;
		} else if (m->userid > userid) { /* It's not present, since the list is sorted. */
			m = NULL;
			break;
		}
	}
	RWLIST_UNLOCK(&username_mappings);

	if (m) {
		return 0; /* Had a cache hit */
	}

	/* This is horribly inefficient */
	bbsuser = bbs_user_from_userid(userid);
	if (!bbsuser) {
		return -1;
	}
	safe_strncpy(buf, bbs_username(bbsuser), len);
	username_mapping_cache_add(userid, bbs_username(bbsuser)); /* Cache, so we don't have to do this again. */
	bbs_user_destroy(bbsuser);
	return 0;
}

int bbs_user_priv_from_userid(unsigned int userid)
{
	int priv = -1;
	int index = 0;
	struct bbs_user *user, **userlist;

	/* We don't check the cache here, since privileges could change during runtime,
	 * although user IDs and username mappings are not at all likely to change. */

	userlist = bbs_user_list();
	if (!userlist) {
		return -1;
	}

	/*! \todo FIXME This is a horrible implementation (linear instead of constant). Apparently,
	 * we have no way to get a user by user ID (only by username) right now,
	 * so that API needs to be added, and then this should be rewritten to use that.
	 * Horrible kludge for now. */
	while ((user = userlist[index++])) {
		if (user->id == userid) {
			priv = user->priv;
			break;
		}
	}

	bbs_user_list_destroy(userlist);
	return priv;
}

static void bbs_user_list_destroy_except(struct bbs_user **userlist, struct bbs_user *except)
{
	int index = 0;
	struct bbs_user *user;
	while ((user = userlist[index++])) {
		if (user != except) {
			bbs_user_destroy(user);
		}
	}
	free(userlist); /* Free the list itself */
}

void bbs_user_list_destroy(struct bbs_user **userlist)
{
	return bbs_user_list_destroy_except(userlist, NULL);
}

struct bbs_user *bbs_user_from_userid(unsigned int userid)
{
	int index = 0;
	struct bbs_user *retuser = NULL;
	struct bbs_user *user, **userlist = bbs_user_list();
	if (!userlist) {
		return NULL;
	}

	/*! \todo FIXME This is a horrible implementation (linear instead of constant). Apparently,
	 * we have no way to get a user by user ID (only by username) right now,
	 * so that API needs to be added, and then this should be rewritten to use that.
	 * Horrible kludge for now. */
	while ((user = userlist[index++])) {
		if (user->id == userid) {
			retuser = user;
			break;
		}
	}

	bbs_user_list_destroy_except(userlist, retuser); /* Free all users except the one we want */
	return retuser;
}

struct bbs_user *bbs_user_from_username(const char *username)
{
	unsigned int userid = bbs_userid_from_username(username);
	if (!userid) {
		return NULL;
	}
	return bbs_user_from_userid(userid);
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
