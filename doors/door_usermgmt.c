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
 * \brief Self-service user account management
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h> /* use random_r */
#include <string.h>

#include "include/node.h"
#include "include/user.h"
#include "include/auth.h"
#include "include/module.h"
#include "include/door.h"
#include "include/term.h"
#include "include/mail.h"
#include "include/crypt.h"

/*! \brief Confirm the password of the currently authenticated user */
static int confirm_current_pw(struct bbs_node *node)
{
	struct bbs_user *user;
	char password[64];
	int res;

	/* This is a bit silly, but using the publicly availabl APIs,
	 * we need to allocate a dummy user in order to confirm authentication. */

	user = bbs_user_request();
	if (!user) {
		return -1;
	}

	bbs_node_clear_screen(node);
	NEG_RETURN(bbs_node_buffer(node));
	bbs_node_echo_off(node); /* Don't display password */
	NEG_RETURN(bbs_node_writef(node, "=== Confirm Current Password ===\n"));
	NEG_RETURN(bbs_node_writef(node, "%-*s", 24, COLOR(TERM_COLOR_WHITE) "Old Password: "));
	NONPOS_RETURN(bbs_node_read_line(node, MIN_MS(1), password, sizeof(password)));
	res = bbs_user_authenticate(user, bbs_username(node->user), password);
	bbs_memzero(password, sizeof(password));
	bbs_user_destroy(user);

	bbs_node_echo_on(node); /* Restore echo */
	bbs_node_writef(node, "\n"); /* Since echo was off, we didn't print one */
	return res;
}

static int do_reset(struct bbs_node *node, const char *username)
{
	char password[73];
	char password2[73];
	int res;
	int tries = 4;

#define MIN_PW_LENGTH 8
	bbs_node_clear_screen(node);
	NEG_RETURN(bbs_node_buffer(node));
	NEG_RETURN(bbs_node_writef(node, "=== Change Password ===\n"));

	if (MIN_PW_LENGTH > 1) {
		NEG_RETURN(bbs_node_writef(node, "Remember, your new password must be at least %s%d%s characters long.\n", COLOR(TERM_COLOR_WHITE), MIN_PW_LENGTH, COLOR_RESET));
	}

	bbs_node_echo_off(node); /* Don't display password */
	for (; tries > 0; tries--) {
		NEG_RETURN(bbs_node_writef(node, "%-*s", 24, COLOR(TERM_COLOR_WHITE) "New Password: "));
		NONPOS_RETURN(bbs_node_read_line(node, MIN_MS(1), password, sizeof(password)));
		NEG_RETURN(bbs_node_writef(node, "%-*s", 24, COLOR(TERM_COLOR_WHITE) "\nConfirm New Password: ")); /* Begin with new line since wasn't echoed */
		NONPOS_RETURN(bbs_node_read_line(node, MIN_MS(1), password2, sizeof(password2)));
		if (s_strlen_zero(password) || strcmp(password, password2)) {
			NEG_RETURN(bbs_node_writef(node, "\n%sPasswords do not match%s\n", COLOR(TERM_COLOR_RED), COLOR_RESET));
			} else if (strlen(password) < MIN_PW_LENGTH) {
			NEG_RETURN(bbs_node_writef(node, "\n%sPassword is too short%s\n", COLOR(TERM_COLOR_RED), COLOR_RESET));
		} else {
			break;
		}
	}
	if (tries <= 0) {
		NEG_RETURN(bbs_node_writef(node, "\n%sIt seems you're having difficulties. Please reach out to your sysop.%s\n", COLOR(COLOR_FAILURE), COLOR_RESET));
		NEG_RETURN(bbs_node_wait_key(node, SEC_MS(75)));
		return 0;
	}
	bbs_node_echo_on(node);

	res = bbs_user_reset_password(username, password);

	/* Zero out passwords from memory after done using them */
	bbs_memzero(password, sizeof(password));
	bbs_memzero(password2, sizeof(password2));

	if (res) {
		NEG_RETURN(bbs_node_writef(node, "\n%sSorry, your password could not be changed.%s\n", COLOR(COLOR_FAILURE), COLOR_RESET));
	} else {
		/* If successful, no need to log, auth.c will do that */
		NEG_RETURN(bbs_node_writef(node, "\n%sYour password has been successfully changed. Please remember it!%s\n", COLOR(COLOR_SUCCESS), COLOR_RESET));
	}

	/* Wait for user to confirm, otherwise the message will disappear since the screen will clear after we return */
	NEG_RETURN(bbs_node_wait_key(node, SEC_MS(75)));
	return res;
}

/*! \brief Forgotten password reset */
static int pwreset_exec(struct bbs_node *node, const char *args)
{
	char username[64];
	char fullname[64];
	char email[64];
	char dob[11];
	char zip[10];
	int rand1, rand2;
	int suffix;
	char randombytes[12];
	char randcode[20];
	char usercode[sizeof(randcode) + 2];
	struct bbs_user *user;
	int res;
	int tries = 5;

	UNUSED(args);

#define MY_WIDTH 45

	bbs_node_clear_screen(node);
	NEG_RETURN(bbs_node_buffer(node));
	NEG_RETURN(bbs_node_writef(node, "=== Reset Password ===\n"));

	NEG_RETURN(bbs_node_writef(node, "Forgot your password? It happens to the best of us.\n"));
	NEG_RETURN(bbs_node_writef(node, "If you've forgotten your username, you must contact the sysop for assistance.\n"));
	NEG_RETURN(bbs_node_writef(node, "You'll need access to the email address you used to register.\n"));

	/* Ask a few questions. */
	res = bbs_get_response(node, MY_WIDTH, COLOR(TERM_COLOR_WHITE) "Username: ", MIN_MS(1), username, sizeof(username), &tries, 2, NULL);
	NONZERO_RETURN(res);

	res = bbs_get_response(node, MY_WIDTH, COLOR(TERM_COLOR_WHITE) "Please enter your full real name: ", MIN_MS(1), fullname, sizeof(fullname), &tries, 4, " "); /* If there's no space, we don't have at least 2 names */
	NONZERO_RETURN(res);

	res = bbs_get_response(node, MY_WIDTH, COLOR(TERM_COLOR_WHITE) "Network mail address (user@domain): ", MIN_MS(1), email, sizeof(email), &tries, 5, "@.");
	NONZERO_RETURN(res);

	res = bbs_get_response(node, MY_WIDTH, COLOR(TERM_COLOR_WHITE) "Birthday (MM/DD/YYYY): ", MIN_MS(1), dob, sizeof(dob), &tries, 10, "/");
	NONZERO_RETURN(res);

	res = bbs_get_response(node, MY_WIDTH, COLOR(TERM_COLOR_WHITE) "ZIP/Postal Code: ", MIN_MS(1), zip, sizeof(zip), &tries, 3, NULL); /* US = 5, other countries??? */
	NONZERO_RETURN(res);

	/* Do some basic checks */
	user = bbs_user_info_by_username(username);
	if (!user || strcmp(bbs_user_email(user), email)) { /* These checks absolutely must pass. */
		if (user) {
			bbs_user_destroy(user);
		}
		NEG_RETURN(bbs_node_writef(node, "\n%sSorry, we can't proceed using the information you provided. Please contact the sysop.%s\n", COLOR(COLOR_FAILURE), COLOR_RESET));
		NEG_RETURN(bbs_node_writef(node, "\nYou will be disconnected momentarily...\n"));
		NEG_RETURN(bbs_node_wait_key(node, SEC_MS(20)));
		return -1; /* Return -1 to disconnect the node, to make it harder for brute force attempts */
	}
	/*! \todo Add some more checks here, with varying levels of tolerance */

	/* If we get here, send the user an email */
	rand1 = (int) random(); /* I know, this isn't thread-safe like random_r... */
	rand2 = rand(); /* And this isn't either like rand_r... */
	/* More importantly, random() and rand() should not be relied on to be secure,
	 * since the time the BBS started (and hence seed to srandom() and srand()) is publicly known
	 * So bbs_rand_alnum() does the real randomness generation here. */

	if (bbs_rand_alnum(randombytes, sizeof(randombytes))) {
		goto fail;
	}

	suffix = rand1 % 2048 + rand2 % 1024;
	snprintf(randcode, sizeof(randcode), "%s%d", randombytes, suffix);

	/* Email the user the reset code. */
	res = bbs_mail_fmt(0, bbs_user_email(user), NULL, NULL, "BBS Password Reset", "Greetings,\r\n\tYour password reset code for your BBS login is %s.\r\nIf you did not request this code, you should change your password immediately.\r\n", randcode);
	if (res) {
		goto fail;
	}

	NEG_RETURN(bbs_node_writef(node, "\n%sWe just emailed you a password reset code. Continue once you've received it.%s\n", COLOR(COLOR_SUCCESS), COLOR_RESET));
	NEG_RETURN(bbs_node_wait_key(node, SEC_MS(600))); /* Wait a bit longer, up to 10 minutes in case email is delayed */

	bbs_get_response(node, 20, COLOR(TERM_COLOR_WHITE) "\nReset Code: ", MIN_MS(3), usercode, sizeof(usercode), &tries, 1, NULL);
	if (strcmp(usercode, randcode)) {
		bbs_user_destroy(user);
		NEG_RETURN(bbs_node_writef(node, "\n%sSorry, the reset code you provided was incorrect.%s\n", COLOR(COLOR_FAILURE), COLOR_RESET));
		NEG_RETURN(bbs_node_writef(node, "\nYou will be disconnected momentarily...\n"));
		NEG_RETURN(bbs_node_wait_key(node, SEC_MS(20)));
		return -1; /* Return -1 to disconnect the node, to make it harder for brute force attempts */
	}

	/* Okay, we're good. Allow the user to reset his or her password. */
	res = do_reset(node, bbs_username(user));
	bbs_user_destroy(user);
	return res;

fail:
	bbs_user_destroy(user);
	NEG_RETURN(bbs_node_writef(node, "\n%sYour request could not be processed. Please contact the sysop.%s\n", COLOR(COLOR_FAILURE), COLOR_RESET));
	NEG_RETURN(bbs_node_wait_key(node, SEC_MS(20)));
	return 0;
}

static int pwchange_exec(struct bbs_node *node, const char *args)
{
	UNUSED(args);

	if (!bbs_user_is_registered(node->user)) {
#if 0
		/* in menus.conf, any access to this option should have |minpriv=1 since anyone with less than that won't be able to use this and will get this error: */
		NEG_RETURN(bbs_node_writef(node, "%sSorry, only registered users can reset their passwords%s\n", COLOR(COLOR_FAILURE), COLOR_RESET));
		return 0;
#else
		return pwreset_exec(node, args); /* Just run the reset handler instead if not logged in */
#endif
	}

	/* Authenticated Password Change */

	/* First, ask the user to confirm current password.
	 * This way if somebody else has terminal access,
	 * we know it's really the user changing it. */
	if (confirm_current_pw(node)) {
		bbs_node_writef(node, "%sSorry, you must confirm your current password to proceed.%s\n", COLOR(COLOR_FAILURE), COLOR_RESET);
		NEG_RETURN(bbs_node_wait_key(node, SEC_MS(20)));
		return 0;
	}

	return do_reset(node, bbs_username(node->user));
}

static int termmgmt_exec(struct bbs_node *node, const char *args)
{
	int c;

	UNUSED(args);

	if (NODE_IS_TDD(node)) {
		/* If in TDD mode, stuck in TDD mode,
		 * since this is more of an internal mode for TDDs */
		bbs_node_writef(node, "TDD mode enabled\n");
		NEG_RETURN(bbs_node_wait_key(node, SEC_MS(20)));
		return 0;
	}

	bbs_node_clear_screen(node);
	bbs_node_writef(node, "%s%s%s\n", COLOR(COLOR_PRIMARY), "Terminal Settings", COLOR_RESET);
	bbs_node_writef(node, "%s%10s%s\n", COLOR(COLOR_SECONDARY), "Speed", COLOR_RESET);

	if (node->calcbps) {
		bbs_node_writef(node, "%s%16s%s %ld bps\n", COLOR(TERM_COLOR_WHITE), "Measured", COLOR_RESET, node->calcbps);
	} else {
		bbs_node_writef(node, "%s%16s%s %s\n", COLOR(TERM_COLOR_WHITE), "Measured", COLOR_RESET, "Broadband");
	}
	if (node->bps) {
		bbs_node_writef(node, "%s%16s%s %u bps\n", COLOR(TERM_COLOR_WHITE), "Throttle", COLOR_RESET, node->bps);
	} else {
		bbs_node_writef(node, "%s%16s%s %s\n", COLOR(TERM_COLOR_WHITE), "Throttle", COLOR_RESET, "Unthrottled");
	}
	if (node->reportedbps) {
		bbs_node_writef(node, "%s%16s%s %u\n", COLOR(TERM_COLOR_WHITE), "Reported", COLOR_RESET, node->reportedbps);
	} else {
		bbs_node_writef(node, "%s%16s%s %s\n", COLOR(TERM_COLOR_WHITE), "Reported", COLOR_RESET, "Unreported");
	}

	bbs_node_writef(node, "%s%10s %s\n", COLOR(COLOR_SECONDARY), "Protocol", node->protname);
	bbs_node_writef(node, "%s%10s %s\n", COLOR(COLOR_SECONDARY), "Term Type", S_OR(node->term, "(Unreported)"));
	bbs_node_writef(node, "%s%10s %s\n", COLOR(COLOR_SECONDARY), "ANSI", node->ansi ? "Yes" : "No");
	if (node->ansi) {
#define DUMP_ANSI_SUPPORT(flag, name) bbs_node_writef(node, "%s       - %-18s%s%3s\n", COLOR(TERM_COLOR_WHITE), name, node->ans & flag ? COLOR(TERM_COLOR_GREEN) : COLOR(TERM_COLOR_RED), node->ans & flag ? "Yes" : "No")
		DUMP_ANSI_SUPPORT(ANSI_CURSOR_QUERY, "Cursor Query");
		DUMP_ANSI_SUPPORT(ANSI_CURSOR_SET, "Cursor Set");
		DUMP_ANSI_SUPPORT(ANSI_COLORS, "Colors");
		DUMP_ANSI_SUPPORT(ANSI_CLEAR_LINE, "Clear Line");
		DUMP_ANSI_SUPPORT(ANSI_CLEAR_SCREEN, "Clear Screen");
		DUMP_ANSI_SUPPORT(ANSI_UP_ONE_LINE, "Up One Line");
		DUMP_ANSI_SUPPORT(ANSI_TERM_TITLE, "Term Titles");
#undef DUMP_ANSI_SUPPORT
	}
	bbs_node_writef(node, "%s<A>%s Toggle ANSI %s<*>%s Exit\n", COLOR(COLOR_SECONDARY), COLOR_RESET, COLOR(COLOR_SECONDARY), COLOR_RESET);
	c = bbs_node_tread(node, MIN_MS(5));
	switch (c) {
		case 'a':
		case 'A':
			/* If disabling, reset color, just in case */
			bbs_node_reset_color(node);
			SET_BITFIELD(node->ansi, !node->ansi); /* XXX Might want to store whether ANSI *really* detected/supported, not just whether currently enabled */
			bbs_node_safe_sleep(node, 10); /* Pause, to allow the PTY thread to send the reset and then see the ANSI state before reading further */
			bbs_node_writef(node, "ANSI %s\n", node->ansi ? "enabled" : "disabled");
			NEG_RETURN(bbs_node_wait_key(node, SEC_MS(75)));
			break;
		default:
			return c < 0 ? -1 : 0;
	}
	bbs_node_clear_screen(node);
	return 0;
}

static int load_module(void)
{
	bbs_register_door("pwchange", pwchange_exec);
	bbs_register_door("termmgmt", termmgmt_exec);
	return 0;
}

static int unload_module(void)
{
	bbs_unregister_door("termmgmt");
	return bbs_unregister_door("pwchange");
}

BBS_MODULE_INFO_STANDARD("Self-Service User Management");
