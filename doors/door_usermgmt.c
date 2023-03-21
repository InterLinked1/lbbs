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
#include <ctype.h> /* use isalnum */
#include <sys/random.h>

#include "include/node.h"
#include "include/user.h"
#include "include/auth.h"
#include "include/module.h"
#include "include/door.h"
#include "include/term.h"
#include "include/mail.h"

static int do_reset(struct bbs_node *node, const char *username)
{
	char password[73];
	char password2[73];
	int res;
	int tries = 4;
	
#define MIN_PW_LENGTH 8
	bbs_clear_screen(node);
	NEG_RETURN(bbs_buffer(node));
	NEG_RETURN(bbs_writef(node, "=== Change Password ===\n"));

	if (MIN_PW_LENGTH > 1) {
		NEG_RETURN(bbs_writef(node, "Remember, your new password must be at least %s%d%s characters long.\n", COLOR(COLOR_WHITE), MIN_PW_LENGTH, COLOR_RESET));
	}

	bbs_echo_off(node); /* Don't display password */
	for (; tries > 0; tries--) {
		NEG_RETURN(bbs_writef(node, "%-*s", 24, COLOR(COLOR_WHITE) "New Password: "));
		NONPOS_RETURN(bbs_readline(node, MIN_MS(1), password, sizeof(password)));
		NEG_RETURN(bbs_writef(node, "%-*s", 24, COLOR(COLOR_WHITE) "\nConfirm New Password: ")); /* Begin with new line since wasn't echoed */
		NONPOS_RETURN(bbs_readline(node, MIN_MS(1), password2, sizeof(password2)));
		if (s_strlen_zero(password) || strcmp(password, password2)) {
			NEG_RETURN(bbs_writef(node, "\n%sPasswords do not match%s\n", COLOR(COLOR_RED), COLOR_RESET));
		} else if (strlen(password) < MIN_PW_LENGTH) {
			NEG_RETURN(bbs_writef(node, "\n%sPassword is too short%s\n", COLOR(COLOR_RED), COLOR_RESET));
		} else {
			break;
		}
	}
	if (tries <= 0) {
		NEG_RETURN(bbs_writef(node, "\n%sIt seems you're having difficulties. Please reach out to your sysop.%s\n", COLOR(COLOR_FAILURE), COLOR_RESET));
		NEG_RETURN(bbs_wait_key(node, SEC_MS(75)));
		return 0;
	}
	bbs_echo_on(node);

	res = bbs_user_reset_password(username, password);

	/* Zero out passwords from memory after done using them */
	bbs_memzero(password, sizeof(password));
	bbs_memzero(password2, sizeof(password2));

	if (res) {
		NEG_RETURN(bbs_writef(node, "\n%sSorry, your password could not be changed.%s\n", COLOR(COLOR_FAILURE), COLOR_RESET));
	} else {
		/* If successful, no need to log, auth.c will do that */
		NEG_RETURN(bbs_writef(node, "\n%sYour password has been successfully changed. Please remember it!%s\n", COLOR(COLOR_SUCCESS), COLOR_RESET));
	}

	/* Wait for user to confirm, otherwise the message will disappear since the screen will clear after we return */
	NEG_RETURN(bbs_wait_key(node, SEC_MS(75)));
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
	long unsigned int i;

	UNUSED(args);

#define MY_WIDTH 45

	bbs_clear_screen(node);
	NEG_RETURN(bbs_buffer(node));
	NEG_RETURN(bbs_writef(node, "=== Reset Password ===\n"));

	NEG_RETURN(bbs_writef(node, "Forgot your password? It happens to the best of us.\n"));
	NEG_RETURN(bbs_writef(node, "If you've forgotten your username, you must contact the sysop for assistance.\n"));
	NEG_RETURN(bbs_writef(node, "You'll need access to the email address you used to register.\n"));

	/* Ask a few questions. */
	res = bbs_get_response(node, MY_WIDTH, COLOR(COLOR_WHITE) "Username: ", MIN_MS(1), username, sizeof(username), &tries, 2, NULL);
	NONZERO_RETURN(res);

	res = bbs_get_response(node, MY_WIDTH, COLOR(COLOR_WHITE) "Please enter your full real name: ", MIN_MS(1), fullname, sizeof(fullname), &tries, 4, " "); /* If there's no space, we don't have at least 2 names */
	NONZERO_RETURN(res); 

	res = bbs_get_response(node, MY_WIDTH, COLOR(COLOR_WHITE) "Network mail address (user@domain): ", MIN_MS(1), email, sizeof(email), &tries, 5, "@.");
	NONZERO_RETURN(res);

	res = bbs_get_response(node, MY_WIDTH, COLOR(COLOR_WHITE) "Birthday (MM/DD/YYYY): ", MIN_MS(1), dob, sizeof(dob), &tries, 10, "/");
	NONZERO_RETURN(res);

	res = bbs_get_response(node, MY_WIDTH, COLOR(COLOR_WHITE) "ZIP/Postal Code: ", MIN_MS(1), zip, sizeof(zip), &tries, 3, NULL); /* US = 5, other countries??? */
	NONZERO_RETURN(res);

	/* Do some basic checks */
	user = bbs_user_info_by_username(username);
	if (!user || strcmp(bbs_user_email(user), email)) { /* These checks absolutely must pass. */
		if (user) {
			bbs_user_destroy(user);
		}
		NEG_RETURN(bbs_writef(node, "\n%sSorry, we can't proceed using the information you provided. Please contact the sysop.%s\n", COLOR(COLOR_FAILURE), COLOR_RESET));
		NEG_RETURN(bbs_writef(node, "\nYou will be disconnected momentarily...\n"));
		NEG_RETURN(bbs_wait_key(node, SEC_MS(20)));
		return -1; /* Return -1 to disconnect the node, to make it harder for brute force attempts */
	}
	/*! \todo Add some more checks here, with varying levels of tolerance */

	/* If we get here, send the user an email */
	rand1 = random(); /* I know, this isn't thread-safe like random_r... */
	rand2 = rand(); /* And this isn't either like rand_r... */
	/* More importantly, random() and rand() should not be relied on to be secure,
	 * since the time the BBS started (and hence seed to srandom() and srand()) is publicly known
	 * So getrandom() does the real randomness generation here. */

	if (getrandom(randombytes, sizeof(randombytes), GRND_NONBLOCK) == -1) {
		bbs_error("getrandom failed: %s\n", strerror(errno));
		goto fail;
	}
	/* getrandom returns... random bytes, not random ASCII characters. Fix that. */
	for (i = 0; i < sizeof(randombytes); i++) {
		if (!isalnum(randombytes[i])) {
			randombytes[i] = 'A' + randombytes[i] % 25;
			/* Now it should be a printable, alphanumeric ASCII char... */
			if (!isalnum(randombytes[i])) {
				bbs_error("Character %d was not an ASCII character?\n", randombytes[i]);
			}
		}
	}

	suffix = rand1 % 2048 + rand2 % 1024;
	snprintf(randcode, sizeof(randcode), "%s%d", randombytes, suffix);

	/* Email the user the reset code. */
	res = bbs_mail_fmt(0, bbs_user_email(user), NULL, NULL, "BBS Password Reset", "Greetings,\r\n\tYour password reset code for your BBS login is %s.\r\nIf you did not request this code, you should change your password immediately.\r\n", randcode);
	if (res) {
		goto fail;
	}

	NEG_RETURN(bbs_writef(node, "\n%sWe just emailed you a password reset code. Continue once you've received it.%s\n", COLOR(COLOR_SUCCESS), COLOR_RESET));
	NEG_RETURN(bbs_wait_key(node, SEC_MS(600))); /* Wait a bit longer, up to 10 minutes in case email is delayed */

	res = bbs_get_response(node, 20, COLOR(COLOR_WHITE) "\nReset Code: ", MIN_MS(3), usercode, sizeof(usercode), &tries, 1, NULL);
	if (strcmp(usercode, randcode)) {
		bbs_user_destroy(user);
		NEG_RETURN(bbs_writef(node, "\n%sSorry, the reset code you provided was incorrect.%s\n", COLOR(COLOR_FAILURE), COLOR_RESET));
		NEG_RETURN(bbs_writef(node, "\nYou will be disconnected momentarily...\n"));
		NEG_RETURN(bbs_wait_key(node, SEC_MS(20)));
		return -1; /* Return -1 to disconnect the node, to make it harder for brute force attempts */
	}

	/* Okay, we're good. Allow the user to reset his or her password. */
	res = do_reset(node, bbs_username(user));
	bbs_user_destroy(user);
	return res;

fail:
	bbs_user_destroy(user);
	NEG_RETURN(bbs_writef(node, "\n%sYour request could not be processed. Please contact the sysop.%s\n", COLOR(COLOR_FAILURE), COLOR_RESET));
	NEG_RETURN(bbs_wait_key(node, SEC_MS(20)));
	return 0;
}

static int pwchange_exec(struct bbs_node *node, const char *args)
{
	UNUSED(args);

	if (!bbs_user_is_registered(node->user)) {
#if 0
		/* in menus.conf, any access to this option should have |minpriv=1 since anyone with less than that won't be able to use this and will get this error: */
		NEG_RETURN(bbs_writef(node, "%sSorry, only registered users can reset their passwords%s\n", COLOR(COLOR_FAILURE), COLOR_RESET));
		return 0;
#else
		return pwreset_exec(node, args); /* Just run the reset handler instead if not logged in */
#endif
	}

	return do_reset(node, bbs_username(node->user));
}

static int load_module(void)
{
	return bbs_register_door("pwchange", pwchange_exec);
}

static int unload_module(void)
{
	return bbs_unregister_door("pwchange");
}

BBS_MODULE_INFO_STANDARD("Self-Service User Management");
