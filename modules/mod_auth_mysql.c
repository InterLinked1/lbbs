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
 * \brief MySQL-backed user authentication and registration
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <time.h>

#include "include/mod_mysql.h"

#include "include/module.h"
#include "include/config.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/node.h" /* needed for user registration */
#include "include/term.h" /* needed for user registration */
#include "include/crypt.h" /* use bbs_password_verify_bcrypt */
#include "include/utils.h" /* use bbs_str_isprint */

/*! \brief Common function to handle user authentication and info retrieval */
#pragma GCC diagnostic ignored "-Wstack-protector"
static struct bbs_user *fetch_user(struct bbs_user *myuser, const char *username, const char *password, struct bbs_user ***userlistptr)
{
	char sql[184];
	MYSQL *mysql = NULL;
	MYSQL_STMT *stmt;
	int mysqlres;
	struct bbs_user **userlist = NULL;
	struct bbs_user *user = NULL;
	/* SQL SELECT */
	const char *fmt = "dssdssssssssttt";
	const unsigned int num_fields = strlen(fmt);

	mysql = sql_connect();
	if (!mysql) {
		return NULL;
	}

	stmt = mysql_stmt_init(mysql);
	if (!stmt) {
		goto cleanup;
	}

	if (username) { /* Specific user */
		snprintf(sql, sizeof(sql), "SELECT id, username, password, priv, email, name, phone, address, city, state, zip, gender, dob, date_registered, last_login FROM %s%susers WHERE username = ? LIMIT 1", DB_NAME_ARGS);
	} else { /* All users */
		/* XXX We should really have a sql_exec function, but since we don't currently, just bind a dummy argument that will cause the query to return all records */
		snprintf(sql, sizeof(sql), "SELECT id, username, password, priv, email, name, phone, address, city, state, zip, gender, dob, date_registered, last_login FROM %s%susers WHERE id > ?", DB_NAME_ARGS);
	}

	if ((username && sql_prep_bind_exec(stmt, sql, "s", username)) || (!username && sql_prep_bind_exec(stmt, sql, "i", 0))) {
		goto cleanup;
	} else {
		/* Indented a block since we need num_fields */
		MYSQL_BIND results[num_fields]; /* should be equal to number of selected cols */
		unsigned long int lengths[num_fields]; /* Only needed for string result fields */
		int bind_ints[num_fields];
		char *bind_strings[num_fields];
		my_bool bind_null[num_fields];
		MYSQL_TIME bind_dates[num_fields];
		int numrows, rownum = 0;
#pragma GCC diagnostic pop

		memset(results, 0, sizeof(results));
		memset(lengths, 0, sizeof(lengths));
		memset(bind_strings, 0, sizeof(bind_strings));

		if (sql_bind_result(stmt, fmt, results, lengths, bind_ints, bind_strings, bind_dates, bind_null)) {
			goto stmtcleanup;
		}

		if (!username) { /* Only needed if fetching all users */
			numrows = mysql_stmt_num_rows(stmt);
			userlist = malloc((numrows + 1) * sizeof(*user)); /* The list will be NULL terminated, so add 1 */
			if (!userlist) {
				goto stmtcleanup;
			}
		}

		while (MYSQL_NEXT_ROW(stmt)) {
			int id, priv;
			char *real_username, *pw_hash, *email, *fullname, *phone, *address, *city, *state, *zip, *gender;
			struct tm dob, registered, lastlogin;

			/* We must do this since we might not fill in the whole struct, even on success. */
			memset(&dob, 0, sizeof(dob));
			memset(&registered, 0, sizeof(registered));
			memset(&lastlogin, 0, sizeof(lastlogin));

			/* Must allocate string results before attempting to use them */
			if (sql_alloc_bind_strings(stmt, fmt, results, lengths, bind_strings)) { /* Needs to be called if we don't use sql_string_prep in advance for all strings. */
				break; /* If we fail for some reason, don't crash attempting to access NULL strings */
			} else if (sql_fetch_columns(bind_ints, NULL, bind_strings, bind_dates, bind_null, fmt, &id, &real_username, &pw_hash, &priv, &email, &fullname, &phone, &address, &city, &state, &zip, &gender, &dob, &registered, &lastlogin)) { /* We have no longs, so NULL is fine */
				break;
			}

			/* Must verify if we have one in order to check out */
			if (!password || !bbs_password_verify_bcrypt(password, pw_hash)) { /* XXX We're explicitly assuming here that the hashes are bcrypt hashes */
				if (!myuser) { /* Info request, allocate a new user */
					user = bbs_user_request();
					if (!user) {
						break;
					}
				} else { /* Login request, we already have a user */
					user = myuser;
				}
				/* Set user info */
				user->id = id;
				if (password && user->username) { /* XXX Why would this ever be non-NULL here? */
					bbs_warning("Already had a username?\n");
					free_if(user->username);
				} else if (strlen_zero(real_username)) {
					bbs_error("Username for row %d is null or empty? (%p)\n", rownum, real_username); /* Remember the row number is 0-indexed here */
					break; /* Zoinks, don't crash. But this shouldn't happen as we expect username is a required field. */
				}
				user->username = strdup(real_username);
				user->priv = priv;
				user->email = strdup_if(email);
				user->fullname = strdup_if(fullname);
				user->phone = strdup_if(phone);
				user->address = strdup_if(address);
				user->city = strdup_if(city);
				user->state = strdup_if(state);
				user->zip = strdup_if(zip);
				user->gender = !strlen_zero(gender) ? *gender : 0;
				MALLOC_MEMCPY(user->dob, bind_null[12], &dob);
				MALLOC_MEMCPY(user->registered, bind_null[13], &registered);
				MALLOC_MEMCPY(user->lastlogin, bind_null[14], &lastlogin); /* Retrieve last login before we update it (in the case of a user login) */

				if (password) { /* Update last_login timestamp to NOW, if this was an actual login vs. just user info retrieval */
					bbs_debug(3, "Successful password auth for %s\n", real_username);
					snprintf(sql, sizeof(sql), "UPDATE %s%susers SET last_login = NOW() WHERE username = ? LIMIT 1", DB_NAME_ARGS);
					if (!sql_prep_bind_exec(stmt, sql, "s", username)) {
						bbs_debug(6, "Updated last_login timestamp\n");
					} else {
						bbs_warning("Failed to update last_login timestamp\n");
					}
				}
				/* Store all users in a linked list (really just an array) */
				if (!username) {
					userlist[rownum] = user;
				}
				rownum++;
			} else if (password) {
				bbs_debug(3, "Failed password auth for %s\n", real_username);
			}
			sql_free_result_strings(num_fields, results, lengths, bind_strings); /* Call inside the while loop, since strings only need to be freed per row */
		}
		if (!username) {
			userlist[rownum] = NULL; /* NULL terminate the array of users */
		}

stmtcleanup:
		sql_free_result_strings(num_fields, results, lengths, bind_strings); /* Won't hurt anything, clean up in case we break from the loop */
		mysql_stmt_close(stmt);
		if (!user && password) {
			/* If we didn't find a user, do a dummy call to bbs_password_verify_bcrypt
			 * to prevent timing attacks (user exists or doesn't exist) */
#define DUMMY_PASSWORD "P@ssw0rd123"
#define DUMMY_PASSWORD_HASH "$2y$10$0uZL6ZrlTFw1Z.pyKPOLXub2cQdrRAPMAuHz0gWsmzwy4W/6oOLt2"
			bbs_password_verify_bcrypt(DUMMY_PASSWORD, DUMMY_PASSWORD_HASH);
#undef DUMMY_PASSWORD
#undef DUMMY_PASSWORD_HASH
		}
	}

cleanup:
	mysql_close(mysql);
	if (!username && userlistptr) {
		*userlistptr = userlist;
	}
	return user;
}

/*!
 * \brief Attempt to authenticate user from MySQL/MariaDB database
 * \param user BBS user struct
 * \param username
 * \param password
 * \retval 0 on successful login, -1 on failure
 */
static int provider(AUTH_PROVIDER_PARAMS)
{
	struct bbs_user *myuser = fetch_user(user, username, password, NULL);
	return myuser ? 0 : -1; /* Returns same user on success, NULL on failure */
}

static struct bbs_user *get_user_info(const char *username)
{
	return fetch_user(NULL, username, NULL, NULL);
}

static struct bbs_user **get_users(void)
{
	struct bbs_user **userlist;
	if (!fetch_user(NULL, NULL, NULL, &userlist)) {
		return NULL;
	}
	return userlist;
}

static int change_password(const char *username, const char *password)
{
	char pw_hash[61];
	MYSQL *mysql = NULL;
	MYSQL_STMT *stmt;
	int res = -1;
	char sql[96];
	const char *types = "ss";

	if (bbs_password_salt_and_hash(password, pw_hash, sizeof(pw_hash))) {
		return -1;
	}

	/* We expect that the users table has a UNIQUE constraint on the username column
	 * Columns like date_registered and priv should be set automatically on INSERT. */
	snprintf(sql, sizeof(sql), "UPDATE %s%susers SET password = ? WHERE username = ?", DB_NAME_ARGS);

	mysql = sql_connect();
	NULL_RETURN(mysql);
	stmt = mysql_stmt_init(mysql);
	if (!stmt || sql_prep_bind_exec(stmt, sql, types, pw_hash, username)) { /* Bind parameters and execute */
		goto cleanup;
	}
	/* XXX Do we still return 0 even if we updated 0 records? If so, should we return -1 instead? */
	res = 0;

cleanup:
	if (stmt) {
		mysql_stmt_close(stmt);
	}
	mysql_close(mysql);
	return res;
}

static int invalid_birthday(struct tm *tm)
{
	struct tm nowtime;
	time_t timenow = time(NULL);

	gmtime_r(&timenow, &nowtime);

	bbs_debug(3, "Analyzing date: %d/%d/%d\n", TM_MONTH(tm->tm_mon), tm->tm_mday, TM_YEAR(tm->tm_year));

	/* Can't be older than the oldest person alive or younger than now. Even this is very conservative, how many infants and centenarians are BBSing? */
	if (TM_YEAR(tm->tm_year) < 1903 || tm->tm_year > nowtime.tm_year) {
		bbs_debug(3, "Year not valid: %d\n", TM_YEAR(tm->tm_year));
		return -1;
	}
	return 0;
}

static int make_user(const char *username, const char *password, const char *fullname, const char *email, const char *phone,
	const char *address, const char *city, const char *state, const char *zip, const char *dob, char gender)
{
	char pw_hash[61];
	MYSQL *mysql = NULL;
	MYSQL_STMT *stmt;
	int res = -1;
	char sql[184];
	char genderbuf[2] = { gender, '\0' }; /* We can't pass a char directly into sql_prep_bind_exec, we must pass a char* */
	struct tm birthday;
	const char *types = "sssssssssts";

	memset(&birthday, 0, sizeof(birthday));

	if (bbs_password_salt_and_hash(password, pw_hash, sizeof(pw_hash))) {
		return -1;
	} else if (strptime(dob, "%m/%d/%Y", &birthday) == NULL || invalid_birthday(&birthday)) { /* Don't use %D since uses 2-digit years */
		bbs_debug(3, "Rejecting '%s' due to invalid DOB\n", dob);
		return -1; /* Invalid date */
	}

	/* We expect that the users table has a UNIQUE constraint on the username column
	 * Columns like date_registered and priv should be set automatically on INSERT. */
	snprintf(sql, sizeof(sql), "INSERT INTO %s%susers (username, password, name, email, phone, address, city, state, zip, dob, gender) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", DB_NAME_ARGS);

	mysql = sql_connect();
	NULL_RETURN(mysql);
	stmt = mysql_stmt_init(mysql);
	if (!stmt || sql_prep_bind_exec(stmt, sql, types, username, pw_hash, fullname, email, phone, address, city, state, zip, &birthday, genderbuf)) { /* Bind parameters and execute */
		goto cleanup;
	}
	res = 0;

cleanup:
	if (stmt) {
		mysql_stmt_close(stmt);
	}
	mysql_close(mysql);
	return res;
}

/*! \note Sysop can always manually adjust the database if needed to override */
#define USERNAME_RESERVED(u) (!strcasecmp(u, "root") || !strcasecmp(u, "sysop") || !strcasecmp(u, "root") || !strcasecmp(u, "bbs") || !strcasecmp(u, "ChanServ") || !strcasecmp(u, "NickServ") || !strcasecmp(u, "services"))

static int user_register(struct bbs_node *node)
{
	/* bcrypt caps password lengths at 72, so that's where that came from */
	char fullname[64], username[64], password[72], password2[72];
	char email[64], phone[16], address[64], city[64], state[32], zip[10], dob[11];
	char how_heard[256];
	char gender, correct;
	int res;
#define MAX_REG_ATTEMPTS 6
	int tries = MAX_REG_ATTEMPTS;

	bbs_buffer(node); /* Buffer input so we can read line by line */

#define REG_FMT COLOR(COLOR_WHITE)
#define REG_QLEN 43
#define get_response(node, qlen, fmt, q, pollms, buf, len, tries, minlen, reqchars) bbs_get_response(node, qlen, fmt q, pollms, buf, len, tries, minlen, reqchars)

	/* Registration notice */
	NEG_RETURN(bbs_clear_screen(node));
	NONPOS_RETURN(bbs_writef(node, "%s%s%s\n", COLOR(COLOR_PRIMARY), "New User Registration", COLOR(COLOR_WHITE))); /* Use white for the questions to stand out */

	for (; tries > 0; tries -= 2) {
		/* No newlines necessary inbetween reads, since echo is on
		 * and input is terminated by a return. */
		/* NONZERO_RETURN is a macro that returns x, so we must NOT call it directly with the function itself */
		res = get_response(node, REG_QLEN, REG_FMT, "How did you hear about this BBS? ", MIN_MS(1), how_heard, sizeof(how_heard), &tries, 0, NULL);
		NONZERO_RETURN(res);
		res = get_response(node, REG_QLEN, REG_FMT, "Please enter your full real name: ", MIN_MS(1), fullname, sizeof(fullname), &tries, 4, " "); /* If there's no space, we don't have at least 2 names */
		NONZERO_RETURN(res); 

		for (; tries > 0; tries--) { /* Retries here count less than retries of the main loop */
			res = get_response(node, REG_QLEN, REG_FMT, "Desired username: ", MIN_MS(1), username, sizeof(username), &tries, 2, NULL);
			NONZERO_RETURN(res);
			if (strchr(username, ' ')) {
				NEG_RETURN(bbs_writef(node, "\n%sUsername cannot contain spaces%s\n", COLOR(COLOR_RED), COLOR_RESET));
			} else if (!bbs_str_isprint(username)) {
				NEG_RETURN(bbs_writef(node, "\n%sUsername contains disallowed characters%s\n", COLOR(COLOR_RED), COLOR_RESET));
			} else if (strlen(username) > 15) {
				NEG_RETURN(bbs_writef(node, "\n%sUsername is too long%s\n", COLOR(COLOR_RED), COLOR_RESET));
			} else if (USERNAME_RESERVED(username)) {
				NEG_RETURN(bbs_writef(node, "\n%sThat username is not allowed%s\n", COLOR(COLOR_RED), COLOR_RESET));
			} else {
				break;
			}
		}
		if (tries <= 0) {
			return 1;
		}

		bbs_echo_off(node); /* Don't display password */
		for (; tries > 0; tries--) { /* Retries here count less than retries of the main loop */
			NEG_RETURN(bbs_writef(node, "%-*s", REG_QLEN, REG_FMT "Password: "));
			NONPOS_RETURN(bbs_readline(node, MIN_MS(1), password, sizeof(password)));
			NEG_RETURN(bbs_writef(node, "%-*s", REG_QLEN, REG_FMT "\nConfirm Password: ")); /* Begin with new line since wasn't echoed */
			NONPOS_RETURN(bbs_readline(node, MIN_MS(1), password2, sizeof(password2)));
			if (s_strlen_zero(password) || strcmp(password, password2)) {
				NEG_RETURN(bbs_writef(node, "\n%sPasswords do not match%s\n", COLOR(COLOR_RED), COLOR_RESET));
			} else if (strlen(password) < 8) {
				NEG_RETURN(bbs_writef(node, "\n%sPassword is too short%s\n", COLOR(COLOR_RED), COLOR_RESET));
			} else {
				break;
			}
		}
		if (tries <= 0) {
			return 1;
		}
		bbs_echo_on(node);

		/* Begin with LF since not echoed from input */
		bbs_writef(node, "\n");

		/* XXX Validation of provided data needed, but should be primarily handled by the SQL schema. We do include some rudimentary format checks. */

		res = get_response(node, REG_QLEN, REG_FMT, "Network mail address (user@domain): ", MIN_MS(1), email, sizeof(email), &tries, 5, "@.");
		NONZERO_RETURN(res);
		res = get_response(node, REG_QLEN, REG_FMT, "Telephone Number: ", MIN_MS(1), phone, sizeof(phone), &tries, 7, NULL);
		NONZERO_RETURN(res);
		res = get_response(node, REG_QLEN, REG_FMT, "Street Address (Line 1/2): ", MIN_MS(1), address, sizeof(address), &tries, 6, " "); /* e.g. 1 E St */
		NONZERO_RETURN(res);
		res = get_response(node, REG_QLEN, REG_FMT, "City: ", MIN_MS(1), city, sizeof(city), &tries, 2, NULL);
		NONZERO_RETURN(res);
		res = get_response(node, REG_QLEN, REG_FMT, "State: ", MIN_MS(1), state, sizeof(state), &tries, 2, NULL);
		NONZERO_RETURN(res);
		res = get_response(node, REG_QLEN, REG_FMT, "ZIP/Postal Code: ", MIN_MS(1), zip, sizeof(zip), &tries, 3, NULL); /* US = 5, other countries??? */
		NONZERO_RETURN(res);
		res = get_response(node, REG_QLEN, REG_FMT, "Birthday (MM/DD/YYYY): ", MIN_MS(1), dob, sizeof(dob), &tries, 10, "/");
		NONZERO_RETURN(res);

		bbs_unbuffer(node); /* We need to be unbuffered for tread */
		for (; tries > 0; tries--) { /* Retries here count less than retries of the main loop */
			NEG_RETURN(bbs_writef(node, "%-*s", REG_QLEN, REG_FMT "\rGender (MFX): ")); /* Erase existing line in case we're retrying */
			gender = bbs_tread(node, MIN_MS(1));
			NONPOS_RETURN(gender);
			gender = tolower(gender);
			if (gender == 'm' || gender == 'f' || gender == 'x') {
				NEG_RETURN(bbs_writef(node, "%c\n", gender)); /* Print response + newline */
				break; /* Got a valid response */
			}
			/* Invalid, try again */
		}
		if (tries <= 0) {
			return 1;
		}

		NEG_RETURN(bbs_writef(node, "%-*s", REG_QLEN, REG_FMT "Is the above information correct? "));
		correct = bbs_tread(node, MIN_MS(1));
		if (tolower(correct) == 'y') {
			break;
		}
		/* Not correct? Start over! */
	}
	if (tries <= 0) {
		return 1;
	}
#undef REG_FMT

	NEG_RETURN(bbs_writef(node, "\n%sProcessing...\n", COLOR(COLOR_SUCCESS)));
	bbs_auth("New registration attempt for user %s from IP %s\n", username, node->ip);

	/* How heard is logged but not passed to make_user */
	bbs_debug(1, "New registration attempt: name = %s, username = %s, email = %s, phone = %s, address = %s, city = %s, state = %s, zip = %s, dob = %s, gender = %c, how heard = %s\n",
		fullname, username, email, phone, address, city, state, zip, dob, gender, how_heard);

	/* Actually create the user */
	res = make_user(username, password, fullname, email, phone, address, city, state, zip, dob, gender);

	if (res) {
		NEG_RETURN(bbs_writef(node, "%s%s%s\n", COLOR(COLOR_FAILURE), "Your registration was rejected.", COLOR_RESET));
		NEG_RETURN(bbs_wait_key(node, SEC_MS(75)));
		return 1;
	}
	/* If user registration actually succeeded, then this function call will succeed. If not, it won't. */
	res = bbs_authenticate(node, username, password);
	if (res) {
		/* Something went wrong */
		NEG_RETURN(bbs_writef(node, "%s%s%s\n", COLOR(COLOR_FAILURE), "An error occured in processing your registration.\n", COLOR_RESET));
		NEG_RETURN(bbs_wait_key(node, SEC_MS(75)));
		return 1;
	}

	/* If successful, no need to log, auth.c will do that */
	NEG_RETURN(bbs_writef(node, "\n%sRegistration successful. Welcome aboard!%s\n", COLOR(COLOR_SUCCESS), COLOR_RESET));
	/* Wait for user to confirm, otherwise the message will disappear since the screen will clear after we return */
	NEG_RETURN(bbs_wait_key(node, SEC_MS(75)));

	return res;
}

static struct bbs_module *depmod = NULL;

static int load_module(void)
{
	/* In reality, this should always succeed if we actually get to executing this.
	 * If the dependency is not satisfied, symbols won't resolve and dlopen will fail.
	 * It still serves a purpose, because we ensure that the dependency can't be unloaded
	 * while there are things that are dependent on it.
	 */
	depmod = bbs_require_module("mod_mysql");
	if (!depmod) {
		return -1;
	}
	bbs_register_user_registration_provider(user_register);
	bbs_register_password_reset_handler(change_password);
	bbs_register_user_info_handler(get_user_info);
	bbs_register_user_list_handler(get_users);
	return bbs_register_auth_provider("MySQL/MariaDB", provider);
}

static int unload_module(void)
{
	int res = bbs_unregister_auth_provider(provider);
	bbs_unregister_user_registration_provider(user_register);
	bbs_unregister_password_reset_handler(change_password);
	bbs_unregister_user_info_handler(get_user_info);
	bbs_unregister_user_list_handler(get_users);
	bbs_unrequire_module(depmod);
	return res;
}

BBS_MODULE_INFO_STANDARD("MySQL/MariaDB User Authentication");
