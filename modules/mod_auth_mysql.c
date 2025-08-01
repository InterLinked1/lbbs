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

/* Included here, for modman */
#include <mysql/mysql.h>

#include "include/mod_mysql.h"

#include "include/module.h"
#include "include/config.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/node.h" /* needed for user registration */
#include "include/term.h" /* needed for user registration */
#include "include/crypt.h" /* use bbs_password_verify_bcrypt */
#include "include/utils.h" /* use bbs_str_isprint */
#include "include/mail.h"

static char buf_dbhostname[32];
static char buf_dbusername[32];
static char buf_dbpassword[32];
static char buf_dbname[32] = "";
/* strlen_zero doesn't like being called directly on char buffers, need pointers */
static char *dbhostname = buf_dbhostname;
static char *dbusername = buf_dbusername;
static char *dbpassword = buf_dbpassword;
static char *dbname = buf_dbname;

/* database.table if database defined, just table otherwise */
#define DB_NAME_ARGS dbname, !strlen_zero(dbname) ? "." : ""

static int register_phone = 1, register_address = 1, register_zip = 1, register_dob = 1, register_gender = 1, register_howheard = 1;
static int verifyregisteremail = 0;

/*! \brief Common function to handle user authentication and info retrieval */
#pragma GCC diagnostic ignored "-Wstack-protector"
static struct bbs_user *fetch_user(struct bbs_user *myuser, const char *username, const char *password, struct bbs_user ***userlistptr)
{
	char sql[195]; /* Min required to avoid truncation warning */
	MYSQL *mysql = NULL;
	MYSQL_STMT *stmt;
	int mysqlres;
	struct bbs_user **userlist = NULL;
	struct bbs_user *user = NULL;
	/* SQL SELECT */
	const char *fmt = "dssdssssssssttt";
	const size_t num_fields = strlen(fmt);

	mysql = sql_connect_db(dbhostname, dbusername, dbpassword, dbname);
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
		size_t numrows;
		int rownum = 0;
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
			if (ALLOC_FAILURE(userlist)) {
				goto stmtcleanup;
			}
		}

		while (MYSQL_NEXT_ROW_DYNAMIC(stmt)) {
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
				user->id = (unsigned int) id;
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
			sql_free_result_strings((int) num_fields, results, lengths, bind_strings); /* Call inside the while loop, since strings only need to be freed per row */
		}
		if (!username) {
			userlist[rownum] = NULL; /* NULL terminate the array of users */
		}

stmtcleanup:
		sql_free_result_strings((int) num_fields, results, lengths, bind_strings); /* Won't hurt anything, clean up in case we break from the loop */
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

	mysql = sql_connect_db(dbhostname, dbusername, dbpassword, dbname);
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
	const char *address, const char *city, const char *state, const char *zip, const char *dob, const char *gender)
{
	char pw_hash[BCRYPT_FULL_HASH_LEN + 1];
	MYSQL *mysql = NULL;
	MYSQL_STMT *stmt;
	int res = -1;
	char sql[184];
	struct tm birthday;
	char types[16] = "sssssssssts";

	memset(&birthday, 0, sizeof(birthday));

	if (bbs_password_salt_and_hash(password, pw_hash, sizeof(pw_hash))) {
		return -1;
	} else if (!strlen_zero(dob) && (strptime(dob, "%m/%d/%Y", &birthday) == NULL || invalid_birthday(&birthday))) { /* Don't use %D since uses 2-digit years */
		bbs_debug(3, "Rejecting '%s' due to invalid DOB\n", dob);
		return -1; /* Invalid date */
	}

	/* We expect that the users table has a UNIQUE constraint on the username column
	 * Columns like date_registered and priv should be set automatically on INSERT. */
	snprintf(sql, sizeof(sql), "INSERT INTO %s%susers (username, password, name, email, phone, address, city, state, zip, dob, gender) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", DB_NAME_ARGS);

	mysql = sql_connect_db(dbhostname, dbusername, dbpassword, dbname);
	NULL_RETURN(mysql);
	stmt = mysql_stmt_init(mysql);
	if (!stmt) {
		goto cleanup;
	}

	/* Bind parameters and execute */
	sql_fmt_autonull(types, username, pw_hash, fullname, email, phone, address, city, state, zip, dob ? &birthday : NULL, gender);
	if (sql_prep_bind_exec(stmt, sql, types, username, pw_hash, fullname, email, phone, address, city, state, zip, dob ? &birthday : NULL, gender)) {
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

static int user_register(struct bbs_node *node)
{
	/* bcrypt caps password lengths at 72, so that's where that came from */
	char fullname[64], username[64], password[72], password2[72];
	char email[64], phone[16] = "", address[64] = "", city[64], state[32], zip[10] = "", dob[11] = "", gender[2] = "";
	char how_heard[256] = "";
	int res;
#define MAX_REG_ATTEMPTS 6
	int tries = MAX_REG_ATTEMPTS;

#define REG_FMT COLOR(TERM_COLOR_WHITE)
#define REG_QLEN 43
#define get_response(node, qlen, fmt, q, pollms, buf, len, tries, minlen, reqchars) bbs_get_response(node, qlen, fmt q, pollms, buf, len, tries, minlen, reqchars)

	for (; tries > 0; tries -= 2) {
		int correct;

		/* Registration notice */
		NEG_RETURN(bbs_node_clear_screen(node));
		NONPOS_RETURN(bbs_node_writef(node, "%s%s%s\n", COLOR(COLOR_PRIMARY), "New User Registration", COLOR(TERM_COLOR_WHITE))); /* Use white for the questions to stand out */

		bbs_node_buffer(node); /* Buffer input so we can read line by line */

		/* No newlines necessary inbetween reads, since echo is on
		 * and input is terminated by a return. */
		/* NONZERO_RETURN is a macro that returns x, so we must NOT call it directly with the function itself */
		if (register_howheard) {
			res = get_response(node, REG_QLEN, REG_FMT, "How did you hear about this BBS? ", MIN_MS(1), how_heard, sizeof(how_heard), &tries, 0, NULL);
			NONZERO_RETURN(res);
		}
		for (; tries > 0; tries--) { /* Retries here count less than retries of the main loop */
			res = get_response(node, REG_QLEN, REG_FMT, "Please enter your full real name: ", MIN_MS(1), fullname, sizeof(fullname), &tries, 4, " "); /* If there's no space, we don't have at least 2 names */
			NONZERO_RETURN(res);

			if (!bbs_str_isprint(fullname)) {
				NEG_RETURN(bbs_node_writef(node, "\n%sName contains disallowed characters%s\n", COLOR(TERM_COLOR_RED), COLOR_RESET));
			} else {
				break;
			}
		}
		if (tries <= 0) {
			return 1;
		}

		for (; tries > 0; tries--) { /* Retries here count less than retries of the main loop */
			res = get_response(node, REG_QLEN, REG_FMT, "Desired username: ", MIN_MS(1), username, sizeof(username), &tries, 2, NULL);
			NONZERO_RETURN(res);
			if (strchr(username, ' ')) {
				NEG_RETURN(bbs_node_writef(node, "\n%sUsername cannot contain spaces%s\n", COLOR(TERM_COLOR_RED), COLOR_RESET));
			} else if (!bbs_str_isprint(username)) {
				NEG_RETURN(bbs_node_writef(node, "\n%sUsername contains disallowed characters%s\n", COLOR(TERM_COLOR_RED), COLOR_RESET));
			} else if (strlen(username) > 15) {
				NEG_RETURN(bbs_node_writef(node, "\n%sUsername is too long%s\n", COLOR(TERM_COLOR_RED), COLOR_RESET));
			} else if (bbs_username_reserved(username)) {
				NEG_RETURN(bbs_node_writef(node, "\n%sThat username is reserved and not allowed%s\n", COLOR(TERM_COLOR_RED), COLOR_RESET));
			} else {
				break;
			}
		}
		if (tries <= 0) {
			return 1;
		}

		/* Users logging in from a TDD can only send uppercase letters, not lowercase.
		 * So if their password contains lowercase letters, they're screwed.
		 * We can't just do a case-insensitive comparison since we never store the password anywhere, only the hash.
		 * Therefore, we must obtain the exact password for authentication,
		 * and the user must explicitly set a compatible password if TTY/TDD compatibility is desired. */
		bbs_node_writef(node, COLOR(TERM_COLOR_RED) "If you want to be able to log in from a TTY/TDD, your password should not contain lowercase letters.\n" COLOR_RESET);

		bbs_node_echo_off(node); /* Don't display password */
		for (; tries > 0; tries--) { /* Retries here count less than retries of the main loop */
			NEG_RETURN(bbs_node_writef(node, "%-*s", REG_QLEN, REG_FMT "Password: "));
			NONPOS_RETURN(bbs_node_read_line(node, MIN_MS(1), password, sizeof(password)));
			NEG_RETURN(bbs_node_writef(node, "%-*s", REG_QLEN, REG_FMT "\nConfirm Password: ")); /* Begin with new line since wasn't echoed */
			NONPOS_RETURN(bbs_node_read_line(node, MIN_MS(1), password2, sizeof(password2)));
			if (s_strlen_zero(password) || strcmp(password, password2)) {
				NEG_RETURN(bbs_node_writef(node, "\n%sPasswords do not match%s\n", COLOR(TERM_COLOR_RED), COLOR_RESET));
			} else if (strlen(password) < 8) {
				NEG_RETURN(bbs_node_writef(node, "\n%sPassword is too short%s\n", COLOR(TERM_COLOR_RED), COLOR_RESET));
			} else {
				break;
			}
		}
		if (tries <= 0) {
			return 1;
		}
		bbs_node_echo_on(node);

		/* Begin with LF since not echoed from input */
		bbs_node_writef(node, "\n");

		/* XXX Validation of provided data needed, but should be primarily handled by the SQL schema. We do include some rudimentary format checks. */

		res = get_response(node, REG_QLEN, REG_FMT, "Network mail address (user@domain): ", MIN_MS(1), email, sizeof(email), &tries, 5, "@.");
		NONZERO_RETURN(res);
		if (register_phone) {
			res = get_response(node, REG_QLEN, REG_FMT, "Telephone Number: ", MIN_MS(1), phone, sizeof(phone), &tries, 7, NULL);
			NONZERO_RETURN(res);
		}
		if (register_address) {
			res = get_response(node, REG_QLEN, REG_FMT, "Street Address (Line 1/2): ", MIN_MS(1), address, sizeof(address), &tries, 6, " "); /* e.g. 1 E St */
			NONZERO_RETURN(res);
		}
		res = get_response(node, REG_QLEN, REG_FMT, "City: ", MIN_MS(1), city, sizeof(city), &tries, 2, NULL);
		NONZERO_RETURN(res);
		res = get_response(node, REG_QLEN, REG_FMT, "State: ", MIN_MS(1), state, sizeof(state), &tries, 2, NULL);
		NONZERO_RETURN(res);
		if (register_zip) {
			res = get_response(node, REG_QLEN, REG_FMT, "ZIP/Postal Code: ", MIN_MS(1), zip, sizeof(zip), &tries, 3, NULL); /* US = 5, other countries??? */
			NONZERO_RETURN(res);
		}
		if (register_dob) {
			res = get_response(node, REG_QLEN, REG_FMT, "Birthday (MM/DD/YYYY): ", MIN_MS(1), dob, sizeof(dob), &tries, 10, "/");
			NONZERO_RETURN(res);
		}

		bbs_node_unbuffer(node); /* We need to be unbuffered for tread */
		if (register_gender) {
			for (; tries > 0; tries--) { /* Retries here count less than retries of the main loop */
				int c;
				NEG_RETURN(bbs_node_writef(node, "%-*s", REG_QLEN, REG_FMT "\rGender (MFX): ")); /* Erase existing line in case we're retrying */
				c = bbs_node_tread(node, MIN_MS(1));
				NONPOS_RETURN(c);
				gender[0] = (char) tolower(c);
				if (gender[0] == 'm' || gender[0] == 'f' || gender[0] == 'x') {
					NEG_RETURN(bbs_node_writef(node, "%s\n", gender)); /* Print response + newline */
					break; /* Got a valid response */
				}
				/* Invalid, try again */
			}
			if (tries <= 0) {
				return 1;
			}
		}
		bbs_node_writef(node, "\n");

confirm:
		NEG_RETURN(bbs_node_writef(node, "%-*s", REG_QLEN, REG_FMT "\rIs the above information correct? [Y/N] "));
		correct = bbs_node_tread(node, MIN_MS(1));
		if (tolower(correct) == 'y') {
			break;
		} else if (tolower(correct) == 'n') {
			/* Not correct? Start over! */
			continue;
		} else if (correct > 0) { /* e.g. just pressed ENTER, since the gender prompt doesn't require that, don't consume that here */
			/* Invalid */
			bbs_node_ring_bell(node);
			goto confirm; /* If we didn't use a goto in this way, we would need to break, and this is simpler to follow */
		}
	}
	if (tries <= 0) {
		return 1;
	}
#undef REG_FMT

	NEG_RETURN(bbs_node_writef(node, "\n%sProcessing...\n", COLOR(COLOR_SUCCESS)));
	bbs_auth("New registration attempt for user %s from IP %s\n", username, node->ip);

	/* How heard is logged but not passed to make_user */
	bbs_debug(1, "New registration attempt: "
		"name = '%s', username = '%s', email = '%s', phone = '%s', address = '%s', city = '%s', state = '%s', zip = '%s', dob = '%s', gender = '%s', how heard = '%s'\n",
		fullname, username, email, S_IF(phone), S_IF(address), city, state, S_IF(zip), S_IF(dob), S_IF(gender), S_IF(how_heard));

#define NULL_IFEMPTY(s) (!*s ? NULL : s)

	if (verifyregisteremail) {
		char usercode[10] = "";
		char randcode[10];
		snprintf(randcode, sizeof(randcode), "%05ld", random() % 8192 + rand() % 8192);
		/* Verify that the user owns the provided email address. */
		res = bbs_mail_fmt(0, email, NULL, NULL, "BBS Registration", "Greetings,\r\n\tYour verification code for your BBS account registration is %s.\r\nIf you did not request this code, you should ignore this email.\r\n", randcode);
		if (res) {
			NEG_RETURN(bbs_node_writef(node, "%s%s%s\n", COLOR(COLOR_FAILURE), "Your registration could not be completed due to a processing error.\nContact the sysop.", COLOR_RESET));
			NEG_RETURN(bbs_node_wait_key(node, SEC_MS(75)));
			return 1;
		}
		NEG_RETURN(bbs_node_writef(node, "\n%sWe just emailed you a verification code. Continue once you've received it.%s\n", COLOR(COLOR_SUCCESS), COLOR_RESET));
		NEG_RETURN(bbs_node_wait_key(node, SEC_MS(600))); /* Wait a bit longer, up to 10 minutes in case email is delayed */

		bbs_node_buffer(node);

		bbs_get_response(node, 20, COLOR(TERM_COLOR_WHITE) "\nVerification Code: ", MIN_MS(3), usercode, sizeof(usercode), &tries, 1, NULL);
		if (strcmp(usercode, randcode)) {
			NEG_RETURN(bbs_node_writef(node, "\n%sSorry, the verification code you provided was incorrect.%s\n", COLOR(COLOR_FAILURE), COLOR_RESET));
			NEG_RETURN(bbs_node_writef(node, "\nPlease try again later...\n"));
			NEG_RETURN(bbs_node_wait_key(node, SEC_MS(20)));
			return 1;
		}
		/* Allow registration to continue. */
	}

	/* Check once more, right before we create it.
	 * Note we are only checking if the username is reserved, since the user database cannot tell us that.
	 * If the username already exists, the INSERT user request will fail. */
	if (bbs_username_reserved(username)) {
		NEG_RETURN(bbs_node_writef(node, "\n%sSorry, the requested username is reserved and not allowed%s\n", COLOR(TERM_COLOR_RED), COLOR_RESET));
		NEG_RETURN(bbs_node_wait_key(node, SEC_MS(20)));
		return 1;
	}

	/* Actually create the user */
	res = make_user(username, password, fullname, email, NULL_IFEMPTY(phone), NULL_IFEMPTY(address), city, state, NULL_IFEMPTY(zip), NULL_IFEMPTY(dob), NULL_IFEMPTY(gender));

	if (res) {
		NEG_RETURN(bbs_node_writef(node, "%s%s%s\n", COLOR(COLOR_FAILURE), "Your registration was rejected.", COLOR_RESET));
		NEG_RETURN(bbs_node_wait_key(node, SEC_MS(75)));
		return 1;
	}
	/* If user registration actually succeeded, then this function call will succeed. If not, it won't. */
	res = bbs_authenticate(node, username, password);
	bbs_memzero(password, sizeof(password)); /* No longer need the password */
	if (res) {
		/* Something went wrong */
		NEG_RETURN(bbs_node_writef(node, "%s%s%s\n", COLOR(COLOR_FAILURE), "An error occured in processing your registration.\n", COLOR_RESET));
		NEG_RETURN(bbs_node_wait_key(node, SEC_MS(75)));
		return 1;
	}

	/* If successful, no need to log, auth.c will do that */
	NEG_RETURN(bbs_node_writef(node, "\n%sRegistration successful. Welcome aboard!%s\n", COLOR(COLOR_SUCCESS), COLOR_RESET));
	/* Wait for user to confirm, otherwise the message will disappear since the screen will clear after we return */
	NEG_RETURN(bbs_node_wait_key(node, SEC_MS(75)));

	return res;
}

static int load_config(void)
{
	int res = 0;
	struct bbs_config *cfg = bbs_config_load("mod_auth_mysql.conf", 0);

	if (!cfg) {
		bbs_error("mod_auth_mysql.conf is missing, module will decline to load\n");
		return -1;
	}

	bbs_config_val_set_true(cfg, "registration", "phone", &register_phone);
	bbs_config_val_set_true(cfg, "registration", "address", &register_address);
	bbs_config_val_set_true(cfg, "registration", "zip", &register_zip);
	bbs_config_val_set_true(cfg, "registration", "dob", &register_dob);
	bbs_config_val_set_true(cfg, "registration", "gender", &register_gender);
	bbs_config_val_set_true(cfg, "registration", "howheard", &register_howheard);
	bbs_config_val_set_true(cfg, "registration", "verifyemail", &verifyregisteremail);

	res |= bbs_config_val_set_str(cfg, "db", "hostname", buf_dbhostname, sizeof(buf_dbhostname));
	res |= bbs_config_val_set_str(cfg, "db", "username", buf_dbusername, sizeof(buf_dbusername));
	res |= bbs_config_val_set_str(cfg, "db", "password", buf_dbpassword, sizeof(buf_dbpassword));
	if (res) {
		bbs_error("Missing either hostname, username, or password\n");
		bbs_config_unlock(cfg);
		bbs_config_free(cfg);
		return -1;
	}
	if (bbs_config_val_set_str(cfg, "db", "database", buf_dbname, sizeof(buf_dbname))) { /* This is optional but highly recommended. */
		bbs_warning("No database name specified in mod_auth_mysql.conf\n");
	}

	bbs_config_unlock(cfg);
	/* Don't destroy the config, mod_auth_mysql will read it again to parse some settings that apply only to it.
	 *
	 * UPDATE: mod_auth_mysql loads the config file with caching disabled, so it will get reparsed anyways.
	 * This is probably a good thing since it reduces the number of places the DB password is in memory...
	 * As such, there's no downside to destroying the config here. */
	bbs_config_free(cfg);
	return 0;
}

static int unload_module(void)
{
	bbs_unregister_auth_provider(provider);
	bbs_unregister_user_registration_provider(user_register);
	bbs_unregister_password_reset_handler(change_password);
	bbs_unregister_user_info_handler(get_user_info);
	bbs_unregister_user_list_handler(get_users);
	return 0;
}

static int load_module(void)
{
	int res;
	if (load_config()) {
		return -1;
	}
	bbs_register_user_registration_provider(user_register);
	bbs_register_password_reset_handler(change_password);
	bbs_register_user_info_handler(get_user_info);
	bbs_register_user_list_handler(get_users);
	res = bbs_register_auth_provider("MySQL/MariaDB", provider);
	REQUIRE_FULL_LOAD(res);
}

BBS_MODULE_INFO_DEPENDENT("MySQL/MariaDB User Authentication", "mod_mysql.so");
