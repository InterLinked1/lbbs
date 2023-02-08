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
 * \brief MySQL/MariaDB interface
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

static char buf_dbhostname[32];
static char buf_dbusername[32];
static char buf_dbpassword[32];
static char buf_dbname[32] = "";
/* strlen_zero doesn't like being called directly on char buffers, need pointers */
static char *dbhostname = buf_dbhostname;
static char *dbusername = buf_dbusername;
static char *dbpassword = buf_dbpassword;
static char *dbname = buf_dbname;

#define log_mysqli_error(mysql) bbs_error("mysql error %d [%s]: %s\n", mysql_errno(mysql), mysql_sqlstate(mysql), mysql_error(mysql))

const char *sql_dbname(void)
{
	return buf_dbname;
}

MYSQL *sql_connect_db(const char *hostname, const char *username, const char *password, const char *database)
{
	MYSQL *mysql;

	hostname = S_OR(hostname, dbhostname);
	username = S_OR(username, dbusername);
	password = S_OR(password, dbpassword);
	database = S_OR(database, dbname);

	if (strlen_zero(hostname) || strlen_zero(username) || strlen_zero(password)) {
		bbs_error("One or more necessary DB config options is missing\n"); /* ^ DB name is optional.... */
		return NULL;
	}
	if (!(mysql = mysql_init(NULL))) {
		bbs_error("mysql_init returned NULL\n");
		return NULL;
	}
	if (mysql_optionsv(mysql, MYSQL_SET_CHARSET_NAME, (void *) "utf8")) {
		goto fail;
	}
	if (!mysql_real_connect(mysql, hostname, username, password, dbname, 0, NULL, 0)) {
		goto fail;
	}
	if (mysql_set_character_set(mysql, "utf8")) { /* Make sure that mysql_real_escape_string can always do its job. */
		goto fail;
	}
	return mysql;

fail:
	log_mysqli_error(mysql);
	mysql_close(mysql);
	return NULL;
}

MYSQL *sql_connect(void)
{
	return sql_connect_db(NULL, NULL, NULL, NULL);
}

int sql_prepare(MYSQL_STMT *stmt, const char *fmt, const char *query)
{
	int i, qlen;
	int num_args;
	const char *cur = fmt;

	if (!stmt) {
		bbs_warning("failed to get stmt\n");
		return -1;
	}
	if (strlen_zero(query)) {
		bbs_warning("No query provided\n");
		return -1;
	}
	if (strlen_zero(fmt)) {
		bbs_warning("No argument format string provided\n");
		return -1;
	}

	num_args = strlen(fmt);
	qlen = strlen(query);

	if (mysql_stmt_prepare(stmt, query, qlen)) {
		bbs_warning("mysql_stmt_prepare failed: %s (%s)\n", mysql_stmt_error(stmt), query);
		return -1;
	}
	if ((int) mysql_stmt_param_count(stmt) != num_args) {
		bbs_warning("Expected %d parameters but prepared %lu?\n", num_args, mysql_stmt_param_count(stmt));
		return -1;
	}

	/* No point in really doing much at this point... just check that our format string is good. */
	for (i = 0; i < num_args; i++) {
		switch (*cur) {
		/* Supported */
		case 'i': /* Integer */
		case 'l': /* Long */
		case 'd': /* Double */
		case 's': /* String */
		case 't': /* Date */
			break;
		/* Not supported */
		case 'b': /* Blob */
		default:
			bbs_warning("Unsupported SQL format type specifier: %c\n", *cur);
			return -1;
		}
		cur++;
	}

	return 0;
}

#if 0
/*! \note Not currently being used, because sql_alloc_bind_strings is more convenient */
static int sql_string_prep(int num_fields, char *bind_strings[], unsigned long int lengths[], int index, int size)
{
	if (index >= num_fields) {
		bbs_warning("Index is out of bounds: %d\n", index);
		return -1;
	}
	lengths[index] = size;
	bind_strings[index] = malloc(lengths[index]);
	if (!bind_strings[index]) {
		bbs_error("malloc failure\n");
		return -1;
	}
	return 0;
}
#endif

int sql_bind_param_single(va_list ap, int i, const char *cur, MYSQL_BIND bind[], unsigned long int lengths[], int bind_ints[], long long bind_longs[], char *bind_strings[], MYSQL_TIME bind_dates[], my_bool bind_null[])
{
	struct tm *tm;
	char format_char = tolower(*cur);
	bind_null[i] = (my_bool) isupper(format_char); /* Uppercase format char means it's NULL */

#if 0
	bbs_debug(10, "Executing fmt char: %c\n", format_char);
#endif

	/* Ref: https://dev.mysql.com/doc/c-api/5.7/en/c-api-prepared-statement-data-structures.html */
	/* See for C <-> MySQL/MariaDB types: https://dev.mysql.com/doc/c-api/5.7/en/c-api-prepared-statement-type-codes.html */
	switch (format_char) {
	case 'i': /* Integer */
		bind_ints[i] = va_arg(ap, int);
		/* This is a number type, so there is no need to specify buffer_length */
		bind[i].buffer_type = MYSQL_TYPE_LONG; /* Yes, this is correct */
		bind[i].buffer = (char *) &bind_ints[i];
		bind[i].is_null = &bind_null[i];
		bind[i].length = 0;
		break;
	case 'l': /* Long int */
		bind_longs[i] = va_arg(ap, long long);
		/* This is a number type, so there is no need to specify buffer_length */
		bind[i].buffer_type = MYSQL_TYPE_LONGLONG;
		bind[i].buffer = (char *) &bind_longs[i];
		bind[i].is_null = &bind_null[i];
		bind[i].length = 0;
		break;
	case 'd': /* Double */
		bind_ints[i] = va_arg(ap, int);
		/* This is a number type, so there is no need to specify buffer_length */
		bind[i].buffer_type = MYSQL_TYPE_LONG;
		bind[i].buffer = (char *) &bind_ints[i];
		bind[i].is_null = &bind_null[i];
		bind[i].length = 0;
		break;
	case 's': /* String */
		bind_strings[i] = va_arg(ap, char *);
		lengths[i] = strlen(S_IF(bind_strings[i]));
		if (!bind_strings[i] && !bind_null[i]) {
			bbs_warning("String at index %d is NULL, but not specified?\n", i);
		}
		bind[i].buffer_type = MYSQL_TYPE_STRING;
		bind[i].buffer = (char *) bind_strings[i];
		bind[i].buffer_length = lengths[i];
		bind[i].is_null = &bind_null[i];
		bind[i].length = &lengths[i]; /* For strings, we actually do need the length. We'll be able to find it in the array. */
		break;
	case 't': /* Date */
		tm = va_arg(ap, struct tm *);
		bind_dates[i].year = TM_YEAR(tm->tm_year);
		bind_dates[i].month = TM_MONTH(tm->tm_mon);
		bind_dates[i].day = tm->tm_mday;
		bind_dates[i].hour = tm->tm_hour;
		bind_dates[i].minute = tm->tm_min;
		bind_dates[i].second = tm->tm_sec;
		bind[i].buffer_type = MYSQL_TYPE_DATE;
		bind[i].buffer = (char *) &bind_dates[i];
		bind[i].is_null = &bind_null[i];
		bind[i].length = 0;
		break;
	case 'b': /* Blob */
		bbs_warning("Blobs are currently unsupported\n");
		return -1;
	default:
		bbs_warning("Unknown SQL format type specifier: %c\n", *cur);
		return -1;
	}
	return 0;
}

#pragma GCC diagnostic ignored "-Wstack-protector"
int sql_prep_bind_exec(MYSQL_STMT *stmt, const char *query, const char *fmt, ...)
{
	int i, num_args = strlen(fmt);
	va_list ap;
	MYSQL_BIND bind[num_args];
	unsigned long int lengths[num_args];
	/* We need an array of the size of the num args, for every type... not sure if there's a better way, but not really a big deal... */
	int bind_ints[num_args];
	long long bind_longs[num_args];
	char *bind_strings[num_args];
	my_bool bind_null[num_args];
	MYSQL_TIME bind_dates[num_args];
	const char *cur = fmt;
#pragma GCC diagnostic pop

	if (sql_prepare(stmt, fmt, query)) {
		return -1;
	}

	memset(bind, 0, sizeof(bind));

	va_start(ap, fmt); 
	for (i = 0; i < num_args; i++, cur++) { /* Bind the parameters themselves for this round */
		if (sql_bind_param_single(ap, i, cur, bind, lengths, bind_ints, bind_longs, bind_strings, bind_dates, bind_null)) {
			va_end(ap);
			return -1;
		}
	}
	va_end(ap);

	/* Finish it off, go in for the execute */
	if (mysql_stmt_bind_param(stmt, bind)) { /* Bind the buffers */
		bbs_error("mysql_stmt_bind_param failed: %s\n", mysql_stmt_error(stmt));
		return -1;
	}
	if (mysql_stmt_execute(stmt)) {
		bbs_error("mysql_stmt_execute failed: %s\n", mysql_stmt_error(stmt));
		return -1;
	}
	return 0;
}

int sql_stmt_fetch(MYSQL_STMT *stmt)
{
	int res = mysql_stmt_fetch(stmt);
	switch (res) {
	case 0: /* Success */
		break;
	case 1: /* Failure */
		bbs_error("SQL STMT fetch failed: %s\n", mysql_stmt_error(stmt));
		break;
	case MYSQL_NO_DATA:
		bbs_debug(3, "SQL STMT fetch returned no more data\n");
		break;
	case MYSQL_DATA_TRUNCATED:
		bbs_debug(3, "SQL STMT fetch data truncated\n"); /* Caller needs to allocate bigger buffer(s), *OR* this is okay, if we're using sql_alloc_bind_strings */
		break;
	default:
		bbs_error("Unexpected SQL STMT fetch return code: %d\n", res);
	}
	return res;
}

void sql_free_result_strings(int num_fields, MYSQL_BIND bind[], unsigned long int lengths[], char *bind_strings[])
{
	int i;
	for (i = 0; i < num_fields; i++) {
		if (lengths[i] && bind[i].buffer_type == MYSQL_TYPE_STRING && bind_strings[i]) {
			/* Some additional cleanup necessary if we're going to
			 * process multiple results and repeatedly call sql_alloc_bind_strings and sql_free_result_strings */
			free(bind_strings[i]);
			bind_strings[i] = NULL;
			bind[i].buffer = NULL; /* This was the same thiing as bind_strings[i], which we've just freed */
			bind[i].buffer_length = 0;
			lengths[i] = 0;
#ifdef DEBUG_SQL
			bbs_debug(6, "Freed string field at index %d\n", i);
#endif
		}
	}
}

int sql_alloc_bind_strings(MYSQL_STMT *stmt, const char *fmt, MYSQL_BIND bind[], unsigned long int lengths[], char *bind_strings[])
{
	int i, res = 0;
	int nullstrings = 0;
	const char *cur = fmt;
	int num_cols = strlen(fmt);

	for (i = 0; i < num_cols; i++) {
		switch (*cur++) {
		case 's': /* String */
			if (bind[i].buffer_length == 0 && lengths[i] > 0) {
				nullstrings++;
			}
			break;
		default:
			break;
		}
	}

	if (nullstrings) {
		/* If we have a string and the buffer length is 0, dynamically allocate memory now. */
#ifdef DEBUG_SQL
		bbs_debug(5, "%d string field%s must be dynamically allocated\n", nullstrings, ESS(nullstrings));
#endif
		for (i = 0; i < num_cols; i++) {
			if (bind[i].buffer_type == MYSQL_TYPE_STRING && bind[i].buffer == NULL && lengths[i] > 0) {
				res = -1;
#ifdef DEBUG_SQL
				bbs_debug(6, "Allocating dynamic buffer at index %d for string of length %lu\n", i, lengths[i]);
#endif
				bind[i].buffer = calloc(1, lengths[i] + 1); /* Add 1 for null terminator, even though MySQL won't add one. */
				if (!bind[i].buffer) {
					bbs_error("malloc failed\n");
					lengths[i] = 0; /* Set back to 0 so we don't attempt to free unallocated memory in sql_free_result_strings */
				} else {
					bind_strings[i] = bind[i].buffer; /* Make sure we have a reference to the allocated memory */
					bind[i].buffer_length = lengths[i];
					/* The official documentation for this function has a typo in it that has never been corrected: https://dev.mysql.com/doc/c-api/8.0/en/mysql-stmt-fetch.html
					 * See: https://bugs.mysql.com/bug.php?id=33086
					 * If there's one thing I really hate, it's documentation that is wrong or not maintained... argh... */
					res = mysql_stmt_fetch_column(stmt, &bind[i], i, 0);
					if (res) { /* ith column, offset 0 to start at beginning */
						bbs_error("mysql_stmt_fetch_column(%d) failed (%d): %s\n", i, res, mysql_stmt_error(stmt));
						/* Free now since this buffer is useless anyways */
						free(bind_strings[i]);
						bind_strings[i] = NULL;
						lengths[i] = 0;
					} else {
						if (strlen(bind_strings[i]) != lengths[i]) {
							bbs_warning("Column %d: expected length %lu but have %lu\n", i, lengths[i], strlen(bind_strings[i]));
						} else {
							res = 0;
						}
						/* No need to null terminate here since we used calloc above */
					}
				}
			}
		}
	} else {
		/* Could happen legitimately if we're querying multiple rows (or even a single one), and some records have NULL for all the string fields that would've been dynamically allocated */
		bbs_debug(1, "No string fields need to be dynamically allocated, this function invocation was unnecessary!\n"); /* No harm done, but not necessary */
	}
	return res;
}

int sql_bind_result(MYSQL_STMT *stmt, const char *fmt, MYSQL_BIND bind[], unsigned long int lengths[], int bind_ints[], char *bind_strings[], MYSQL_TIME bind_dates[], my_bool bind_null[])
{
	int num_cols, num_rows, expect_cols;
	int i, res = -1;
	MYSQL_RES *prepare_meta_result;
	const char *cur = fmt;

	prepare_meta_result = mysql_stmt_result_metadata(stmt);
	if (!prepare_meta_result) {
		bbs_warning("mysql_stmt_result_metadata returned NULL: %s\n", mysql_stmt_error(stmt));
		return -1;
	}

	expect_cols = strlen(fmt);
	num_cols = mysql_num_fields(prepare_meta_result);

	/* Ensure number of columns in results is what we expected */
	if (num_cols != expect_cols) {
		bbs_warning("Expected %d columns but got %d?\n", expect_cols, num_cols);
		goto cleanup;
	}

	for (i = 0; i < num_cols; i++) {
		switch (*cur++) {
		case 'i': /* Integer */
			/* This is a number type, so there is no need to specify buffer_length */
			bind[i].buffer_type = MYSQL_TYPE_LONG; /* Yes, this is correct */
			bind[i].buffer = (char *) &bind_ints[i];
			bind[i].is_null = &bind_null[i];
			bind[i].length = 0;
			break;
		case 'd': /* Double */
			/* This is a number type, so there is no need to specify buffer_length */
			bind[i].buffer_type = MYSQL_TYPE_LONG;
			bind[i].buffer = (char *) &bind_ints[i];
			bind[i].is_null = &bind_null[i];
			bind[i].length = 0;
			break;
		case 's': /* String */
			bind[i].buffer_type = MYSQL_TYPE_STRING;
			bind[i].buffer = (char *) bind_strings[i];
			bind[i].buffer_length = lengths[i];
			bind[i].is_null = &bind_null[i];
			bind[i].length = &lengths[i]; /* For strings, we actually do need the length. We'll be able to find it in the array. */
			break;
		case 't': /* Date */
			bind[i].buffer_type = MYSQL_TYPE_DATE;
			bind[i].buffer = (char *) &bind_dates[i];
			bind[i].buffer_length = lengths[i];
			bind[i].is_null = &bind_null[i];
			bind[i].length = 0;
			break;
		case 'b': /* Blob */
			bbs_warning("Blobs are currently unsupported\n");
			goto cleanup;
		case 'l': /*! \todo Not supported here yet, because it would break the API, and we haven't needed l for this func yet, so kicking the can down the road... */
		default:
			bbs_warning("Unknown SQL format type specifier: %c\n", *cur);
			goto cleanup;
		}
	}

	/* Bind result buffers */
	if (mysql_stmt_bind_result(stmt, bind)) {
		bbs_warning("mysql_stmt_bind_result failed: %s\n", mysql_stmt_error(stmt));
		goto cleanup;
	}

	/* Don't call sql_alloc_bind_strings here, because then we've already fetched the first row of results before we enter the while loop.
	 * And generally speaking, sql_alloc_bind_strings needs to be called (and the allocated strings freed) once per row,
	 * so that's the more general way to handle it. */

	if (mysql_stmt_store_result(stmt)) {
		bbs_warning("mysql_stmt_store_result failed: %s\n", mysql_stmt_error(stmt));
		goto cleanup;
	}

	num_rows = mysql_stmt_num_rows(stmt);
	bbs_debug(10, "Query returned %d rows\n", num_rows);

	res = 0;
cleanup:
	mysql_free_result(prepare_meta_result);
	return res;
}

int sql_fetch_columns(int bind_ints[], long long bind_longs[], char *bind_strings[], MYSQL_TIME bind_dates[], my_bool bind_null[], const char *fmt, ...)
{
	int i, num_args = strlen(fmt);
	va_list ap;
	const char *cur = fmt;
	char format_char;
	int *tmpint;
	long long *tmplong;
	char **tmpstr;
	struct tm *tmptm;
	MYSQL_TIME datetime;

	va_start(ap, fmt);
	for (i = 0; i < num_args; i++, cur++) { /* Bind the parameters themselves for this round */
		format_char = tolower(*cur);
		switch (format_char) {
		case 'i': /* Integer */
		case 'd': /* Double */
			tmpint = va_arg(ap, int *);
			*tmpint = bind_ints[i];
			break;
		case 'l': /* Long int */
			tmplong = va_arg(ap, long long *);
			*tmplong = bind_longs[i];
			break;
		case 's': /* String */
			tmpstr = va_arg(ap, char **);
			*tmpstr = bind_strings[i];
			break;
		case 't': /* Date */
			tmptm = va_arg(ap, struct tm *); /* If we don't call va_arg for each argument, that will throw subsequent ones off */
			if (bind_null[i]) { /* It's all good that we memset tmptm, but if we don't check for NULL, we'll set the clean memory to uninitialized bytes */
				bbs_debug(3, "Index %d is NULL\n", i);
			} else {
				time_t tmptime;
				struct tm tmptm2;
				datetime = bind_dates[i];
				tmptm->tm_year = TO_TM_YEAR(datetime.year);
				tmptm->tm_mon = TO_TM_MONTH(datetime.month);
				tmptm->tm_mday = datetime.day;
				tmptm->tm_hour = datetime.hour;
				tmptm->tm_min = datetime.minute;
				tmptm->tm_sec = datetime.second;
				/* Note that we haven't filled in tm_wday at this point (MYSQL_TIME doesn't have a field for it), so the day of the week is defaulted to Sunday
				 * Hack to recover this information from what we have: */
				tmptime = mktime(tmptm); /* Convert to epoch */
				localtime_r(&tmptime, &tmptm2); /* Now convert back to a tm. */
				/* Thanks, localtime, now we can fill in the day of the week,
				 * and other fields that weren't available to us before,
				 * to actually fully fill out the struct.
				 * Keep the original tm, just in case there are other differences. */
				tmptm->tm_wday = tmptm2.tm_wday;
				tmptm->tm_yday = tmptm2.tm_yday;
			}
			break;
		case 'b': /* Blob */
			bbs_warning("Blobs are currently unsupported\n");
			return -1;
		default:
			bbs_warning("Unknown SQL format type specifier: %c\n", *cur);
			return -1;
		}
	}
	va_end(ap);

	return 0;
}

static int load_config(void)
{
	int res = 0;
	struct bbs_config *cfg = bbs_config_load("mod_auth_mysql.conf", 0);

	if (!cfg) {
		bbs_error("mod_auth_mysql.conf is missing, module will decline to load\n");
		return -1;
	}

	res |= bbs_config_val_set_str(cfg, "db", "hostname", buf_dbhostname, sizeof(buf_dbhostname));
	res |= bbs_config_val_set_str(cfg, "db", "username", buf_dbusername, sizeof(buf_dbusername));
	res |= bbs_config_val_set_str(cfg, "db", "password", buf_dbpassword, sizeof(buf_dbpassword));
	if (res) {
		bbs_error("Missing either hostname, username, or password\n");
		bbs_config_free(cfg);
		return -1;
	}
	if (bbs_config_val_set_str(cfg, "db", "database", buf_dbname, sizeof(buf_dbname))) { /* This is optional but highly recommended. */
		bbs_warning("No database name specified in mod_auth_mysql.conf\n");
	}

	bbs_config_free(cfg); /* Destroy the config now, rather than waiting until shutdown, since it will NEVER be used again for anything. */
	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	return 0;
}

static int unload_module(void)
{
	mysql_library_end();
	return 0;
}

BBS_MODULE_INFO_FLAGS("MySQL/MariaDB Interface", MODFLAG_GLOBAL_SYMBOLS);
