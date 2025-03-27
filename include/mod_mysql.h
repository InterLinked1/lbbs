/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 */

/*! \file
 *
 * \brief MySQL/MariaDB interface
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/*
 * Full MySQL/MariaDB C API documentation available here:
 * https://mariadb.com/kb/en/mariadb-connectorc-api-functions/
 */

/* see ctime(3) */
#define TM_MONTH(m) (m + 1)
#define TM_YEAR(y) (y + 1900)
#define TO_TM_MONTH(m) (m - 1)
#define TO_TM_YEAR(y) (y - 1900)

/*!
 * \brief Connect to a database with the provided connection information.
 * \param hostname
 * \param username
 * \param password
 * \param database. May be NULL.
 */
MYSQL *sql_connect_db(const char *hostname, const char *username, const char *password, const char *database);

int sql_prepare(MYSQL_STMT *stmt, const char *fmt, const char *query);

/*! \brief Automatically adjust the format string based on whether any arguments are NULL */
int sql_fmt_autonull(char *fmt, ...);

#define sql_prep_bind_exec(stmt, query, fmt, ...) __sql_prep_bind_exec(stmt, query, __FILE__, __LINE__, __func__, fmt, ## __VA_ARGS__)

int __sql_prep_bind_exec(MYSQL_STMT *stmt, const char *query, const char *file, int line, const char *func, const char *fmt, ...);

/* if mysql_stmt_fetch returns 1 or MYSQL_NO_DATA, break */
#define MYSQL_NEXT_ROW(stmt) (!(mysqlres = __sql_stmt_fetch(stmt, 0)) || (mysqlres == MYSQL_DATA_TRUNCATED))

/* If we use sql_alloc_bind_strings instead of sql_string_prep in advance, then the result will initially be truncated, until we call sql_alloc_bind_strings */
/* if mysql_stmt_fetch returns 1 or MYSQL_NO_DATA, break */
#define MYSQL_NEXT_ROW_DYNAMIC(stmt) (!(mysqlres = __sql_stmt_fetch(stmt, 1)) || (mysqlres == MYSQL_DATA_TRUNCATED))

/*!
 * \brief Fetch the next row of results
 * \param stmt
 * \param dynamic Whether the buffers for the results will be dynamically allocated (i.e. sql_alloc_bind_strings is called within the retrieval loop)
 * \retval 0 on success
 * \retval 1 on failure
 * \retval MYSQL_NO_DATA for end of data
 * \retval MYSQL_DATA_TRUNCATED if truncation occured. If dynamic == 1, this is typically expected since the result can't be stored yet
 * \note Do not use this function directly. Use the MYSQL_NEXT_ROW or MYSQL_NEXT_ROW_DYNAMIC macro.
 */
int __sql_stmt_fetch(MYSQL_STMT *stmt, int dynamic);

void sql_free_result_strings(int num_fields, MYSQL_BIND bind[], unsigned long int lengths[], char *bind_strings[]);

/*! \brief Automatically allocate any memory needed to hold string results */
/*! \note You must call sql_stmt_fetch BEFORE calling this and sql_free_result_strings AFTER calling done with the results */
int sql_alloc_bind_strings(MYSQL_STMT *stmt, const char *fmt, MYSQL_BIND bind[], unsigned long int lengths[], char *bind_strings[]);

int sql_bind_result(MYSQL_STMT *stmt, const char *fmt, MYSQL_BIND bind[], unsigned long int lengths[], int bind_ints[], char *bind_strings[], MYSQL_TIME bind_dates[], my_bool bind_null[]);

int sql_fetch_columns(int bind_ints[], long long bind_longs[], char *bind_strings[], MYSQL_TIME bind_dates[], my_bool bind_null[], const char *fmt, ...);

/*! \brief malloc some memory if data is present and and memcpy into it if malloc succeeds */
#define MALLOC_MEMCPY(field, isnull, data) \
	field = isnull ? NULL : malloc(sizeof(*field)); \
	if (field) { \
		memcpy(field, data, sizeof(*field)); \
	}
