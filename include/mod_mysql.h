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

#define DB_NAME_ARGS sql_dbname(), !strlen_zero(sql_dbname()) ? "." : ""

/* see ctime(3) */
#define TM_MONTH(m) (m + 1)
#define TM_YEAR(y) (y + 1900)
#define TO_TM_MONTH(m) (m - 1)
#define TO_TM_YEAR(y) (y - 1900)

const char *sql_dbname(void);

/*! \brief Connect to a database with the provided connection information. If any parameters are NULL, the default will be used. */
MYSQL *sql_connect_db(const char *hostname, const char *username, const char *password, const char *database);

/*! \brief Connect to the default database (using the default parameters, as configured in mod_auth_mysql.conf) */
MYSQL *sql_connect(void);

int sql_prepare(MYSQL_STMT *stmt, const char *fmt, const char *query);

/*! \brief Automatically adjust the format string based on whether any arguments are NULL */
int sql_fmt_autonull(char *fmt, ...);

int sql_bind_param_single(va_list ap, int i, const char *cur, MYSQL_BIND bind[], unsigned long int lengths[], int bind_ints[], long long bind_longs[], char *bind_strings[], MYSQL_TIME bind_dates[], my_bool bind_null[]);

int sql_prep_bind_exec(MYSQL_STMT *stmt, const char *query, const char *fmt, ...);

/* If we use sql_alloc_bind_strings instead of sql_string_prep in advance, then the result will initially be truncated, until we call sql_alloc_bind_strings */
/* if mysql_stmt_fetch returns 1 or MYSQL_NO_DATA, break */
#define MYSQL_NEXT_ROW(stmt) (!(mysqlres = sql_stmt_fetch(stmt)) || (mysqlres == MYSQL_DATA_TRUNCATED))

int sql_stmt_fetch(MYSQL_STMT *stmt);

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
