/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief General utility functions
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/readline.h"

#ifdef BBS_MAIN_PROCESS
/* Forward declarations */
struct bbs_node;
struct sockaddr_in;

#include "include/string.h"
#include "include/thread.h"

/* Note: Most actual I/O functions are in socket.c but declared in node.h */
#include "include/socket.h"
#include "include/tcp.h"
#endif

/* Forward declarations */
struct bbs_user;
struct dirent;

/*!
 * \brief Generate a UUID (universally unique identifier), all lowercase
 * \return UUID on success, NULL on failure
 */
char *bbs_uuid(void);

/*! \note This really should be opaque, but it's declared here so that callers can stack allocate it */
struct dyn_str {
	char *buf;
	size_t len;
	size_t used;
};

/*! \brief Reset a dyn_str */
void dyn_str_reset(struct dyn_str *dynstr);

/*!
 * \brief Append to a dyn_str
 * \param dynstr
 * \param s Data to append. The buffer will be dynamically expanded if needed.
 * \param len Length of s (use strlen if needed first)
 * \retval -1 on failure
 * \return On success, actual length of the string currently in the dyn_str buffer (not the current allocation size)
 */
int dyn_str_append(struct dyn_str *dynstr, const char *s, size_t len) __attribute__((nonnull (1, 2)));

/*!
 * \brief Append to a dyn_str using a format string
 * \param dynstr
 * \param fmt printf-style format string
 * \retval -1 on failure
 * \return On success, actual length of the string currently in the dyn_str buffer (not the current allocation size)
 */
int __attribute__ ((format (gnu_printf, 2, 3))) dyn_str_append_fmt(struct dyn_str *dynstr, const char *fmt, ...);

/*!
 * \brief Get the length of a dyn_str
 * \param dynstr
 * \return Length of string
 */
#define dyn_str_len(dynstr) (dynstr->used)

/*! \brief Whether s is a "truthy" value */
int bbs_truthy_value(const char *s);

/*! \brief Whether s is a "falsy" value */
int bbs_falsy_value(const char *s);

struct bbs_url {
	const char *prot;
	const char *user;
	char *pass;			/* Not const, so it can be zeroed when no longer needed */
	const char *host;
	int port;
	const char *resource;
};

/*!
 * \brief Parse a URL into its components
 * \param url
 * \param s String that will get used up
 * \retval 0 on success, -1 on failure
 */
int bbs_parse_url(struct bbs_url *url, char *restrict s);

/*! \brief URL decode a string, in place */
void bbs_url_decode(char *restrict s);

/*!
 * \brief Decode an base64-encoded RFC4616 SASL PLAIN response into its components
 * \param s SASL PLAIN response from client
 * \param[out] authorization Authorization ID (may be empty)
 * \param[out] authentication Authentication ID
 * \param[out] passwd Password
 * \retval base64-decoded string, which must be freed, or NULL on failure.
 * \note Use bbs_sasl_authenticate if possible instead of using this function directly.
 */
unsigned char *bbs_sasl_decode(const char *s, char **authorization, char **authentication, char **passwd);

/*!
 * \brief Create a base64 encoded SASL PLAIN authentication string
 * \param nickname
 * \param username
 * \param password
 * \retval encoded string on success, which must be freed, or NULL on failure.
 */
char *bbs_sasl_encode(const char *nickname, const char *username, const char *password);

/*!
 * \brief Parse an email address identity into its components
 * \param addr Identity (which will be consumed). Can be user\@host or name <user\@host> format.
 * \param[out] name Name portion, if any. NULL if not present.
 * \param[out] user Username portion
 * \param[out] host Hostname portion
 * \retval 0 on success, -1 on failure
*/
int bbs_parse_email_address(char *addr, char **name, char **user, char **host);

/*!
 * \brief Detect a mismatch between an email identity and the currently authenticated user
 * \param user
 * \param from Identity string. Can be user\@host or name <user\@host> format.
 * \retval 0 if okay, -1 on error, -1 if mismatch detected
 */
int bbs_user_identity_mismatch(struct bbs_user *user, const char *from);

/*!
 * \brief Append a byte stuffed line (for SMTP or NNTP data) to a fp
 * \param fp
 * \param line
 * \param len Nominal length of the line. If it starts with a ., the first period will be skipped. A CR LF will be appended.
 * \retval -1 on failure, number of bytes actually written to file on success
 */
int bbs_append_stuffed_line_message(FILE *fp, const char *line, size_t len);

/*!
 * \brief Drop-in replacement for basename(3)
 * \param s
 * \return NULL if input is NULL or string ends in a /
 * \return Basename component of file path
 */
const char *bbs_basename(const char *s);

/*!
 * \brief Traverse all the files and directories in a directory, non-recursively
 * \param path Directory to traverse
 * \param on_file Callback function to execute for each file or directory. Should return 0 to continue iterating and non-zero to stop.
 * \param obj Argument to callback function
 * \retval 0 on success, -1 on failure
 */
int bbs_dir_traverse_items(const char *path, int (*on_file)(const char *dir_name, const char *filename, int dir, void *obj), void *obj);

/*!
 * \brief Traverse all the files in a directory, recursively
 * \param path Directory to traverse recursively
 * \param bbs_file_on_file Callback function to execute for each file. Should return 0 to continue iterating and non-zero to stop.
 * \param obj Argument to callback function
 * \param max_depth
 * \retval 0 on success, -1 on failure
 */
int bbs_dir_traverse(const char *path, int (*bbs_file_on_file)(const char *dir_name, const char *filename, void *obj), void *obj, int max_depth);

/*!
 * \brief Traverse all the directories in a directory, recursively
 * \param path Directory to traverse recursively
 * \param on_file Callback function to execute for each file. Should return 0 to continue iterating and non-zero to stop.
 * \param obj Argument to callback function
 * \param max_depth
 * \retval 0 on success, -1 on failure
 * \note This function serves no useful functional purpose. It's mainly present to list directories recursively by watching the debug messages.
 */
int bbs_dir_traverse_dirs(const char *path, int (*on_file)(const char *dir_name, const char *filename, void *obj), void *obj, int max_depth);

/*!
 * \brief Free all of the individual dirent entries in a scandir dirents**
 * \param entries Entries to be freed
 * \param numfiles Number of items in entries
 */
void bbs_free_scandir_entries(struct dirent **entries, int numfiles);

/*!
 * \brief Determine whether a directory has any files starting with a named prefix
 * \param path Directory to check, non-recursively
 * \param prefix Prefix with which a file must start for there to be a "match"
 * \retval -1 on failure, 0 if no match, 1 if at least one match
 */
int bbs_dir_has_file_prefix(const char *path, const char *prefix);

/*!
 * \brief Determine whether a directory has any subdirectories
 * \param path Directory to check, non-recursively
 * \retval -1 on failure, 0 if no subdirectories, 1 if at least one subdirectory
 */
int bbs_dir_has_subdirs(const char *path);

/*!
 * \brief Get the size of all the files in a directory, recursively to all subdirectories (up to 32 levels)
 * \param path Directory to traverse recursively
 * \retval -1 on failure, size in bytes on success
 */
long bbs_dir_size(const char *path);

/*!
 * \brief Get the number of files in a directory
 * \param path Directory to traverse recursively
 * \retval -1 on failure
 * \return number of files on success
 */
int bbs_dir_num_files(const char *path);

/*!
 * \brief Check if a file exists
 * \param path Full path to file
 * \retval 1 if file exists, 0 if file does not exist
 */
int bbs_file_exists(const char *path);

/*!
 * \brief Ensure that a directory exists, creating it if necessary
 * \param path Directory to create if needed
 * \note The parent directory should exist, this is not recursive
 * \retval 0 on success, -1 on failure
 */
int bbs_ensure_directory_exists(const char *path);

/*! \brief Same as bbs_ensure_directory_exists, but recursively creating parent directories as needed */
int bbs_ensure_directory_exists_recursive(const char *path);

/*!
 * \brief Recursively delete a directory
 * \param path Directory to delete, recursively
 * \retval 0 on success, -1 on failure
 */
int bbs_delete_directory(const char *path);

/*!
 * \brief Delete a file that is assumed to exist
 * \param path Full path of file to delete
 * \retval 0 on success, -1 on failure
 */
int bbs_delete_file(const char *path);

/*!
 * \brief Create a temporary FILE*
 * \param template template ending in XXXXXX to pass to mkstemp
 * \param mode File mode for chmod
 * \returns FILE* handle on success, NULL on failure
 */
FILE *bbs_mkftemp(char *template, mode_t mode);

/*!
 * \brief Efficiently copy part (or all) of a file between two file descriptors
 * \param srcfd File descriptor from which to copy. Must be a regular file.
 * \param destfd Destination file descriptor. Must be a regular file.
 * \param start Offset from start, in bytes, from which to start copying
 * \param bytes Number of bytes to copy, starting from start
 * \retval -1 on failure, number of bytes copied on success
 */
int bbs_copy_file(int srcfd, int destfd, int start, int bytes); /* gcc has fd_arg attributes, but not widely supported yet */

enum bbs_copy_flags {
	COPY_RECURSIVE = (1 << 0), /* Whether to copy recursively (e.g. cp -r) */
	COPY_CLOBBER = (1 << 1), /* Whether to allow clobbering of existing files (inverse of cp -n) */
};

/*!
 * \brief Copy file(s) to another location, by filename (equivalent of cp command)
 * \param source Full path to source file
 * \param dest Full path where destination file should be created
 * \param flags Any flags for copy operation
 * \retval 0 on success, -1 on failure
 */
int bbs_copy_files(const char *source, const char *dest, enum bbs_copy_flags flags);

/*!
 * \brief Efficiently copy data between two file descriptors.
 * \param fd_in Input fd. Must NOT be a pipe.
 * \param fd_out Output fd. Must be a pipe.
 * \param len Number of bytes to copy
 * \retval -1 on failure, number of bytes copied on success
 */
ssize_t bbs_splice(int fd_in, int fd_out, size_t len);

/*!
 * \brief Send all the data in a file to a file descriptor
 * \param filepath Filename
 * \param wfd Destination file descriptor
 * \retval -1 on failure
 * \return Number of bytes sent on succes
 */
ssize_t bbs_send_file(const char *filepath, int wfd);

/*!
 * \brief Load the contents of a file into a string
 * \param filename Full path to file
 * \param maxsize Maximum file size to load into a string (for safety reasons, to avoid allocating enormous amounts of memory). 0 for no limit.
 * \param[out] length The length of the output string, not including the NUL terminator
 * \returns string on success, NULL on failure
 */
char *bbs_file_to_string(const char *filename, size_t maxsize, int *restrict length);

/*! \brief Get a timeval for the current time */
struct timeval bbs_tvnow(void);

/*! \brief Get difference, in ms, between 2 times */
int64_t bbs_tvdiff_ms(struct timeval end, struct timeval start);

/*!
 * \brief Print the current time with format like 01/01 01:01pm
 * \param buf
 * \param len Length of buf. Should be at least 14 (no larger is necessary)
 * \retval same as strftime (number of bytes written, -1 on failure)
 */
int bbs_time_friendly_short_now(char *buf, size_t len);

/*!
 * \brief Print the current time with format like Sat Dec 31 2000 09:45 am EST
 * \param buf
 * \param len Length of buf. Should be at least 29 (no larger is necessary)
 * \retval same as strftime (number of bytes written, -1 on failure)
 */
int bbs_time_friendly_now(char *buf, size_t len);

/*!
 * \brief Print a time with format like Sat Dec 31 2000 09:45 am EST
 * \param epoch Epoch time
 * \param buf
 * \param len Length of buf. Should be at least 29 (no larger is necessary)
 * \retval same as strftime (number of bytes written, -1 on failure)
 */
int bbs_time_friendly(time_t epoch, char *buf, size_t len);

/*!
 * \brief Print time elapsed e.g. 0:33:21
 * \param start
 * \param end End time. 0 to automatically call time(NULL) for current time.
 *             If you call multiple related functions at the same time, doing this yourself
 *             and passing it will be more efficient, avoiding duplicate calls to time().
 * \param buf Buffer.
 * \param len Size of buffer. Minimum 12 recommended.
 */
void print_time_elapsed(time_t start, time_t end, char *buf, size_t len);

/*!
 * \brief Print days elapsed e.g. (0 days, 0 hrs, 33 mins, 21 secs)
 * \param start
 * \param end End time. 0 to automatically call time(NULL) for current time.
 *             If you call multiple related functions at the same time, doing this yourself
 *             and passing it will be more efficient, avoiding duplicate calls to time().
 * \param buf Buffer.
 * \param len Size of buffer. Minimum 36 recommended.
 */
void print_days_elapsed(time_t start, time_t end, char *buf, size_t len);

/*!
 * \brief Parse an RFC822/RFC2822 date (i.e. date from an email header)
 * \param s
 * \param[out] tm
 * \retval 0 on success, -1 on failure
 */
int bbs_parse_rfc822_date(const char *s, struct tm *tm);
