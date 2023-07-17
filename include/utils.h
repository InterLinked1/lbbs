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
#include "include/string.h"
#endif

#define HAVE_OPENSSL

/* Forward declaration of SSL* needed */
#ifdef HAVE_OPENSSL
#include <openssl/bio.h>
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

struct bbs_url {
	char *prot;
	char *user;
	char *pass;
	char *host;
	int port;
	char *resource;
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

/*! \brief Get thread ID of current thread */
int bbs_gettid(void);

/*!
 * \brief Disable cancellability of a thread
 * \warning This function should be avoided if possible, but must be used if it is needed
 */
void bbs_pthread_disable_cancel(void);

/*!
 * \brief Restore cancellability of a thread
 */
void bbs_pthread_enable_cancel(void);

/*!
 * \brief Cancel and kill a thread
 * \deprecated
 * \warning Avoid this function if possible, as threads may not clean up properly if cancelled/killed in the wrong place
 */
int bbs_pthread_cancel_kill(pthread_t thread);

int __bbs_pthread_join(pthread_t thread, void **retval, const char *file, const char *func, int line);

/*! \brief Join a non-detached thread */
#define bbs_pthread_join(thread, retval) __bbs_pthread_join(thread, retval, __FILE__, __func__, __LINE__)

int __bbs_pthread_create_detached(pthread_t *thread, pthread_attr_t *attr, void *(*start_routine)(void *), void *data, const char *file, const char *func, int line, const char *start_fn);

/*!
 * \brief Create a detached pthread
 * \retval 0 on success, -1 on failure
 */
#define bbs_pthread_create_detached(thread, attr, start_routine, data) __bbs_pthread_create_detached(thread, attr, start_routine, data, __FILE__, __func__, __LINE__, #start_routine)

int __bbs_pthread_create(pthread_t *thread, pthread_attr_t *attr, void *(*start_routine)(void *), void *data, const char *file, const char *func, int line, const char *start_fn);

/*!
 * \brief Create a non-detached pthread
 * \retval 0 on success, -1 on failure
 */
#define bbs_pthread_create(thread, attr, start_routine, data) __bbs_pthread_create(thread, attr, start_routine, data, __FILE__, __func__, __LINE__, #start_routine)

/*! \brief Destroy thread registrations (on shutdown) */
void bbs_thread_cleanup(void);

/*!
 * \brief Get the thread ID (LWP) of a registered thread
 * \param thread pthread_t handle
 * \retval -1 if thread not currently registered, LWP/thread ID otherwise
 */
int bbs_pthread_tid(pthread_t thread);

/*!
 * \brief Print list of active BBS threads
 * \param fd File descriptor to which to print thread listing
 * \warning This may not include all threads, such as those that do not use the BBS pthread creation wrappers (external libraries, etc.)
 */
int bbs_dump_threads(int fd);

/*!
 * \brief Create a UNIX domain socket
 * \param sock Pointer to socket
 * \param sockfile Socket file path
 * \param perm Permissions for socket
 * \param uid User ID. -1 to not change.
 * \param gid Group ID. -1 to not change.
 * \retval 0 on success, -1 on failure
 */
int bbs_make_unix_socket(int *sock, const char *sockfile, const char *perm, uid_t uid, gid_t gid);

/*!
 * \brief Create a TCP socket
 * \param sock Pointer to socket
 * \param port Port number on which to create the socket
 * \retval 0 on success, -1 on failure
 */
int bbs_make_tcp_socket(int *sock, int port);

/* Forward declarations */
struct bbs_node;
struct sockaddr_in;

/*! \brief Put a socket in nonblocking mode */
int bbs_unblock_fd(int fd);

/*! \brief Put a socket in blocking mode */
int bbs_block_fd(int fd);

/*!
 * \brief Resolve a hostname to an IP address
 * \param hostname Hostname or IP address
 * \param[out] buf IP address
 * \param[out] len Size of buf.
 * \retval -1 on failure, 0 on success
 */
int bbs_resolve_hostname(const char *hostname, char *buf, size_t len);

struct bbs_tcp_client {
	char *buf;
	size_t len;
	struct readline_data rldata;
	int fd;
	int rfd;
	int wfd;
	SSL *ssl;
	unsigned int secure:1;
};

/*! \brief Clean up a TCP client */
void bbs_tcp_client_cleanup(struct bbs_tcp_client *client);

/*!
 * \brief Establish a TCP client connection to a server
 * \param[out] client This is filled in, but memset this to 0 first.
 * \param url Server address
 * \param secure Whether to use implicit TLS when establishing the connection
 * \param buf Buffer for readline operations
 * \param len Size of buf
 * \retval 0 on success, -1 on failure
 */
int bbs_tcp_client_connect(struct bbs_tcp_client *client, struct bbs_url *url, int secure, char *buf, size_t len);

/*!
 * \brief Send data on a TCP client connection
 * \param client
 * \param fmt printf-style format string
 * \retval same as write
 */
int bbs_tcp_client_send(struct bbs_tcp_client *client, const char *fmt, ...) __attribute__ ((format (gnu_printf, 2, 3))) ;

/*!
 * \brief Expect a response containing a substring on a TCP connection
 * \param client
 * \param delim Delimiter to use for readline operations (CR LF is typical)
 * \param attempts Maximum number of responses (typically lines) that will be parsed. Typically 1.
 * \param ms argument to poll()
 * \param str Substring to expect
 * \retval 0 on success (substring contained in response), -1 on failure, 1 if max attempts reached
 */
int bbs_tcp_client_expect(struct bbs_tcp_client *client, const char *delim, int attempts, int ms, const char *str);

/*!
 * \brief Open a TCP socket to another server
 * \param hostname DNS hostname of server
 * \param port Destination port number
 * \retval -1 on failure, socket file descriptor otherwise
 * \note This does not perform TLS negotiation, use ssl_client_new immediately or later in the session for encryption.
 */
int bbs_tcp_connect(const char *hostname, int port);

/*!
 * \brief Wrapper around accept(), with poll timeout
 * \param socket Socket fd
 * \param ms poll time in ms
 * \param ip Optional IP restriction. NULL to allow any IP address.
 * \retval -1 on failure, socket file descriptor otherwise
 */
int bbs_timed_accept(int socket, int ms, const char *ip);

/*!
 * \brief Cleanly shutdown and close a socket
 * \param socket Pointer to socket fd
 */
void bbs_socket_close(int *socket);

/*!
 * \brief Cleanly shutdown and close a socket and an associated listening thread
 * \param socket Pointer to socket fd
 * \param thread
 */
void bbs_socket_thread_shutdown(int *socket, pthread_t thread);

/*!
 * \brief Check whether a socket has been closed by the remote peer, without reading from it
 * \param fd
 * \retval 1 if closed, 0 if no activity
 */
int bbs_socket_pending_shutdown(int fd);

/*!
 * \brief Listen on a TCP socket
 * \param port TCP port number
 * \param name Name of network service
 * \param handler Handler to execute to handle nodes spawned by this listener
 * \retval 0 on success, -1 on failure
 */
#define bbs_start_tcp_listener(port, name, handler) __bbs_start_tcp_listener(port, name, handler, BBS_MODULE_SELF)

int __bbs_start_tcp_listener(int port, const char *name, void *(*handler)(void *varg), void *module);

/*! \brief Same as bbs_start_tcp_listener but, like bbs_tcp_listener3, for multiple TCP listeners at once */
#define bbs_start_tcp_listener3(port, port2, port3, name, name2, name3, handler) __bbs_start_tcp_listener3(port, port2, port3, name, name2, name3, handler, BBS_MODULE_SELF)

int __bbs_start_tcp_listener3(int port, int port2, int port3, const char *name, const char *name2, const char *name3, void *(*handler)(void *varg), void *module);

/*!
 * \brief Stop a TCP listener registered previously using bbs_start_tcp_listener
 * \param port TCP port number
 * \retval 0 on success, -1 on failure
 * \note This does not close the socket
 */
int bbs_stop_tcp_listener(int port);

/*!
 * \brief Run a terminal services TCP network login service listener thread
 * \param socket Socket fd
 * \param name Name of network login service, e.g. Telnet, RLogin, etc.
 * \param handshake Handshake callback function. It should return 0 to proceed and -1 to abort.
 * \param module Module reference
 */
void bbs_tcp_comm_listener(int socket, const char *name, int (*handshake)(struct bbs_node *node), void *module);

/*!
 * \brief Run a generic TCP network login service listener thread
 * \param socket Socket fd
 * \param name Name of network login service, e.g. Telnet, RLogin, etc.
 * \param handler Service handler function
 * \param module Module reference
 */
void bbs_tcp_listener(int socket, const char *name, void *(*handler)(void *varg), void *module);

/*!
 * \brief Run a generic TCP network login service listener thread for up to 2 sockets
 * \param socket Socket fd (typically the insecure socket). -1 if not needed.
 * \param socket2 Optional 2nd fd (typically the secure socket). -1 if not needed.
 * \param name Name of network login service corresponding to socket
 * \param name2 Name of network login service corresponding to socket2
 * \param handler Common service handler function (for both sockets)
 * \param module Module reference
 */
void bbs_tcp_listener2(int socket, int socket2, const char *name, const char *name2, void *(*handler)(void *varg), void *module);

/*!
 * \brief Run a generic TCP network login service listener thread for up to 3 sockets
 * \param socket Socket fd (typically the insecure socket). -1 if not needed.
 * \param socket2 Optional 2nd fd (typically the secure socket). -1 if not needed.
 * \param socket3 Optional 3rd fd. -1 if not needed.
 * \param name Name of network login service corresponding to socket
 * \param name2 Name of network login service corresponding to socket2
 * \param name3 Name of network login service corresponding to socket3
 * \param handler Common service handler function (for all sockets)
 * \param module Module reference
 */
void bbs_tcp_listener3(int socket, int socket2, int socket3, const char *name, const char *name2, const char *name3, void *(*handler)(void *varg), void *module);

/*!
 * \brief Get local IP address
 * \param buf
 * \param len
 * \retval 0 on success, -1 on failure
 */
int bbs_get_local_ip(char *buf, size_t len);

/*!
 * \brief Get the hostname of an IP address
 * \param ip IP address
 * \param[out] buf
 * \param len Size of buf
 * \retval 0 on success, -1 on failure
 * \note If no hostname is determinable, the IP address may be returned and this will count as success.
 */
int bbs_get_hostname(const char *ip, char *buf, size_t len);

/*!
 * \brief Get remote IP address
 * \param sinaddr
 * \param buf
 * \param len
 * \retval 0 on success, -1 on failure
 */
int bbs_get_remote_ip(struct sockaddr_in *sinaddr, char *buf, size_t len);

/*!
 * \brief Save remote IP address
 * \param sinaddr
 * \param node
 * \retval 0 on success, -1 on failure
 */
int bbs_save_remote_ip(struct sockaddr_in *sinaddr, struct bbs_node *node);

/*! \brief Check whether a hostname is an IPv4 address */
int bbs_hostname_is_ipv4(const char *hostname);

/*!
 * \brief Check if an IP address is within a specified CIDR range
 * \param ip IP address to check, e.g. 192.168.1.1
 * \param cidr CIDR range, e.g. 192.168.1.1/24
 * \retval 1 if in range, 0 if error or not in range
 */
int bbs_cidr_match_ipv4(const char *ip, const char *cidr);

/*!
 * \brief Check if an IP address matches an IP address, CIDR range, or hostname
 * \param ip IP address to check, e.g. 192.168.1.1
 * \param s IPv4 address, IPv4 CIDR range, or hostname (not recommended, since it will only match one of the returned IPs, if multiple)
 * \retval 1 if IP address matches, 0 if not
 */
int bbs_ip_match_ipv4(const char *ip, const char *s);

/*! \brief Get the name of a poll revent */
const char *poll_revent_name(int revents);

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

/*!
 * \brief Create a temporary FILE*
 * \param template template ending in XXXXXX to pass to mkstemp
 * \param mode File mode for chmod
 * \returns FILE* handle on success, NULL on failure
 */
FILE *bbs_mkftemp(char *template, mode_t mode);

/*!
 * \brief Efficiently copy part (or all) of a file between two file descriptors
 * \param srcfd File descriptor from which to copy
 * \param destfd Destination file descriptor
 * \param start Offset from start, in bytes, from which to start copying
 * \param bytes Number of bytes to copy, starting from start
 * \retval -1 on failure, number of bytes copied on success
 * \note srcfd and destfd are closed by this function, regardless of outcome
 */
int bbs_copy_file(int srcfd, int destfd, int start, int bytes); /* gcc has fd_arg attributes, but not widely supported yet */

/*!
 * \brief Load the contents of a file into a string
 * \param filename Full path to file
 * \param maxsize Maximum file size to load into a string (for safety reasons, to avoid allocating enormous amounts of memory). 0 for no limit.
 * \param[out] length The length of the output string, not including the NUL terminator
 * \returns string on success, NULL on failure
 */
char *bbs_file_to_string(const char *filename, size_t maxsize, int *length);

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
int bbs_time_friendly(int epoch, char *buf, size_t len);

/*!
 * \brief Print time elapsed e.g. 0:33:21
 * \param start
 * \param end End time. 0 to automatically call time(NULL) for current time.
 *             If you call multiple related functions at the same time, doing this yourself
 *             and passing it will be more efficient, avoiding duplicate calls to time().
 * \param buf Buffer.
 * \param len Size of buffer. Minimum 12 recommended.
 */
void print_time_elapsed(int start, int end, char *buf, size_t len);

/*!
 * \brief Print days elapsed e.g. (0 days, 0 hrs, 33 mins, 21 secs)
 * \param start
 * \param end End time. 0 to automatically call time(NULL) for current time.
 *             If you call multiple related functions at the same time, doing this yourself
 *             and passing it will be more efficient, avoiding duplicate calls to time().
 * \param buf Buffer.
 * \param len Size of buffer. Minimum 36 recommended.
 */
void print_days_elapsed(int start, int end, char *buf, size_t len);

/*!
 * \brief Parse an RFC822/RFC2822 date (i.e. date from an email header)
 * \param s
 * \param[out] tm
 * \retval 0 on success, -1 on failure
 */
int bbs_parse_rfc822_date(const char *s, struct tm *tm);
