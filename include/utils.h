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

/*! \brief Get thread ID of current thread */
int bbs_gettid(void);

int __bbs_pthread_join(pthread_t thread, void **retval, const char *file, const char *func, int line);
#define bbs_pthread_join(thread, retval) __bbs_pthread_join(thread, retval, __FILE__, __FUNCTION__, __LINE__)

int __bbs_pthread_create_detached(pthread_t *thread, pthread_attr_t *attr, void *(*start_routine)(void *), void *data, const char *file, const char *func, int line, const char *start_fn);

/*!
 * \brief Create a detached pthread
 * \retval 0 on success, -1 on failure
 */
#define bbs_pthread_create_detached(thread, attr, start_routine, data) __bbs_pthread_create_detached(thread, attr, start_routine, data, __FILE__, __FUNCTION__, __LINE__, #start_routine)

int __bbs_pthread_create_detached_killable(pthread_t *thread, pthread_attr_t *attr, void *(*start_routine)(void *), void *data, const char *file, const char *func, int line, const char *start_fn);

/*!
 * \brief Create a detached pthread that can be killed using bbs_thread_cleanup
 * \retval 0 on success, -1 on failure
 */
#define bbs_pthread_create_detached_killable(thread, attr, start_routine, data) __bbs_pthread_create_detached_killable(thread, attr, start_routine, data, __FILE__, __FUNCTION__, __LINE__, #start_routine)

int __bbs_pthread_create(pthread_t *thread, pthread_attr_t *attr, void *(*start_routine)(void *), void *data, const char *file, const char *func, int line, const char *start_fn);

/*!
 * \brief Create a non-detached pthread
 * \retval 0 on success, -1 on failure
 */
#define bbs_pthread_create(thread, attr, start_routine, data) __bbs_pthread_create(thread, attr, start_routine, data, __FILE__, __FUNCTION__, __LINE__, #start_routine)

/*!
 * \brief Kill detached threads that were created by this file that are marked as killable
 * \retval Number of threads killed
 */
#define bbs_thread_cancel_killable() __bbs_thread_cancel_killable(__FILE__)

int __bbs_thread_cancel_killable(const char *filename);

/*! \brief Destroy thread registrations (on shutdown) */
void bbs_thread_cleanup(void);

/*!
 * \brief Get the thread ID (LWP) of a registered thread
 * \param pid pthread_t handle
 * \retval -1 if thread not currently registered, LWP/thread ID otherwise
 */
int bbs_pthread_tid(pthread_t thread);

/*!
 * \brief Print list of active BBS threads
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
 * \param Port number on which to create the socket
 * \retval 0 on success, -1 on failure
 */
int bbs_make_tcp_socket(int *sock, int port);

/* Forward declarations */
struct bbs_node;
struct sockaddr_in;

/*!
 * \brief Wrapper around accept(), with poll timeout
 * \param socket Socket fd
 * \param ms poll time in ms
 * \param ip Optional IP restriction. NULL to allow any IP address.
 * \retval -1 on failure, socket file descriptor otherwise
 */
int bbs_timed_accept(int socket, int ms, const char *ip);

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

/*! \brief Get the name of a poll revent */
const char *poll_revent_name(int revents);

/*!
 * \brief Traverse all the files and directories in a directory, non-recursively
 * \param path Directory to traverse
 * \param bbs_file_on_file Callback function to execute for each file or directory. Should return 0 to continue iterating and non-zero to stop.
 * \param obj Argument to callback function
 * \param max_depth
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
 * \param bbs_file_on_file Callback function to execute for each file. Should return 0 to continue iterating and non-zero to stop.
 * \param obj Argument to callback function
 * \param max_depth
 * \retval 0 on success, -1 on failure
 * \note This function serves no useful functional purpose. It's mainly present to list directories recursively by watching the debug messages.
 */
int bbs_dir_traverse_dirs(const char *path, int (*on_file)(const char *dir_name, const char *filename, void *obj), void *obj, int max_depth);

/*!
 * \brief Create a temporary FILE*
 * \param template template ending in XXXXXX to pass to mkstemp
 * \param mode File mode for chmod
 * \returns FILE* handle on success, NULL on failure
 */
FILE *bbs_mkftemp(char *template, mode_t mode);

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
 * \param end. End time. 0 to automatically call time(NULL) for current time.
 *             If you call multiple related functions at the same time, doing this yourself
 *             and passing it will be more efficient, avoiding duplicate calls to time().
 * \param buf Buffer.
 * \param len Size of buffer. Minimum 12 recommended.
 */
void print_time_elapsed(int start, int end, char *buf, size_t len);

/*!
 * \brief Print days elapsed e.g. (0 days, 0 hrs, 33 mins, 21 secs)
 * \param start
 * \param end. End time. 0 to automatically call time(NULL) for current time.
 *             If you call multiple related functions at the same time, doing this yourself
 *             and passing it will be more efficient, avoiding duplicate calls to time().
 * \param buf Buffer.
 * \param len Size of buffer. Minimum 36 recommended.
 */
void print_days_elapsed(int start, int end, char *buf, size_t len);

/*!
 * \brief Get the printable length of a string (how many columns it would take up on a terminal)
 * \param s String
 * \returns Number of columns the string will occupy on a terminal
 * \warning This function cannot be accurate for all possible characters, e.g. TAB, whose number of cols occupied depends entirely on location on the terminal.
 */
int bbs_printable_strlen(const char *s);

/*!
 * \brief Process backspaces and deletes in a stream of characters and output the new result
 * \note Mainly needed because not all terminal emulators behave the same way, some like SyncTERM are more broken when it comes to backspace handling. PuTTY/KiTTY don't need this.
 * \param s Original input string
 * \param buf Output buffer
 * \param len Size of buf. Should be exactly as large as the original length of s, but larger is unnecessary
 * \retval 0 on success, -1 on failure (truncation)
 */
int bbs_str_process_backspaces(const char *s, char *buf, size_t len);

/*!
 * \brief Create a safely printable representation of a string (for debugging or dumping).
 *        The string created, when printed, will not contain any escape sequences or formatting.
 * \param s Original string (containing potentially "unsafe" characters, e.g. CR, LF, ESC, and other formatting or control chars)
 * \param buf Buffer
 * \param len Size of buf
 * \retval 0 on success, -1 on failure/truncation
 */
int bbs_str_safe_print(const char *s, char *buf, size_t len);

/*!
 * \brief Copy s into buf, except for any whitespace characters
 * \param s Original string
 * \param[out] buf
 * \param len Length of bug
 * \retval 0 on success, -1 on failure (truncation)
 */
int bbs_strcpy_nospaces(const char *s, char *buf, size_t len);

/*!
 * \brief Whether all characters in a string are printable (spaces are included)
 * \param s String to check
 * \retval 1 if yes, 0 if no
 */
int bbs_str_isprint(const char *s);

/*!
 * \brief Whether a string contains some non-space printable character
 * \param s String to check
 * \retval 1 if yes, 0 if no
 */
int bbs_str_anyprint(const char *s);
