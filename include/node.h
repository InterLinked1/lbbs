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
 * \brief BBS node
 *
 */

#include "linkedlists.h" /* for RWLIST_ENTRY */
#include "keys.h" /* key definitions */
#include "io.h" /* for I/O transformations */

struct bbs_module;
struct bbs_user;
struct bbs_vars;
struct readline_data;
struct pollfd;
struct sockaddr_in;

#define ANSI_CURSOR_QUERY (1 << 0)
#define ANSI_CURSOR_SET (1 << 1)
#define ANSI_COLORS (1 << 2)
#define ANSI_CLEAR_LINE (1 << 3)
#define ANSI_CLEAR_SCREEN (1 << 4)
#define ANSI_UP_ONE_LINE (1 << 5)
#define ANSI_TERM_TITLE (1 << 6)

struct bbs_node {
	unsigned int id;			/*!< Node number, 1-indexed for user-friendliness */
	unsigned int lifetimeid;	/*!< Lifetime node number, 1-indexed */
	int sfd;					/*!< Node socket file descriptor */
	int fd;						/*!< Node "real" file descriptor */
	int rfd;					/*!< File descriptor for reading */
	int wfd;					/*!< File descriptor for writing */
	int amaster;				/*!< PTY master file descriptor */
	int slavefd;				/*!< PTY slave file descriptor */
	char slavename[84];			/*!< PTY slave name */
	int spyfd;					/*!< Sysop's STDOUT file descriptor */
	int spyfdin;				/*!< Sysop's STDIN file descriptor */
	struct bbs_io_transformations trans; /*!< I/O transformations */
	unsigned int rows;			/*!< Screen size: number of rows */
	unsigned int cols;			/*!< Screen size: number of columns */
	pthread_t thread;			/*!< Thread handling socket I/O */
	pthread_t ptythread;		/*!< Thread handling PTY master */
	struct bbs_module *module;	/*!< Module reference for socket/network driver module */
	struct bbs_module *doormod;	/*!< Module reference for current door being executed */
	const char *protname;		/*!< Socket driver protocol name */
	struct bbs_user *user;		/*!< Active user of a BBS node */
	struct bbs_vars *vars;		/*!< Variables */
	const char *menu;			/*!< Current menu */
	const char *menuitem;		/*!< Currently executed menu item */
	int menustack;				/*!< Current menu stack level */
	char *term;					/*!< Terminal type (TERM) */
	char *ip;					/*!< Remote IP Address */
	unsigned short int rport;	/*!< Remote port number */
	unsigned short int port;	/*!< Local port number */
	bbs_mutex_t lock;		/*!< Node lock */
	bbs_mutex_t ptylock;	/*!< Node PTY lock */
	time_t created;				/*!< Creation time */
	pid_t childpid;				/*!< Child PID of process node is currently exec'ing (0 if none) */
	size_t slow_bytes_left;		/*!< Number of bytes left */
	long int calcbps;			/*!< Calculated terminal speed (from measurements) */
	unsigned int reportedbps;	/*!< Reported terminal speed (by client) */
	unsigned int bps;			/*!< Emulated terminal speed */
	unsigned int speed;			/*!< Pause time for emulated terminal speed, in us */
	/* Node flags */
	unsigned int active:1;		/*!< Active or not */
	unsigned int buffered:1;	/*!< TTY currently buffered */
	unsigned int echo:1;		/*!< TTY echo enabled */
	unsigned int interrupt:1;	/*!< Interrupt request active */
	unsigned int interruptack:1;/*!< Interrupt request acknowledged by interrupted function */
	unsigned int spy:1;			/*!< Target of active node spy */
	unsigned int skipjoin:1;	/*!< If node_shutdown should not join the node thread */
	unsigned int inmenu:1;		/*!< Whether actively displaying a menu */
	unsigned int slow:1;		/*!< Terminal is using slow connection */
	unsigned int nonagle:1;		/*!< Nagle's algorithm disabled */
	unsigned int dimensions:1;	/*!< Aware of actual terminal dimensions */
	unsigned int ansi:1;		/*!< Terminal supports ANSI escape sequences */
	unsigned int secure:1;		/*!< Connection encrypted using TLS */
	int ans;					/*!< Detailed ANSI support flags */
	/* TDD stuff */
	char ioreplace[10][2];		/*!< Character replacement for TDDs and other keyboard input-limited endpoints. 2D list with 10 slots. */
	unsigned int ioreplaces;	/*!< Number of characters currently being replaced. Purely for speed of access in pty.c */
	/* Next entry */
	RWLIST_ENTRY(bbs_node) entry;
};

/*! \brief Node is running an interactive terminal protocol */
#define NODE_INTERACTIVE(node) (node->amaster != -1)

/*! \brief Node is interactive and has an active pseudoterminal */
#define NODE_HAS_PTY(node) (node->slavefd != -1)

/*!
 * \brief Number of columns on a TDD's screen
 * \note Yes, I counted on mine
 */
#define NUM_TDD_COLS 20

/*!
 * \brief Whether, based on terminal dimensions, the node is a TDD
 *        (telecommunications device for the deaf),
 *        also sometimes but less correctly known as a TTY
 * \note This macro is mainly used when choosing whether to print more or less "stuff".
 *       For example, colors and other escape sequences aren't useful for TDDs.
 *       Additionally, shorter output is often desired for TDDs due to their limited
 *       screen size and the slow data rate (45.45 or 50 bps) of the connection.
 */
#define NODE_IS_TDD(node) (node->rows == 1 && node->cols == NUM_TDD_COLS)

/*! \brief Whether guest login is allowed */
int bbs_guest_login_allowed(void);

/*!
 * \brief Load node settings
 * \retval 0 on success, -1 on failure
 */
int bbs_load_nodes(void);

/*!
 * \brief Get number of allocated nodes
 * \retval Number of nodes
 */
unsigned int bbs_node_count(void);

/*!
 * \brief Get number of allocated nodes currently using a certain module
 * \param mod Module reference
 * \retval Number of current nodes created by or using mod
 * \note Works for nets and doors only
 */
unsigned int bbs_node_mod_count(void *mod);

/*!
 * \brief Get number of allocated nodes connected from a certain IP address
 * \param sinaddr
 * \retval Number of current nodes connected from specified IP address
 */
unsigned int bbs_node_ip_count(struct sockaddr_in *sinaddr);

/*!
 * \brief Get the highest-numbered node's number
 * \retval 0 if no nodes, positive node number otherwise
 */
unsigned int bbs_max_nodenum(void);

/*! \brief Get the configured minimum uptime to display */
unsigned int bbs_min_uptime_threshold(void);

/*!
 * \brief Get the configured idle timeout in ms
 * \note Certain scenarios warrant using a custom or specified value,
 *       but for screens where a user may be expected to idle,
 *       it is preferable to use this value.
 */
unsigned int bbs_idle_ms(void);

/*!
 * \brief Get the maximum number of nodes allowed
 * \retval non-negative max nodes allowed
 */
unsigned int bbs_maxnodes(void);

/*!
 * \brief Get the maximum number of nodes allowed to connect per IP address
 * \retval non-negative max nodes allowed
 */
unsigned int bbs_maxnodes_per_ip(void);

/*! \brief Get configured BBS hostname */
const char *bbs_hostname(void);

/*! \brief Get configured BBS name */
const char *bbs_name(void);

/*! \brief Get configured BBS tagline */
const char *bbs_tagline(void);

/*! \brief Get configured BBS sysop */
const char *bbs_sysop(void);

/*!
 * \brief Used by network comm drivers to request a BBS node
 * \param fd Socket file descriptor
 * \param protname Protocol name
 * \param[in] sinaddr Internet address structure for TCP/UDP connections, NULL for UNIX (non-IP) connections
 * \param sfd Override for socket file descriptor (currently only used by net_ssh). -1 for no override.
 * \param mod Module reference
 * \retval Node on success, NULL on failure
 */
struct bbs_node *__bbs_node_request(int fd, const char *protname, struct sockaddr_in *restrict sinaddr, int sfd, void *mod) __attribute__ ((nonnull (2, 5)));

/*!
 * \brief Used by network comm drivers to request a BBS node
 * \param fd Socket file descriptor
 * \param protname Protocol name
 * \param[in] sinaddr Internet address structure for TCP/UDP connections, NULL for UNIX (non-IP) connections
 * \param sfd Override for socket file descriptor (currently only used by net_ssh). -1 for no override.
 * \retval Node on success, NULL on failure
 */
#define bbs_node_request(fd, protname, sinaddr, sfd) __bbs_node_request(fd, protname, sinaddr, sfd, BBS_MODULE_SELF)

/*! Lock a BBS node */
int bbs_node_lock(struct bbs_node *node);

/*!
 * \brief Try locking a BBS node
 * \retval 0 if successful, -1 if failed to acquire lock
 */
int __attribute__ ((warn_unused_result)) bbs_node_trylock(struct bbs_node *node);

/*! Unlock a BBS node */
int bbs_node_unlock(struct bbs_node *node);

/*! Lock a BBS node for PTY operations */
int bbs_node_pty_lock(struct bbs_node *node);

/*! Unlock a BBS node for PTY operations */
int bbs_node_pty_unlock(struct bbs_node *node);

/*!
 * \brief Translate input characters from a node
 * \param node
 * \param c Input character
 * \retval New input character
 */
char bbs_node_input_translate(struct bbs_node *node, char c);

/*!
 * \brief Add a character to a node's input replacement table
 * \param node
 * \param in Input character
 * \param out Character to which in should be translated
 * \retval 0 on success, -1 on failure
 */
int bbs_node_input_replace(struct bbs_node *node, char in, char out);

/*!
 * \brief Remove a character from a node's input replacement table
 * \param node
 * \param in Character that was being replaced
 * \retval 0 on success, -1 on failure
 */
int bbs_node_input_unreplace(struct bbs_node *node, char in);

/*!
 * \brief Suspend execution of a node. This is a safe alternative to usleep for anything more than a few dozen ms.
 * \param node
 * \param ms Milliseconds for which to sleep.
 * \return Same as bbs_poll
 */
int bbs_node_safe_sleep(struct bbs_node *node, int ms);

/*!
 * \brief Kill the child process associated with a node
 * \param node
 * \retval 0 on success, -1 on failure
 */
int bbs_node_kill_child(struct bbs_node *node);

/*!
 * \brief Log out of a node
 * \param node
 * \retval 0 on success, -1 on failure
*/
int bbs_node_logout(struct bbs_node *node);

/*!
 * \brief Remove and free a BBS node
 * \param node Node to unlink
 * \note This should only be called by the node handling thread itself
 * \retval 0 on success, -1 on failure
 */
int bbs_node_unlink(struct bbs_node *node);

/*!
 * \brief Request a shutdown on a specific BBS node
 * \param nodenum Number (ID) of node to shut down
 * \retval 0 on success, -1 on failure
 */
int bbs_node_shutdown_node(unsigned int nodenum);

/*!
 * \brief Request any nodes using a particular module be kicked from that module
 * \param mod Module reference
 * \note For nets, this will kick the module. For doors, it will interrupt the node to force it to exit the door.
 * \return Number of nodes kicked from this module
 */
unsigned int bbs_node_shutdown_mod(void *mod);

/*!
 * \brief Shut down and cleanup any active nodes
 * \param shutdown 1 if BBS is shutting down and new node requests should be denied, 0 to simply kick all currently active nodes
 */
int bbs_node_shutdown_all(int shutdown);

/*!
 * \brief Asynchronously interrupt a blocking system call on a BBS node
 * \param nodenum Number of node to interrupt
 * \retval 0 on success, -1 if node does not exist or cannot be interrupted, 1 on failure to interrupt
 * \note This function must not be called from a node's own thread.
 * \note This function only works for nodes with a PTY.
 */
int bbs_interrupt_node(unsigned int nodenum);

/*!
 * \brief Whether or not this node was interrupted by another thread
 * \param node
 * \note This function may only be called frm a node's own thread.
 * \retval 1 if interrupted, 0 if not interrupted
 */
int bbs_node_interrupted(struct bbs_node *node);

/*!
 * \brief Wait for an interrupted node to acknowledge and clear the interrupt
 * \param node
 * \param ms If positive, maximum number of milliseconds to wait
 * \retval 1 if interrupt cleared, 0 if timer expired (like poll)
 * \note May be called in any thread, as long as node is guaranteed to remain a valid reference
 *       for the duration of this function (e.g. owning thread owns the node or holds a global node list lock)
 */
int bbs_node_interrupt_wait(struct bbs_node *node, int ms);

/*!
 * \brief Clear the interrupt status for a node
 * \param node
 */
void bbs_node_interrupt_clear(struct bbs_node *node);

/*!
 * \brief Acknowledge an interrupt system call
 * \param node
 * \note Must only be called from a node's own thread
 */
#define bbs_node_interrupt_ack(node) __bbs_node_interrupt_ack(node, __FILE__, __LINE__, __func__)

void __bbs_node_interrupt_ack(struct bbs_node *node, const char *file, int line, const char *func);

/*!
 * \brief Check whether a user is active on any nodes
 * \param userid User ID of user to check for activity
 * \retval 1 if user is online (logged into at least one node), 0 otherwise
 */
int bbs_user_online(unsigned int userid);

/*!
 * \brief Retrieve a node by node number
 * \param nodenum Node number
 * \note If a node is returned, it is returned locked and must be unlocked by the caller.
 *       This is because nodes are not refcounted, and this prevents a node from being
 *       destroyed while it is still being used by an arbitrary caller.
 * \retval node on success, NULL if no such node
 */
struct bbs_node *bbs_node_get(unsigned int nodenum);

/*!
 * \brief Set screen size of a BBS node's terminal
 * \param node
 * \param cols Number of columns
 * \param rows Number of rows
 * \retval 0 on success, -1 on failure.
 */
int bbs_node_update_winsize(struct bbs_node *node, int cols, int rows);

/*!
 * \brief Get the effective speed of a node, useful for synchronization or pacing
 * \param node
 * \retval 0 if high-speed
 * \return nonzero if bounded by some measure
 */
unsigned int bbs_node_speed(struct bbs_node *node);

/*!
 * \brief Set emulated output speed for BBS node
 * \param node
 * \param bps Bits per second (e.g. 110, 300, 1200, 2400, 4800). Specify 0 to disable emulated speed (i.e. normal max speed)
 * \retval 0 on success, -1 on failure.
 */
int bbs_node_set_speed(struct bbs_node *node, unsigned int bps);

#define NODE_SPEED_BUFSIZ_SMALL 6
#define NODE_SPEED_BUFSIZ_LARGE 10

/*!
 * \brief Create a friendly representation of the node speed
 * \param node
 * \param buf
 * \param len Size of buf, which should be NODE_SPEED_BUFSIZ_SMALL or NODE_SPEED_BUFSIZ_LARGE.
 * \retval -1 if speed is <= 0
 * \retval 0 if speed is > 0 and <= 64kbps
 * \retval 1 if speed is > 64kbps
 */
int bbs_node_format_speed(struct bbs_node *node, char *restrict buf, size_t len);

/*!
 * \brief Display status of all nodes
 * \param node
 * \param username Optional username filter. If NULL, all nodes will be included, otherwise only those logged in as the specified user.
 */
int bbs_node_statuses(struct bbs_node *node, const char *username);

/*!
 * \brief wrapper around poll()
 * \param fd
 * \param ms -1 to wait forever, 0 for nonblocking, positive number of ms for timed poll
 * \retval Same as poll()
 */
int bbs_poll(int fd, int ms);

/*!
 * \brief wrapper around poll() for multiple file descriptors
 * \param pfds File descriptors to monitor
 * \param numfds Number of file descriptors
 * \param ms -1 to wait forever, 0 for nonblocking, positive number of ms for timed poll
 * \retval -1 on error, 0 if no activity
 * \retval positive (1-indexed) number of file descriptor with activity
 */
int bbs_multi_poll(struct pollfd *pfds, int numfds, int ms);

/*!
 * \brief wrapper around poll() for BBS node and other file descriptors
 * \param node
 * \param ms -1 to wait forever, 0 for nonblocking, positive number of ms for timed poll
 * \param fd Another file descriptor to poll
 * \retval The 1-indexed file descriptor with activity. i.e. if the node has activity, it will return 1; if fd has activity, it will return 2.
 */
int bbs_node_poll2(struct bbs_node *node, int ms, int fd);

/*!
 * \brief wrapper around poll() for BBS node
 * \param node
 * \param ms -1 to wait forever, 0 for nonblocking, positive number of ms for timed poll
 * \retval Same as poll()
 */
int bbs_node_poll(struct bbs_node *node, int ms);

/*! \brief Same as bbs_node_poll, but print notice if poll times out */
int bbs_node_tpoll(struct bbs_node *node, int ms);

/*!
 * \brief wrapper around read() for BBS node
 * \param node
 * \param buf Buffer for data
 * \param len Size of buf
 * \retval Same as read() i.e. 0 if fd closed, -1 on failure, positive number of bytes read otherwise
 */
ssize_t bbs_node_read(struct bbs_node *node, char *buf, size_t len);

/*!
 * \brief wrapper around poll() and read() for BBS node
 * \param node
 * \param ms for poll
 * \param buf Buffer for data
 * \param len Size of buf
 * \retval Same as poll() and read(), except -1 is returned if read returns 0
 */
ssize_t bbs_node_poll_read(struct bbs_node *node, int ms, char *buf, size_t len);

/*!
 * \brief wrapper around poll() and read()
 * \param fd
 * \param ms for poll
 * \param buf Buffer for data
 * \param len Size of buf
 * \retval Same as poll() and read(), except -1 is returned if read returns 0
 */
ssize_t bbs_poll_read(int fd, int ms, char *buf, size_t len);

/*!
 * \brief wrapper around bbs_poll_read that expects a substring to appear in the read response
 * \param fd
 * \param ms for poll
 * \param buf Buffer for data
 * \param len Size of buf
 * \param str String that should appear (checked using strstr)
 * \retval -1 on error, 0 if found, 1 if got a response that didn't contain str
 * \warning This function will not wait for a full line of input if less is read initially. Use bbs_expect_line if you need stronger guarantees.
 */
int bbs_expect(int fd, int ms, char *buf, size_t len, const char *str);

/*!
 * \brief wrapper around bbs_poll_read that expects a substring to appear in the read response
 * \param fd
 * \param ms for poll
 * \param rldata A readline data structure
 * \param str String that should appear (checked using strstr)
 * \retval -1 on error, 0 if found, 1 if got a response that didn't contain str
 */
int bbs_expect_line(int fd, int ms, struct readline_data *rldata, const char *str);

/*!
 * \brief wrapper around poll() and read() for BBS node
 * \param node
 * \param ms for poll
 * \note This is useful for reading a single character (in non-canonical mode) with no delay
 * \retval 0 if fd closed, -1 on failure, non-negative character read otherwise
 */
char bbs_node_tread(struct bbs_node *node, int ms);

/*! * \brief Same as bbs_node_read_escseq, but directly on a file descriptor, rather than a node */
int bbs_read_escseq(int fd);

/*!
 * \brief Read an escape sequence, after the key 27 (ESCAPE) is read
 * \param node
 * \retval -1 node disconnected
 * \retval 0 ESC (just the ESC key, no escape sequence)
 * \retval positive escape sequence code
 */
int bbs_node_read_escseq(struct bbs_node *node);

/*!
 * \brief Read a line of input from a BBS node
 * \param node
 * \param ms Timeout, in ms. This applies to each character, not the total read time.
 *           However, if the TTY is in canonical mode, then it will effectively apply to the entire read.
 * \param buf Buffer for data
 * \param len Size of buf
 * \retval Same as poll() and/or read(), depending on which function is called last.
 * \note This function will null terminate a CR or LF received. However, this will not change the return value.
 *       This means this function may return a value larger than the length of the string in the buffer,
 *       and the return value MUST NOT BE USED to deduce the length of the string in the buffer.
 */
int bbs_node_readline(struct bbs_node *node, int ms, char *buf, size_t len);

/*!
 * \brief Solicit a response to a question, retrying if necessary
 * \param node
 * \param qlen Format length of q (left aligned). If 0, will not be length-formatted.
 * \param q Question string. Should not contain a newline.
 * \param pollms Response timeout for entire response
 * \param buf Buffer in which to store response
 * \param len Length of buf
 * \param tries Pointer to number of tries remaining
 * \param minlen Minimum length required of response
 * \param reqchars String of characters that must each appear in the response
 * \note This function should only be used in canonical mode
 * \retval -1 on disconnect, 0 on success, 1 if max attempts exceeded
 */
int bbs_get_response(struct bbs_node *node, int qlen, const char *q, int pollms, char *buf, int len, int *tries, int minlen, const char *reqchars);

/*!
 * \brief Flush (discard) all input (typically used prior to bbs_node_poll so it doesn't return immediately due to backlogged input)
 * \param fd
 * \retval Same as read()
 * \warning Use this function judiciously. Input should be handled properly if feasible, avoid this function if possible.
 */
int bbs_flush_input(int fd);

/*!
 * \brief Flush (discard) all input (typically used prior to bbs_node_poll so it doesn't return immediately due to backlogged input)
 * \param node
 * \retval Same as read()
 * \warning Use this function judiciously. Input should be handled properly if feasible, avoid this function if possible.
 */
int bbs_node_flush_input(struct bbs_node *node);

/*!
 * \brief wrapper around write() for BBS node. Unlike write, this will write the whole buffer before returning.
 * \param node
 * \param buf Buffer of data to write
 * \param len Number of bytes to write
 * \retval Same as write()
 */
ssize_t bbs_node_write(struct bbs_node *node, const char *buf, size_t len);

/*!
 * \brief Same as bbs_node_write, but directly on a file descriptor
 * \note Do not use this function to write to file descriptors associated with a node (whether node->fd, node->slavefd, or any other node fd).
 *       Use bbs_node_fd_write instead. (Same thing for the formatted versions of both.)
 */
ssize_t bbs_write(int fd, const char *buf, size_t len);

/*!
 * \brief Read a specified amount of data from a file descriptor
 * \param fd File descriptor
 * \param[out] buf
 * \param len
 * \param ms Maximum time in ms to wait after each read call for further data
 * \retval Same as read
 */
ssize_t bbs_timed_read(int fd, char *restrict buf, size_t len, int ms);

/*!
 * \brief Write to a file descriptor without blocking
 * \param fd File descriptor
 * \param buf Buffer to write
 * \param len Length of buf
 * \param ms Maximum number of milliseconds to wait before aborting
 * \return Number of bytes written to out_fd
 * \retval -1 on failure
 */
ssize_t bbs_timed_write(int fd, const char *buf, size_t len, int ms);

/*!
 * \brief Wrapper around sendfile(2) that attempts to fully copy the requested number of bytes
 * \param out_fd File descriptor open for writing. May be any file (kernels >= 2.6.33)
 * \param in_fd File descriptor open for reading. Must support mmap(2)-like operations (i.e. cannot be a socket).
 *               If offset is NULL, offset of in_fd is adjusted to reflect number of bytes read.
 * \param offset If non-NULL, offset from which to begin reading; upon return, will be the offset of the first unread byte.
 *               If NULL, read starting at the offset of in_fd and update the file's offset.
 * \param count Number of bytes to copy from in_fd to out_fd.
 * \return Number of bytes written to out_fd
 * \retval -1 on failure
 */
ssize_t bbs_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);

/*!
 * \brief Write to a file descriptor associated with a node (but not necessarily the node file descriptor)
 * \param node Node associated with this file descriptor
 * \param fd File descriptor to which to write
 * \param buf Data to write
 * \param len Length of buf
 * \retval Same as write()
 * \note This function may only be used by the thread handling a node
 * \note This function provides its own concurrency control. Callers should not hold any locks when calling this function.
 */
ssize_t bbs_node_fd_write(struct bbs_node *node, int fd, const char *buf, size_t len) __attribute__ ((nonnull (1)));

/*!
 * \brief Write formatted data to a file descriptor associated with a node (but not necessarily the node file descriptor)
 * \param node Node associated with this file descriptor
 * \param fd File descriptor to which to write
 * \param fmt printf-style format string
 * \retval Same as write()
 * \note This function may only be used by the thread handling a node
 * \note This function provides its own concurrency control. Callers should not hold any locks when calling this function.
 */
ssize_t __attribute__ ((format (gnu_printf, 3, 4))) bbs_node_fd_writef(struct bbs_node *node, int fd, const char *fmt, ...) __attribute__ ((nonnull (1)));

/*!
 * \brief Similar to bbs_node_fd_writef, but node may be NULL (in which case bbs_writef is used automatically)
 * \note This is a convenience wrapper. Use bbs_write (node is always NULL) or bbs_node_fd_write (node is never NULL) directly if appropriate.
 */
ssize_t __attribute__ ((format (gnu_printf, 3, 4))) bbs_auto_fd_writef(struct bbs_node *node, int fd, const char *fmt, ...);

/*!
 * \brief Hybrid between bbs_auto_fd_writef and bbs_node_any_fd_write. Use ONLY when writing to either a node not owned by the current thread or a file descriptor not associated with a node.
 *        This is the most lenient high-level bbs_write I/O function that exists, since it tolerates both a NULL node and writing to a node owned by a different thread.
 * \param node Node associated with this file descriptor. May be NULL.
 * \param fd File descriptor to which to write
 * \param fmt printf-style format string
 * \retval Same as write()
 * \note Usage: If node is never NULL, use bbs_node_any_fd_write instead. If node always belongs to the current thread, use bbs_auto_fd_writef.
 */
ssize_t __attribute__ ((format (gnu_printf, 3, 4))) bbs_auto_any_fd_writef(struct bbs_node *node, int fd, const char *fmt, ...);

/*!
 * \brief Write to a file descriptor associated with a node (but not necessarily the node file descriptor)
 * \param node Node associated with this file descriptor
 * \param fd File descriptor to which to write
 * \param buf Data to write
 * \param len Length of buf
 * \retval Same as write()
 * \note Unlike bbs_write, this does not guarantee the buffer will be fully written before returning.
 *       Applications SHOULD use bbs_node_fd_write instead of this function when writing from the node thread.
 */
ssize_t bbs_node_any_fd_write(struct bbs_node *node, int fd, const char *buf, size_t len) __attribute__ ((nonnull (1)));

/*!
 * \brief Write formatted data to a file descriptor associated with a node (but not necessarily the node file descriptor)
 * \param node Node associated with this file descriptor
 * \param fd File descriptor to which to write
 * \param fmt printf-style format string
 * \retval Same as write()
 * \note Unlike bbs_write, this does not guarantee the buffer will be fully written before returning.
 *       Applications SHOULD use bbs_node_fd_write instead of this function when writing from the node thread.
 */
ssize_t __attribute__ ((format (gnu_printf, 3, 4))) bbs_node_any_fd_writef(struct bbs_node *node, int fd, const char *fmt, ...) __attribute__ ((nonnull (1)));

/*!
 * \brief Write data to an arbitrary node
 * \param node
 * \param buf Data to write
 * \param len Length of bfu
 * \retval Same as write()
 * \note Unlike bbs_write, this does not guarantee the buffer will be fully written before returning.
 *       Applications SHOULD use bbs_node_write instead of this function when writing from the node thread.
 */
#define bbs_node_any_write(node, fmt, ...) bbs_node_any_fd_writef(node, node->slavefd, fmt, ## __VA_ARGS__)

/*!
 * \brief Write formatted data to an arbitrary node
 * \param node
 * \param fmt printf-style format string
 * \retval Same as write()
 * \note Unlike bbs_write, this does not guarantee the buffer will be fully written before returning.
 *       Applications SHOULD use bbs_node_writef instead of this function when writing from the node thread.
 */
#define bbs_node_any_writef(node, fmt, ...) bbs_node_any_fd_writef(node, node->slavefd, fmt, ## __VA_ARGS__)

/*!
 * \brief printf-style wrapper for bbs_node_write.
 * \param node
 * \param fmt printf-format string
 * \retval Same as write()
 */
ssize_t bbs_node_writef(struct bbs_node *node, const char *fmt, ...) __attribute__ ((format (gnu_printf, 2, 3))) __attribute__ ((nonnull (1)));

/*!
 * \brief Same as bbs_node_writef, but directly on a file descriptor
 * \note This is not exactly the same thing as a function like dprintf, since it returns the value returned by write()
 */
ssize_t bbs_writef(int fd, const char *fmt, ...) __attribute__ ((format (gnu_printf, 2, 3)));

/*!
 * \brief Clear the terminal screen on a node's connected TTY
 * \param node
 * \retval -1 on failure, 0 on success
 */
int bbs_node_clear_screen(struct bbs_node *node);

/*!
 * \brief Clear the current line on a node's connected TTY
 * \param node
 * \retval -1 on failure, 0 on success
 */
int bbs_node_clear_line(struct bbs_node *node);

/*!
 * \brief Query the current cursor position of a node's terminal
 * \param node, which must be unbuffered for this operation
 * \param[out] row 1-indexed row position
 * \param[out] col 1-indexed col position
 * \retval -1 on node disconnect, 0 if failed to get cursor position, positive on success
 */
int node_get_cursor_pos(struct bbs_node *node, int *restrict row, int *restrict col);

/*!
 * \brief Set the cursor position of a node's TTY explicitly
 * \param node
 * \param row (1-indexed)
 * \param col (1-indexed)
 * \retval -1 on failure, 0 on success
 */
int bbs_node_set_pos(struct bbs_node *node, int row, int col);

/*!
 * \brief Go up one line on the node's connected TTY
 * \param node
 * \retval -1 on failure, 0 on success
 */
int bbs_node_up_one_line(struct bbs_node *node);

/*!
 * \brief Set the terminal title
 * \param node
 * \param s Title text. This is what will show up in the terminal emulator's window title, taskbar, etc.
 * \retval -1 on failure, 0 on success
 */
int bbs_node_set_term_title(struct bbs_node *node, const char *s);

/*!
 * \brief Restore the previous terminal title
 * \param node
 * \retval -1 on failure, 0 on success
 */
int bbs_node_restore_term_title(struct bbs_node *node);

/*!
 * \brief Set the terminal icon
 * \param node
 * \param s Icon text
 * \retval -1 on failure, 0 on success
 */
int bbs_node_set_term_icon(struct bbs_node *node, const char *s);

/*!
 * \brief Reset color to normal on a node's connected TTY
 * \param node
 * \retval -1 on failure, 0 on success
 */
int bbs_node_reset_color(struct bbs_node *node);

/*!
 * \brief Draw a line of a specified character across the screen
 * \param node
 * \param c Character to repeat all the way across the screen
 * \retval -1 on failure, 0 on success
 */
int bbs_node_draw_line(struct bbs_node *node, char c);

/*!
 * \brief Trigger bell / alert sound on a node's connected TTY
 * \param node
 * \retval -1 on failure, 0 on success
 */
int bbs_node_ring_bell(struct bbs_node *node);

/*!
 * \brief Wait for user to hit a key (any key)
 * \param node
 * \param ms Timeout in milliseconds
 * \retval 0 on success, -1 on failure
 */
int bbs_node_wait_key(struct bbs_node *node, int ms);

/*! \brief Begin handling a node
 * \note Not needed if you use bbs_node_handler
 */
void bbs_node_begin(struct bbs_node *node);

/*! \brief Begin handling a node from a network protocol
 * \note Only intended for network protocols that don't use psuedoterminals
 */
void bbs_node_net_begin(struct bbs_node *node);

/*!
 * \brief Start TLS on a node, splitting node->fd into node->rfd and node->wfd for TLS I/O
 * \param node
 * \retval 0 on success, -1 on failure, 1 if TLS not available
 */
int bbs_node_starttls(struct bbs_node *node);

/*! \brief Stop handling a node
 * \note Not needed if you use bbs_node_handler
 * \note After calling this function, node will no longer be a valid reference
 */
void bbs_node_exit(struct bbs_node *node) __attribute__ ((nonnull (1)));

/*!
 * \brief Top-level node handler for terminal protocols
 * \param varg BBS node
 */
void *bbs_node_handler(void *varg);
