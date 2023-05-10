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

#include <pthread.h>

#include "linkedlists.h" /* for RWLIST_ENTRY */
#include "keys.h" /* key definitions */

struct bbs_module;
struct bbs_user;
struct bbs_vars;
struct readline_data;
struct pollfd;

struct bbs_node {
	unsigned int id;			/*!< Node number, 1-indexed for user-friendliness */
	int fd;						/*!< Socket file descriptor */
	int rfd;					/*!< File descriptor for reading */
	int wfd;					/*!< File descriptor for writing */
	int amaster;				/*!< PTY master file descriptor */
	int slavefd;				/*!< PTY slave file descriptor */
	char slavename[84];			/*!< PTY slave name */
	int spyfd;					/*!< Sysop's STDOUT file descriptor */
	int spyfdin;				/*!< Sysop's STDIN file descriptor */
	unsigned int rows;			/*!< Screen size: number of rows */
	unsigned int cols;			/*!< Screen size: number of columns */
	pthread_t thread;			/*!< Thread handling socket I/O */
	pthread_t ptythread;		/*!< Thread handling PTY master */
	struct bbs_module *module;	/*!< Module reference for socket/network driver module */
	const char *protname;		/*!< Socket driver protocol name */
	struct bbs_user *user;		/*!< Active user of a BBS node */
	struct bbs_vars *vars;		/*!< Variables */
	const char *menu;			/*!< Current menu */
	const char *menuitem;		/*!< Currently executed menu item */
	int menustack;				/*!< Current menu stack level */
	char *ip;					/*!< IP Address */
	pthread_mutex_t lock;		/*!< Node lock */
	pthread_mutex_t ptylock;	/*!< Node PTY lock */
	int created;				/*!< Creation time */
	pid_t childpid;				/*!< Child PID of process node is currently exec'ing (0 if none) */
	unsigned int bps;			/*!< Emulated terminal speed */
	unsigned int speed;			/*!< Pause time for emulated terminal speed, in us */
	/* Node flags */
	unsigned int active:1;		/*!< Active or not */
	unsigned int buffered:1;	/*!< TTY currently buffered */
	unsigned int echo:1;		/*!< TTY echo enabled */
	unsigned int spy:1;			/*!< Target of active node spy */
	unsigned int skipjoin:1;	/*!< If node_shutdown should not join the node thread */
	unsigned int inmenu:1;		/*!< Whether actively displaying a menu */
	unsigned int ansi:1;		/*!< Terminal supports ANSI escape sequences */
	/* TDD stuff */
	char ioreplace[10][2];		/*!< Character replacement for TDDs and other keyboard input-limited endpoints. 2D list with 10 slots. */
	unsigned int ioreplaces;	/*!< Number of characters currently being replaced. Purely for speed of access in pty.c */
	/* Next entry */
	RWLIST_ENTRY(bbs_node) entry;
};

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
 * \brief Get number of allocated nodes created by a certain module
 * \param mod Module reference
 * \retval Number of current nodes created by mod
 */
unsigned int bbs_node_mod_count(void *mod);

/*!
 * \brief Get the highest-numbered node's number
 * \retval 0 if no nodes, positive node number otherwise
 */
unsigned int bbs_max_nodenum(void);

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

/*! \brief Get configured BBS hostname */
const char *bbs_hostname(void);

/*! \brief Get configured BBS name */
const char *bbs_name(void);

/*!
 * \brief Used by network comm drivers to request a BBS node
 * \param fd Socket file descriptor
 * \param protname Protocol name
 * \param mod Module reference
 * \retval Node on success, NULL on failure
 */
struct bbs_node *__bbs_node_request(int fd, const char *protname, void *mod);

/*!
 * \brief Used by network comm drivers to request a BBS node
 * \param fd Socket file descriptor
 * \param protname Protocol name
 * \retval Node on success, NULL on failure
 */
#define bbs_node_request(fd, protname) __bbs_node_request(fd, protname, BBS_MODULE_SELF)

/*! Lock a BBS node */
int bbs_node_lock(struct bbs_node *node);

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
 * \brief Request a shut down of all nodes created using a particular module
 * \param mod Module reference
 * \return Number of nodes kicked
 */
unsigned int bbs_node_shutdown_mod(void *mod);

/*!
 * \brief Shut down and cleanup any active nodes
 * \param shutdown 1 if BBS is shutting down and new node requests should be denied, 0 to simply kick all currently active nodes
 */
int bbs_node_shutdown_all(int shutdown);

/*! \brief Print node list */
int bbs_nodes_print(int fd);

/*!
 * \brief Print information about a node
 * \param fd File descriptor to which to print info
 * \param nodenum Node number
 * \retval 0 (always)
 */
int bbs_node_info(int fd, unsigned int nodenum);

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
 * \brief Set emulated output speed for BBS node
 * \param node
 * \param bps Bits per second (e.g. 110, 300, 1200, 2400, 4800). Specify 0 to disable emulated speed (i.e. normal max speed)
 * \retval 0 on success, -1 on failure.
 */
int bbs_node_set_speed(struct bbs_node *node, unsigned int bps);

/*! \brief Display status of all nodes */
int bbs_node_statuses(struct bbs_node *node);

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
int bbs_node_read(struct bbs_node *node, char *buf, size_t len);

/*!
 * \brief wrapper around poll() and read() for BBS node
 * \param node
 * \param ms for poll
 * \param buf Buffer for data
 * \param len Size of buf
 * \retval Same as poll() and read()
 */
int bbs_node_poll_read(struct bbs_node *node, int ms, char *buf, size_t len);

/*!
 * \brief wrapper around poll() and read()
 * \param fd
 * \param ms for poll
 * \param buf Buffer for data
 * \param len Size of buf
 * \retval Same as poll() and read()
 */
int bbs_poll_read(int fd, int ms, char *buf, size_t len);

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
int bbs_node_write(struct bbs_node *node, const char *buf, unsigned int len);

/*! \brief Same as bbs_node_write, but directly on a file descriptor */
int bbs_write(int fd, const char *buf, unsigned int len);

/*!
 * \brief printf-style wrapper for bbs_node_write.
 * \param node
 * \param fmt printf-format string
 * \retval Same as write()
 */
int bbs_node_writef(struct bbs_node *node, const char *fmt, ...) __attribute__ ((format (gnu_printf, 2, 3))) ;

/*!
 * \brief Same as bbs_node_writef, but directly on a file descriptor
 * \note This is not exactly the same thing as a function like dprintf, since it returns the value returned by write()
 */
int bbs_writef(int fd, const char *fmt, ...) __attribute__ ((format (gnu_printf, 2, 3))) ;

/*!
 * \brief Clear the terminal screen on a node's connected TTY
 * \param node
 * \retval Same as write()
 */
int bbs_node_clear_screen(struct bbs_node *node);

/*!
 * \brief Clear the current line on a node's connected TTY
 * \param node
 * \retval Same as write()
 */
int bbs_node_clear_line(struct bbs_node *node);

/*!
 * \brief Set the terminal title
 * \param node
 * \param s Title text. This is what will show up in the terminal emulator's window title, taskbar, etc.
 * \retval Same as write()
 */
int bbs_node_set_term_title(struct bbs_node *node, const char *s);

/*!
 * \brief Set the terminal icon
 * \param node
 * \param s Icon text
 * \retval Same as write()
 */
int bbs_node_set_term_icon(struct bbs_node *node, const char *s);

/*!
 * \brief Reset color to normal on a node's connected TTY
 * \param node
 * \retval Same as write()
 */
int bbs_node_reset_color(struct bbs_node *node);

/*!
 * \brief Draw a line of a specified character across the screen
 * \param node
 * \param c Character to repeat all the way across the screen
 * \retval Same as write()
 */
int bbs_node_draw_line(struct bbs_node *node, char c);

/*!
 * \brief Trigger bell / alert sound on a node's connected TTY
 * \param node
 * \retval Same as write()
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

/*! \brief Stop handling a node
 * \note Not needed if you use bbs_node_handler
 */
void bbs_node_exit(struct bbs_node *node) __attribute__ ((nonnull (1))) ;

/*!
 * \brief Top-level node handler
 * \param varg BBS node
 */
void *bbs_node_handler(void *varg);
