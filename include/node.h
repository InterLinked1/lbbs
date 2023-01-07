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

struct bbs_node {
	unsigned int id;			/*!< Node number, 1-indexed for user-friendliness */
	int fd;						/*!< Socket file descriptor */
	int amaster;				/*!< PTY master file descriptor */
	int slavefd;				/*!< PTY slave file descriptor */
	char slavename[84];			/*!< PTY slave name */
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
	/* Next entry */
	RWLIST_ENTRY(bbs_node) entry;
};

/*! \brief Clear screen */
#define TERM_CLEAR "\e[1;1H\e[2J"

#define TERM_ERASE_LINE "\33[2K"

/*! \brief Clear and reset cursor to beginning of current line */
#define TERM_RESET_LINE TERM_ERASE_LINE "\r"

/*! \brief Ring the bell on the TTY/terminal */
#define TERM_BELL "\a"

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
 * \brief Get the highest-numbered node's number
 * \retval 0 if no nodes, positive node number otherwise
 */
unsigned int bbs_max_nodenum(void);

/*!
 * \brief Get the maximum number of nodes allowed
 * \retval non-negative max nodes allowed
 */
unsigned int bbs_maxnodes(void);

/*! \brief Get configured BBS hostname */
const char *bbs_hostname(void);

/*!
 * \brief Used by socket drivers to request a BBS node
 * \param fd Socket file descriptor
 * \param protname Protocol name
 * \param mod Module reference
 * \retval Node on success, NULL on failure
 */
struct bbs_node *__bbs_node_request(int fd, const char *protname, void *mod);

/*! Lock a BBS node */
int bbs_node_lock(struct bbs_node *node);

/*! Unlock a BBS node */
int bbs_node_unlock(struct bbs_node *node);

/*!
 * \brief Used by socket drivers to request a BBS node
 * \param fd Socket file descriptor
 * \param protname Protocol name
 * \retval Node on success, NULL on failure
 */
#define bbs_node_request(fd, protname) __bbs_node_request(fd, protname, BBS_MODULE_SELF) 

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

/*!
 * \brief wrapper around poll()
 * \param fd
 * \param ms -1 to wait forever, 0 for nonblocking, positive number of ms for timed poll
 * \retval Same as poll()
 */
int bbs_std_poll(int fd, int ms);

/*!
 * \brief wrapper around poll() for BBS node and other file descriptors
 * \param node
 * \param ms -1 to wait forever, 0 for nonblocking, positive number of ms for timed poll
 * \param fd Another file descriptor to poll
 * \retval The 1-indexed file descriptor with activity. i.e. if the node has activity, it will return 1; if fd has activity, it will return 2.
 */
int bbs_poll2(struct bbs_node *node, int ms, int fd);

/*!
 * \brief wrapper around poll() for BBS node
 * \param node
 * \param ms -1 to wait forever, 0 for nonblocking, positive number of ms for timed poll
 * \retval Same as poll()
 */
int bbs_poll(struct bbs_node *node, int ms);

/*! \brief Same as bbs_poll, but print notice if poll times out */
int bbs_tpoll(struct bbs_node *node, int ms);

/*!
 * \brief wrapper around read() for BBS node
 * \param node
 * \param buf Buffer for data
 * \param len Size of buf
 * \retval Same as read() i.e. 0 if fd closed, -1 on failure, positive number of bytes read otherwise
 */
int bbs_read(struct bbs_node *node, char *buf, size_t len);

/*!
 * \brief wrapper around poll() and read() for BBS node
 * \param node
 * \param ms for poll
 * \param buf Buffer for data
 * \param len Size of buf
 * \retval Same as poll() and read()
 */
int bbs_poll_read(struct bbs_node *node, int ms, char *buf, size_t len);

/*!
 * \brief wrapper around poll() and read()
 * \param fd
 * \param ms for poll
 * \param buf Buffer for data
 * \param len Size of buf
 * \retval Same as poll() and read()
 */
int bbs_fd_poll_read(int fd, int ms, char *buf, size_t len);

/*!
 * \brief wrapper around poll() and read() for BBS node
 * \param node
 * \param buf Buffer for data
 * \param len Size of buf
 * \note This is useful for reading a single character (in non-canonical mode) with no delay
 * \retval Same as read() i.e. 0 if fd closed, -1 on failure, non-negative character read otherwise
 */
char bbs_tread(struct bbs_node *node, int ms);

/*! * \brief Same as bbs_read_escseq, but directly on a file descriptor, rather than a node */
int bbs_fd_read_escseq(int fd);

/*!
 * \brief Read an escape sequence, after the key 27 (ESCAPE) is read
 * \param node
 * \retval -1 node disconnected
 * \retval 0 ESC (just the ESC key, no escape sequence)
 * \retval positive escape sequence code
 */
int bbs_read_escseq(struct bbs_node *node);

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
int bbs_readline(struct bbs_node *node, int ms, char *buf, size_t len);

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
 * \brief Flush (discard) all input (typically used prior to bbs_poll so it doesn't return immediately due to backlogged input)
 * \param fd
 * \retval Same as read()
 * \warning Use this function judiciously. Input should be handled properly if feasible, avoid this function if possible.
 */
int bbs_std_flush_input(int fd);

/*!
 * \brief Flush (discard) all input (typically used prior to bbs_poll so it doesn't return immediately due to backlogged input)
 * \param node
 * \retval Same as read()
 * \warning Use this function judiciously. Input should be handled properly if feasible, avoid this function if possible.
 */
int bbs_flush_input(struct bbs_node *node);

/*!
 * \brief wrapper around write() for BBS node. Unlike write, this will write the whole buffer before returning.
 * \param node
 * \param buf Buffer of data to write
 * \param len Number of bytes to write
 * \retval Same as write()
 */
int bbs_write(struct bbs_node *node, const char *buf, unsigned int len);

/*!
 * \brief printf-style wrapper for bbs_write.
 * \param node
 * \param fmt printf-format string
 * \retval Same as write()
 */
int __attribute__ ((format (gnu_printf, 2, 3))) bbs_writef(struct bbs_node *node, const char *fmt, ...);

/*!
 * \brief Clear the terminal screen on a node's connected TTY
 * \param node
 * \retval Same as write()
 */
int bbs_clear_screen(struct bbs_node *node);

/*!
 * \brief Clear the current line on a node's connected TTY
 * \param node
 * \retval Same as write()
 */
int bbs_clear_line(struct bbs_node *node);

/*!
 * \brief Reset color to normal on a node's connected TTY
 * \param node
 * \retval Same as write()
 */
int bbs_reset_color(struct bbs_node *node);

/*!
 * \brief Draw a line of a specified character across the screen
 * \param node
 * \param c Character to repeat all the way across the screen
 * \retval Same as write()
 */
int bbs_draw_line(struct bbs_node *node, char c);

/*!
 * \brief Trigger bell / alert sound on a node's connected TTY
 * \param node
 * \retval Same as write()
 */
int bbs_ring_bell(struct bbs_node *node);

/*!
 * \brief Wait for user to hit a key (any key)
 * \param node
 * \param Timeout in ms
 * \retval 0 on success, -1 on failure
 */
int bbs_wait_key(struct bbs_node *node, int ms);

/*!
 * \brief Top-level node handler
 * \param node
 */
void *bbs_node_handler(void *varg);
