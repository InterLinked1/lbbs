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
 * \brief System and shell stuff
 *
 */

/* Forward declarations */
struct bbs_node;

/*!
 * \brief Parse a string into an argv. Similar to wordexp, but without the unnecessary (and insecure?) shell expansion overhead
 *        This function will separate on spaces, but keep a quoted argument together as a single argument.
 * \param[out] argv
 * \param argc Size of argv
 * \param s String to parse
 * \retval Value of argc (new argc + 1)
 */
int bbs_argv_from_str(char **argv, int argc, char *s);

/*!
 * \brief Wrapper around execvpe(). This will fork(), then call execvp(), then wait for the child to exit.
 * \param node Node to use for I/O. If NULL, output will be written to a temporary pipe and logged, but otherwise discarded
 * \param filename Filename of program to execute (path is optional)
 * \param argv
 * \retval 0 on success, -1 on failure
 * \warning Do not call bbs_execvp from a node thread with NULL for node. Use bbs_execvp_headless.
 */
int bbs_execvp(struct bbs_node *node, const char *filename, char *const argv[]);

/*!
 * \brief Wrapper around execvpe() that creates a process in an isolated container. This will clone(), then call execvp(), then wait for the child to exit.
 * \param node Node to use for I/O. If NULL, output will be written to a temporary pipe and logged, but otherwise discarded
 * \param filename Filename of program to execute (path is optional)
 * \param argv
 * \retval 0 on success, -1 on failure
 * \warning Do not call bbs_execvp from a node thread with NULL for node. Use bbs_execvp_headless.
 */
int bbs_execvp_isolated(struct bbs_node *node, const char *filename, char *const argv[]);

/*! \brief Same as bbs_execvp, but node will not be used for I/O. */
int bbs_execvp_headless(struct bbs_node *node, const char *filename, char *const argv[]);

/*!
 * \brief Wrapper around execvpe(). This will fork(), then call execvp(), then wait for the child to exit.
 * \param node Node to use for I/O. If NULL and fdout == -1, output will be written to a temporary pipe and logged, but otherwise discarded
 * \param fdin If node is NULL, file descriptor to use for STDIN. If -1, there will be no standard input available to the executed program.
 * \param fdout If node is NULL, file descriptor to use for STDOUT/STDERR. If -1, output will be written to a temporary pipe and logged, but otherwise discarded.
 * \param filename Filename of program to execute (path is optional)
 * \param argv
 * \retval 0 on success, -1 on failure
 * \warning Do not call bbs_execvp_fd from a node thread with NULL for node. Use bbs_execvp_fd_headless.
 */
int bbs_execvp_fd(struct bbs_node *node, int fdin, int fdout, const char *filename, char *const argv[]);

/*! \brief Same as bbs_execvp_fd, but node will not be used for I/O. */
int bbs_execvp_fd_headless(struct bbs_node *node, int fdin, int fdout, const char *filename, char *const argv[]);

/*! \brief Same as bbs_execvp_fd_headless, but allow passing an envp */
int bbs_execvpe_fd_headless(struct bbs_node *node, int fdin, int fdout, const char *filename, char *const argv[], char *const envp[]);

/*! \brief Load system.conf config at startup */
int bbs_init_system(void);
