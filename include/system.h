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
 * \brief Wrapper around execvpe(). This will fork(), then call execvp(), then wait for the child to exit.
 * \param node Node to use for I/O. If NULL, output will be written to a temporary pipe and logged, but otherwise discarded
 * \param filename Filename of program to execute (path is optional)
 * \param argv
 * \retval 0 on success, -1 on failure
 * \warning Do not call bbs_execvpe from a node thread with NULL for node. Use bbs_execvpe_headless.
 */
int bbs_execvpe(struct bbs_node *node, const char *filename, char *const argv[]);

/*!
 * \brief Wrapper around execvpe() that creates a process in an isolated container. This will clone(), then call execvp(), then wait for the child to exit.
 * \param node Node to use for I/O. If NULL, output will be written to a temporary pipe and logged, but otherwise discarded
 * \param filename Filename of program to execute (path is optional)
 * \param argv
 * \retval 0 on success, -1 on failure
 * \warning Do not call bbs_execvpe from a node thread with NULL for node. Use bbs_execvpe_headless.
 */
int bbs_execvpe_isolated(struct bbs_node *node, const char *filename, char *const argv[]);

/*! \brief Same as bbs_execvpe, but node will not be used for I/O. */
int bbs_execvpe_headless(struct bbs_node *node, const char *filename, char *const argv[]);

/*!
 * \brief Wrapper around execvpe(). This will fork(), then call execvp(), then wait for the child to exit.
 * \param node Node to use for I/O. If NULL and fdout == -1, output will be written to a temporary pipe and logged, but otherwise discarded
 * \param fdin If node is NULL, file descriptor to use for STDIN. If -1, there will be no standard input available to the executed program.
 * \param fdout If node is NULL, file descriptor to use for STDOUT/STDERR. If -1, output will be written to a temporary pipe and logged, but otherwise discarded.
 * \param filename Filename of program to execute (path is optional)
 * \param argv
 * \retval 0 on success, -1 on failure
 * \warning Do not call bbs_execvpe_fd from a node thread with NULL for node. Use bbs_execvpe_fd_headless.
 */
int bbs_execvpe_fd(struct bbs_node *node, int fdin, int fdout, const char *filename, char *const argv[]);

/*! \brief Same as bbs_execvpe_fd, but node will not be used for I/O. */
int bbs_execvpe_fd_headless(struct bbs_node *node, int fdin, int fdout, const char *filename, char *const argv[]);
