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
 * \brief Pseudoterminals
 *
 */

/* Forward declarations */
struct winsize;
struct termios;

/*!
 * \brief POSIX version of BSD openpty function
 * \param amaster Will be set to master fd
 * \param aslave Will be set to slave fd
 * \param name Will be set to slave name, if non-NULL
 * \param termp Terminal attributes to set, if non-NULL
 * \param winp Window size to set, if non-NULL
 * \retval 0 on success, -1 on failure
 */
int bbs_openpty(int *amaster, int *aslave, char *name, const struct termios *termp, const struct winsize *winp);

/*!
 * \brief Create and spawn a generic PTY master relay for arbitrary file descriptors
 * \param fd Socket file descriptor
 * \note This thread will continue until either file descriptor closes. It should be created detached.
 * \retval -1 on failure, slave file descriptor on success
 */
int bbs_spawn_pty_master(int fd);

/*! \brief Allocate and set up a pseudoterminal for a BBS node */
int bbs_pty_allocate(struct bbs_node *node);

/*!
 * \brief Spy on the input and output of a node
 * \param fdin Spyer's input file descriptor (e.g. STDIN_FILENO)
 * \param fdout Spyer's output file descriptor (e.g. STDOUT_FILENO)
 * \param nodenum ID of node on which to spy
 * \retval 0 on success, -1 on failure
 */
int bbs_node_spy(int fdin, int fdout, int nodenum);

/*!
 * \brief PTY master side handling
 * \param varg BBS node
 */
void *pty_master(void *varg);
