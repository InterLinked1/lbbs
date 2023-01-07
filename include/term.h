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
 * \brief BBS terminal manipulation
 *
 */

/*!
 * \brief Disable input buffering on a fd
 * \param fd
 * \param echo Whether to enable local echo
 * \retval 0 on success, -1 on failure
 */
int bbs_fd_unbuffer_input(int fd, int echo);

/*!
 * \brief Enable input buffering on a fd
 * \param fd
 * \param echo Whether to enable local echo
 * \retval 0 on success, -1 on failure
 */
int bbs_fd_buffer_input(int fd, int echo);

/*!
 * \brief Set echo on/off on a fd
 * \param fd
 * \param echo Whether to enable local echo
 * \retval 0 on success, -1 on failure
 */
int bbs_fd_echo(int fd, int echo);

/*! \brief Wrapper for bbs_unbuffer_input that disables canonical mode and echo */
#define bbs_unbuffer(node) bbs_unbuffer_input(node, 0)

/*! \brief Wrapper for bbs_buffer_input that enables canonical mode and echo */
#define bbs_buffer(node) bbs_buffer_input(node, 1)

/*!
 * \brief Disable input buffering for BBS node
 * \param node
 * \param echo Whether to enable local echo
 * \retval 0 on success, -1 on failure
 */
int bbs_unbuffer_input(struct bbs_node *node, int echo);

/*!
 * \brief Enable input buffering for BBS node
 * \param node
 * \param echo Whether to enable local echo
 * \retval 0 on success, -1 on failure
 */
int bbs_buffer_input(struct bbs_node *node, int echo);

#define bbs_echo_on(node) bbs_echo(node, 1)
#define bbs_echo_off(node) bbs_echo(node, 0)

/*!
 * \brief Set echo on/off for a BBS node
 * \param node
 * \param echo Whether to enable local echo
 * \retval 0 on success, -1 on failure
 */
int bbs_echo(struct bbs_node *node, int echo);

/*!
 * \brief Make a TTY fd raw (pass most input unaltered)
 * \param PTY master fd
 * \retval 0 on success, -1 on failure
 */
int bbs_term_makeraw(int fd);

/*!
 * \brief Set line discipline appropriately
 * \param fd
 * \retval 0 on success, -1 on failure
 */
int tty_set_line_discipline(int fd);
