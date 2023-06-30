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
 * \brief Simple Proxied IMAP Client
 *
 */

void imap_close_remote_mailbox(struct imap_session *imap);

int my_imap_client_login(struct bbs_tcp_client *client, struct bbs_url *url, struct imap_session *imap);

#define imap_client_send_wait_response(imap, fd, ms, fmt, ...) __imap_client_send_wait_response(imap, fd, ms, 1, __LINE__, fmt, ## __VA_ARGS__)
#define imap_client_send_wait_response_noecho(imap, fd, ms, fmt, ...) __imap_client_send_wait_response(imap, fd, ms, 0, __LINE__, fmt, ## __VA_ARGS__)

int __attribute__ ((format (gnu_printf, 6, 7))) __imap_client_send_wait_response(struct imap_session *imap, int fd, int ms, int echo, int lineno, const char *fmt, ...);

/*! \retval Number of replacements made */
int imap_substitute_remote_command(struct imap_session *imap, char *s);

/*! \brief Whether a specific mailbox path has a virtual mapping to a mailbox on a remote server */
int load_virtual_mailbox(struct imap_session *imap, const char *path);

char *remote_mailbox_name(struct imap_session *imap, char *restrict mailbox);
