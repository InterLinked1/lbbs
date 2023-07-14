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

/*! \brief Disconnect all proxied client connections */
void imap_shutdown_clients(struct imap_session *imap);

/*! \brief Disconnect the current active proxied client connection */
void imap_close_remote_mailbox(struct imap_session *imap);

/*! \brief Retrieve or create a new IMAP client connection by name and URL */
struct imap_client *imap_client_get_by_url(struct imap_session *imap, const char *name, char *restrict urlstr);

#define imap_client_send_wait_response(client, fd, ms, fmt, ...) __imap_client_send_wait_response(client, fd, ms, 1, __LINE__, NULL, NULL, fmt, ## __VA_ARGS__)
#define imap_client_send_wait_response_cb(client, fd, ms, cb, cbdata, fmt, ...) __imap_client_send_wait_response(client, fd, ms, 1, __LINE__, cb, cbdata, fmt, ## __VA_ARGS__)
#define imap_client_send_wait_response_noecho(client, fd, ms, fmt, ...) __imap_client_send_wait_response(client, fd, ms, 0, __LINE__, NULL, NULL, fmt, ## __VA_ARGS__)

int __attribute__ ((format (gnu_printf, 8, 9))) __imap_client_send_wait_response(struct imap_client *client, int fd, int ms, int echo, int lineno, int (*cb)(struct imap_client *client, const char *buf, size_t len, void *cbdata), void *cbdata, const char *fmt, ...);

/*! \retval Number of replacements made */
int imap_substitute_remote_command(struct imap_client *client, char *s);

/*!
 * \brief Load a remote mailbox
 * \param imap
 * \param path
 * \param[out] exists Whether the mailbox exists (e.g. mailbox may have a mapping that exists, but be currently unavailable)
 * \return client, or NULL if not available/doesn't exist
 */
struct imap_client *load_virtual_mailbox(struct imap_session *imap, const char *path, int *exists);

char *remote_mailbox_name(struct imap_client *client, char *restrict mailbox);
