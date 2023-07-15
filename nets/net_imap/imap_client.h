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

/*!
 * \brief Poll an IMAP session and all remote sessions for activity
 * \param imap
 * \param ms Poll time, in ms
 * \param[out] clientout If return value is positive, the IMAP client with activity, or NULL if the main client had activity
 * \retval -1 poll error
 * \retval 0 No activity
 * \retval 1 Activity on the IMAP session or an IMAP client. Refer to clientout to see what had activity.
 */
int imap_poll(struct imap_session *imap, int ms, struct imap_client **clientout);

/*!
 * \brief Start idling on the currently selected mailbox
 * \param client
 * \retval 0 on success, -1 on failure
 */
int imap_client_idle_start(struct imap_client *client);

/*!
 * \brief Stop idling on the currently selected mailbox
 * \param client
 * \retval 0 on success, -1 on failure
 */
int imap_client_idle_stop(struct imap_client *client);

void imap_client_idle_notify(struct imap_client *client);

/*! \brief Disconnect the current active proxied client connection */
void imap_close_remote_mailbox(struct imap_session *imap);

/*! \brief Retrieve or create a new IMAP client connection by name and URL */
struct imap_client *imap_client_get_by_url(struct imap_session *imap, const char *name, char *restrict urlstr);

#define imap_client_send_wait_response(client, fd, ms, fmt, ...) __imap_client_send_wait_response(client, fd, ms, 1, __LINE__, NULL, NULL, fmt, ## __VA_ARGS__)
#define imap_client_send_wait_response_cb(client, fd, ms, cb, cbdata, fmt, ...) __imap_client_send_wait_response(client, fd, ms, 1, __LINE__, cb, cbdata, fmt, ## __VA_ARGS__)
#define imap_client_send_wait_response_noecho(client, fd, ms, fmt, ...) __imap_client_send_wait_response(client, fd, ms, 0, __LINE__, NULL, NULL, fmt, ## __VA_ARGS__)
#define imap_client_send_wait_response_cb_noecho(client, fd, ms, cb, cbdata, fmt, ...) __imap_client_send_wait_response(client, fd, ms, 0, __LINE__, cb, cbdata, fmt, ## __VA_ARGS__)

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

/*!
 * \brief Whether a mailbox name is remotely mapped
 * \param imap
 * \param path Mailbox name
 * \retval 1 Remote mapping exists
 * \retval 0 No remote mapping exists
 */
int mailbox_remotely_mapped(struct imap_session *imap, const char *path);

char *remote_mailbox_name(struct imap_client *client, char *restrict mailbox);
