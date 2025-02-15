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

/*! \brief Check basic invariants to ensure corruption has not occured */
void imap_client_integrity_check(struct imap_session *imap, struct imap_client *client);

/*!
 * \brief Unlink and destroy a client
 * \param imap
 * \param client
 */
void imap_client_unlink(struct imap_session *imap, struct imap_client *client);

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

/*!
 * \brief Get the number of seconds until the next IDLE expiration occurs (across all idling clients)
 * \param imap
 * \retval 0 if no clients are idling
 * \return Number of seconds until next expiration
 */
int imap_clients_next_idle_expiration(struct imap_session *imap);

/*!
 * \brief Recreate a client if it is dead
 * \note The clients list must NOT be locked when calling this
 */
int imap_recreate_client(struct imap_session *imap, struct imap_client *client);

/*!
 * \brief Renew IDLE on all idling clients that are close to expiring
 * \param imap
 * \param except Renew IDLE on all clients except this one, if non-NULL
 */
void imap_clients_renew_idle(struct imap_session *imap, struct imap_client *except);

void imap_client_idle_notify(struct imap_client *client);

/*! \brief Disconnect the current active proxied client connection */
void imap_close_remote_mailbox(struct imap_session *imap);

#define imap_client_get_by_url(imap, name, urlstr) __imap_client_get_by_url(imap, name, urlstr, 0)
#define imap_client_get_by_url_parallel(imap, name, urlstr) __imap_client_get_by_url(imap, name, urlstr, 1)

/*! \brief Retrieve or create a new IMAP client connection by name and URL */
struct imap_client *__imap_client_get_by_url(struct imap_session *imap, const char *name, char *restrict urlstr, int parallel);

/*!
 * \brief Send a printf-formatted buffer on an IMAP client
 * \param client
 * \param log Whether to log the command
 * \param fmt
 * \retval -1 on failure
 * \return Same as write
 */
ssize_t __attribute__ ((format (gnu_printf, 3, 4))) __imap_client_send_log(struct imap_client *client, int log, const char *fmt, ...);

#define imap_client_send(client, fmt, ...) __imap_client_send_log(client, 0, fmt, ## __VA_ARGS__)
#define imap_client_send_log(client, fmt, ...) __imap_client_send_log(client, 1, fmt, ## __VA_ARGS__)

#define imap_client_wait_response(client, fd, ms) __imap_client_wait_response(client, fd, ms, 1, __LINE__, NULL, NULL)
#define imap_client_wait_response_noecho(client, fd, ms) __imap_client_wait_response(client, fd, ms, 0, __LINE__, NULL, NULL)
#define imap_client_wait_response_noechotag(client, fd, ms) __imap_client_wait_response(client, fd, ms, 2, __LINE__, NULL, NULL)

#define imap_client_send_wait_response(client, fd, ms, fmt, ...) __imap_client_send_wait_response(client, fd, ms, 1, __LINE__, NULL, NULL, fmt, ## __VA_ARGS__)
#define imap_client_send_wait_response_cb(client, fd, ms, cb, cbdata, fmt, ...) __imap_client_send_wait_response(client, fd, ms, 1, __LINE__, cb, cbdata, fmt, ## __VA_ARGS__)
#define imap_client_send_wait_response_noecho(client, fd, ms, fmt, ...) __imap_client_send_wait_response(client, fd, ms, 0, __LINE__, NULL, NULL, fmt, ## __VA_ARGS__)
#define imap_client_send_wait_response_cb_noecho(client, fd, ms, cb, cbdata, fmt, ...) __imap_client_send_wait_response(client, fd, ms, 0, __LINE__, cb, cbdata, fmt, ## __VA_ARGS__)

/*! \brief Same as __imap_client_send_wait_response, but don't send a command initially, just wait for the tagged response */
int __imap_client_wait_response(struct imap_client *client, int fd, int ms, int echo, int lineno, int (*cb)(struct imap_client *client, const char *buf, size_t len, void *cbdata), void *cbdata);

/*!
 * \brief Send a command to remote IMAP server and wait for a response, passing through any receive untagged responses inbetween directly back to the client
 * \param client
 * \param fd Additional file descriptor on which to poll(used only for IDLE, -1 otherwise)
 * \param ms Max time to wait for poll / bbs_readline
 * \param echo 1 to relay output from remote server to our local client, 2 to relay output except tagged repsonse, 0 to not relay any output
 * \param lineno
 * \param cb Custom callback to run for each line received from remote server. Returning -1 from callback will terminate wait loop
 * \param cbdata Callback data for callback function
 * \param fmt printf-style fmt string
 */
int __attribute__ ((format (gnu_printf, 8, 9))) __imap_client_send_wait_response(struct imap_client *client, int fd, int ms, int echo, int lineno, int (*cb)(struct imap_client *client, const char *buf, size_t len, void *cbdata), void *cbdata, const char *fmt, ...);

/*! \retval Number of replacements made */
int imap_substitute_remote_command(struct imap_client *client, char *s);

/*!
 * \brief Get the path to the .imapremote file
 * \param imap
 * \param[out] buf
 * \param len
 * \retval 0 on success, -1 on failure
 */
int imap_client_mapping_file(struct imap_session *imap, char *buf, size_t len);

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

/*! \brief Convert a local mailbox name to its name on a remote server */
const char *remote_mailbox_name(struct imap_client *client, char *restrict mailbox);
