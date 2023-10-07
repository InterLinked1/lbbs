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
 * \brief RFC 6455 WebSocket Server
 *
 */

/* Must be less than 5 minutes */
#define MAX_WEBSOCKET_POLL_MS (MIN_MS(5) - 5)

/* Forward declaration of private structure */
struct ws_session;

struct ws_callbacks {
	int (*on_open)(struct ws_session *ws);
	int (*on_close)(struct ws_session *ws, void *data);
	int (*on_text_message)(struct ws_session *ws, void *data, const char *buf, size_t len);
	int (*on_poll_activity)(struct ws_session *ws, void *data);
	int (*on_poll_timeout)(struct ws_session *ws, void *data);
};

/*!
 * \brief Register a WebSocket route (separate from HTTP routes)
 * \param uri Unique WebSocket URI (across all ports)
 * \param on_open Optional callback to execute when a WebSocket connection is established to this route. Return non-zero to abort connection.
 * \param on_close Optional callback to execute when a WebSocket connection is closed.
 * \param on_text_message Optional callback to execute when a text payload is received from a WebSocket client. Return nonzero to close connection.
 * \retval 0 on success, -1 on failure
 */
#define websocket_route_register(uri, callbacks) __websocket_route_register(uri, callbacks, BBS_MODULE_SELF)

int __websocket_route_register(const char *uri, struct ws_callbacks *callbacks, void *mod);

/*! \brief Unregister a route previously registered by websocket_route_register */
int websocket_route_unregister(const char *uri);

/*! \brief Set the custom user data of a ws_session */
void websocket_attach_user_data(struct ws_session *ws, void *data);

/*!
 * \brief Get a string session variable from a WebSocket session
 * \param ws
 * \param key Session variable name
 * \return Session variable value, or NULL if not found
 */
const char *websocket_session_data_string(struct ws_session *ws, const char *key);

/*!
 * \brief Get a integer or boolean session variable from a WebSocket session
 * \param ws
 * \param key Session variable name
 * \return Session variable value, or 0 if not found
 */
int websocket_session_data_number(struct ws_session *ws, const char *key);

/*!
 * \brief Get a string query parameter from the WebSocket URI
 * \param ws
 * \param key Query parameter name
 * \return Query parameter, or NULL if not found
 */
const char *websocket_query_param(struct ws_session *ws, const char *key);

/*!
 * \brief Get a serialized key value from an HTTP cookie
 * \param ws
 * \param cookiename Cookie name. This may be any cookie name, but per ws, only one cookie name is supported.
 * \param valkey Name of key of member inside the cookie
 * \return Cookie value, or NULL if not found
 */
const char *websocket_cookie_val(struct ws_session *ws, const char *cookiename, const char *valkey);

/*!
 * \brief Set custom polling settings
 * \param ws
 * \param fd Additional file descriptor to poll, or -1 if no additional fd
 * \param pollms Timeout argument to poll() that should be used. Limited to maximum of MAX_WEBSOCKET_POLL_MS.
 */
void websocket_set_custom_poll_fd(struct ws_session *ws, int fd, int pollms);

/*!
 * \brief Send text payload to client
 * \param ws
 * \param buf Text data to send. Does not have to be null terminated.
 * \param len Length of buf.
 * \retval 0 on success, -1 on failure
 */
int websocket_sendtext(struct ws_session *ws, const char *buf, size_t len);
