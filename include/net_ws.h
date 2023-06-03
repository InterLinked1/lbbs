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

/* Forward declaration of private structure */
struct ws_session;

/*!
 * \brief Register a WebSocket route (separate from HTTP routes)
 * \param uri Unique WebSocket URI (across all ports)
 * \param on_open Optional callback to execute when a WebSocket connection is established to this route. Return non-zero to abort connection.
 * \param on_close Optional callback to execute when a WebSocket connection is closed.
 * \param on_text_message Optional callback to execute when a text payload is received from a WebSocket client. Return nonzero to close connection.
 * \retval 0 on success, -1 on failure
 */
#define websocket_route_register(uri, on_open, on_close, on_text_message) __websocket_route_register(uri, on_open, on_close, on_text_message, BBS_MODULE_SELF)

int __websocket_route_register(const char *uri, int (on_open)(struct ws_session *ws), int (on_close)(struct ws_session *ws, void *data), int (on_text_message)(struct ws_session *ws, void *data, const char *buf, size_t len), void *mod);

/*! \brief Unregister a route previously registered by websocket_route_register */
int websocket_route_unregister(const char *uri);

/*! \brief Set the custom user data of a ws_session */
void websocket_attach_user_data(struct ws_session *ws, void *data);

/*!
 * \brief Send text payload to client
 * \param ws
 * \param buf Text data to send. Does not have to be null terminated.
 * \param len Length of buf.
 */
void websocket_sendtext(struct ws_session *ws, const char *buf, size_t len);
