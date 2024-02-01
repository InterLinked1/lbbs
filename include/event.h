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
 * \brief Internal Event Bus
 *
 */

enum bbs_event_type {
	EVENT_STARTUP = 0,
	EVENT_SHUTDOWN,
	EVENT_NODE_SHORT_SESSION,		/*!< Extremely short node session (where abnormal) */
	EVENT_NODE_ENCRYPTION_FAILED,	/*!< TLS setup failed */
	EVENT_NODE_LOGIN_FAILED,		/*!< Authentication failed */
	EVENT_NODE_BAD_REQUEST,			/*!< Bad request received */
	EVENT_NODE_INTERACTIVE_START,	/*!< Interactive terminal session started */
	EVENT_NODE_INTERACTIVE_LOGIN,	/*!< Interactive terminal login */
	EVENT_USER_REGISTRATION,		/*!< New user registration */
	EVENT_USER_LOGIN,				/*!< Successful authentication (any protocol) */
	EVENT_USER_LOGOFF,				/*!< User logout (any protocol) */
	EVENT_USER_PASSWORD_CHANGE,		/*!< User password change */
};

struct bbs_event {
	enum bbs_event_type type;
	unsigned int nodenum;
	unsigned int userid;
	struct bbs_node *node;			/*!< Only set for EVENT_NODE_INTERACTIVE_START and EVENT_NODE_INTERACTIVE_LOGIN */
	char protname[10];
	char username[64];
	char ipaddr[64];
};

/* Forward declaration */
struct bbs_node;

/*! \note Callback should return 0 if not handled, 1 if handled, and 2 if handled and no other callbacks should be called */
#define bbs_register_event_consumer(callback) __bbs_register_event_consumer(callback, BBS_MODULE_SELF)

int __bbs_register_event_consumer(int (*callback)(struct bbs_event *event), void *mod);

int bbs_unregister_event_consumer(int (*callback)(struct bbs_event *event));

/*! \brief Get a string representation of an event type's name */
const char *bbs_event_name(enum bbs_event_type type);

/*! \brief Broadcast an event to all event consumers */
int bbs_event_broadcast(struct bbs_event *event);

/*! \brief Build and dispatch an event to all event consumers */
int bbs_event_dispatch(struct bbs_node *node, enum bbs_event_type type);

/*! \brief Same as bbs_event_dispatch, but provide optional custom data, used depending on the type */
int bbs_event_dispatch_custom(struct bbs_node *node, enum bbs_event_type type, const void *data);
