/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief Abstract I/O transformations interface
 *
 */

#ifndef _BBS_IO_TRANSFORM
#define _BBS_IO_TRANSFORM

enum bbs_io_transform_type {
	TRANSFORM_TLS_ENCRYPTION = 0,	/*!< TLS encryption/decryption */
	TRANSFORM_DEFLATE_COMPRESSION = 1,	/*!< zlib compression/decompression */
	TRANSFORM_SESSION_LOGGING = 2,	/*!< Log I/O session for debugging */
};

/* Number of transform types in above enum + a few more if we allow other kinds */
#define MAX_IO_TRANSFORMS 3

enum bbs_io_session_type {
	TRANSFORM_SESSION_NODE = 0,
	TRANSFORM_SESSION_TCPCLIENT,
};

enum bbs_io_transform_dir {
	TRANSFORM_SERVER_TX = (1 << 0),
	TRANSFORM_SERVER_RX = (1 << 1),
	TRANSFORM_CLIENT_TX = (1 << 2),
	TRANSFORM_CLIENT_RX = (1 << 3),
};

#define TRANSFORM_SERVER (TRANSFORM_SERVER_TX | TRANSFORM_SERVER_RX)
#define TRANSFORM_CLIENT (TRANSFORM_CLIENT_TX | TRANSFORM_CLIENT_RX)
#define TRANSFORM_SERVER_CLIENT_TX_RX (TRANSFORM_SERVER_TX | TRANSFORM_SERVER_RX | TRANSFORM_CLIENT_TX | TRANSFORM_CLIENT_RX)

#define TRANSFORM_QUERY_TLS_REUSE 0 /* TRANSFORM_TLS_ENCRYPTION: Get whether SSL session was reused, using arg as output */
#define TRANSFORM_QUERY_COMPRESSION_FLUSH 1 /* TRANSFORM_DEFLATE_COMPRESSION: Do a full flush (arg not used) */
#define TRANSFORM_QUERY_SET_COMPRESSION_LEVEL 2 /* TRANSFORM_DEFLATE_COMPRESSION: Set compression level (0 = none, 9 = max, slowest), using arg as input */

struct bbs_io_transformer;

struct bbs_io_transformation {
	struct bbs_io_transformer *transformer; /* Transformer */
	void *data; /* Transformer's private data */
	int inner_rfd;	/* The read file descriptor used by this transformation */
	int inner_wfd;	/* The write file descriptor used by this transformation */
	int outer_rfd;	/* The original read file descriptor prior to this transformation being added */
	int outer_wfd;	/* The original write file descriptor prior to this transformation being added */
};

struct bbs_io_transformations {
	struct bbs_io_transformation transformations[MAX_IO_TRANSFORMS];
};

struct bbs_io_transformer_functions {
	/*! \brief Setup callback */
	int (*setup)(int *rfd, int *wfd, enum bbs_io_transform_dir dir, void **restrict data, const void *arg);
	/*! \brief Query callback. Optional. */
	int (*query)(struct bbs_io_transformation *tran, int query, void *data);
	/*! \brief Cleanup callback. */
	void (*cleanup)(struct bbs_io_transformation *tran);
};

int __bbs_io_transformer_register(const char *name, struct bbs_io_transformer_functions *funcs, enum bbs_io_transform_type type, enum bbs_io_transform_dir dir, void *module) __attribute__ ((nonnull (1, 2, 5)));

/*!
 * \brief Register I/O transformer callbacks.
 * \param name
 * \param funcs
 * \param type
 * \param dir
 * \retval 0 on success, -1 on failure
 */
#define bbs_io_transformer_register(name, funcs, type, dir) __bbs_io_transformer_register(name, funcs, type, dir, BBS_MODULE_SELF)

/*! \brief Unergister I/O transformer callback */
int bbs_io_transformer_unregister(const char *name);

/*! \brief Check if a transformer is registered by name */
int bbs_io_named_transformer_available(const char *name);

/*! \brief Check if a suitable transformer is available */
int bbs_io_transformer_available(enum bbs_io_transform_type transform_type);

/*!
 * \brief Register an I/O session
 * \param s
 * \param type Session type
 * \param owner Data structure for associated session type's owner
 * \note Must call int bbs_io_session_unregister when done with session
 */
int bbs_io_session_register(struct bbs_io_transformations *s, enum bbs_io_session_type type, void *owner);

/*! \brief Unregister an I/O session */
int bbs_io_session_unregister(struct bbs_io_transformations *s);

/*!
 * \brief Check whether a transformation is possible, given what transformations are already running
 * \param trans
 * \param type
 * \retval 1 transformation allowed
 * \retval 0 not allowed, and calling bbs_io_transform_setup will fail
 */
int bbs_io_transform_possible(struct bbs_io_transformations *trans, enum bbs_io_transform_type type);

/*!
 * \brief Begin using a transformer. This action is permanent (only bbs_io_teardown_all_transformers will end transformation)
 * \param trans
 * \param type
 * \param direction
 * \param rfd Must be initialized, but may be modified
 * \param wfd Must be initialized, but may be modified
 * \param arg Optional data. For TRANSFORM_TLS_ENCRYPTION and TRANSFORM_CLIENT, the Server Name Indication hostname
 * \retval 0 on success, -1 on failure
 */
int bbs_io_transform_setup(struct bbs_io_transformations *trans, enum bbs_io_transform_type type, enum bbs_io_transform_dir direction, int *rfd, int *wfd, const void *arg);

/*!
 * \brief Check whether a transformation is currently active
 * \param trans
 * \param type
 * \retval 1 if currently active, 0 if not
 * \note For checking if TLS is active on a node, use node->secure instead
 */
int bbs_io_transform_active(struct bbs_io_transformations *trans, enum bbs_io_transform_type type);

/*!
 * \brief Read and/or write a setting while a transformation is active
 * \param trans
 * \param type
 * \param query A TRANSFORM_QUERY argument
 * \param Either an input and/or output parameter depending on the query. For TRANSFORM_QUERY_TLS_REUSE, will be set to whether the connection was reused
 * \retval 0 on success
 * \retval 1 no query callback
 * \retval -1 on failure or no such type
 */
int bbs_io_transform_query(struct bbs_io_transformations *trans, enum bbs_io_transform_type type, int query, void *data);

/*!
 * \brief Wait synchronously for all I/O to finish
 * \param trans
 * \retavl 0 on success, -1 on failure
 * \note There is currently nothing using this API
 */
int bbs_io_drain(struct bbs_io_transformations *trans);

/*!
 * \brief Terminate all transformations, typically immediately before closing the surrounding file descriptors
 * \param trans
 * \note This function is idempotent (it may be called repeatedly without side effects)
 */
void bbs_io_teardown_all_transformers(struct bbs_io_transformations *trans);

#define ssl_available() (bbs_io_transformer_available(TRANSFORM_TLS_ENCRYPTION))
#define deflate_compression_available() (bbs_io_transformer_available(TRANSFORM_DEFLATE_COMPRESSION))

int bbs_io_init(void);

#endif /* _BBS_IO_TRANSFORM */
