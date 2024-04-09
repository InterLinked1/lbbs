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
	TRANSFORM_ZLIB_COMPRESSION = 1,	/*!< zlib compression/decompression */
};

/* Number of transform types in above enum + a few more if we allow other kinds */
#define MAX_IO_TRANSFORMS 2

enum bbs_io_transform_dir {
	TRANSFORM_SERVER_TX = (1 << 0),
	TRANSFORM_SERVER_RX = (1 << 1),
	TRANSFORM_CLIENT_TX = (1 << 2),
	TRANSFORM_CLIENT_RX = (1 << 3),
};

#define TRANSFORM_SERVER (TRANSFORM_SERVER_TX | TRANSFORM_SERVER_RX)
#define TRANSFORM_CLIENT (TRANSFORM_CLIENT_TX | TRANSFORM_CLIENT_RX)
#define TRANSFORM_SERVER_CLIENT_TX_RX (TRANSFORM_SERVER_TX | TRANSFORM_SERVER_RX | TRANSFORM_CLIENT_TX | TRANSFORM_CLIENT_RX)

#define TRANSFORM_QUERY_TLS_REUSE 0

struct bbs_io_transformer;

struct bbs_io_transformation {
	struct bbs_io_transformer *transformer; /* Transformer */
	void *data; /* Transformer's private data */
};

struct bbs_io_transformations {
	struct bbs_io_transformation transformations[MAX_IO_TRANSFORMS];
};

int __bbs_io_transformer_register(const char *name, int (*setup)(int *rfd, int *wfd, enum bbs_io_transform_dir dir, void **restrict data, const void *arg),
	int (*query)(struct bbs_io_transformation *tran, int query, void *data),
	void (*cleanup)(struct bbs_io_transformation *tran), enum bbs_io_transform_type type, enum bbs_io_transform_dir dir, void *module);

/*!
 * \brief Register I/O transformer callbacks.
 * \param name
 * \param setup
 * \param query Optional
 * \param cleanup
 * \param type
 * \param dir
 * \retval 0 on success, -1 on failure
 */
#define bbs_io_transformer_register(name, setup, query, cleanup, type, dir) __bbs_io_transformer_register(name, setup, query, cleanup, type, dir, BBS_MODULE_SELF)

/*! \brief Unergister I/O transformer callback */
int bbs_io_transformer_unregister(const char *name);

/*! \brief Check if a transformer is registered by name */
int bbs_io_named_transformer_available(const char *name);

/*! \brief Check if a suitable transformer is available */
int bbs_io_transformer_available(enum bbs_io_transform_type transform_type);

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
 * \brief Terminate all transformations, typically immediately before closing the surrounding file descriptors
 * \param trans
 * \note This function is idempotent (it may be called repeatedly without side effects)
 */
void bbs_io_teardown_all_transformers(struct bbs_io_transformations *trans);

#define ssl_available() (bbs_io_transformer_available(TRANSFORM_TLS_ENCRYPTION))

#endif /* _BBS_IO_TRANSFORM */
