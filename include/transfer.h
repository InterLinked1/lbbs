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
 * \brief Protocol-agnostic file transfer settings
 *
 */

/* Forward declarations */
struct bbs_node;

#define TRANSFER_ACCESS 0
#define TRANSFER_DOWNLOAD 1
#define TRANSFER_UPLOAD 2
#define TRANSFER_NEWDIR 3
#define TRANSFER_DESTRUCTIVE 4

/*! \brief Whether file listings are allowed */
#define bbs_transfer_canaccess(node) bbs_transfer_operation_allowed(node, TRANSFER_ACCESS)

/*! \brief Whether read operations (downloads) are allowed */
#define bbs_transfer_canread(node) bbs_transfer_operation_allowed(node, TRANSFER_DOWNLOAD)

/*! \brief Whether write operations (uploads) are allowed */
#define bbs_transfer_canwrite(node) bbs_transfer_operation_allowed(node, TRANSFER_UPLOAD)

/*! \brief Whether new directories may be created */
#define bbs_transfer_canmkdir(node) bbs_transfer_operation_allowed(node, TRANSFER_NEWDIR)

/*! \brief Whether destructive operations (delete, rename, etc.) are allowed */
#define bbs_transfer_candelete(node) bbs_transfer_operation_allowed(node, TRANSFER_DESTRUCTIVE)

/*!
 * \brief Whether a certain kind of transfer operation is allowed
 * \note Generally the macros above should be used, rather than this function directly
 * \retval 1 if allowed, 0 if not allowed
 */
int bbs_transfer_operation_allowed(struct bbs_node *node, int operation);

/*!
 * \brief Get file transfer root directory
 * \retval Full system path for root directory, no trailing slash
 */
const char *bbs_transfer_rootdir(void);

/*! \brief Get configured transfer timeout, in milliseconds */
int bbs_transfer_timeout(void);

/*!
 * \brief Load transfer settings config
 * \note This is safe to call multiple times, but must be called before using settings at least once.
 *       Therefore, all modules that need these settings should call this function when loading.
 * \retval 0 on success, -1 on failure. If failure occurs, any dependent module must not
 *         attempt to make use of any file transfer functionality configured here.
 */
int bbs_transfer_config_load(void);
