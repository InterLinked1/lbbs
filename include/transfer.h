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
#define bbs_transfer_canaccess(node) bbs_transfer_operation_allowed(node, TRANSFER_ACCESS, NULL)

/*! \brief Whether read operations (downloads) are allowed */
#define bbs_transfer_canread(node, mypath) bbs_transfer_operation_allowed(node, TRANSFER_DOWNLOAD, mypath)

/*! \brief Whether write operations (uploads) are allowed */
#define bbs_transfer_canwrite(node, mypath) bbs_transfer_operation_allowed(node, TRANSFER_UPLOAD, mypath)

/*! \brief Whether new directories may be created */
#define bbs_transfer_canmkdir(node, mypath) bbs_transfer_operation_allowed(node, TRANSFER_NEWDIR, mypath)

/*! \brief Whether destructive operations (delete, rename, etc.) are allowed */
#define bbs_transfer_candelete(node, mypath) bbs_transfer_operation_allowed(node, TRANSFER_DESTRUCTIVE, mypath)

/*!
 * \brief Whether a certain kind of transfer operation is allowed
 * \note Generally the macros above should be used, rather than this function directly
 * \retval 1 if allowed, 0 if not allowed
 */
int bbs_transfer_operation_allowed(struct bbs_node *node, int operation, const char *fullpath);

/*!
 * \brief Make a ls-format directory listing for a file
 * \param file Filename
 * \param st
 * \param[out] buf
 * \param len Size of buf
 * \param ftp Whether listing is for the FTP protocol
 * \retval Number of bytes written to buf
 */
int transfer_make_longname(const char *file, struct stat *st, char *buf, size_t len, int ftp);

/*!
 * \brief Get file transfer root directory
 * \retval Full system path for root directory, no trailing slash
 */
const char *bbs_transfer_rootdir(void);

/*! \brief Get configured transfer timeout, in milliseconds */
int bbs_transfer_timeout(void);

/*! \brief Get maximum upload file size, in bytes */
int bbs_transfer_max_upload_size(void);

/*!
 * \brief Get the path on disk user's home directory
 * \param node
 * \param[out] buf
 * \param len Size of buf
 * \retval 0 on success, -1 on failure
 */
int bbs_transfer_home_dir(struct bbs_node *node, char *buf, size_t len)  __attribute__((nonnull (1, 2)));

/*! \brief Get the user-facing transfer path from a full disk path */
const char *bbs_transfer_get_user_path(struct bbs_node *node, const char *diskpath);

/*!
 * \brief Get a directory using an absolute argument
 * \param node
 * \param userpath The absolute or relative path argument
 * \param[out] buf The new directory
 * \param len Size of buf
 * \retval 0 on success, -1 on failure (e.g. no such directory, unsafe path)
 */
#define bbs_transfer_set_disk_path_absolute(node, userpath, buf, len) __bbs_transfer_set_disk_path_absolute(node, userpath, buf, len, 1)

/*! \brief Same as bbs_transfer_set_disk_path_absolute, but doesn't require the target path exists */
#define bbs_transfer_set_disk_path_absolute_nocheck(node, userpath, buf, len) __bbs_transfer_set_disk_path_absolute(node, userpath, buf, len, 0)

/*!
 * \brief Get a directory using an absolute path argument
 * \param node
 * \param userpath The absolute path argument
 * \param[out] buf The new directory
 * \param len Size of buf
 * \param mustexist Whether the path must exist to be deemed "valid"
 * \retval 0 on success, -1 on failure (e.g. no such directory, unsafe path)
 */
int __bbs_transfer_set_disk_path_absolute(struct bbs_node *node, const char *userpath, char *buf, size_t len, int mustexist);

/*!
 * \brief Get a directory using an absolute or relative path argument
 * \param node
 * \param current The current full path on disk
 * \param userpath The absolute or relative path argument
 * \param[out] buf The new directory
 * \param len Size of buf
 * \retval 0 on success, -1 on failure (e.g. no such directory, unsafe path)
 */
#define bbs_transfer_set_disk_path_relative(node, current, userpath, buf, len) __bbs_transfer_set_disk_path_relative(node, current, userpath, buf, len, 1)

/*! \brief Same as bbs_transfer_set_disk_path_relative, but doesn't require the target path exists */
#define bbs_transfer_set_disk_path_relative_nocheck(node, current, userpath, buf, len) __bbs_transfer_set_disk_path_relative(node, current, userpath, buf, len, 0)

/*!
 * \brief Get a directory using an absolute or relative path argument
 * \param node
 * \param current The current full path on disk
 * \param userpath The absolute or relative path argument
 * \param[out] buf The new directory
 * \param len Size of buf
 * \param mustexist Whether the path must exist to be deemed "valid"
 * \retval 0 on success, -1 on failure (e.g. no such directory, unsafe path)
 */
int __bbs_transfer_set_disk_path_relative(struct bbs_node *node, const char *current, const char *userpath, char *buf, size_t len, int mustexist);

/*!
 * \brief Get the parent directory of the current directory
 * \param node
 * \param diskpath The current directory on disk
 * \param[out] buf The new (parent) directory, or the current directory if currently at the transfer root
 * \param len Size of buf
 * \retval 0 on success (updated to parent dir), -1 on failure (unchanged)
 */
int bbs_transfer_set_disk_path_up(struct bbs_node *node, const char *diskpath, char *buf, size_t len);

/*!
 * \brief Load transfer settings config
 * \note This is safe to call multiple times, but must be called before using settings at least once.
 *       Therefore, all modules that need these settings should call this function when loading.
 * \retval 0 on success, -1 on failure. If failure occurs, any dependent module must not
 *         attempt to make use of any file transfer functionality configured here.
 */
int bbs_transfer_config_load(void);
