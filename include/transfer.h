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

/* These cannot be bits, since they are used as array indices */
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
 * \brief Whether or not to display all home directories in directory listings of /home
 * \retval 1 if yes, 0 if no
 */
int bbs_transfer_show_all_home_dirs(void);

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
size_t bbs_transfer_max_upload_size(void);

/*!
 * \brief Get the path on disk for a user's home directory (~)
 * \param userid
 * \param[out] buf
 * \param len Size of buf
 * \retval 0 on success, -1 on failure
 * \note Calling this function implictly creates the directory if it does not already exist
 */
int bbs_transfer_home_dir(unsigned int userid, char *buf, size_t len);

/*!
 * \brief Initialize a home directory, if needed, for the currently authenticated user
 * \param node
 * \retval 0 on success, -1 on failure
 * \note This function should be called to autocreate a user's home directory if needed (e.g. for FTP, SFTP)
 */
int bbs_transfer_home_dir_init(struct bbs_node *node);

/*!
 * \brief Change directories to a user's home directory (~)
 * \param node
 * \param[out] buf Path on disk to home directory.
 * \param len
 * \retval 0 on success (directory written to buffer)
 * \retval -1 if failure or not authenticated
 */
int bbs_transfer_home_dir_cd(struct bbs_node *node, char *buf, size_t len);

/*!
 * \brief Set default directory on connection (home directory if authenticated, transfer root otherwise)
 * \param node
 * \param[out] buf
 * \param len
 * \retval 0 on success (directory written to buffer)
 * \retval -1 on failure
 */
int bbs_transfer_set_default_dir(struct bbs_node *node, char *buf, size_t len);

/*!
 * \brief Get the path on disk for a user's configuration directory (~/.config)
 * \param userid
 * \param[out] buf
 * \param len Size of buf
 * \retval 0 on success, -1 on failure
 * \note Calling this function implictly creates the directory if it does not already exist
 */
int bbs_transfer_home_config_dir(unsigned int userid, char *buf, size_t len);

/*!
 * \brief Get the path on disk of a subdirectory in a user's home directory
 * \param userid
 * \param name Name of subdirectory
 * \param[out] buf
 * \param len Size of buf
 * \retval 0 on success, -1 on failure
 * \note Calling this function DOES NOT implicitly create the directory, if it does not already exist
 */
int bbs_transfer_home_config_subdir(unsigned int userid, const char *name, char *buf, size_t len);

/*!
 * \brief Get the path on disk for a user's named configuration file
 * \param userid
 * \param name Name of configuration file in the configuration directory. By convention, SHOULD begin with a period (.)
 * \param[out] buf
 * \param len Size of buf
 * \retval 0 if configuration file exists, -1 on failure or if file does not exist
 */
int bbs_transfer_home_config_file(unsigned int userid, const char *name, char *buf, size_t len);

/*!
 * \brief Get the user-facing transfer path from a full disk path
 * \param node
 * \param diskpath
 * \param[out] buf
 * \param len Size of buf
 * \retval 0 on success
 * \retval -1 on failure
 */
int bbs_transfer_get_user_path(struct bbs_node *node, const char *diskpath, char *buf, size_t len);

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
 * \param current The current user path on disk
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
 * \param current The current user path on disk
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
 * \brief Whether or not file transfers are possible
 * \retval 1 if possible
 * \retval 0 if not possible
 */
int bbs_transfer_available(void);

/*!
 * \brief Load transfer settings config
 * \retval 0 on success, -1 on failure.
 */
int bbs_transfer_config_load(void);
