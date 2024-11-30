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
 * \brief maildir++ interface
 *
 */

/* Forward declaration for imap_uidsort */
#include <dirent.h>

/*! \brief Wrapper around uidsort */
int imap_uidsort(const struct dirent **da, const struct dirent **db);

/*!
 * \brief Translate an IMAP directory path to the full path of the IMAP mailbox on disk
 * \param imap
 * \param directory The mailbox name (a misnomer, it's not referring to any actual directory path)
 * \param buf
 * \param len
 * \param[out] acl
 * \retval 0 on success, -1 on failure
 */
int imap_translate_dir(struct imap_session *imap, const char *directory, char *buf, size_t len, int *acl);

/*! \brief Same as imap_translate_dir, but do not update the currently active mbox */
int imap_translate_dir_readonly(struct imap_session *imap, const char *directory, char *buf, size_t len, int *acl);

/*! \brief Set the current maildir (e.g. SELECT, EXAMINE) */
int set_maildir(struct imap_session *imap, const char *mailbox);

/*! \brief Set a maildir without making it the current maildir (e.g. STATUS) */
int set_maildir_readonly(struct imap_session *imap, struct imap_traversal *traversal, const char *mailbox);

long parse_modseq_from_filename(const char *filename, unsigned long *modseq);

int parse_size_from_filename(const char *filename, unsigned long *size);

/*! \brief Find the disk filename of a message, given its sequence number or UID in a cur maildir folder */
int imap_msg_to_filename(const char *directory, int seqno, unsigned int uid, char *buf, size_t len);
