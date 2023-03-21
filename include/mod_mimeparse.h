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
 * \brief MIME Parser Supplements for IMAP Server
 *
 */

/*!
 * \brief Generate the BODY/BODYSTRUCTURE data item for FETCH responses
 * \param itemname BODY or BODYSTRUCTURE
 * \param file File containing email message
 * \returns NULL on failure, BODYSTRUCTURE text on success, which must be be freed using free()
 */
char *mime_make_bodystructure(const char *itemname, const char *file);
