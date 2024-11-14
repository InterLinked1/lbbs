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

struct bbs_mime_message;

/*!
 * \brief Create a MIME message structure by parsing a message file
 * \param filename Path to email message
 * \return NULL on failure, opaque MIME structure on success which must be destroyed using bbs_mime_message_parse
 */
struct bbs_mime_message *bbs_mime_message_parse(const char *filename) __attribute__((nonnull (1)));

/*!
 * \brief Destroy a MIME message structure
 */
void bbs_mime_message_destroy(struct bbs_mime_message *mime) __attribute__((nonnull (1)));

/*!
 * \brief Generate the BODY/BODYSTRUCTURE data item for FETCH responses
 * \param mime
 * \returns NULL on failure, BODYSTRUCTURE text on success, which must be be freed using free()
 */
char *bbs_mime_make_bodystructure(struct bbs_mime_message *mime) __attribute__((nonnull (1)));

enum mime_part_filter {
	MIME_PART_FILTER_ALL = 0,		/* Retrieve the entire part */
	MIME_PART_FILTER_MIME,			/* Retrieve just the MIME of the part */
	MIME_PART_FILTER_HEADERS,		/* Retrieve the headers, but only if the part's Content-Type is message/rfc822 */
	MIME_PART_FILTER_TEXT,			/* Retrieve the text, but only if the part's Content-Type is message/rfc822 */
};

/*!
 * \brief Retrieve a particular part of the body, by part specification
 * \param mime
 * \param spec Part specification, e.g. 2.3. This should be ONLY the part number portion of the spec (e.g. not including .MIME, .TEXT, etc.)
 * \param[out] outlen Length of returned part, if return value is non-NULL
 * \param[in] filter What to retrieve and return
 * \returns NULL on failure, requested section on success, which must be freed using free()
 */
char *bbs_mime_get_part(struct bbs_mime_message *mime, const char *spec, size_t *restrict outlen, enum mime_part_filter filter) __attribute__((nonnull (1, 2, 3)));
