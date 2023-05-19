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
 * \brief Delimited read helper
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/*! \note This really should be opaque, but it's declared here so that callers can stack allocate it */
struct readline_data {
	/* Global data */
	char *buf;
	size_t len;
	int timeout;
	/* Internal pointers */
	char *pos;
	size_t left;
	size_t leftover;
	unsigned int waiting:1;
};

/*!
 * \brief Initialize a readline_data struct
 * \param rldata
 * \param buf Buffer to use for reading data. This should be large enough for at least the largest possible single input.
 * \param len Size of buf.
 */
void bbs_readline_init(struct readline_data *rldata, char *buf, size_t len);

/*!
 * \brief Read input from a file descriptor, up to a delimiter. This function handles reading partial inputs, multiple inputs, etc. automatically.
 * \param fd File descriptor from which to read
 * \param rldata Previously initialized using bbs_readline_init
 * \param delim A delimiter (can be multiple characters). CR LF is typical for most network applications.
 * \param timeout Timeout in ms for any call to poll()
 * \retval -2 on failure, -1 if read or poll returns 0, and number of bytes read in first input chunk otherwise, not including the delimiter.
 *         A return value of 0 means that only the delimiter was read.
 *         If a positive value is returned, the caller can read the input in the buffer passed to bbs_readline_init. It will be null terminated after the first input chunk,
 *         not including the delimiter.
 * \note The actual number of bytes read may be greater than the number of bytes returned. These bytes will be returned in subsequent calls to this function.
 */
int bbs_readline(int fd, struct readline_data *restrict rldata, const char *restrict delim, int timeout);

/*!
 * \brief Read exactly n bytes from a file descriptor and write them to another file descriptor
 * \param fd Source file descriptor
 * \param destfd Destination file descriptor
 * \param rldata
 * \param timeout Timeout for activity (applies to each read/poll, not overall)
 * \param n Number of bytes to read
 * \retval -1 on failure
 * \return number of bytes read
 * \note The written data is NOT NUL-terminated, this is a binary operation
 */
int bbs_readline_getn(int fd, int destfd, struct readline_data *restrict rldata, int timeout, size_t n);

/*!
 * \brief Append to a readline_data buffer
 * \param rldata
 * \param delim
 * \param buf Bytes to append. Does not need to be null terminated.
 * \param len Number of bytes to append.
 * \param[out] ready Whether a complete message is ready for processing.
 * \retval Number of bytes appended to buffer. May be less than len, if insufficient space is left in the internal buffer.
 */
int bbs_readline_append(struct readline_data *restrict rldata, const char *restrict delim, char *restrict buf, size_t len, int *restrict ready);
