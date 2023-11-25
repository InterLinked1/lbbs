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
 * \brief ANSI escape sequences
 *
 */

/*!
 * \brief Strip all ANSI characters from a string and put the output in a new buffer
 * \param in A null terminated string. Any ANSI escape sequences will be removed from the output.
 * \param inlen Length of in
 * \param out Buffer in which the stripped string will be placed
 * \param outlen Size of out. Should be at least inlen, but no more than it.
 * \param strippedlen Will be set to the actual length of the stripped output, not including null terminator.
 * \retval 0 on success, -1 on failure
 */
int bbs_ansi_strip(const char *restrict in, size_t inlen, char *restrict out, size_t outlen, int *restrict strippedlen);
