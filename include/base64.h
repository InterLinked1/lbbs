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
 * \brief Base64 encoding and decoding
 *
 */

/*!
 * \brief base64 encode a file by full file path
 * \param filename Path of input file to base64 encode
 * \param outputfile FILE* pointer into which output will be dumped
 * \param endl Line ending to use (CR LF or just LF)
 * \retval -1 on failure, 0 on success *
 */
int base64_encode_file(const char *restrict filename, FILE *restrict outputfile, const char *restrict endl);

/*!
 * \brief base64 decode a string
 * \param data Data to decode
 * \param input_length Size of input
 * \param outlen Pointer to int in which output length will be stored
 * \returns decoded string on success (which must be freed), NULL on failure
 */
unsigned char *base64_decode(const unsigned char *restrict data, int input_length, int *restrict outlen);

/*!
 * \brief base64 encode a buffer (which may contain NUL characters as part of the data itself)
 * \param data Data to encode
 * \param input_length Length of data
 * \param[out] outlen Length of encoded data
 * \retval encoded data on success (which must be freed), NULL on failure
*/
char *base64_encode(const char *restrict data, int input_length, int *restrict outlen);
