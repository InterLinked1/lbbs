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
 * \brief Base64 encoding
 *
 */

/*!
 * \brief base64 encode a file by full file path
 * \param filename Path of input file to base64 encode
 * \param outputfile FILE* pointer into which output will be dumped
 * \param endl Line ending to use (CR LF or just LF)
 * \retval -1 on failure, 0 on success *
 */
int base64_encode_file(const char *filename, FILE *outputfile, const char *endl);

/*!
 * \brief base64 decode a string
 * \param data Data to decode
 * \param input_length Size of input
 * \param outlen Pointer to int in which output length will be stored
 * \returns decoded string on success, NULL on failure
 */
unsigned char *base64_decode(const unsigned char *data, int input_length, int *outlen);
