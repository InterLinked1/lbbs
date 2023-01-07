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
