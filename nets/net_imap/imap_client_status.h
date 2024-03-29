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
 * \brief Remote IMAP STATUS
 *
 */

char *remove_size(char *restrict s);

ssize_t remote_status(struct imap_client *client, const char *remotename, const char *items, int size);

int imap_client_send_converted_status_response(struct imap_client *client, const char *remotename, const char *response);
