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
 * \brief cURL
 *
 */

#define HTTP_RESPONSE_SUCCESS(code) (code / 100 == 2)

struct bbs_curl {
	/* Input fields */
	const char *url;			/*!< URL to request */
	const char *postfields;		/*!< POST request body */
	/* Output fields */
	int http_code;
	char *response;				/*!< Response body */
	/* Input flags */
	unsigned int forcefail:1;	/* Return failure if return code is not a success (2xx) code */
};

/*! \note Doesn't free acurl itself, just dynamically allocated things inside it */
void bbs_curl_free(struct bbs_curl *c);

/*! \brief HTTP GET request */
int bbs_curl_get(struct bbs_curl *c);

/*!
 * \brief Make an HTTP GET request, saving the output to a file
 */
int bbs_curl_get_file(struct bbs_curl *c, const char *filename);

/*! \brief HTTP POST request */
int bbs_curl_post(struct bbs_curl *c);

/*! \brief Shut down cURL */
int bbs_curl_shutdown(void);

/*! \brief Initialize cURL */
int bbs_curl_init(void);
