/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2025, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 */

/*! \file
 *
 * \brief Email Message Generation
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

extern int send_count;

/*!
 * \brief Send a sample payload for the DATA command
 * \param clientfd
 * \param from
 * \retval 0 on success, -1 on failure
 */
int test_send_sample_body(int clientfd, const char *from);

#define test_send_message(clientfd, recipient) test_send_message_with_extra_bytes(clientfd, recipient, 0)

/*!
 * \brief Send a test email message to TEST_USER
 * \param clientfd Client file descriptor for SMTP transaction (should be connected to port 25)
 * \param recipient Recipient email
 * \param extrabytes Number of extra 'a' bytes to include
 * \retval 0 on success, -1 on failure
 */
int test_send_message_with_extra_bytes(int clientfd, const char *recipient, size_t extrabytes);

/*!
 * \brief Send n sample email messages to TEST_USER
 * \param recipient Recipient email
 * \param nummsg Number of messages to send
 * \retval 0 on success, nonzero on total or partial failure
 */
int test_make_messages(const char *recipient, int nummsg);

/*! \brief Ensure that any temp files were cleaned up */
#define ENSURE_TMP_QUEUE_FILES_CLEANED_UP() \
	if (system("! ls /tmp/smtpf* 2>/dev/null")) { \
		bbs_error("Resource leak: files exist matching path '/tmp/smtp*'\n"); \
		goto cleanup; \
	} \
	usleep(100000); /* The temp file created in handle_data is only deleted after the response */ \
	if (system("! ls /tmp/smtpd* 2>/dev/null")) { \
		bbs_error("Resource leak: files exist matching path '/tmp/smtp*'\n"); \
		goto cleanup; \
	}
