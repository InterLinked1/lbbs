/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief RFC 3977 Network News Transfer Protocol (NNTP)
 *
 * \note Supports RFC 4642 STARTTLS
 * \note Supports RFC 4643 AUTHINFO
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <sys/sendfile.h>
#include <dirent.h>

#include "include/tls.h"

#include "include/module.h"
#include "include/config.h"
#include "include/net.h"
#include "include/utils.h"
#include "include/node.h"
#include "include/auth.h"
#include "include/user.h"

#include "include/mod_mail.h"

/* NNTP ports */
/* Reading server */
#define DEFAULT_NNTP_PORT 119
#define DEFAULT_NNTPS_PORT 563
/* Transit server */
#define DEFAULT_NNSP_PORT 433

/*
 * If you are new to newsgroups (no pun intended),
 * here are a few resources to help you get started:
 *
 * - https://www.eternal-september.org/
 * - https://www.big-8.org/wiki/Newsgroup_Creation_FAQ#Can_I_propose_a_new_newsgroup_now.3F
 * - https://www.eyrie.org/~eagle/faqs/mod-pitfalls.html
 * - https://www.eyrie.org/~eagle/faqs/usenet-hier.html
 * - ftp://ftp.isc.org/pub/usenet/CONFIG/
 */

static int nntp_port = DEFAULT_NNTP_PORT;
static int nntps_port = DEFAULT_NNTPS_PORT;
static int nnsp_port = DEFAULT_NNSP_PORT;

static pthread_t nntp_listener_thread = -1;
static pthread_t nnsp_listener_thread = -1;

static int nntp_enabled = 1, nntps_enabled = 1, nnsp_enabled = 1;
static int nntp_socket = -1, nntps_socket = -1, nnsp_socket = -1;

static pthread_mutex_t nntp_lock;

static char newsdir[256] = "";
static char newsgroups_file[sizeof(newsdir) + STRLEN("/newsgroups")] = "";

static int require_login = 1;
static int require_secure_login = 0;
static int require_login_posting = 1;
static int min_priv_post = 1;
static unsigned int max_post_size = 100000; /* 100 KB should be plenty */

#define NNTP_MODE_TRANSIT 0
#define NNTP_MODE_READER 1

struct nntp_session {
	int rfd;
	int wfd;
	struct bbs_node *node;
	char *currentgroup;
	int currentarticle;
	char grouppath[512];
	char *user;
	char *post;
	char *fromheader;
	unsigned int postlen;
	unsigned int mode:1;	/* MODE (0 = transit, 1 = reader) */
	unsigned int inpost:1;
	unsigned int inpostheaders:1;
	unsigned int postfail:1;
	unsigned int secure:1;
	unsigned int dostarttls:1;
};

static void nntp_destroy(struct nntp_session *nntp)
{
	free_if(nntp->fromheader);
	free_if(nntp->user);
	free_if(nntp->post);
	free_if(nntp->currentgroup);
	UNUSED(nntp);
}

#undef dprintf
#define _nntp_send(nntp, fmt, ...) bbs_debug(4, "%p <= " fmt, nntp, ## __VA_ARGS__); dprintf(nntp->wfd, fmt, ## __VA_ARGS__);
#define nntp_send(nntp, code, fmt, ...) _nntp_send(nntp, "%d " fmt "\r\n", code, ## __VA_ARGS__)

#define REQUIRE_ARGS(s) \
	if (strlen_zero(s)) { \
		nntp_send(nntp, 501, "Arguments required"); \
		return 0; \
	}

static int build_newsgroup_path(const char *name, char *buf, size_t len)
{
	if (strstr(name, "..")) { /* Reject dangerous inputs */
		return -1;
	}
	snprintf(buf, len, "%s/%s", newsdir, name);
	if (eaccess(buf, R_OK)) {
		return -1; /* Doesn't exist */
	}
	return 0;
}

static int scan_newsgroup(const char *path, int *min, int *max, int *total)
{
	DIR *dir;
	struct dirent *entry;
	int fno = 0;

	*total = *min = *max = 0;

	if (!(dir = opendir(path))) {
		bbs_error("Error opening directory - %s: %s\n", path, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		int articleid;
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		*total += 1;
		if (!fno++) {
			*min = *max = atoi(entry->d_name);
			continue;
		}
		articleid = atoi(entry->d_name);
		if (articleid > *max) {
			*max = articleid;
		}
		if (!*min || articleid < *min) {
			*min = articleid;
		}
	}

	closedir(dir);
	return 0;
}

/*! \brief Cache newsgroup info in a file for LIST, GROUP, etc. The generated newsgroups_file can be sent as a response to LIST ACTIVE
 * Doing this once will be much more efficient at runtime, since messages are read far more often than they are posted. */
static int scan_newsgroups(void)
{
	struct dirent *entry, **entries;
	FILE *fp;
	int fno = 0;
	int subs;
	char fullpath[512];

	/* Overwrite anything currently in the file. */
	pthread_mutex_lock(&nntp_lock);
	fp = fopen(newsgroups_file, "w");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", newsgroups_file, strerror(errno));
		pthread_mutex_unlock(&nntp_lock);
		return -1;
	}
	/* Conduct an ordered traversal of all the directorys in the newsdir. */
	subs = scandir(newsdir, &entries, NULL, alphasort);
	if (subs < 0) {
		bbs_error("scandir(%s) failed: %s\n", newsdir, strerror(errno));
		pthread_mutex_unlock(&nntp_lock);
		return -1;
	}
	while (fno < subs && (entry = entries[fno++])) {
		char groupinfo[282];
		int min, max, total;
		char perm = 'y'; /* posting allowed: y, n, m (moderated) */
		if (entry->d_type != DT_DIR || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			free(entry);
			continue;
		}
		snprintf(fullpath, sizeof(fullpath), "%s/%s", newsdir, entry->d_name);
		scan_newsgroup(fullpath, &min, &max, &total);
		snprintf(groupinfo, sizeof(groupinfo), "%s %d %d %c", entry->d_name, min, max, perm);
		bbs_debug(4, "Loading newsgroup: %s\n", groupinfo);
		fprintf(fp, "%s\r\n", groupinfo);
		free(entry);
	}
	free(entries);
	fclose(fp);
	pthread_mutex_unlock(&nntp_lock);
	return 0;
}

static int nntp_traverse(const char *path, int (*on_file)(const char *dir_name, const char *filename, struct nntp_session *nntp, int number, int msgfilter, const char *msgidfilter), struct nntp_session *nntp, int msgfilter, const char *msgidfilter)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	int res, msgno;

	/* use scandir instead of opendir/readdir, so the listing is ordered */
	files = scandir(path, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			free(entry);
			continue;
		}
		/* Filename format is ARTICLEID_MESSAGEID */
		msgno = atoi(entry->d_name); /* atoi should stop at the _ */
		if ((res = on_file(path, entry->d_name, nntp, msgno, msgfilter, msgidfilter))) {
			free(entry);
			break; /* If the handler returns non-zero then stop */
		}
		free(entry);
	}
	free(entries);
	return res;
}

static int nntp_traverse2(const char *path, int (*on_file)(const char *dir_name, const char *filename, struct nntp_session *nntp, int number), struct nntp_session *nntp, int min, int max)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	int res, msgno;

	/* use scandir instead of opendir/readdir, so the listing is ordered */
	files = scandir(path, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			goto cleanup;
		}
		/* Filename format is ARTICLEID_MESSAGEID */
		msgno = atoi(entry->d_name); /* atoi should stop at the _ */
		if (msgno < min || msgno > max) {
			goto cleanup;
		}
		if ((res = on_file(path, entry->d_name, nntp, msgno))) {
			free(entry);
			break; /* If the handler returns non-zero then stop */
		}
cleanup:
		free(entry);
	}
	free(entries);
	return res;
}

static int sendfile_full(const char *filepath, int wfd)
{
	int fd, sent;
	off_t size, offset;

	fd = open(filepath, O_RDONLY, 0600);
	if (fd < 0) {
		bbs_error("open(%s) failed: %s\n", filepath, strerror(errno));
		return -1;
	}
	size = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	offset = 0;
	sent = sendfile(wfd, fd, &offset, size);
	close(fd);
	if (sent != size) {
		bbs_error("Wanted to write %lu bytes but only wrote %d?\n", size, sent);
		return -1;
	} else {
		bbs_debug(6, "Sent %d bytes to fd %d\n", sent, wfd);
	}
	return 0;
}

static int on_head(const char *dir_name, const char *filename, struct nntp_session *nntp, int number, int msgfilter, const char *msgidfilter)
{
	FILE *fp;
	char fullpath[256];
	const char *msgid;
	char msgbuf[1001]; /* Enough for longest possible line */

	if (msgfilter && number != msgfilter) { /* Filtering by article ID? */
		return 0;
	}

	msgid = strchr(filename, '_');
	if (!msgid++) {
		bbs_error("Invalid newsgroup article filename: %s\n", filename);
		return 0;
	}
	if (msgidfilter) { /* Message filtering by msgid? */
		if (strcmp(msgidfilter, msgid)) {
			return 0;
		}
	}

	snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_name, filename);
	fp = fopen(fullpath, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", fullpath, strerror(errno));
		return 0;
	}

	nntp_send(nntp, 221, "%d <%s> Headers follow", number, msgid);
	while ((fgets(msgbuf, sizeof(msgbuf), fp))) {
		if (!strcmp(msgbuf, "\r\n")) {
			break; /* End of headers, now begin counting */
		} else if (!strcmp(msgbuf, "\n")) { /* Broken line endings */
			bbs_error("File %s using LF line endings instead of CR LF?\n", fullpath);
			break;
		}
		_nntp_send(nntp, "%s", msgbuf); /* msgbuf already includes CR LF */
	}
	fclose(fp);
	_nntp_send(nntp, ".\r\n"); /* Termination character. */
	return 1; /* Stop traversal */
}

static int on_article(const char *dir_name, const char *filename, struct nntp_session *nntp, int number, int msgfilter, const char *msgidfilter)
{
	char fullpath[256];
	const char *msgid;

	if (msgfilter && number != msgfilter) { /* Filtering by article ID? */
		return 0;
	}

	msgid = strchr(filename, '_');
	if (!msgid++) {
		bbs_error("Invalid newsgroup article filename: %s\n", filename);
		return 0;
	}
	if (msgidfilter) { /* Message filtering by msgid? */
		if (strcmp(msgidfilter, msgid)) {
			return 0;
		}
	}

	snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_name, filename);
	nntp_send(nntp, 220, "%d <%s> Article follows", number, msgid);
	if (sendfile_full(fullpath, nntp->wfd)) {
		return -1; /* Just disconnect */
	}
	dprintf(nntp->wfd, ".\r\n"); /* Termination character. */
	return 1; /* Stop traversal */
}

static int find_header(FILE *fp, const char *header, char **ptr, char *buf, size_t len)
{
	int hdrlen = strlen(header);

	*ptr = NULL;
	rewind(fp);

	while (fgets(buf, len, fp)) {
		if (!strncasecmp(buf, header, hdrlen)) {
			char *start;
			start = buf + hdrlen;
			while (*start && isspace(*start)) { /* ltrim doesn't work here */
				start++;
			}
			bbs_strterm(start, '\r'); /* This should be sufficient, but do LF as well just in case */
			bbs_strterm(start, '\n');
			*ptr = start;
			return 0;
		}
	}
	/* Didn't find it */
	*buf = '\0';
	bbs_debug(3, "Didn't find any lines starting with '%s'\n", header);
	return -1;
}

static int on_xover(const char *dir_name, const char *filename, struct nntp_session *nntp, int number)
{
	FILE *fp;
	char fullpath[256];
	char subjbuf[256], authorbuf[256], datebuf[256], bytecountbuf[12] = "";
	char *subject = subjbuf, *author = authorbuf, *date = datebuf, *msgid = NULL, *references = NULL, *bytecount = bytecountbuf, *linecount = NULL;
	struct stat st;

	msgid = strchr(filename, '_');
	if (!msgid++) {
		bbs_error("Invalid newsgroup article filename: %s\n", filename);
		return 0;
	}

	snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_name, filename);

	fp = fopen(fullpath, "r");
	if (!fp) {
		bbs_error("fopen(%s) failed: %s\n", fullpath, strerror(errno));
		return 0;
	}

	find_header(fp, "Subject:", &subject, subjbuf, sizeof(subjbuf));
	find_header(fp, "From:", &author, authorbuf, sizeof(authorbuf));
	find_header(fp, "Date:", &date, datebuf, sizeof(datebuf));

	if (!stat(fullpath, &st)) {
		snprintf(bytecountbuf, sizeof(bytecountbuf), "%ld", st.st_size);
	}

	/* subject, author, date, message ID, references, byte count, line count */
	_nntp_send(nntp, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\r\n", number, S_IF(subject), S_IF(author), S_IF(date), S_IF(msgid), S_IF(references), S_IF(bytecount), S_IF(linecount));
	return 0;
}

static int do_post(struct nntp_session *nntp)
{
	char *newsgroups_header, *end;
	char *newsgroup, *newsgroups = NULL;
	char *dup, *uuid = NULL;
	int res = -1;

	/* Carefully extract just the Newsgroups header, without duplicating the entire message */
	newsgroups_header = strcasestr(nntp->post, "Newsgroups:");
	if (!newsgroups_header) {
		goto cleanup;
	}
	newsgroups_header += STRLEN("Newsgroups:");
	if (strlen_zero(newsgroups_header)) {
		goto cleanup;
	}

	end = strchr(newsgroups_header, '\r');
	if (!end) {
		goto cleanup;
	}
	newsgroups = strndup(newsgroups_header, end - newsgroups_header);
	if (!newsgroups) {
		goto cleanup;
	}

	/* Check the From header. */
	if (!nntp->fromheader) {
		goto cleanup;
	} else {
		const char *from = nntp->fromheader + 5; /* Skip From: */
		if (bbs_user_identity_mismatch(nntp->node->user, from)) {
			bbs_warning("Rejected NNTP post by user %d with identity %s\n", nntp->node->user ? nntp->node->user->id : 0, S_IF(from));
			nntp_send(nntp, 441, "Identity not allowed for posting");
			goto cleanup2;
		}
	}

	uuid = bbs_uuid(); /* Use same UUID for all newsgroups */
	if (!uuid) {
		goto cleanup;
	}

	/*! \todo On failure, should we keep track of Message ID to prevent duplicates on retries? But we assign the Message ID, so.... */
	/*! \todo Do we need to inject the header? snprintf(msgid, sizeof(msgid), "Message-ID: <%s@%s>", uuid, bbs_hostname()); */

	dup = newsgroups;
	ltrim(dup);
	while ((newsgroup = strsep(&dup, ","))) {
		char group[512];
		char filename[512];

		int min, max, total;
		int msgno;
		int fd;

		bbs_debug(5, "Processing newsgroup %s\n", newsgroup);
		if (build_newsgroup_path(newsgroup, group, sizeof(group))) {
			bbs_warning("Newsgroup '%s' does not exist\n", newsgroup); /* Try to deliver to any other groups listed */
			continue;
		}

		/* Atomically assign the new message ID. */
		pthread_mutex_lock(&nntp_lock);
		scan_newsgroup(group, &min, &max, &total);
		msgno = max + 1; /* Assign new message number, for this newsgroup. */
		pthread_mutex_unlock(&nntp_lock);

		/* The only way this file would already exist is if the client is posting to the same newsgroup twice.
		 * Ignore any such attempts.
		 * Check using current max UID since message would have already posted by now. */
		snprintf(filename, sizeof(filename), "%s/%s/%d_%s@%s", newsdir, newsgroup, msgno - 1, uuid, bbs_hostname());
		if (!eaccess(filename, R_OK)) {
			bbs_debug(2, "Ignoring duplicate post attempt\n");
			continue;
		}
		snprintf(filename, sizeof(filename), "%s/%s/%d_%s@%s", newsdir, newsgroup, msgno, uuid, bbs_hostname());
		fd = open(filename, O_CREAT | O_WRONLY, 0600);
		if (fd < 0) {
			bbs_warning("open(%s) failed: %s\n", filename, strerror(errno));
			continue;
		}
		bbs_std_write(fd, nntp->post, nntp->postlen);
		close(fd);
		res = 0;
		bbs_debug(3, "Posted article %s\n", filename);
	}

cleanup:
	if (res) {
		nntp_send(nntp, 441, "Posting failed");
	} else {
		/* Posting succeeded to at least one newsgroup. */
		nntp_send(nntp, 240, "Article received OK");
		scan_newsgroups(); /* Rebuild the newsgroups file so that LIST responses are accurate. */
	}
cleanup2:
	free_if(uuid);
	free_if(newsgroups);
	return 0;
}

static int parse_min_max(char *s, int *min, int *max, char sep)
{
	char *tmp;

	tmp = strchr(s, sep);
	if (!tmp) {
		*min = *max = atoi(s);
		return 0;
	}
	*tmp++ = '\0';
	*min = atoi(s);
	*max = atoi(tmp);
	return 0;
}

#define REQUIRE_GROUP() \
	if (!nntp->currentgroup) { \
		nntp_send(nntp, 412, "No newsgroup selected"); \
		return 0; \
	}

static int nntp_process(struct nntp_session *nntp, char *s)
{
	char *command;

	if (nntp->inpost) {
		int dlen;

		if (!strcmp(s, ".")) {
			nntp->inpost = 0;
			if (nntp->postfail) {
				nntp->postfail = 0;
				nntp_send(nntp, 441, "Posting failed%s", nntp->postlen >= max_post_size ? " (too large)" : "");
				return 0;
			}
			return do_post(nntp);
		} else if (*s == '.') {
			s++; /* If first character is a period but there's more data afterwards, skip the first period. */
		}

		if (nntp->postfail) {
			return 0; /* Corruption already happened, just ignore the rest of the message for now. */
		}

		dlen = strlen(s); /* s may be empty but will not be NULL */

		if (nntp->inpostheaders && STARTS_WITH(s, "From:")) {
			free_if(nntp->fromheader);
			nntp->fromheader = strdup(s);
		}

		if (!nntp->post) { /* First line */
			nntp->post = malloc(dlen + 3); /* Use malloc instead of strdup so we can tack on a CR LF */
			if (!nntp->post) {
				nntp->postfail = 1;
				return 0;
			}
			strcpy(nntp->post, s); /* Safe */
			strcpy(nntp->post + dlen, "\r\n"); /* Safe */
			nntp->postlen = dlen + 2;
		} else { /* Additional line */
			char *newstr;
			newstr = realloc(nntp->post, nntp->postlen + dlen + 3);
			if (!newstr) {
				nntp->postfail = 1;
				return 0;
			}
			strcpy(newstr + nntp->postlen, s);
			strcpy(newstr + nntp->postlen + dlen, "\r\n");
			nntp->postlen += dlen + 2;
			nntp->post = newstr;
		}
		if (nntp->inpostheaders && dlen == 2) {
			nntp->inpostheaders = 0; /* Got CR LF, end of headers */
		}
		if (nntp->postlen >= max_post_size) {
			nntp->postfail = 1;
		}
		return 0;
	}

	command = strsep(&s, " ");

	if (!strcasecmp(command, "QUIT")) {
		nntp_send(nntp, 205, "Bye!");
		return -1;
	} else if (!strcasecmp(command, "MODE")) {
		command = strsep(&s, " ");
		REQUIRE_ARGS(command);
		if (!strcasecmp(command, "READER")) {
			nntp->mode = NNTP_MODE_READER;
			nntp_send(nntp, 200, "Reader mode, posting permitted");
		} else {
			bbs_error("Unknown mode: %s\n", command);
		}
	} else if (!strcasecmp(command, "CAPABILITIES")) {
		/* This is very reminiscent of the POP3 CAPABILITIES command: */
		nntp_send(nntp, 101, "Capability list:");
		_nntp_send(nntp, "VERSION 2\r\n"); /* Must be first */
		/* Don't advertise MODE-READER, just READER */
		if (nntp->mode == NNTP_MODE_READER) {
			_nntp_send(nntp, "READER\r\n");
			_nntp_send(nntp, "POST\r\n");
			if (!nntp->secure) {
				_nntp_send(nntp, "STARTTLS\r\n");
			}
			_nntp_send(nntp, "LIST ACTIVE\r\n");
		} /*! \todo else if transit */
		_nntp_send(nntp, "XSECRET\r\n");
		if ((nntp->secure || !require_secure_login) && !bbs_user_is_registered(nntp->node->user)) {
			_nntp_send(nntp, "AUTHINFO USER\r\n");
			_nntp_send(nntp, "SASL PLAIN\r\n");
		}
		_nntp_send(nntp, "IMPLEMENTATION %s\r\n", BBS_SHORTNAME);
		_nntp_send(nntp, ".\r\n");
	} else if (!strcasecmp(command, "STARTTLS")) {
		if (!ssl_available()) {
			nntp_send(nntp, 580, "STARTTLS may not be used");
		} else if (!nntp->secure) {
			nntp_send(nntp, 382, "Ready to start TLS");
			nntp->dostarttls = 1;
		} else {
			nntp_send(nntp, 502, "Already using TLS");
		}
	} else if (!strcasecmp(command, "XSECRET")) {
		/* XSECRET appears in RFC 3977, in passing, but there is no actual documentation anywhere of it that I can find.
		 * My newsreader seems to use AUTHINFO instead, so if XSECRET/XENCRYPT are not widely used
		 * or are long deprecated, this can probably be removed. */
		int res;
		char *user, *pass, *domain;
		if (bbs_user_is_registered(nntp->node->user)) {
			nntp_send(nntp, 480, "Already authenticated"); /*! \todo Proper numeric response code? */
			return 0;
		}
		user = strsep(&s, " ");
		pass = s;
		REQUIRE_ARGS(user);
		REQUIRE_ARGS(pass);
		/* Strip the domain, if present,
		 * but the domain must match our domain, if present. */
		domain = strchr(user, '@');
		if (domain) {
			*domain++ = '\0';
			if (strlen_zero(domain) || strcmp(domain, bbs_hostname())) {
				nntp_send(nntp, 452, "Authorization rejected"); /*! \todo right code? */
				return 0;
			}
		}
		res = bbs_authenticate(nntp->node, user, pass);
		memset(pass, 0, strlen(pass)); /* Destroy the password from memory. */
		if (res) {
			nntp_send(nntp, 452, "Authorization rejected"); /*! \todo right code? */
			return 0;
		}
		nntp_send(nntp, 290, "Password for %s accepted", user); /*! \todo Is this really the right response code? */
	} else if ((nntp->secure || !require_secure_login) && !strcasecmp(command, "AUTHINFO")) {
		/* RFC 4643 AUTHINFO */
		/* If this command is not implemented and we send a 480,
		 * Thunderbirds will just go into a loop sending AUTH INFO commands, forever,
		 * even if AUTHINFO isn't listed as one of our capabilities.
		 * But RFC 4643 does say we MUST NOT response to an AUTHINFO with a 480, so that's probably why...
		 */
		int res;
		char *pass, *domain;

		if (bbs_user_is_registered(nntp->node->user)) {
			nntp_send(nntp, 502, "Already authenticated"); /*! \todo Proper numeric response code? */
			return 0;
		}

		command = strsep(&s, " ");
		if (!strcasecmp(command, "USER")) {
			free_if(nntp->user);
			REQUIRE_ARGS(s);
			nntp->user = strdup(s);
			nntp_send(nntp, 381, "Password required");
		} else if (!strcasecmp(command, "PASS")) {
			pass = s;
			if (!nntp->user) {
				nntp_send(nntp, 482, "Authentication commands issued out of sequence");
				return 0;
			}
			REQUIRE_ARGS(pass);
			/* Strip the domain, if present,
			 * but the domain must match our domain, if present. */
			domain = strchr(nntp->user, '@');
			if (domain) {
				*domain++ = '\0';
				if (strlen_zero(domain) || strcmp(domain, bbs_hostname())) {
					nntp_send(nntp, 452, "Authorization rejected"); /*! \todo right code? */
					return 0;
				}
			}
			res = bbs_authenticate(nntp->node, nntp->user, pass);
			free_if(nntp->user);
			memset(pass, 0, strlen(pass)); /* Destroy the password from memory. */
			if (res) {
				nntp_send(nntp, 481, "Authentication failed");
				return 0;
			}
			nntp_send(nntp, 281, "Authentication accepted");
		} else if (!strcasecmp(command, "SASL")) {
			/* RFC 4643 SASL */
			command = strsep(&s, " ");
			if (!strcasecmp(command, "PLAIN")) {
				unsigned char *decoded;
				char *authorization_id, *authentication_id, *password;

				decoded = bbs_sasl_decode(s, &authorization_id, &authentication_id, &password);
				if (!decoded) {
					return -1;
				}

				/* Can't use bbs_sasl_authenticate directly since we need to strip the domain */
				bbs_strterm(authentication_id, '@');
				res = bbs_authenticate(nntp->node, authentication_id, password);
				memset(password, 0, strlen(password)); /* Destroy the password from memory before we free it */
				free(decoded);

				if (res) {
					nntp_send(nntp, 481, "Authentication failed");
					return 0;
				}
				nntp_send(nntp, 281, "Authentication accepted");
			} else {
				/* RFC 4643 says we MUST implement the DIGEST-MD5 mechanism, but, well, we don't. */
				nntp_send(nntp, 503, "Mechanism not recognized");
			}
		} else {
			nntp_send(nntp, 501, "Unknown AUTHINFO command");
		}
	/* Must be authenticated, past this point, if so configured */
	} else if (require_login && !bbs_user_is_registered(nntp->node->user)) {
		nntp_send(nntp, 480, "Must authenticate first");
	} else if (!strcasecmp(command, "LIST")) {
		char *keyword, *wildmat; /* wildmat or argument */
		keyword = strsep(&s, " ");
		if (strlen_zero(keyword)) {
			keyword = "ACTIVE"; /* Default if no keyword provided */
		}
		if (!strcasecmp(keyword, "ACTIVE")) {
			/* List all groups available, in current state. */
			nntp_send(nntp, 215, "Newsgroup listing follows");
			/* name, high water mark, low water mark, current status (posting permitted: y/n/m (moderated) */
			if (sendfile_full(newsgroups_file, nntp->wfd)) {
				return -1; /* Just disconnect */
			}
			_nntp_send(nntp, ".\r\n");
		} else {
			bbs_error("Unsupported LIST keyword: %s\n", keyword);
		}
		UNUSED(wildmat);
	} else if (!strcasecmp(command, "GROUP")) {
		char group[512];
		int min, max, total;
		if (build_newsgroup_path(s, group, sizeof(group))) {
			nntp_send(nntp, 411, "%s is unknown", s);
			return 0;
		}
		/* Must not change current group unless we succeed */
		free_if(nntp->currentgroup);
		nntp->currentgroup = strdup(s);
		safe_strncpy(nntp->grouppath, group, sizeof(nntp->grouppath));
		scan_newsgroup(group, &min, &max, &total);
		nntp_send(nntp, 211, "%d %d %d %s", total, min, max, s);
		nntp->currentarticle = min;
	} else if (!strcasecmp(command, "HEAD")) {
		int msgid;
		REQUIRE_GROUP();
		REQUIRE_ARGS(s);
		msgid = atoi(s); /*! \todo BUGBUG If we're filtering by msg id (not article ID), but msg ID begins with a numeric, atoi will not return 0 */
		if (!msgid) {
			bbs_strterm(s, '>'); /* Strip <> from msgid */
			if (*s == '<') {
				s++;
			}
		}
		if (!nntp_traverse(nntp->grouppath, on_head, nntp, msgid, msgid ? NULL : s)) {
			nntp_send(nntp, 430, "No Such Article Found");
			return 0;
		}
	} else if (!strcasecmp(command, "ARTICLE")) {
		int msgid;
		REQUIRE_GROUP();
		REQUIRE_ARGS(s);
		msgid = atoi(s); /*! \todo BUGBUG If we're filtering by msg id (not article ID), but msg ID begins with a numeric, atoi will not return 0 */
		if (!msgid) {
			bbs_strterm(s, '>'); /* Strip <> from msgid */
			if (*s == '<') {
				s++;
			}
		}
		if (!nntp_traverse(nntp->grouppath, on_article, nntp, msgid, msgid ? NULL : s)) {
			nntp_send(nntp, 430, "No Such Article Found");
			return 0;
		}
	} else if (!strcasecmp(command, "POST")) {
		if (require_login_posting && !bbs_user_is_registered(nntp->node->user)) {
			nntp_send(nntp, 480, "Must authenticate first");
			return 0;
		} else if (min_priv_post > nntp->node->user->priv) {
			nntp_send(nntp, 502, "Insufficient privileges to post");
			return 0;
		}
		/* Group not required, the headers will say groups() to which message should be posted. */
		nntp_send(nntp, 340, "Input article; end with a period on its own line");
		nntp->inpost = 1;
		nntp->inpostheaders = 1;
	} else if (!strcasecmp(command, "XOVER")) {
		/* RFC 2980 XOVER */
		/* Thunderbird-based clients prefer XOVER to HEAD, and will only issue a HEAD if XOVER is not available. */
		/* XXX For some reason, Thunderbird-based clients bork on HEAD and don't show any body (and don't ask for it),
		 * but with XOVER, no matter how complete/incomplete the response, it'll issue an ARTICLE and get the whole thing properly.
		 * Personally, I think this command is especially stupid. HEAD ought to have been sufficient enough for everyone.
		 * Either way, this really needs to work properly: */
		int min, max;

		REQUIRE_GROUP();
		if (strlen_zero(s)) {
			parse_min_max(s, &min, &max, '-');
		} else {
			if (!nntp->currentarticle) {
				nntp_send(nntp, 420, "No article(s) selected");
				return 0;
			}
			min = max = nntp->currentarticle;
		}
		nntp_send(nntp, 224, "Overview information follows");
		nntp_traverse2(nntp->grouppath, on_xover, nntp, min, max);
		_nntp_send(nntp, ".\r\n");
	} else {
		/*! \todo add:
		 * RFC 2980 extensions
		 * Also see RFC 5536
		 */
		nntp_send(nntp, 500, "Unknown command");
	}
	return 0;
}

static void handle_client(struct nntp_session *nntp, SSL **sslptr)
{
	char buf[1001];
	int res;
	struct readline_data rldata;

	bbs_readline_init(&rldata, buf, sizeof(buf));
	/* 200 means client can post, 201 means not, but this is not a perfect distinction (see RFC) */
	nntp_send(nntp, 200, "%s Newsgroup Service Ready, posting permitted", bbs_hostname());

	for (;;) {
		res = bbs_fd_readline(nntp->rfd, &rldata, "\r\n", MIN_MS(5));
		if (res < 0) {
			res += 1; /* Convert the res back to a normal one. */
			/* We should NOT send any response to the client when terminating a connection due to timeout. */
			break;
		}
		if ((!strncasecmp(buf, "XSECRET", STRLEN("XSECRET")) || !strncasecmp(buf, "AUTHINFO PASS", STRLEN("AUTHINFO PASS")))) {
			/* Mask login to avoid logging passwords */
			if (*buf == 'X') {
				bbs_debug(6, "%p => XSECRET ******\n", nntp);
			} else {
				bbs_debug(6, "%p => AUTHINFO PASS ******\n", nntp);
			}
		} else {
			bbs_debug(6, "%p => %s\n", nntp, buf);
		}
		if (nntp_process(nntp, buf)) {
			break;
		}
		if (nntp->dostarttls) {
			/* RFC 4642 */
			bbs_debug(3, "Starting TLS\n");
			nntp->dostarttls = 0;
			*sslptr = ssl_new_accept(nntp->node->fd, &nntp->rfd, &nntp->wfd);
			if (!*sslptr) {
				bbs_error("Failed to create SSL\n");
				break; /* Just abort */
			}
			nntp->secure = 1;
			free_if(nntp->currentgroup);
			nntp->currentarticle = 0;
		}
	}
}

/*! \brief Thread to handle a single NNTP/NNTPS client */
static void nntp_handler(struct bbs_node *node, int secure, int reader)
{
#ifdef HAVE_OPENSSL
	SSL *ssl;
#endif
	int rfd, wfd;
	struct nntp_session nntp;

	/* Start TLS if we need to */
	if (secure) {
		ssl = ssl_new_accept(node->fd, &rfd, &wfd);
		if (!ssl) {
			bbs_error("Failed to create SSL\n");
			return;
		}
	} else {
		rfd = wfd = node->fd;
	}

	memset(&nntp, 0, sizeof(nntp));
	nntp.rfd = rfd;
	nntp.wfd = wfd;
	nntp.node = node;
	nntp.secure = secure;
	nntp.mode = reader;

	handle_client(&nntp, &ssl);

#ifdef HAVE_OPENSSL
	if (nntp.secure) { /* implies ssl */
		ssl_close(ssl);
		ssl = NULL;
	}
#endif
	nntp_destroy(&nntp);
}

static void *__nntp_handler(void *varg)
{
	struct bbs_node *node = varg;

	node->thread = pthread_self();
	bbs_node_begin(node);

	nntp_handler(node, !strcmp(node->protname, "NNTPS"), NNTP_MODE_READER);

	bbs_debug(3, "Node %d has ended its %s session\n", node->id, node->protname);
	bbs_node_exit(node); /* node is no longer a valid reference */
	return NULL;
}

static void *__nnsp_handler(void *varg)
{
	struct bbs_node *node = varg;

	node->thread = pthread_self();
	bbs_node_begin(node);

	nntp_handler(node, !strcmp(node->protname, "NNTPS"), NNTP_MODE_TRANSIT);

	bbs_debug(3, "Node %d has ended its %s session\n", node->id, node->protname);
	bbs_node_exit(node); /* node is no longer a valid reference */
	return NULL;
}

/*! \brief Single listener thread for NNTP and/or NNTPS */
static void *nntp_listener(void *unused)
{
	UNUSED(unused);
	bbs_tcp_listener2(nntp_socket, nntps_socket, "NNTP", "NNTPS", __nntp_handler, BBS_MODULE_SELF);
	return NULL;
}

static void *nnsp_listener(void *unused)
{
	UNUSED(unused);
	bbs_tcp_listener(nnsp_socket, "NNSP", __nnsp_handler, BBS_MODULE_SELF);
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg;

	cfg = bbs_config_load("net_nntp.conf", 1);
	if (!cfg) {
		return -1;
	}

	if (bbs_config_val_set_path(cfg, "general", "newsdir", newsdir, sizeof(newsdir))) {
		return -1;
	}
	snprintf(newsgroups_file, sizeof(newsgroups_file), "%s/newsgroups", newsdir);
	bbs_config_val_set_true(cfg, "general", "requirelogin", &require_login);
	bbs_config_val_set_true(cfg, "general", "requiresecurelogin", &require_secure_login);
	bbs_config_val_set_true(cfg, "general", "requireloginforposting", &require_login_posting);
	bbs_config_val_set_int(cfg, "general", "minpostpriv", &min_priv_post);
	bbs_config_val_set_uint(cfg, "general", "maxpostsize", &max_post_size);

	/* NNTP */
	bbs_config_val_set_true(cfg, "nntp", "enabled", &nntp_enabled);
	bbs_config_val_set_port(cfg, "nntp", "port", &nntp_port);

	/* NNTPS */
	bbs_config_val_set_true(cfg, "nntps", "enabled", &nntps_enabled);
	bbs_config_val_set_port(cfg, "nntps", "port", &nntps_port);

	/* NNSP */
	bbs_config_val_set_true(cfg, "nnsp", "enabled", &nnsp_enabled);
	bbs_config_val_set_port(cfg, "nnsp", "port", &nnsp_port);

	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	/* Since load_config returns 0 if no config, do this check here instead of in load_config: */
	if (!nntp_enabled && !nntps_enabled && !nnsp_enabled) {
		bbs_debug(3, "Neither NNTP nor NNTPS nor NNSP is enabled, declining to load\n");
		return -1; /* Nothing is enabled */
	}
	if (nntps_enabled && !ssl_available()) {
		bbs_error("TLS is not available, NNTPS may not be used\n");
		return -1;
	}
	if (strlen_zero(bbs_hostname())) {
		bbs_error("A BBS hostname in nodes.conf is required for newsgroup services\n");
		return -1;
	}

	pthread_mutex_init(&nntp_lock, NULL);

	if (scan_newsgroups()) {
		return -1;
	}

	/* If we can't start the TCP listeners, decline to load */
	if (nntp_enabled && bbs_make_tcp_socket(&nntp_socket, nntp_port)) {
		return -1;
	}
	if (nntps_enabled && bbs_make_tcp_socket(&nntps_socket, nntps_port)) {
		close_if(nntp_socket);
		return -1;
	}
	if (nnsp_enabled && bbs_make_tcp_socket(&nnsp_socket, nnsp_port)) {
		close_if(nntp_socket);
		close_if(nntps_socket);
		return -1;
	}

	if (bbs_pthread_create(&nntp_listener_thread, NULL, nntp_listener, NULL)) {
		bbs_error("Unable to create NNTP listener thread.\n");
		close_if(nntp_socket);
		close_if(nntps_socket);
		return -1;
	} else if (bbs_pthread_create(&nnsp_listener_thread, NULL, nnsp_listener, NULL)) {
		bbs_error("Unable to create SMTP MSA listener thread.\n");
		close_if(nnsp_socket);
		close_if(nntp_socket);
		close_if(nntps_socket);
		pthread_cancel(nntp_listener_thread);
		pthread_kill(nntp_listener_thread, SIGURG);
		bbs_pthread_join(nntp_listener_thread, NULL);
		return -1;
	}

	if (nntp_enabled) {
		bbs_register_network_protocol("NNTP", nntp_port);
	}
	if (nntps_enabled) {
		bbs_register_network_protocol("NNTPS", nntps_port);
	}
	if (nnsp_enabled) {
		bbs_register_network_protocol("NNSP", nnsp_port);
	}
	return 0;
}

static int unload_module(void)
{
	pthread_cancel(nntp_listener_thread);
	pthread_kill(nntp_listener_thread, SIGURG);
	bbs_pthread_join(nntp_listener_thread, NULL);
	pthread_cancel(nnsp_listener_thread);
	pthread_kill(nnsp_listener_thread, SIGURG);
	bbs_pthread_join(nnsp_listener_thread, NULL);
	if (nntp_enabled) {
		bbs_unregister_network_protocol(nntp_port);
		close_if(nntp_socket);
	}
	if (nntps_enabled) {
		bbs_unregister_network_protocol(nntps_port);
		close_if(nntps_socket);
	}
	if (nnsp_enabled) {
		bbs_unregister_network_protocol(nnsp_port);
		close_if(nnsp_socket);
	}
	pthread_mutex_destroy(&nntp_lock);
	return 0;
}

BBS_MODULE_INFO_STANDARD("RFC3977 NNTP/NNSP");
