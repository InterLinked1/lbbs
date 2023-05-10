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

#include "include/stringlist.h"
#include "include/module.h"
#include "include/config.h"
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

static int nntp_enabled = 1, nntps_enabled = 1, nnsp_enabled = 1;

static pthread_mutex_t nntp_lock;

static char newsdir[256] = "";
static char newsgroups_file[sizeof(newsdir) + STRLEN("/newsgroups")] = "";

/* Relay in */
static int requirerelaytls = 1;

/* Relay out */
static unsigned int relayfrequency = 3600;
static unsigned int relaymaxage = 86400;

static int require_login = 1;
static int require_secure_login = 0;
static int require_login_posting = 1;
static int min_priv_post = 1;
static unsigned int max_post_size = 100000; /* 100 KB should be plenty */

#define NNTP_MODE_TRANSIT 0
#define NNTP_MODE_READER 1

static struct stringlist inpeers;
static struct stringlist outpeers;

struct nntp_session {
	int rfd;
	int wfd;
	struct bbs_node *node;
	char *currentgroup;
	int currentarticle;
	int nextlastarticle;
	char grouppath[512];
	char template[64];
	char *user;
	FILE *fp;
	char *newsgroups;
	char *fromheader;
	char *articleid;
	char *rxarticleid;
	unsigned int postlen;
	unsigned int mode:1;	/* MODE (0 = transit, 1 = reader) */
	unsigned int inpost:1;
	unsigned int inpostheaders:1;
	unsigned int postfail:1;
	unsigned int secure:1;
	unsigned int dostarttls:1;
};

static void nntp_reset_data(struct nntp_session *nntp)
{
	free_if(nntp->newsgroups);
	if (nntp->fp) {
		fclose(nntp->fp);
		nntp->fp = NULL;
		if (unlink(nntp->template)) {
			bbs_error("Failed to delete %s: %s\n", nntp->template, strerror(errno));
		}
	}
}

static void nntp_destroy(struct nntp_session *nntp)
{
	nntp_reset_data(nntp);
	free_if(nntp->rxarticleid);
	free_if(nntp->articleid);
	free_if(nntp->fromheader);
	free_if(nntp->user);
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
	/* Conduct an ordered traversal of all the directories in the newsdir. */
	subs = scandir(newsdir, &entries, NULL, alphasort);
	if (subs < 0) {
		bbs_error("scandir(%s) failed: %s\n", newsdir, strerror(errno));
		fclose(fp);
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
	int res = 0, msgno;

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
	int res = 0;

	/* use scandir instead of opendir/readdir, so the listing is ordered */
	files = scandir(path, &entries, NULL, alphasort);
	if (files < 0) {
		bbs_error("scandir(%s) failed: %s\n", path, strerror(errno));
		return -1;
	}
	while (fno < files && (entry = entries[fno++])) {
		int msgno;
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

static int on_last(const char *dir_name, const char *filename, struct nntp_session *nntp, int number)
{
	UNUSED(dir_name);
	UNUSED(filename);
	/* Keep going since each match is higher than the previous one. */
	if (nntp->currentarticle != number) {
		nntp->nextlastarticle = number;
	}
	return 0;
}

static int on_next(const char *dir_name, const char *filename, struct nntp_session *nntp, int number)
{
	UNUSED(dir_name);
	UNUSED(filename);
	/* We go in order, so stop on first match */
	if (number > nntp->currentarticle) {
		nntp->nextlastarticle = number;
		return 1;
	}
	return 0;
}

static int on_find_article(const char *dir_name, const char *filename, struct nntp_session *nntp, int number)
{
	const char *msgid = strchr(filename, '_');
	UNUSED(dir_name);
	UNUSED(number);
	if (!msgid) {
		bbs_error("Invalid filename: %s\n", filename);
		return -1;
	}
	nntp->articleid = strdup(filename); /* This callback should only execute at most once for any traversal */
	return 1;
}

/*! \brief Check if any newsgroup(s) contains an article with the specified article ID */
static int article_id_exists(const char *articleid)
{
	DIR *dir, *dir2;
	struct dirent *entry;
	char fulldir[512];
	int exists = 0;

	/* Order of newsgroup traversal doesn't matter.
	 * In fact, order of traversal within each newsgroup doesn't matter either.
	 * So use opendir instead of scandir. */

	bbs_debug(3, "Checking if article <%s> already exists\n", articleid);
	if (*articleid == '<') {
		bbs_warning("Malformed article ID: %s\n", articleid); /* Bug in calling function */
	}

	if (!(dir = opendir(newsdir))) {
		bbs_error("Error opening directory - %s: %s\n", newsdir, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type != DT_DIR || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		/* Check this directory */
		snprintf(fulldir, sizeof(fulldir), "%s/%s", newsdir, entry->d_name);
		dir2 = opendir(fulldir);
		if (!dir2) {
			bbs_error("Error opening directory - %s: %s\n", fulldir, strerror(errno));
			continue;
		}
		while ((entry = readdir(dir2)) != NULL) {
			if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
				continue;
			}
			if (strstr(entry->d_name, articleid)) {
				exists = 1;
				break;
			}
		}
		closedir(dir2);
		if (exists) {
			break;
		}
	}

	closedir(dir);
	return exists;
}

static char *get_article_id(struct nntp_session *nntp, int number)
{
	free_if(nntp->articleid);
	nntp_traverse2(nntp->grouppath, on_find_article, nntp, number, number);
	return nntp->articleid;
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
	sent = (int) sendfile(wfd, fd, &offset, (size_t) size);
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

static int on_body(const char *dir_name, const char *filename, struct nntp_session *nntp, int number, int msgfilter, const char *msgidfilter)
{
	char fullpath[256];
	char linebuf[1001];
	const char *msgid;
	FILE *fp;

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

	/* Read the file until the first CR LF CR LF (end of headers) */
	fp = fopen(fullpath, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", fullpath, strerror(errno));
		return -1;
	}
	/* Skip headers */
	while ((fgets(linebuf, sizeof(linebuf), fp))) {
		/* fgets does store the newline, so line should end in CR LF */
		if (!strcmp(linebuf, "\r\n")) {
			break; /* End of headers */
		}
	}
	/* This is the body */
	nntp_send(nntp, 220, "%d <%s>", number, msgid);
	/* XXX Easy, but not as efficient as calculating offset and then using sendfile... */
	while ((fgets(linebuf, sizeof(linebuf), fp))) {
		dprintf(nntp->wfd, "%s", linebuf);
	}
	fclose(fp);

	dprintf(nntp->wfd, ".\r\n"); /* Termination character. */
	return 1; /* Stop traversal */
}

static int find_header(FILE *fp, const char *header, char **ptr, char *buf, size_t len)
{
	size_t hdrlen = strlen(header);

	*ptr = NULL;
	rewind(fp);

	while (fgets(buf, (int) len, fp)) {
		if (!strncasecmp(buf, header, hdrlen)) {
			char *start;
			start = buf + hdrlen;
			while (*start && isspace(*start)) { /* ltrim doesn't work here */
				start++;
			}
			bbs_term_line(start); /* CR should be sufficient, but do LF as well just in case */
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
	char fullpath[3 * 256];
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

static int do_post(struct nntp_session *nntp, const char *srcfilename)
{
	char *newsgroup, *newsgroups = NULL;
	char *uuid = NULL;
	int res = -1;
	int srcfd;

	if (!nntp->newsgroups) {
		goto cleanup;
	}

	if (nntp->mode == NNTP_MODE_READER) {
		/* Check the From header. */
		if (!nntp->fromheader) {
			goto cleanup;
		} else {
			const char *from = nntp->fromheader + STRLEN("From:");
			ltrim(from);
			if (bbs_user_identity_mismatch(nntp->node->user, from)) {
				bbs_warning("Rejected NNTP post by user %d with identity %s\n", nntp->node->user ? nntp->node->user->id : 0, S_IF(from));
				nntp_send(nntp, 441, "Identity not allowed for posting");
				goto cleanup2;
			}
		}
		uuid = bbs_uuid(); /* Use same UUID (and by extension, the same Article ID) for all newsgroups */
		if (!uuid) {
			goto cleanup;
		}
	} else { /* else if TRANSIT, just trust what the other end says (presumably the original server validated the identity). */
		/* Could be a race condition, maybe we didn't have the article when the client said IHAVE,
		 * but now we do (possibly from some other server). Check again. */
		if (article_id_exists(nntp->rxarticleid)) {
			nntp_send(nntp, 437, "Duplicate; do not resend");
			return 0;
		}
		if (strlen_zero(nntp->rxarticleid)) {
			bbs_error("Posting article ID is invalid: %s\n", nntp->rxarticleid);
		}
	}

	/*! \todo On failure, should we keep track of Message ID to prevent duplicates on retries? But we assign the Message ID, so.... */
	/*! \todo Do we need to inject the header? snprintf(msgid, sizeof(msgid), "Message-ID: <%s@%s>", uuid, bbs_hostname()); */

	srcfd = open(srcfilename, O_RDONLY);
	if (srcfd < 0) {
		bbs_error("Failed to open %s: %s\n", srcfilename, strerror(errno));
		goto cleanup;
	}

	newsgroups = nntp->newsgroups + STRLEN("Newsgroups:");
	ltrim(newsgroups);
	while ((newsgroup = strsep(&newsgroups, ","))) {
		char group[512];
		char filename[512];

		int min, max, total;
		int msgno;
		int fd;

		bbs_debug(5, "Processing newsgroup %s (%s)\n", newsgroup, nntp->mode == NNTP_MODE_READER ? "READER" : "TRANSIT");
		if (build_newsgroup_path(newsgroup, group, sizeof(group))) {
			if (nntp->mode == NNTP_MODE_READER) {
				bbs_warning("Newsgroup '%s' does not exist\n", newsgroup); /* Try to deliver to any other groups listed */
			} else if (nntp->mode == NNTP_MODE_TRANSIT) {
				bbs_debug(3, "Newsgroup '%s' does not exist\n", newsgroup); /* Try to deliver to any other groups listed */
			}
			continue;
		}

		/* Atomically assign the new message ID. */
		pthread_mutex_lock(&nntp_lock); /* Could really just be a per-newsgroup lock, but we don't have such locks at the moment. */
		scan_newsgroup(group, &min, &max, &total);
		msgno = max + 1; /* Assign new message number, for this newsgroup. */
		/* The only way this file would already exist is if the client is posting to the same newsgroup twice.
		 * Ignore any such attempts.
		 * Check using current max UID since message would have already posted by now. */
		if (nntp->mode == NNTP_MODE_READER) {
			snprintf(filename, sizeof(filename), "%s/%s/%d_%s@%s", newsdir, newsgroup, msgno - 1, uuid, bbs_hostname());
		} else {
			snprintf(filename, sizeof(filename), "%s/%s/%d_%s", newsdir, newsgroup, msgno - 1, nntp->rxarticleid);
		}
		if (!eaccess(filename, R_OK)) {
			bbs_debug(2, "Ignoring duplicate post attempt\n");
			pthread_mutex_unlock(&nntp_lock);
			continue;
		}
		if (nntp->mode == NNTP_MODE_READER) {
			snprintf(filename, sizeof(filename), "%s/%s/%d_%s@%s", newsdir, newsgroup, msgno, uuid, bbs_hostname());
		} else {
			snprintf(filename, sizeof(filename), "%s/%s/%d_%s", newsdir, newsgroup, msgno, nntp->rxarticleid);
		}
		fd = open(filename, O_CREAT | O_WRONLY, 0600);
		if (fd < 0) {
			bbs_warning("open(%s) failed: %s\n", filename, strerror(errno));
			pthread_mutex_unlock(&nntp_lock);
			continue;
		}
		bbs_copy_file(srcfd, fd, 0, (int) nntp->postlen);
		close(fd);
		pthread_mutex_unlock(&nntp_lock);
		res = 0;
		bbs_debug(3, "Posted article %s to newsgroup %s\n", filename, newsgroup);
	}
	close(srcfd);

cleanup:
	if (res) {
		/* Should we instead do permanent error for transit (437), if newsgroup doesn't exist? But what if it's added later? */
		nntp_send(nntp, nntp->mode == NNTP_MODE_READER ? 441 : 436, "Posting failed");
	} else {
		/* Posting succeeded to at least one newsgroup. */
		nntp_send(nntp, nntp->mode == NNTP_MODE_READER ? 240 : 235, "Article received OK");
		scan_newsgroups(); /* Rebuild the newsgroups file so that LIST responses are accurate. */
	}
cleanup2:
	free_if(uuid);
	free_if(newsgroups);
	nntp->postlen = 0;
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

static int sender_match(struct nntp_session *nntp, const char *s)
{
	bbs_debug(6, "Checking peer %s/%s against %s\n", nntp->node->ip, bbs_username(nntp->node->user), s);
	/* Could have:
	 * user=sysop
	 * ip=127.0.0.1
	 * ip=127.0.0.1/32
	 * host=example.com
	 */
	if (!strchr(s, '.')) {
		/* It's a username */
		if (bbs_user_is_registered(nntp->node->user) && !strcmp(bbs_username(nntp->node->user), s)) {
			bbs_debug(5, "Authorized by username match: %s\n", s);
			return 1;
		}
	} else {
		char ip[256];
		/* It's an IP address or hostname. */
		if (strchr(s, '/')) {
			/* It's a CIDR range. Do a direct comparison. */
			if (bbs_cidr_match_ipv4(nntp->node->ip, s)) {
				bbs_debug(5, "Authorized by CIDR match: %s\n", s);
				return 1;
			}
			return 0;
		}
		/* Resolve the hostname (if it is one) to an IP, then do a direct comparison. */
		bbs_resolve_hostname(s, ip, sizeof(ip));
		if (!strcmp(ip, nntp->node->ip)) {
			bbs_debug(5, "Authorized by IP match: %s -> %s\n", s, ip);
			return 1;
		}
	}
	return 0;
}

static int sender_authorized(struct nntp_session *nntp)
{
	const char *s;
	struct stringitem *i = NULL;
	RWLIST_RDLOCK(&inpeers);
	while ((s = stringlist_next(&inpeers, &i))) {
		if (sender_match(nntp, s)) {
			break;
		}
	}
	RWLIST_UNLOCK(&inpeers);
	return s ? 1 : 0;
}

#define REQUIRE_GROUP() \
	if (!nntp->currentgroup) { \
		nntp_send(nntp, 412, "No newsgroup selected"); \
		return 0; \
	}

static int nntp_process(struct nntp_session *nntp, char *s, int len)
{
	char *command;

	if (nntp->inpost) {
		int res;
		if (!strcmp(s, ".")) {
			nntp->inpost = 0;
			if (nntp->postfail) {
				nntp->postfail = 0;
				if (nntp->mode == NNTP_MODE_TRANSIT) {
					if (nntp->inpostheaders || nntp->postlen >= max_post_size) {
						/* Permanent error */
						nntp_send(nntp, 437, "Transfer rejected (%s); do not retry", nntp->inpostheaders ? "article mismatch" : "too large");
					} else {
						nntp_send(nntp, 436, "Transfer not possible; try again later"); /* Temporary error */
					}
				} else {
					nntp_send(nntp, 441, "Posting failed%s", nntp->postlen >= max_post_size ? " (too large)" : "");
				}
				return 0;
			}
			fclose(nntp->fp);
			nntp->fp = NULL;
			res = do_post(nntp, nntp->template);
			unlink(nntp->template);
			return res;
		}

		if (nntp->postfail) {
			return 0; /* Corruption already happened, just ignore the rest of the message for now. */
		}

		if (nntp->inpostheaders) {
			if (STARTS_WITH(s, "From:")) {
				REPLACE(nntp->fromheader, s);
			} else if (nntp->mode == NNTP_MODE_TRANSIT && STARTS_WITH(s, "Message-ID:")) {
				/* The article better be the article that the other server said it was in IHAVE */
				if (!strstr(s, nntp->rxarticleid)) { /* XXX What if it's a substring? */
					nntp->postfail = 1;
					return 0;
				}
			} else if (STARTS_WITH(s, "Newsgroups:")) {
				REPLACE(nntp->newsgroups, s);
			} else if (!len) {
				nntp->inpostheaders = 0; /* Got CR LF, end of headers */
			}
		}

		if (nntp->postlen + (unsigned int) len >= max_post_size) {
			nntp->postfail = 1;
			nntp->postlen = max_post_size; /* This isn't really true, this is so we can detect that the message was too large. */
		}

		res = bbs_append_stuffed_line_message(nntp->fp, s, (size_t) len); /* Should return len + 2, unless it was byte stuffed, in which case it'll be len + 1 */
		if (res < 0) {
			nntp->postfail = 1;
		}
		nntp->postlen += (unsigned int) res;
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
		} else if (!strcasecmp(command, "READER")) {
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
		if (!nntp->secure) {
			_nntp_send(nntp, "STARTTLS\r\n");
		}
		if (nntp->mode == NNTP_MODE_READER) {
			_nntp_send(nntp, "READER\r\n");
			_nntp_send(nntp, "POST\r\n");
			_nntp_send(nntp, "LIST ACTIVE\r\n");
		} else {
			_nntp_send(nntp, "IHAVE\r\n");
			_nntp_send(nntp, "MODE-READER\r\n");
		}
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
	} else if (!strcasecmp(command, "DATE")) {
		char datestr[15];
		time_t timenow;
		struct tm nowtime;
		timenow = (int) time(NULL);
		gmtime_r(&timenow, &nowtime);
		strftime(datestr, sizeof(datestr), "%Y%m%d%H%M%S", &nowtime); /* yyyymmddhhmmss */
		nntp_send(nntp, 111, "%s", datestr);
	} else if (!strcasecmp(command, "HELP")) {
		nntp_send(nntp, 100, "Help text follows");
		/* XXX Could add descriptions too */
		_nntp_send(nntp, "QUIT\r\n");
		_nntp_send(nntp, "MODE\r\n");
		_nntp_send(nntp, "DATE\r\n");
		_nntp_send(nntp, "HELP\r\n");
		_nntp_send(nntp, "CAPABILITIES\r\n");
		_nntp_send(nntp, "STARTTLS\r\n");
		_nntp_send(nntp, "XSECRET\r\n");
		_nntp_send(nntp, "AUTHINFO\r\n");
		_nntp_send(nntp, "USER\r\n");
		_nntp_send(nntp, "PASS\r\n");
		_nntp_send(nntp, "SASL\r\n");
		_nntp_send(nntp, "LIST, LIST.ACTIVE\r\n");
		_nntp_send(nntp, "GROUP\r\n");
		_nntp_send(nntp, "XOVER\r\n");
		_nntp_send(nntp, "HEAD\r\n");
		_nntp_send(nntp, "ARTICLE\r\n");
		_nntp_send(nntp, "BODY\r\n");
		_nntp_send(nntp, "LAST\r\n");
		_nntp_send(nntp, "NEXT\r\n");
		_nntp_send(nntp, "POST\r\n");
		_nntp_send(nntp, "IHAVE\r\n");
		_nntp_send(nntp, ".\r\n");
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
		bbs_memzero(pass, strlen(pass)); /* Destroy the password from memory. */
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
			bbs_memzero(pass, strlen(pass)); /* Destroy the password from memory. */
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
				bbs_memzero(password, strlen(password)); /* Destroy the password from memory before we free it */
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
	} else if (nntp->mode == NNTP_MODE_READER && require_login && !bbs_user_is_registered(nntp->node->user)) {
		nntp_send(nntp, 480, "Must authenticate first");
	} else if (!strcasecmp(command, "LIST")) {
		const char *keyword;
		char *wildmat; /* wildmat or argument */
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
	} else if (nntp->mode == NNTP_MODE_READER && !strcasecmp(command, "GROUP")) {
		char group[512];
		int min, max, total;
		if (build_newsgroup_path(s, group, sizeof(group))) {
			nntp_send(nntp, 411, "%s is unknown", s);
			return 0;
		}
		/* Must not change current group unless we succeed */
		REPLACE(nntp->currentgroup, s);
		safe_strncpy(nntp->grouppath, group, sizeof(nntp->grouppath));
		scan_newsgroup(group, &min, &max, &total);
		nntp_send(nntp, 211, "%d %d %d %s", total, min, max, s);
		nntp->currentarticle = min;
	} else if (nntp->mode == NNTP_MODE_READER && !strcasecmp(command, "XOVER")) {
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
	} else if (nntp->mode == NNTP_MODE_READER && !strcasecmp(command, "HEAD")) {
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
			nntp_send(nntp, msgid ? 423 : 430, "No Such Article Found");
			return 0;
		}
	} else if (nntp->mode == NNTP_MODE_READER && !strcasecmp(command, "ARTICLE")) {
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
			nntp_send(nntp, msgid ? 423 : 430, "No Such Article Found");
			return 0;
		}
	} else if (nntp->mode == NNTP_MODE_READER && !strcasecmp(command, "BODY")) {
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
		if (!nntp_traverse(nntp->grouppath, on_body, nntp, msgid, msgid ? NULL : s)) {
			nntp_send(nntp, 430, "No Such Article Found");
			return 0;
		}
	} else if (nntp->mode == NNTP_MODE_READER && !strcasecmp(command, "LAST")) {
		REQUIRE_GROUP();
		if (!nntp->currentarticle) {
			nntp_send(nntp, 420, "Current article number is invalid");
			return 0;
		}
		/* Find the max article number less than nntp->currentarticle, if there is one. */
		nntp->nextlastarticle = 0;
		nntp_traverse2(nntp->grouppath, on_last, nntp, 1, nntp->currentarticle - 1);
		if (nntp->currentarticle == nntp->nextlastarticle) {
			nntp_send(nntp, 422, "No previous article in group");
			return 0;
		}
		if (!get_article_id(nntp, nntp->nextlastarticle)) {
			bbs_error("Couldn't find article ID for %s #%d???\n", nntp->currentgroup, nntp->nextlastarticle);
			nntp_send(nntp, 422, "No previous article in group");
			return 0;
		}
		nntp_send(nntp, 223, "%d %s", nntp->nextlastarticle, nntp->articleid);
		free_if(nntp->articleid);
	} else if (nntp->mode == NNTP_MODE_READER && !strcasecmp(command, "NEXT")) {
		REQUIRE_GROUP();
		if (!nntp->currentarticle) {
			nntp_send(nntp, 420, "Current article number is invalid");
			return 0;
		}
		nntp->nextlastarticle = 0;
		nntp_traverse2(nntp->grouppath, on_next, nntp, nntp->currentarticle + 1, INT_MAX);
		if (!nntp->nextlastarticle) {
			nntp_send(nntp, 421, "No next article in group");
			return 0;
		}
		if (!get_article_id(nntp, nntp->nextlastarticle)) {
			bbs_error("Couldn't find article ID for %s #%d???\n", nntp->currentgroup, nntp->nextlastarticle);
			nntp_send(nntp, 421, "No next article in group");
			return 0;
		}
		nntp_send(nntp, 223, "%d %s", nntp->nextlastarticle, nntp->articleid);
		free_if(nntp->articleid);
	} else if (nntp->mode == NNTP_MODE_READER && !strcasecmp(command, "POST")) {
		if (require_login_posting && !bbs_user_is_registered(nntp->node->user)) {
			nntp_send(nntp, 480, "Must authenticate first");
			return 0;
		} else if (min_priv_post > nntp->node->user->priv) {
			nntp_send(nntp, 502, "Insufficient privileges to post");
			return 0;
		}
		/* Group not required, the headers will say group(s) to which message should be posted. */
		nntp_reset_data(nntp);
		strcpy(nntp->template, "/tmp/nntpXXXXXX");
		nntp->fp = bbs_mkftemp(nntp->template, 0600);
		if (!nntp->fp) {
			nntp_send(nntp, 440, "Server error, posting temporarily unavailable");
		} else {
			nntp_send(nntp, 340, "Input article; end with a period on its own line");
			nntp->inpost = 1;
			nntp->inpostheaders = 1;
		}
	} else if (nntp->mode == NNTP_MODE_TRANSIT && !strcasecmp(command, "IHAVE")) {
		/* Check if client is authorized to relay us articles. */
		if (requirerelaytls && !nntp->secure) {
			nntp_send(nntp, 483, "Secure connection required");
			return 0;
		}
		if (!sender_authorized(nntp)) {
			bbs_warning("Sender %s/%s unauthorized to send us articles\n", bbs_username(nntp->node->user), nntp->node->ip);
			nntp_send(nntp, 500, "Not authorized to relay articles");
			return 0;
		}
		/* Group not required, the headers will say group(s) to which message should be posted. */
		REQUIRE_ARGS(s);
		/* Strip <> */
		if (*s == '<') {
			s++;
		}
		bbs_strterm(s, '>')
		REQUIRE_ARGS(s);
		/* Check if any message with this ID exists in any newsgroup. */
		if (article_id_exists(s)) {
			nntp_send(nntp, 435, "Duplicate");
			return 0;
		}
		REPLACE(nntp->rxarticleid, s);
		if (!nntp->rxarticleid) {
			nntp_send(nntp, 436, "Retry later");
			return 0;
		}
		nntp_reset_data(nntp);
		strcpy(nntp->template, "/tmp/nntpXXXXXX");
		nntp->fp = bbs_mkftemp(nntp->template, 0600);
		if (!nntp->fp) {
			nntp_send(nntp, 436, "Temporary server error, try again later");
		} else {
			nntp_send(nntp, 335, "Send it; end with a period on its own line");
			/* Reuse the POST logic */
			nntp->inpost = 1;
			nntp->inpostheaders = 1;
		}
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
	struct readline_data rldata;

	bbs_readline_init(&rldata, buf, sizeof(buf));
	/* 200 means client can post, 201 means not, but this is not a perfect distinction (see RFC) */
	nntp_send(nntp, 200, "%s Newsgroup Service Ready, posting permitted", bbs_hostname());

	for (;;) {
		int res = bbs_readline(nntp->rfd, &rldata, "\r\n", MIN_MS(5));
		if (res < 0) {
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
		if (nntp_process(nntp, buf, res)) {
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
	SSL *ssl = NULL;
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
	SET_BITFIELD(nntp.secure, secure);
	SET_BITFIELD(nntp.mode, reader);

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

	nntp_handler(node, !strcmp(node->protname, "NNTPS"), !strcmp(node->protname, "NNSP") ? NNTP_MODE_TRANSIT: NNTP_MODE_READER);

	bbs_debug(3, "Node %d has ended its %s session\n", node->id, node->protname);
	bbs_node_exit(node); /* node is no longer a valid reference */
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;

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

	bbs_config_val_set_true(cfg, "relayin", "requiretls", &requirerelaytls);
	bbs_debug(3, "Setting: %d\n", requirerelaytls);

	bbs_config_val_set_uint(cfg, "relayout", "frequency", &relayfrequency);
	bbs_config_val_set_uint(cfg, "relayout", "maxage", &relaymaxage);

	/* If reload without unloading/loading were supported, we'd want to empty the list first. */
	stringlist_empty(&inpeers);
	stringlist_empty(&outpeers);

	while ((section = bbs_config_walk(cfg, section))) {
		if (!strcasecmp(bbs_config_section_name(section), "trusted")) {
			RWLIST_WRLOCK(&inpeers);
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				/* Internally we don't actually differentiate between host=,ip=,user= when storing config in memory */
				stringlist_push(&inpeers, bbs_keyval_val(keyval));
			}
			RWLIST_UNLOCK(&inpeers);
		} else if (!strcasecmp(bbs_config_section_name(section), "relayto")) {
			RWLIST_WRLOCK(&outpeers);
			while ((keyval = bbs_config_section_walk(section, keyval))) {
				stringlist_push(&outpeers, bbs_keyval_val(keyval));
			}
			RWLIST_UNLOCK(&outpeers);
		}
	}

	return 0;
}

static int load_module(void)
{
	memset(&inpeers, 0, sizeof(inpeers));
	memset(&outpeers, 0, sizeof(outpeers));
	if (load_config()) {
		return -1;
	}
	/* Since load_config returns 0 if no config, do this check here instead of in load_config: */
	if (!nntp_enabled && !nntps_enabled && !nnsp_enabled) {
		bbs_debug(3, "Neither NNTP nor NNTPS nor NNSP is enabled, declining to load\n");
		goto cleanup; /* Nothing is enabled */
	}
	if (nntps_enabled && !ssl_available()) {
		bbs_error("TLS is not available, NNTPS may not be used\n");
		goto cleanup;
	}
	if (strlen_zero(bbs_hostname())) {
		bbs_error("A BBS hostname in nodes.conf is required for newsgroup services\n");
		goto cleanup;
	}

	pthread_mutex_init(&nntp_lock, NULL);

	if (scan_newsgroups()) {
		goto cleanup;
	}

	return bbs_start_tcp_listener3(nntp_enabled ? nntp_port : 0, nntps_enabled ? nntps_port : 0, nnsp_enabled ? nnsp_port : 0, "NNTP", "NNTPS", "NNSP", __nntp_handler);

cleanup:
	stringlist_empty(&inpeers);
	stringlist_empty(&outpeers);
	return -1;
}

static int unload_module(void)
{
	if (nntp_enabled) {
		bbs_stop_tcp_listener(nntp_port);
	}
	if (nntps_enabled) {
		bbs_stop_tcp_listener(nntps_port);
	}
	if (nnsp_enabled) {
		bbs_stop_tcp_listener(nnsp_port);
	}
	pthread_mutex_destroy(&nntp_lock);
	stringlist_empty(&inpeers);
	stringlist_empty(&outpeers);
	return 0;
}

BBS_MODULE_INFO_STANDARD("RFC3977 NNTP/NNSP");
