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
 * \brief RFC1939 Post Office Protocol Version 3 (POP3)
 *
 * \note STARTTLS is not supported for cleartext POP3, as proposed in RFC2595, as this guidance
 *       is obsoleted by RFC8314. Implicit TLS (POP3S) should be preferred.
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>

#include "include/tls.h"

#include "include/module.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/node.h"
#include "include/auth.h"
#include "include/user.h"
#include "include/test.h"

#include "include/mod_mail.h"

/* POP3 ports */
#define DEFAULT_POP3_PORT 110
#define DEFAULT_POP3S_PORT 995

static int pop3_port = DEFAULT_POP3_PORT;
static int pop3s_port = DEFAULT_POP3S_PORT;

static int pop3_enabled = 0, pop3s_enabled = 1;

struct pop3_session {
	int rfd;
	int wfd;
	struct bbs_node *node;
	struct mailbox *mbox;
	char *username;
	char *folder;
	/* maildir */
	char dir[256];
	char newdir[260]; /* 4 more, for /new and /cur */
	char curdir[260];
	/* Delete */
	char trashmaildir[262]; /* 6 more, for .Trash */
	char *deletions; /* Use char for storing bits, since char is 1 byte while int is more */
	/* Other */
	int toplines;
	/* Traversal flags */
	unsigned int totalnew;
	unsigned int totalcur;
	unsigned int totalbytes;
	unsigned int delsize;
	unsigned int delbytes;
	unsigned int innew:1;
};

static void pop3_destroy(struct pop3_session *pop3)
{
	if (pop3->mbox) {
		mailbox_unlock(pop3->mbox); /* Release our write lock on this mailbox */
	}
	free_if(pop3->deletions);
	free_if(pop3->username);
	free_if(pop3->folder);
}

#define pop3_send(pop3, fmt, ...) bbs_debug(4, "%p <= " fmt, pop3, ## __VA_ARGS__); bbs_node_fd_writef(pop3->node, pop3->wfd, fmt, ## __VA_ARGS__);
#define pop3_ok(pop3, fmt, ...) pop3_send(pop3, "+OK " fmt "\r\n", ## __VA_ARGS__)
#define pop3_err(pop3, fmt, ...) pop3_send(pop3, "-ERR " fmt "\r\n", ## __VA_ARGS__)

/*! \note In practice, this function should only be called once during a POP3 session, since the number of messages visible will not change */
static int init_deletions(struct pop3_session *pop3)
{
	int rem;
	unsigned int bytesize;
	unsigned int newcount = pop3->totalnew + pop3->totalcur;
	/* sizeof(int) is probably 4, maybe 8.
	 * Round up the number of messages to the nearest multiple of sizeof(int).
	 * Then divide by it to get the actual size array we need. */
	rem = newcount % (8 * sizeof(char)); /* 8 bits in a byte */
	bytesize = newcount / (unsigned int) (8 * sizeof(char)) + (rem ? 1 : 0); /* Add an extra int position if there was a remainder */

	/* We can't just set the Deleted flag like with IMAP.
	 * The deletion flags shouldn't be committed until we quit,
	 * and we need to be able to easily undo them all. */

	/* We're using an array of ints here,
	 * but what we really need is just an array of bits.
	 * Doing it this way (assuming int = 4 bytes), we can use 32 times less memory.
	 * The math becomes a little more complicated,
	 * but storage/memory-wise, this should be more efficient.
	 * Main issue is accounting for the size of int on different architectures. */
	if (pop3->deletions) {
		if (pop3->delsize) {
			/* Already have a size. If it's bigger, realloc.
			 * If it's smaller, just let it be.
			 * The latter is the more likely case, so realloc won't be too common. */
			if (bytesize > pop3->delbytes) {
				char *newdel = realloc(pop3->deletions, bytesize);
				if (ALLOC_FAILURE(newdel)) {
					/* This is bad... just abort. */
					return -1;
				}
				/* realloc does not initialize the new memory, so memset it */
				pop3->deletions = newdel;
				memset(pop3->deletions + pop3->delbytes, 0, bytesize - pop3->delbytes);
			}
		}
	} else {
		pop3->deletions = calloc(1, bytesize);
		if (ALLOC_FAILURE(pop3->deletions)) {
			return -1;
		}
	}

	pop3->delsize = newcount; /* Allocate based on # messages from last traversal. */
	pop3->delbytes = bytesize;
	return 0;
}

#pragma GCC diagnostic ignored "-Wconversion"
static int mark_deleted(struct pop3_session *pop3, int message)
{
	int element, bit;

	if (message > (int) pop3->delsize) {
		bbs_warning("Attempt to delete message out of range: %d > %u\n", message, pop3->delsize);
		return -1;
	}
	bbs_assert_exists(pop3->deletions);
	element = (message - 1) / (int) (8 * sizeof(char)); /* Subtract 1 to make 0-indexed, then determine which int index it is */
	bit = (message - 1) % (int) (8 * sizeof(char));
	bbs_debug(3, "Setting bit %d of element %d (%d/%d)\n", bit, element, pop3->delsize, pop3->delbytes);
	pop3->deletions[element] |= (1 << bit); /* Set bit high to mark deleted. */
	return 0;
}

static int is_deleted(struct pop3_session *pop3, unsigned int message)
{
	unsigned int element, bit;

	if (message > pop3->delsize) {
#ifdef EXTRA_DEBUG
		bbs_debug(7, "Index %d does not exist\n", message - 1);
#endif
		return 0; /* Nonexistent index, return 0 */
	}
	bbs_assert_exists(pop3->deletions);
	element = (message - 1) / (8 * sizeof(char)); /* Subtract 1 to make 0-indexed, then determine which int index it is */
	bit = (message - 1) % (8 * sizeof(char));
#ifdef EXTRA_DEBUG
	bbs_debug(7, "Checking bit %u of element %u (%d/%d) = %d\n", bit, element, pop3->delsize, pop3->delbytes, (pop3->deletions[element] & (1 << bit)) ? 1 : 0);
#endif
	return (pop3->deletions[element] & (1 << bit)) ? 1 : 0;
}
#pragma GCC diagnostic pop

static void clear_deleted(struct pop3_session *pop3)
{
	if (pop3->delbytes) {
		memset(pop3->deletions, 0, pop3->delbytes); /* Clear all bits */
	}
}

static int test_deletion_sequences(void)
{
	struct pop3_session pop3;
	int res = -1;

	memset(&pop3, 0, sizeof(pop3));

	pop3.totalnew = 2;
	pop3.totalcur = 3;
	init_deletions(&pop3);

	bbs_test_assert_equals(0, is_deleted(&pop3, 1));
	mark_deleted(&pop3, 1);
	bbs_test_assert_equals(1, is_deleted(&pop3, 1));
	bbs_test_assert_equals(0, is_deleted(&pop3, 5));
	mark_deleted(&pop3, 5);
	bbs_test_assert_equals(1, is_deleted(&pop3, 5));
	clear_deleted(&pop3);
	bbs_test_assert_equals(0, is_deleted(&pop3, 5));
	bbs_test_assert_equals(0, is_deleted(&pop3, 1));
	
	mark_deleted(&pop3, 5);
	bbs_test_assert_equals(1, is_deleted(&pop3, 5));
	pop3.totalnew = 5;
	pop3.totalcur = 5;
	init_deletions(&pop3);

	bbs_test_assert_equals(1, is_deleted(&pop3, 5));
	bbs_test_assert_equals(0, is_deleted(&pop3, 10));
	mark_deleted(&pop3, 10); /* Test a bit that's in the 2nd byte */
	bbs_test_assert_equals(1, is_deleted(&pop3, 10));

	res = 0;

cleanup:
	free_if(pop3.deletions);
	return res;
}

static int pop3_traverse(const char *path, int (*on_file)(const char *dir_name, const char *filename, struct pop3_session *pop3, int number, int msgfilter), struct pop3_session *pop3, int msgfilter)
{
	struct dirent *entry, **entries;
	int files, fno = 0;
	unsigned int msgno = 0;
	int res = 0;

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
		msgno++;
		/* Omit if marked for deletion. */
		if (is_deleted(pop3, msgno)) {
			if (msgfilter) {
				pop3_err(pop3, "No such message");
				free(entry);
				continue;
			}
		}
		if ((res = on_file(path, entry->d_name, pop3, (int) msgno, msgfilter))) {
			free(entry);
			break; /* If the handler returns non-zero then stop */
		}
		free(entry);
	}
	free(entries);
	return res;
}

/* Traverse curdir first, since everything in new is newer than anything in cur, and once moved to cur would be doubled counted if we did it the other way */
#define POP3_TRAVERSAL(pop3) \
	pop3->totalnew = 0; \
	pop3->totalcur = 0; \
	pop3->totalbytes = 0; \
	pop3->innew = 0; \
	pop3_traverse(pop3->curdir, on_stat, pop3, 0); \
	pop3->innew = 1; \
	pop3_traverse(pop3->newdir, on_stat, pop3, 0); \
	init_deletions(pop3);

static int on_delete(const char *dir_name, const char *filename, struct pop3_session *pop3, int number, int msgfilter)
{
	char fullpath[516];
	char newdir[267];
	unsigned int msguid;

	UNUSED(msgfilter);

	if (!is_deleted(pop3, (unsigned int) number)) {
		return 0;
	}

	snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_name, filename);
	/* Can't specify the new filename directly here.
	 * Since we're moving it to a new mailbox (from an IMAP perspective), it will need to be assigned a new UID. */
	snprintf(newdir, sizeof(newdir), "%s/.Trash", dir_name);

	bbs_debug(5, "Deleting message %d (%s)\n", number, fullpath);
	maildir_move_msg(pop3->mbox, pop3->node, fullpath, filename, pop3->trashmaildir, NULL, NULL); /* Move message to Trash folder */

	/* It would be more efficient to batch deletions like with IMAP, but that would require moving this outside of the callback,
	 * and given POP3 is just not intended to be as smart as IMAP, I am not sure that is worth the effort. */
	maildir_parse_uid_from_filename(filename, &msguid);
	/* We pass NULL for the seqno argument.
	 * Because POP3 doesn't do an ordered traversal, number is not necessarily the sequence number.
	 * Yes, we could do an ordered traversal using maildir_ordered_traverse, but
	 * more importantly, since only IMAP needs the sequence number list,
	 * and because POP3 exclusively locks the mailbox,
	 * this means that there aren't any IMAP clients that can be connected to this mailbox,
	 * and thus IMAP will not end up consuming this event anyways. Therefore, we don't need to provide sequence numbers. */
	maildir_indicate_expunged(EVENT_MESSAGE_EXPUNGE, pop3->node, pop3->mbox, dir_name, &msguid, NULL, 1, 0);
	return 0;
}

static int on_stat(const char *dir_name, const char *filename, struct pop3_session *pop3, int number, int msgfilter)
{
	char oldfile[256];

	UNUSED(number);
	UNUSED(msgfilter);

	snprintf(oldfile, sizeof(oldfile), "%s/%s", dir_name, filename);
	bbs_debug(4, "Analyzing file %s\n", oldfile);

	/* POP3 only cares about the root maildir new and cur folders, nothing else.
	 * We will look in both the "new" and "cur" directory.
	 * Any messages we find in new are immediately moved to cur, just like with IMAP.
	 * If the client deletes a message, it is deleted (from cur).
	 * Otherwise, the message remains in cur, but if it was downloaded, we mark it as read (by adding the Seen flag, for IMAP).
	 * We don't have to deal with marking emails as "unread" again for POP, since we don't actually
	 * indicate to the client whether a message is read or not. Clients keep track of that locally.
	 */

	if (pop3->innew) {
		pop3->totalnew += 1;
	} else {
		pop3->totalcur += 1;
	}

	/* Unlike IMAP operations that can be read only (not move messages from new to cur), POP3 has no such thing. Always move from new to cur. */
	if (pop3->innew) {
		int res;
		/* If we wanted to hash the file here, we would do it first, because maildir_move_new_to_cur will move it to a new location.
		 * However, we don't need to compute UIDL here, so we can do that later, once everything is in the cur directory. */
		res = maildir_move_new_to_cur(pop3->mbox, pop3->node, mailbox_maildir(pop3->mbox), pop3->curdir, pop3->newdir, filename, NULL, NULL);
		if (res > 0) {
			pop3->totalbytes += (unsigned int) res;
		}
	} else {
		unsigned int size;
		const char *sizestr;
		sizestr = strstr(filename, ",S=");
		if (!sizestr) {
			bbs_error("Missing size in file %s\n", filename);
			return 0;
		}
		sizestr += STRLEN(",S=");
		size = (unsigned int) atoi(sizestr);
		pop3->totalbytes += size;
	}

	return 0;
}

static int on_uidl(const char *dir_name, const char *filename, struct pop3_session *pop3, int number, int msgfilter)
{
	unsigned int uid, uidl;
	const char *uidstr;

	if (msgfilter) { /* Only want a specific message. */
		if (msgfilter != number) {
			return 0;
		}
	}

	UNUSED(dir_name);

	/* The UIDL must be unique and identical, and unchanging as long as this message exists.
	 * It's tempting to just reuse the IMAP UID, which is already in the filename.
	 * Technically, UID has weaker requirements in IMAP than UIDL does in POP3, because IMAP servers
	 * are allowed to invalidate UIDs if needed (by resetting UIDVALIDITY), although a good IMAP server should never do this
	 * (and we do our best to avoid doing that).
	 * What's important is we don't store the UIDL, only the UID, persistently, so we need to be able to recompute
	 * the UIDL and get the same result every single time.
	 *
	 * Don't use the filename, since that could change between sessions (because of IMAP).
	 *
	 * Proposal 1:
	 * Just hash the message headers.
	 * Hashing the whole file is pointless, since bodies could be unique for many messages,
	 * and the headers are likely the part that contribute to uniqueness the most anyways.
	 *
	 * Proposal 2:
	 * Just use the IMAP UID (which is already in the filename at this point).
	 * It's going to be way faster than hashing any part of the message, since we don't need to read the file,
	 * and is already guaranteed to be unique, in theory.
	 * (Note that Gmail stores a POP3 UIDL per message, so they don't scan the message to compute, either).
	 *
	 * In practice, I don't know of any other POP3 servers that reuse the IMAP UID, they use something separate for the UIDL,
	 * but that doesn't mean it's not possible.
	 * RFC 1939 says UIDLs should be 1-70 characters (in range x21 to x7E), so using just a number is certainly possible...
	 *
	 * Here, we go with proposal 2, since we're confident in the BBS's ability to maintain UIDs and never reset UIDVALIDITY.
	 * (Worst case, if it got reset, the messages should have new UIDs, so mail would be redownloaded, but not lost - but this shouldn't happen).
	 * While in theory, the IMAP UID doesn't have the strong guarantees required of the POP3 UIDL,
	 * nothing stops us from doing our best to enforce them.
	 */

	uidstr = strstr(filename, ",U=");
	if (!uidstr) {
		bbs_error("Missing UID in file %s\n", filename);
		return 0;
	}
	uidstr += STRLEN(",U=");
	uid = (unsigned int) atoi(uidstr); /* We don't actually need a numeric representation since we're printing, but this implicitly discards anything after the number */

	uidl = uid; /* Just use the IMAP UID */

	if (msgfilter) {
		pop3_ok(pop3, "%d %u", number, uidl);
	} else {
		pop3_send(pop3, "%d %u\r\n", number, uidl); /* pop3_send doesn't tack on CR LF automatically, so don't forget it */
	}
	return 0;
}

static int on_list(const char *dir_name, const char *filename, struct pop3_session *pop3, int number, int msgfilter)
{
	unsigned int size;
	const char *sizestr;

	if (msgfilter) { /* Only want a specific message. */
		if (msgfilter != number) {
			return 0;
		}
	}

	UNUSED(dir_name);

	/* Since all files are in cur at this point, they should all have the size in the filename. No need to stat. */
	sizestr = strstr(filename, ",S=");
	if (!sizestr) {
		bbs_error("Missing size in file %s\n", filename);
		if (msgfilter) {
			pop3_err(pop3, "Server error");
		}
		return 0;
	}
	sizestr += STRLEN(",S=");
	size = (unsigned int) atoi(sizestr);
	if (msgfilter) {
		pop3_ok(pop3, "%d %u", number, size);
	} else {
		pop3_send(pop3, "%d %u\r\n", number, size); /* pop3_send doesn't tack on CR LF automatically, so don't forget it */
	}
	return 0;
}

static int on_retr(const char *dir_name, const char *filename, struct pop3_session *pop3, int number, int msgfilter)
{
	FILE *fp;
	unsigned int res, size, realsize;
	const char *sizestr;
	char fullpath[516];
	off_t offset;

	if (number != msgfilter) {
		return 0;
	}

	/* Since all files are in cur at this point, they should all have the size in the filename. No need to stat. */
	sizestr = strstr(filename, ",S=");
	if (!sizestr) {
		bbs_error("Missing size in file %s\n", filename);
		return 0;
	}
	sizestr += STRLEN(",S=");
	size = (unsigned int) atoi(sizestr);

	snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_name, filename);
	fp = fopen(fullpath, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", fullpath, strerror(errno));
		pop3_err(pop3, "Server error");
		return 0;
	}

	/*! \todo BUGBUG . (termination character) needs to be byte stuffed? */

	/* Already know the size, so no need to seek to end then rewind to determine it
	 * Of course, this assumes that nobody has messed with us, so maybe check anyways. */

	fseek(fp, 0L, SEEK_END); /* Go to EOF */
	realsize = (unsigned int) ftell(fp);
	rewind(fp);

	if (size != realsize) { /* Shouldn't happen unless some tampered with the message on disk... naughty tyke... */
		bbs_error("Expected %s to be %u bytes, but it's really %d bytes?\n", fullpath, size, realsize);
		pop3_err(pop3, "Server error"); /* Don't send the message unless it's the right size. */
		fclose(fp);
		return 0;
	}

	pop3_ok(pop3, "%u octets", realsize);
	offset = 0;
	res = (unsigned int) bbs_sendfile(pop3->wfd, fileno(fp), &offset, realsize);
	bbs_debug(6, "Sent %d bytes\n", res);
	bbs_node_fd_writef(pop3->node, pop3->wfd, ".\r\n");
	fclose(fp);
	return 0;
}

static int on_top(const char *dir_name, const char *filename, struct pop3_session *pop3, int number, int msgfilter)
{
	FILE *fp;
	char fullpath[516];
	int lineno = 0;
	int headersdone = 0;
	char msgbuf[1001]; /* Enough for longest possible line */

	if (number != msgfilter) {
		return 0;
	}

	snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_name, filename);
	fp = fopen(fullpath, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", fullpath, strerror(errno));
		pop3_err(pop3, "Server error");
		return 0;
	}

	/*! \todo BUGBUG . (termination character) needs to be byte stuffed? */

	pop3_ok(pop3, "");
	while ((fgets(msgbuf, sizeof(msgbuf), fp))) {
		if (headersdone) {
			++lineno;
			if (lineno > pop3->toplines) {
				break;
			}
		}
		bbs_node_fd_writef(pop3->node, pop3->wfd, "%s", msgbuf); /* msgbuf already includes CR LF */
		if (headersdone && lineno >= pop3->toplines) {
			break; /* That was the last line we wanted to read. */
		}
		if (!headersdone && !strcmp(msgbuf, "\r\n")) {
			headersdone = 1; /* End of headers, now begin counting */
		}
	}
	fclose(fp);
	bbs_node_fd_writef(pop3->node, pop3->wfd, ".\r\n"); /* Termination character. */
	return 0;
}

#define POP3_ENSURE_MESSAGE_EXISTS(msg) \
	if (msg > pop3->totalnew + pop3->totalcur) { \
		pop3_err(pop3, "No such message, only %d message%s in maildrop", pop3->totalnew + pop3->totalcur, ESS(pop3->totalnew + pop3->totalcur)); \
		return 0; \
	}

static int pop3_process(struct pop3_session *pop3, char *s)
{
	int res;
	char *command;

	command = strsep(&s, " ");

	if (!strcasecmp(command, "QUIT")) {
		if (pop3->mbox) {
			/* UPDATE state */
			pop3_traverse(pop3->curdir, on_delete, pop3, 0); /* Remove any messages marked for deletion */
		}
		pop3_ok(pop3, "POP3 server signing off");
		return -1;
	} if (!strcasecmp(command, "CAPA")) {
		/* RFC 2449 CAPA extension */
		pop3_ok(pop3, "Capability list follows");
		pop3_send(pop3, "TOP\r\nUSER\r\nUIDL\r\nEXPIRE NEVER\r\nRESP-CODES\r\nIMPLEMENTATION %s\r\n.\r\n", BBS_SHORTNAME); /* Must add CR LF pairs manually, must send termination char at end. */
	} else if (!strcasecmp(command, "USER")) {
		if (pop3->username) {
			pop3_err(pop3, "Invalid command sequence"); /* Already got a USER, but no PASS yet */
			return 0;
		}
		pop3->username = strdup(s);
		/* Don't validate the user yet, wait until we get a password */
		pop3_ok(pop3, "");
	} else if (!strcasecmp(command, "PASS")) {
		char *domain;

		if (strlen_zero(s)) {
			pop3_err(pop3, "Missing argument");
			return 0;
		}

		if (!pop3->username) { /* Must get USER first */
			bbs_memzero(s, strlen(s)); /* Destroy the password */
			pop3_err(pop3, "Invalid command sequence"); /* No such mailbox, since wrong domain! */
			return 0;
		}

		domain = strchr(pop3->username, '@');
		if (domain) {
			*domain++ = '\0';
			if (strlen_zero(domain) || strcmp(domain, bbs_hostname())) {
				bbs_memzero(s, strlen(s)); /* Destroy the password */
				pop3_err(pop3, "Invalid username or password"); /* No such mailbox, since wrong domain! */
				return 0;
			}
		}
		/* Try to authenticate */
		res = bbs_authenticate(pop3->node, pop3->username, s);
		free_if(pop3->username);
		bbs_memzero(s, strlen(s)); /* Destroy the password from memory. */
		if (res) {
			pop3_err(pop3, "Invalid username or password");
			return 0;
		}
		pop3->mbox = mailbox_get_by_userid(pop3->node->user->id); /* Retrieve the mailbox for this user */
		if (!pop3->mbox) {
			bbs_error("Successful authentication, but unable to retrieve mailbox for user %d\n", pop3->node->user->id);
			pop3_err(pop3, "System error");
			return -1; /* Just disconnect, we probably won't be able to proceed anyways. */
		}
		/* Grab an exclusive write lock on the entire mailbox.
		 * This is needed so other POP3 clients (or other IMAP clients, for that matter),
		 * can't delete or move messages while we're using them.
		 * New messages could arrive via SMTP, but they'll go into the "new" directory, so we won't see them. */
		if (mailbox_wrlock(pop3->mbox)) {
			pop3->mbox = NULL;
			pop3_err(pop3, "[IN-USE] Do you have another POP or IMAP session running?");
			return -1; /* Disconnect immediately */
		}
		pop3_ok(pop3, "");
		mailbox_maildir_init(mailbox_maildir(pop3->mbox)); /* Edge case: initialize if needed (necessary if user is accessing via POP before any messages ever delivered to it via SMTP) */
		snprintf(pop3->curdir, sizeof(pop3->curdir), "%s/cur", mailbox_maildir(pop3->mbox));
		snprintf(pop3->newdir, sizeof(pop3->newdir), "%s/new", mailbox_maildir(pop3->mbox));
		snprintf(pop3->trashmaildir, sizeof(pop3->trashmaildir), "%s/.Trash", mailbox_maildir(pop3->mbox));
		mailbox_dispatch_event_basic(EVENT_LOGIN, pop3->node, pop3->mbox, NULL);
		POP3_TRAVERSAL(pop3); /* Do our initial traversal of the mailbox to get stats */
		/* Past this point (during the remainder of the session), we must never process the new directory again (in fact, nothing in the BBS is allowed to, or able to) */
	/* APOP not supported */
	/* Past this point, must be logged in. */
	} else if (!bbs_user_is_registered(pop3->node->user)) {
		pop3_err(pop3, "Not logged in");
	} else if (!strcasecmp(command, "NOOP")) {
		pop3_ok(pop3, "");
	} else if (!strcasecmp(command, "STAT")) {
		/* Report total number of messages and total number of octets (bytes) */
		pop3_ok(pop3, "%d %d", pop3->totalnew + pop3->totalcur, pop3->totalbytes);
	} else if (!strcasecmp(command, "LIST")) {
		unsigned int filter = (unsigned int) atoi(S_IF(s));
		/* Just in case the client didn't issue a STAT first, move any messages in new into cur. */
		POP3_ENSURE_MESSAGE_EXISTS(filter);
		/* Proceed with a LISTing, just using the cur directory (since new should be empty now). */
		if (!filter) {
			pop3_ok(pop3, "%d message%s (%d octets)", pop3->totalnew + pop3->totalcur, ESS(pop3->totalnew + pop3->totalcur), pop3->totalbytes);
		}
		pop3_traverse(pop3->curdir, on_list, pop3, (int) filter);
		if (!filter) {
			pop3_send(pop3, ".\r\n"); /* Termination octet */
		}
	} else if (!strcasecmp(command, "UIDL")) {
		unsigned int filter = (unsigned int) atoi(S_IF(s));
		/* UIDL is technically optional in RFC 1939, but proper POP3 servers should really provide it (also see RFC 1957) */
		POP3_ENSURE_MESSAGE_EXISTS(filter);
		if (!filter) {
			pop3_ok(pop3, "");
		}
		pop3_traverse(pop3->curdir, on_uidl, pop3, (int) filter);
		if (!filter) {
			pop3_send(pop3, ".\r\n"); /* Termination octet */
		}
	} else if (!strcasecmp(command, "RETR")) {
		unsigned int filter = (unsigned int) atoi(S_IF(s));
		if (!filter) {
			pop3_err(pop3, "Missing message ID");
			return 0;
		}
		POP3_ENSURE_MESSAGE_EXISTS(filter);
		/* Report total number of messages and total number of octets (bytes) */
		pop3_traverse(pop3->curdir, on_retr, pop3, (int) filter);
	} else if (!strcasecmp(command, "TOP")) {
		const char *lines, *msg;
		unsigned int filter;

		msg = strsep(&s, " ");
		lines = s;
		filter = (unsigned int) atoi(S_IF(msg));
		if (!filter) {
			pop3_err(pop3, "Missing message ID");
			return 0;
		}
		POP3_ENSURE_MESSAGE_EXISTS(filter);
		/* Report total number of messages and total number of octets (bytes) */
		pop3->toplines = atoi(S_IF(lines));
		pop3_traverse(pop3->curdir, on_top, pop3, (int) filter);
	} else if (!strcasecmp(command, "DELE")) {
		unsigned int filter = (unsigned int) atoi(S_IF(s));
		if (!filter) {
			pop3_err(pop3, "Missing message ID");
			return 0;
		}
		/* A traversal should have been done already. */
		POP3_ENSURE_MESSAGE_EXISTS(filter);
		if (is_deleted(pop3, filter)) {
			pop3_err(pop3, "Message %u already deleted", filter);
			return 0;
		}
		if (mark_deleted(pop3, (int) filter)) {
			pop3_err(pop3, "Failed to mark message %u for deletion", filter);
			return 0;
		}
		pop3_ok(pop3, "Message %u deleted", filter);
	} else if (!strcasecmp(command, "RSET")) {
		/* Undo all deletions */
		clear_deleted(pop3);
		pop3_ok(pop3, "Maildrop has %d message%s (%d octets)", pop3->totalnew + pop3->totalcur, ESS(pop3->totalnew + pop3->totalcur), pop3->totalbytes);
	} else {
		pop3_err(pop3, "Unsupported command");
	}
	return 0;
}

static void handle_client(struct pop3_session *pop3)
{
	char buf[1001];
	struct readline_data rldata;

	bbs_readline_init(&rldata, buf, sizeof(buf));
	pop3_ok(pop3, "POP3 Server Ready");

	for (;;) {
		ssize_t res = bbs_readline(pop3->rfd, &rldata, "\r\n", MIN_MS(3));
		if (res < 0) {
			res += 1; /* Convert the res back to a normal one. */
			if (res == 0) {
				/* Timeout occured. */
				pop3_err(pop3, "POP3 server terminating connection");
			}
			break;
		}
		if (!strncasecmp(buf, "PASS", STRLEN("PASS"))) {
			bbs_debug(6, "%p => PASS ******\n", pop3); /* Mask login to avoid logging passwords */
		} else {
			bbs_debug(6, "%p => %s\n", pop3, buf);
		}
		if (pop3_process(pop3, buf)) {
			break;
		}
	}
}

/*! \brief Thread to handle a single POP3/POP3S client */
static void pop3_handler(struct bbs_node *node, int secure)
{
#ifdef HAVE_OPENSSL
	SSL *ssl = NULL;
#endif
	int rfd, wfd;
	struct pop3_session pop3;

	/* Start TLS if we need to */
	if (secure) {
		ssl = ssl_node_new_accept(node, &rfd, &wfd);
		if (!ssl) {
			bbs_error("Failed to create SSL\n");
			return;
		}
	} else {
		rfd = wfd = node->fd;
	}

	memset(&pop3, 0, sizeof(pop3));
	pop3.rfd = rfd;
	pop3.wfd = wfd;
	pop3.node = node;

	handle_client(&pop3);
	mailbox_dispatch_event_basic(EVENT_LOGOUT, node, NULL, NULL);

#ifdef HAVE_OPENSSL
	if (secure) { /* implies ssl */
		ssl_close(ssl);
		ssl = NULL;
	}
#endif
	pop3_destroy(&pop3);
}

static void *__pop3_handler(void *varg)
{
	struct bbs_node *node = varg;

	bbs_node_net_begin(node);
	pop3_handler(node, !strcmp(node->protname, "POP3S"));
	bbs_node_exit(node);
	return NULL;
}

static int load_config(void)
{
	struct bbs_config *cfg;

	cfg = bbs_config_load("net_pop3.conf", 1);
	if (!cfg) {
		return 0;
	}

	/* POP3 */
	bbs_config_val_set_true(cfg, "pop3", "enabled", &pop3_enabled);
	bbs_config_val_set_port(cfg, "pop3", "port", &pop3_port);

	/* POP3S */
	bbs_config_val_set_true(cfg, "pop3s", "enabled", &pop3s_enabled);
	bbs_config_val_set_port(cfg, "pop3s", "port", &pop3s_port);

	return 0;
}

static struct bbs_unit_test tests[] =
{
	{ "POP3 Deletion Bits", test_deletion_sequences },
};

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	/* Since load_config returns 0 if no config, do this check here instead of in load_config: */
	if (!pop3_enabled && !pop3s_enabled) {
		bbs_debug(3, "Neither POP3 nor POP3S is enabled, declining to load\n");
		return -1; /* Nothing is enabled */
	}
	if (pop3s_enabled && !ssl_available()) {
		bbs_error("TLS is not available, POP3S may not be used\n");
		return -1;
	}

	bbs_register_tests(tests);
	return bbs_start_tcp_listener3(pop3_enabled ? pop3_port : 0, pop3s_enabled ? pop3s_port : 0, 0, "POP3", "POP3S", NULL, __pop3_handler);
}

static int unload_module(void)
{
	bbs_unregister_tests(tests);
	if (pop3_enabled) {
		bbs_stop_tcp_listener(pop3_port);
	}
	if (pop3s_enabled) {
		bbs_stop_tcp_listener(pop3s_port);
	}
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC1939 POP3", "mod_mail.so");
