/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2025, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Integrated IRC Bouncer
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/* Not a bouncer in the sense of a thing to which users can attach to proxy
 * their connection, but in the sense that they can quit IRC, come back,
 * and view the messages they missed. */

/* Note: At present, configs are only scanned when the module is loaded,
 * since this module needs to be reloaded in order to pick up new, deleted,
 * or modified bouncer configs (which users can't do themselves).
 * There is a FIXME comment for this. */

#include "include/bbs.h"

#include <stdarg.h>
#include <ctype.h>
#include <limits.h> /* use PATH_MAX */

#include "include/linkedlists.h"
#include "include/config.h"
#include "include/module.h"
#include "include/transfer.h"
#include "include/utils.h"
#include "include/mail.h"
#include "include/node.h" /* use bbs_hostname */
#include "include/user.h"
#include "include/cli.h"
#include "include/startup.h"

#include "include/net_irc.h"

/* To avoid a conflict with the actual user's nick,
 * suffix with an underscore, and if that's taken, more can get tacked on.
 * While not required (net_irc supports auto-swapping nicks if we wanted
 * to assume the real one here), it avoids nick changes for the bouncer
 * if it is running concurrently with its owner's session.
 *
 * However, using the same nick may be desired to create the illusion
 * that the user is really there, and that a bouncer is not being used.
 * It's also less disruptive, as we can suppress the JOIN/PART/QUIT/KICK
 * messages normally broadcast around, if and only if the nicknames
 * used by the two clients is identical and just being swapped.
 * Technically, if clients issue a NAMES command to see who's in the
 * channel, they'll find some user that was never announced by JOIN,
 * but the important thing is that the corresponding user's client
 * is also active in the channel.
 *
 * If USE_REAL_NICK_WHEN_POSSIBLE is defined, we will start by using
 * the user's actual nick (if possible), and the next time the user
 * joins, he will swap nicks with the bouncer so he gets the real one.
 * The only time we would then try to change it back is if the user has
 * disconnected (handled where USE_REAL_NICK_WHEN_POSSIBLE is defined).
 *
 * Also, ensure that USE_REAL_NICK_WHEN_POSSIBLE is defined in test_irc_bouncer
 * if and only if it's defined in this file. */

#define USE_REAL_NICK_WHEN_POSSIBLE

static int user_maxbouncers = 25; /* A user can only enable the bouncer for this many bouncers, max */
static long int max_logfile_size = SIZE_MB(5); /* 5 MB ought to be plenty for IRC logs to get by between interactive sessions */
static int unloading = 0;

static pthread_t email_thread = 0;

/* Forward declaration */
struct bouncer_user;

struct bouncer_channel {
	struct bouncer_user *bu;		/*!< Handle to parent bouncer_user */
	const char *channel;			/*!< Channel */
	FILE *fp;						/*!< Bouncer log file */
	time_t last_flush;				/*!< Last flush */
	unsigned int email_frequency;	/*!< Email flush frequency (0 to disable) */
	unsigned int interactive:1;		/*!< Interactive flushing? */
	RWLIST_ENTRY(bouncer_channel) entry;
	char *data;	/* Not quite a flexible struct member, but sufficient */
};

RWLIST_HEAD(bouncer_channels, bouncer_channel);

struct bouncer_user {
	unsigned int userid;			/*!< User associated with this bouncer */
	const char *username;			/*!< Username */
	struct irc_user *user;			/*!< IRC pseudo user */
	bbs_mutex_t lock;				/*!< Lock */
	struct bouncer_channel *pmbc;	/*!< Bouncer channel for private messages */
	struct bouncer_channels channels;
	unsigned int active_bouncers;	/*!< Number of active bouncer sessions */
	RWLIST_ENTRY(bouncer_user) entry;
	unsigned int msgid;				/*!< Counter for Message-ID uniqueness */
	char data[];
};

/* Note: We only lock bouncer_users (the outer list), but not its bouncer_channels lock */
static RWLIST_HEAD_STATIC(bouncer_users, bouncer_user);

#define TIMESTAMP_CHARS 20 /* 2000-01-01 12:59:59 =  19 chars + trailing space = 20 */

static int interactive_flush_cb(struct irc_user *user, void *obj)
{
	FILE *fp = obj;
	int lines = 0;
	char buf[612]; /* Max line length in IRC is 512, so that and then some */

	while ((fgets(buf, sizeof(buf) - 2, fp))) {
		char *lf, *sp, *msg;
		/* Extract the timestamp,
		 * the remaining bits constitute the payload in
		 * a format that is already protocol-ready. */
		msg = buf + TIMESTAMP_CHARS;
		lf = strchr(buf, '\n');
		if (!lf || lf <= msg) {
			bbs_warning("Skipping invalid line '%s'\n", buf);
			continue;
		}
		strcpy(lf, "\r\n"); /* CR LF NUL */
		/* For PRIVMSG, inject the timestamp into the message,
		 * since there is nowhere in the protocol to explicitly
		 * convey and overridden timestamp.
		 * For other commands, just ignore the timestamp,
		 * not so important and no good way to convey either. */
		sp = strchr(msg, ' ');
		if (!sp) {
			bbs_warning("Skipping invalid line '%s'\n", buf);
			continue;
		}
		if (!strncmp(sp, " PRIVMSG ", STRLEN(" PRIVMSG "))) {
			char newbuf[612];
			char *hostmask, *cmd, *arg1, *arg2;
			hostmask = strsep(&msg, " ");
			cmd = strsep(&msg, " ");
			arg1 = strsep(&msg, " ");
			arg2 = msg;
			if (strlen_zero(arg2)) {
				bbs_warning("Skipping invalid line '%s'\n", buf);
				continue;
			}
			/* Skip leading : in original message since we prepend before timestamp (which also includes a trailing space) */
			snprintf(newbuf, sizeof(newbuf), "%s %s %s :%.*s%s", hostmask, cmd, arg1, TIMESTAMP_CHARS, buf, arg2 + 1);
			if (irc_user_send_chunk(user, newbuf) < 0) {
				return -1;
			}
		} else {
			if (irc_user_send_chunk(user, msg) < 0) {
				return -1;
			}
		}
		lines++;
	}
	bbs_debug(5, "Flushed %d line%s from bouncer log\n", lines, ESS(lines));
	return 0;
}

static FILE *open_logfile_for_reading(struct bouncer_user *bu, const char *channel, char *full_filename, size_t len)
{
	FILE *fp;
	char filename[128];

	/* Open the log file anew, in read-only mode, and iterate it and write
	 * out any saved messages to the client. */
	snprintf(filename, sizeof(filename), ".bouncer.d/%s", channel);
	bbs_transfer_home_config_file(bu->userid, filename, full_filename, len);

	/* First, try opening the file. If it doesn't exist or it's empty,
	 * then no need to bother beginning the flush process. */
	fp = fopen(full_filename, "r+"); /* Open for reading and writing, since we may truncate at end (but stream still pos. at beginning) */
	if (!fp) {
		/* If there aren't any messages (the file doesn't exist), it's not an error */
		if (errno != ENOENT) {
			bbs_error("Failed to open %s: %s\n", full_filename, strerror(errno));
		} else {
			bbs_debug(9, "Nothing to flush for '%s' (file %s does not exist)\n", channel, full_filename);
		}
		return NULL;
	}
	return fp;
}

/*! \brief Truncate a file, after we've replayed everything in it */
static int file_truncate(FILE *fp)
{
	int fd = fileno(fp);
	if (fd != -1) {
		if (!ftruncate(fd, 0)) {
			rewind(fp); /* The man page for ftruncate(2) says the offset is not changed, so explicitly seek to beginning */
			return 0;
		}
	}
	return -1;
}

/*! \note Must be called locked */
static int interactive_flush(struct bouncer_user *bu, const char *channel)
{
	char full_filename[PATH_MAX];
	int res;
	FILE *fp = open_logfile_for_reading(bu, channel, full_filename, sizeof(full_filename));
	if (!fp) {
		return -1;
	}

	bbs_debug(5, "Flushing bouncer logs for %s:%s\n", bu->username, channel);

	/* There could be a LOT of lines in this file.
	 * A naive approach of calling a function in net_irc to blast this out to the user
	 * would involve a linear number of searches (which are themselves linear operations),
	 * leading to polynomial search time, excluding the writing itself!
	 * And that's just for one channel! If we have a large number of channels,
	 * it goes from quadratic to cubic!
	 *
	 * The approach here ensures that net_irc only needs to search for the user once.
	 * At least, once per channel that is being flushed, since that is the scope
	 * of this function (it only knows about this channel), so that's the best we can do. */
	res = irc_user_send_multiple(bu->username, interactive_flush_cb, fp);
	if (!res) {
		file_truncate(fp);
	}
	fclose(fp);
	/* Better yet, delete the file, so empty files don't pile up over time */
	bbs_delete_file(full_filename);
	return res;
}

#define IS_CHANNEL(bc) (bc != bc->bu->pmbc)

/*! \note Must be called locked, with fp offset at the beginning of the file */
static int email_flush(struct bouncer_channel *bc, FILE *in_fp, time_t now)
{
	char buf[612];
	char date[48];
	char mailfrom[256];
	char tmpfilename[128] = "/tmp/ircbouncerXXXXXX";
	struct tm tm;
	FILE *fp = bbs_mkftemp(tmpfilename, 0666);

	if (!fp) {
		return -1;
	}

	strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S %z", localtime_r(&now, &tm));
	fprintf(fp, "Date: %s\r\n", date);

	/* If the message was being delivered only locally, we don't even need a hostname;
	 * however, if the message is forwarded by a filter outside the BBS,
	 * then the receiving mail server probably won't like seeing an email where the 'From'
	 * address has only a user part and no domain. So for that reason (and ONLY that reason),
	 * we include a hostname here. */

	/*! \todo FIXME smtp_hostname() is really more correct from a delivery standpoint,
	 * since the hostname used for SMTP with DNS records configured may
	 * not match the regular BBS hostname, but that would require a dependency on net_smtp,
	 * which we want to avoid.
	 * The fix would be to have a "bbs_smtp_hostname()" function in mail.c,
	 * and net_smtp could then register the SMTP hostname with it;
	 * if not specified, this would default to the BBS hostname, just like smtp_hostname() does. */
	fprintf(fp, "From: IRC Bouncer <irc@%s>\r\n", bbs_hostname()); /* We don't have a hard dependency on net_smtp, so can't use smtp_hostname() */
	/* Email goes to the user, and conveniently, a user's email address is, at simplest, just the user's username.
	 * This is nice and simple, if this causes delivery issues for forwarded messages, then it may be better
	 * to tack on a hostname, but it's not really necessary otherwise. */
	fprintf(fp, "To: %s <%s>\r\n", bc->bu->username, bc->bu->username);
	if (IS_CHANNEL(bc)) {
		fprintf(fp, "Subject: Missed IRC messages in %s\r\n", bc->channel);
	} else {
		fprintf(fp, "Subject: Missed private messages from IRC\r\n");
	}

	/* Note that we can use either our username or the channel name directly in the email header.
	 * # and & (currently the only channel prefix characters supported in net_irc)
	 * are both legal characters in email addresses (and by extension, the Message-ID header). */
	fprintf(fp, "Message-ID: <%s-%s-%u-%" TIME_T_FMT "@%s>\r\n", "ircbouncer", bc->channel, bc->bu->msgid++, now, bbs_hostname()); /* Time isn't necessarily unique, but we're not going to be running this more than once a minute */

	/* We want mail clients to be able to thread related messages together.
	 * Here, we use a cheap trick that requires no memory of Message-ID's over time,
	 * deterministically referring to an ancestor that doesn't exist.
	 * This string we can recompute on the fly and it should always be the same. */
	fprintf(fp, "In-Reply-To: <%s-%s@%s>\r\n", "ircbouncer", bc->channel, bbs_hostname());
	fprintf(fp, "References: <%s-%s@%s>\r\n", "ircbouncer", bc->channel, bbs_hostname());

	fprintf(fp, "MIME-Version: 1.0\r\n");
	fprintf(fp, "Content-Type: text/plain; format=flowed\r\n");
	fprintf(fp, "\r\n"); /* EOH */

	/* It would be more efficient to just use bbs_sendfile,
	 * but since we need to format the email as format=flowed,
	 * we have to process each line of the email. */

	/* Our job is to read everything in the file, and email it to the user.
	 * If this is the private message file, note that
	 * ALL PMs are interleaved together. */
	while ((fgets(buf, sizeof(buf) - 1, in_fp))) {
		/* Take each line and append it to fp, in chunks of 72-character lines */
		char *miniline;
		size_t linelen;
		char *pos = buf;
		char *lf;

		lf = strchr(buf, '\n');
		if (!lf) {
			bbs_error("Skipping flush of invalid line\n");
			continue;
		}
		*lf = '\0'; /* Trim trailing newline */
		linelen = (size_t) (lf - buf);
		if (linelen > 0 && *(lf - 1) == '\r') {
			*(lf - 1) = '\0'; /* If for some reason line is CR LF terminated, handle that too */
			linelen--;
		}

		/* Split the line up into 72-character chunks */
		while (linelen > 72) {
			/* Find the last space within the first 72 characters. That's where we'll add a line break. */
			char *end = pos + (72 - 1);
			/* The condition we want to check here is end > pos
			 * However, this triggers a strict-overflow warning on newer versions of gcc,
			 * so the condition is rewritten as such: */
			while (end - pos > 0) {
				if (*end == ' ') {
					break;
				}
				end--;
			}
			/* Assuming we found one, replace the space with a newline */
			if (end > pos) {
				*end = '\n';
			}
			pos += 72;
			linelen -= 72;
		}

		/* Now, write the smaller lines into the email file, each line succeeded by a space if needed, then terminated with CR LF */
		pos = buf;
		while ((miniline = strsep(&pos, "\n"))) {
			fprintf(fp, "%s%s\r\n", miniline, !strlen_zero(pos) ? " " : ""); /* If there was more on this line, make sure we have a trailing space for format=flowed */
		}
	}
	fclose(fp);
	snprintf(mailfrom, sizeof(mailfrom), "irc@%s", bbs_hostname());
	return bbs_mail_message(tmpfilename, mailfrom, NULL);
}

static int periodic_channel_flush(struct bouncer_channel *bc, time_t now)
{
	if (bc->fp) {
		/* If the log file is currently open, check if it's non-empty. */
		if (ftell(bc->fp) == 0) { /* We're at the end of the file, so if that's 0, it's empty */
			return 0; /* It's empty, there's nothing to flush */
		}
		rewind(bc->fp); /* Since we're going to flush everything, seek to beginning */
		if (!email_flush(bc, bc->fp, now)) {
			file_truncate(bc->fp);
			return 0;
		}
		/* If we truncated the file, we're positioned at the beginning,
		 * ... but if we failed, then seek back to the end. */
		fseek(bc->fp, 0, SEEK_END);
	} else {
		int ch;
		char full_filename[PATH_MAX];
		/* If the log file isn't open (as will always be the case for bu->pmbc)
		 * there's probably nothing to flush...
		 * but check to see if it exists and is non-empty. */
		FILE *fp = open_logfile_for_reading(bc->bu, bc->channel, full_filename, sizeof(full_filename));
		if (!fp) {
			/* There's no log file, so there's nothing to flush */
			return 0;
		}
		/* Make extra sure the file is non-empty */
		ch = fgetc(fp);
		if (ch == EOF) { /* File is empty, for some reason... we have no use for an empty log file, so delete it on the way out */
			fclose(fp);
			bbs_delete_file(full_filename);
			return 0;
		}
		ungetc(ch, fp);
		if (!email_flush(bc, fp, now)) {
			fclose(fp);
			bbs_delete_file(full_filename);
			return 0;
		}
		fclose(fp);
	}
	return 1;
}

#define TIME_TO_FLUSH(bc) (bc->last_flush < now - bc->email_frequency)

static void *periodic_emailer(void *unused)
{
	UNUSED(unused);

	for (;;) {
		time_t now;
		struct bouncer_user *bu;
		struct bouncer_channel *bc;
		/* Check if any bouncer channels need to be flushed */
		now = time(NULL);
		RWLIST_RDLOCK(&bouncer_users);
		RWLIST_TRAVERSE(&bouncer_users, bu, entry) {
			bbs_mutex_lock(&bu->lock);

			/* First, flush any PMs */
			if (TIME_TO_FLUSH(bu->pmbc)) {
				if (!periodic_channel_flush(bu->pmbc, now)) {
					bu->pmbc->last_flush = now;
				}
			}

			/* Now, check the channels */
			RWLIST_TRAVERSE(&bu->channels, bc, entry) {
				if (TIME_TO_FLUSH(bc)) {
					if (!periodic_channel_flush(bc, now)) {
						bc->last_flush = now;
					}
				}
			}
			bbs_mutex_unlock(&bu->lock);
		}
		RWLIST_UNLOCK(&bouncer_users);
		/* Don't use usleep, as the SIGURG signal doesn't succeed in interrupting it */
		if (bbs_safe_sleep_interrupt(MIN_MS(1))) { /* Only check once per minute, since that's the granularity of the email digest frequency */
			bbs_debug(5, "Safe sleep returned\n");
			break;
		}
	}
	return NULL;
}

/*! \note Must be called locked */
static int __attribute__ ((format (gnu_printf, 2, 3))) bouncer_send(struct irc_user *user, const char *fmt, ...)
{
	char *buf;
	int len, res = 0;
	char *crlf;
	va_list ap;

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}

	crlf = strstr(buf, "\r\n");
	if (crlf) {
		bbs_warning("Caller should not add a trailing CR LF\n");
		*crlf = '\0';
	}

	bbs_debug(5, "<= %s\n", buf);
	res |= irc_user_exec(user, buf);

	free(buf);
	return res;
}

/*! \note Must be called locked */
static void stop_bouncer_client(struct bouncer_user *bu)
{
	bbs_verb(5, "Stopping bouncer client for %s\n", bu->username);
	bbs_assert_exists(bu->user);
	irc_unregister_programmatic_user(bu->user);
	irc_user_destroy(bu->user);
	bu->user = NULL;
}

/*! \note Must be called locked */
static void __stop_bouncer_for_channel(struct bouncer_channel *bc)
{
	if (bc->fp) {
		fclose(bc->fp);
		bc->fp = NULL;
	}
	/* For the dummy bouncer channel created for PMs,
	 * we never increment active_bouncers, so don't
	 * decrement it now. */
	if (IS_CHANNEL(bc) && !--bc->bu->active_bouncers) {
		/* No bouncers are running anymore, we can disconnect */
		stop_bouncer_client(bc->bu);
	}
	if (bc->email_frequency && !bc->interactive) {
		time_t now = time(NULL);
		/* If only email mode is enabled, since we're stopping, flush anything remaining. */
		periodic_channel_flush(bc, now);
		bc->last_flush = now;
	}
}

/*! \note Must be called locked */
static void stop_bouncer_for_channel(struct bouncer_channel *bc)
{
	/* Only do these for real channels, not for private messages */
	if (IS_CHANNEL(bc)) {
		bbs_verb(4, "Stopping bouncer session for %s:%s\n", bc->bu->username, bc->channel);

		if (bc->bu->user) {
			/* Leave the desired channel */
			if (bouncer_send(bc->bu->user, "PART %s", bc->channel)) {
				bbs_warning("Bouncer failed to PART %s\n", bc->channel);
				/* XXX What now? */
			}
		} /* else, if we had no client, we obviously weren't in the channel in the first place */
	}
	__stop_bouncer_for_channel(bc);
}

static void free_bouncer_channel(struct bouncer_channel *bc)
{
	if (IS_CHANNEL(bc)) { /* We only do this for real channels */
		stop_bouncer_for_channel(bc);
	}
	free(bc->data);
	free(bc);
}

static void free_bouncer_user(struct bouncer_user *bu)
{
	bbs_mutex_lock(&bu->lock);
	RWLIST_WRLOCK_REMOVE_ALL(&bu->channels, entry, free_bouncer_channel);
	if (bu->pmbc) {
		free_bouncer_channel(bu->pmbc);
	}
	bbs_mutex_unlock(&bu->lock);

	bbs_mutex_destroy(&bu->lock);
	free(bu);
}

/*! \brief Find a bouncer channel for a user, which is returned locked */
static struct bouncer_channel *find_bouncer_channel(const char *username, const char *channel)
{
	struct bouncer_user *bu;
	struct bouncer_channel *bc;
	unsigned int userid = bbs_userid_from_username(username);

	RWLIST_RDLOCK(&bouncer_users);
	RWLIST_TRAVERSE(&bouncer_users, bu, entry) {
		if (bu->userid != userid) {
			continue;
		}
		RWLIST_TRAVERSE(&bu->channels, bc, entry) {
			if (!strcmp(bc->channel, channel)) {
				bbs_mutex_lock(&bc->bu->lock);
				RWLIST_UNLOCK(&bouncer_users);
				return bc;
			}
		}
	}
	RWLIST_UNLOCK(&bouncer_users);
	return NULL;
}

/*! \brief Must be called locked */
static struct bouncer_channel *create_bouncer_channel(struct bouncer_user *bu, const char *channel, unsigned int interactive, unsigned int email_digest_freq)
{
	struct bouncer_channel *bc = calloc(1, sizeof(*bc));
	if (ALLOC_FAILURE(bc)) {
		return NULL;
	}
	bc->data = strdup(channel);
	if (ALLOC_FAILURE(bc->data)) {
		free(bc);
		return NULL;
	}
	bc->bu = bu;
	bc->channel = bc->data;
	SET_BITFIELD(bc->interactive, interactive);
	bc->email_frequency = email_digest_freq;
	return bc;
}

/*! \note bc->bu must be locked when calling */
static int bouncer_logfile_append(struct bouncer_channel *bc, const char *s, size_t len)
{
	if (bbs_assertion_failed(bc->fp != NULL)) {
		bbs_warning("Bouncer log file '%s:%s' not open?\n", bc->bu->username, bc->channel);
		return -1;
	}
	/* There is a cap on the size of the log file, which we must enforce here. */
	if (ftell(bc->fp) >= max_logfile_size) {
		bbs_debug(1, "Bouncer log file %u/.config/.bouncer.d/%s is full (%lu bytes), not appending\n", bc->bu->userid, bc->channel, ftell(bc->fp));
		return -1;
	}
	if (fwrite(s, 1, len, bc->fp) != len) {
		bbs_error("Failed to append to log file: %s\n", strerror(errno));
		return -1;
	}
	/* For performance, don't automatically flush writes each time.
	 * Even though we're storing it in a hidden subdirectory in the user's home dir,
	 * all interaction with the log file should be through this module,
	 * so it's fine if it's not immediately up to date on disk. */
	return 0;
}

/*! \note bc->bu must be locked when calling */
static void log_helper(struct bouncer_channel *bc, enum irc_command_callback_event event, const char *cmd, const char *channel, const char *hostmask, const char *data)
{
	char buf[584];
	time_t lognow;
	char *pos = buf + TIMESTAMP_CHARS;
	size_t left = sizeof(buf) - TIMESTAMP_CHARS;
	struct tm logdate;

	/* Prepare the buffer to write to the logfile.
	 * Since IRC doesn't have timestamps, we generate our own timestamp,
	 * then append the payload.
	 * Also note the time is local server time, not UTC or the user's local time. */
	lognow = time(NULL);
	localtime_r(&lognow, &logdate);
	strftime(buf, sizeof(buf), "%Y-%m-%d %T", &logdate);
	buf[TIMESTAMP_CHARS - 1] = ' '; /* Don't bother appending a NUL after, since snprintf below will overwrite, starting there */

	/* Log the message in the wire/protocol format for IRC */
	switch (event) {
		case IRCCMD_EVENT_JOIN:
		case IRCCMD_EVENT_PART:
		case IRCCMD_EVENT_KICK:
			snprintf(pos, left, ":%s %s %s\n", hostmask, cmd, channel);
			break;
		case IRCCMD_EVENT_QUIT:
			if (!strlen_zero(data)) {
				snprintf(pos, left, ":%s %s\n", hostmask, cmd); /* This is not a per-channel message in IRC, but the event is per-channel */
			} else {
				snprintf(pos, left, ":%s %s :%s\n", hostmask, cmd, data); /* This is not a per-channel message in IRC, but the event is per-channel */
			}
			break;
		case IRCCMD_EVENT_PRIVMSG:
		case IRCCMD_EVENT_TOPIC:
			snprintf(pos, left, ":%s %s %s :%s\n", hostmask, cmd, channel, data);
			break;
		case IRCCMD_EVENT_MODE:
			/* Sometimes there are 2 arguments, sometimes there are 3 (the channel is in the args if needed) */
			snprintf(pos, left, ":%s %s %s\n", hostmask, cmd, data);
			break;
		default:
			/* Unhandled, don't care */
			return;
	}

	bbs_debug(7, "Appending to bouncer log: %s", buf); /* Already ends in LF */
	bouncer_logfile_append(bc, buf, strlen(buf));
}

static int open_bouncer_logfile(struct bouncer_channel *bc, const char *username)
{
	char buf[1024], filename[1092];

	if (bc->fp) {
		bbs_debug(4, "Bouncer started elsewhere before we could do it, aborting\n");
		return -1;
	}

	bbs_transfer_home_config_subdir(bc->bu->userid, ".config/.bouncer.d", buf, sizeof(buf));
	bbs_ensure_directory_exists(buf);
	/* We know the filename is safe and contains no funny chars, since we validated it when reading the config */
	snprintf(filename, sizeof(filename), "%s/%s", buf, bc->channel); /* Filename is .config/.bouncer.d/#channel */

	bbs_verb(4, "Starting bouncer session for %s:%s\n", username, bc->channel);

	bc->fp = fopen(filename, "a+");
	if (!bc->fp) {
		bbs_error("Failed to open %s: %s\n", filename, strerror(errno));
		return -1;
	}
	return 0;
}

static void privmsg_cb(const char *hostmask, const char *sender, const char *recipient, char *msg)
{
	struct bouncer_user *bu;
	unsigned int userid = bbs_userid_from_username(recipient);

	UNUSED(sender); /* use hostmask instead */

	/* Someone is trying to private message us.
	 * Unlike the bouncer channels, we have no log file currently open
	 * for this operation, so we open the general PRIVMSG log file
	 * for this user, append to it, and exit.
	 * (Which is not a HUGE since private messages are much less frequent
	 *  than messages in ALL channels combined!) */

	RWLIST_RDLOCK(&bouncer_users);
	RWLIST_TRAVERSE(&bouncer_users, bu, entry) {
		if (bu->userid != userid) {
			continue;
		}
		break;
	}
	if (!bu) {
		goto done;
	}

	/* Bouncer enabled for this user.
	 * Now we need to determine if we should log private messages or not.
	 * Unlike actual channels, there is no concept of being "active"
	 * in a private message with a user.
	 * If the user is really logged in, but inactive, we don't,
	 * since the IRC client will pop open the private message.
	 * Only if no real user is connected should we do this. */
	if (irc_user_inactive(recipient) != -1) {
		goto done;
	}

	/* User is truly offline, go ahead and log it.
	 *
	 * There are two possible approaches to logging we can take here.
	 * One is to use a log file for every user that private messages us,
	 * treating each of those just like a channel.
	 * The other is to use a single log file for all private messages.
	 * The latter is more efficient, and also avoids issues caused by
	 * strange characters in transformed nicks for relayed networks, e.g. /,
	 * which could be interpreted as a directory hierarchy delimiter. */

	bbs_mutex_lock(&bu->lock);
	/* Note that we key this by our username, not the sender's, so all
	 * PMs received will share the same log file. This ensures we don't
	 * have to worry about characters in usernames or subdirectories.
	 * We don't keep this around persistently, because unlike channels,
	 * there aren't really tangible "channels" for PMs, and also receiving
	 * PMs is much less common so there's less point in keeping a handle around. */
	if (!open_bouncer_logfile(bu->pmbc, bu->username)) { /* We don't call start_bouncer_for_channel, so we need to open the log file manually */
		/* Format is same as channel messages, except our nickname is used instead of the channel name. */
		log_helper(bu->pmbc, IRCCMD_EVENT_PRIVMSG, "PRIVMSG", recipient, hostmask, msg);
		__stop_bouncer_for_channel(bu->pmbc);
	}
	bbs_mutex_unlock(&bu->lock);

done:
	RWLIST_UNLOCK(&bouncer_users);
}

static void command_cb(const char *cb_username, enum irc_command_callback_event event, const char *cmd, const char *channel, const char *hostmask, const char *username, const char *data)
{
	struct bouncer_channel *bc;

	UNUSED(username); /* We use the full hostmask instead */

	/* During unloads, a deadlock is possible between net_irc:&channels <-> mod_irc_bouncers <-> &bouncer_users:
	 *
	 * Thread B:
	 * mod_irc_bouncer: find_bouncer_channel -> attempt to RDLOCK &bouncer_users
	 * mod_irc_bouncer: command_cb
	 * net_irc: broadcast_channel_event
	 * net_irc: drop_member_if_present
	 * net_irc: leave_all_channels -> holds WRLOCK on &channels (with recursive locking enabled, for this thread)
	 *
	 * Thread A:
	 * net_irc: leave_channel -> attempt to WRLOCK &channels
	 * net_irc: irc_user_exec
	 * mod_irc_bouncer: bouncer_send("PART <channel>")
	 * mod_irc_bouncer: stop_bouncer_for_channel
	 * mod_irc_bouncer: free_bouncer_user
	 * mod_irc_bouncer: unload_module -> holds WRLOCK on &bouncer_users
	 */
	if (unloading) {
		/* Prevent deadlock by aborting, we don't need to log stuff during unload anyways */
		bbs_debug(1, "Ignoring activity for %s:%s, since we're unloading\n", cb_username, channel);
		return;
	}

	/* Find the bouncer channel that corresponds */
	bc = find_bouncer_channel(cb_username, channel); /* returned locked, if found */
	if (!bc) {
		/* The bouncer client is active for this user, but this channel is not being watched. */
		bbs_debug(7, "Ignoring, no bouncer channel for %s:%s\n", cb_username, channel);
	} else {
		/* We only log if the bouncer is actually enabled.
		 * i.e. if the user is in the channel, we don't. */
		if (bc->fp) {
			log_helper(bc, event, cmd, channel, hostmask, data);
		}
		bbs_mutex_unlock(&bc->bu->lock);
	}
}

struct irc_event_callbacks event_callbacks = {
	.privmsg_cb = privmsg_cb,
	.command_cb = command_cb,
};

/*! \brief Start bouncer for a regular channel (not including private messages) */
static int start_bouncer_for_channel(struct bouncer_channel *bc)
{
	bbs_mutex_lock(&bc->bu->lock);

	if (open_bouncer_logfile(bc, bc->bu->username)) {
		bbs_mutex_unlock(&bc->bu->lock);
		return -1;
	}

	/* If we don't yet have a user, create one */
	if (!bc->bu->user) {
		const char *nickname = bc->bu->username;
#ifndef USE_REAL_NICK_WHEN_POSSIBLE
		char alt_nickname[64];
#endif
		bbs_verb(5, "Starting bouncer client for %s\n", bc->bu->username);
		/* We create a sort of dummy user that will JOIN each channel.
		 * This ensures that we have permission to join the channel
		 * and that the user is enumerated when the bouncer is active.
		 * By all practical purposes, the bouncer user will look and smell
		 * mostly like the real user.
		 * However, actual message exchange does not take place using the IRC
		 * protocol (using file descriptors and such), but using event callbacks,
		 * the same way that ChanServ is implemented. */
		bc->bu->user = irc_user_create(USER_MODE_SECURE); /* Since it's a loopback connection, treat it as secure */
		if (!bc->bu->user) {
			fclose(bc->fp);
			bbs_mutex_unlock(&bc->bu->lock);
			bbs_error("Failed to create pseudo user for bouncer client\n");
			return -1;
		}
#ifndef USE_REAL_NICK_WHEN_POSSIBLE
		snprintf(alt_nickname, sizeof(alt_nickname), "%s_", bc->bu->username);
		nickname = alt_nickname;
#endif
		if (irc_user_set_identity(bc->bu->user, bc->bu->username, nickname, bc->bu->username, "IRCBouncer")
			|| irc_register_programmatic_user(bc->bu->user, &event_callbacks, IRCCMD_EVENT_PRIVMSG | IRCCMD_EVENT_JOIN | IRCCMD_EVENT_PART | IRCCMD_EVENT_QUIT | IRCCMD_EVENT_KICK | IRCCMD_EVENT_TOPIC)) {
			irc_user_destroy(bc->bu->user);
			fclose(bc->fp);
			bbs_mutex_unlock(&bc->bu->lock);
			bbs_error("Failed to create pseudo user for bouncer client\n");
			return -1;
		}
	} else {
		/* If we already have one, but the user has just left, we may want to switch nicknames. */
#ifdef USE_REAL_NICK_WHEN_POSSIBLE
		if (irc_user_inactive(bc->bu->username) == -1) {
			/* User isn't on IRC anymore, if we have a non-canonical nickname, try to assume the canonical nick. If it fails, oh well, keep the existing one.
			 * No change will occur if we already have it. */
			irc_user_set_nickname(bc->bu->user, bc->bu->username);
		}
#endif
	}

	bc->bu->active_bouncers++;

	/* Join the desired channel */
	if (bouncer_send(bc->bu->user, "JOIN %s", bc->channel)) {
		/* We failed to join the channel. */
		bbs_notice("Bouncer failed to JOIN %s\n", bc->channel); /* Maybe this user doesn't have permission to join the channel or something */
		__stop_bouncer_for_channel(bc);
	}

	bbs_mutex_unlock(&bc->bu->lock);
	return 0;
}

static int start_bouncers(void)
{
	struct bouncer_user *bu;
	struct bouncer_channel *bc;

	RWLIST_RDLOCK(&bouncer_users);
	RWLIST_TRAVERSE(&bouncer_users, bu, entry) {
		/* First, check if the user is active. If so, no need to start the bouncer now */
		if (!irc_user_inactive(bu->username)) {
			continue;
		}
		RWLIST_TRAVERSE(&bu->channels, bc, entry) {
			start_bouncer_for_channel(bc);
		}
	}
	RWLIST_UNLOCK(&bouncer_users);
	return 0;
}

static int away_cb(const char *username, enum irc_user_status userstatus, const char *msg)
{
	struct bouncer_user *bu;
	unsigned int userid = bbs_userid_from_username(username);

	UNUSED(msg);

	/* We only care if an IRC user has just logged onto IRC. */
	if (userstatus != IRC_USER_STATUS_JOIN) {
		return 0;
	}

	RWLIST_RDLOCK(&bouncer_users);
	RWLIST_TRAVERSE(&bouncer_users, bu, entry) {
		if (userid != bu->userid) {
			continue;
		}
		if (bu->pmbc->interactive) {
			/* Since the user just logged into IRC, flush any PMs that might be queued */
			interactive_flush(bu, username);
		}
		break;
	}
	RWLIST_UNLOCK(&bouncer_users);
	return 0;
}

static int join_leave(const char *username, const char *channel, int is_join)
{
	struct bouncer_user *bu;
	struct bouncer_channel *bc;
	unsigned int userid = bbs_userid_from_username(username);

	RWLIST_RDLOCK(&bouncer_users);
	RWLIST_TRAVERSE(&bouncer_users, bu, entry) {
		if (userid != bu->userid) {
			continue;
		}
		RWLIST_TRAVERSE(&bu->channels, bc, entry) {
			if (strcasecmp(channel, bc->channel)) {
				continue;
			}
			/* It's a match.
			 * In both cases, we are being called before anyone in the channel
			 * is notified about the JOIN, PART, or QUIT.
			 * Our task here is to ensure that we can gracefully swap places
			 * with the real user, so that nobody need know that anything happened. */
			if (is_join) {
				/* The user is in the channel now, although we haven't yet announced it to the channel.
				 * Stop the bouncer and, if appropriate, suppress the system message for JOIN/PART/QUIT/KICK. */
				bbs_mutex_lock(&bc->bu->lock);
				stop_bouncer_for_channel(bc); /* The channels list is already unlocked, so we can go ahead and drop immediately */

				bbs_assert(bc->fp == NULL); /* The log file should already be closed. */
				if (bc->interactive) {
					interactive_flush(bu, bc->channel); /* If interactive digest enabled, flush any messages for this channel now */
				}

				bbs_mutex_unlock(&bc->bu->lock);
				RWLIST_UNLOCK(&bouncer_users);
#ifdef USE_REAL_NICK_WHEN_POSSIBLE
				return 1;
#else
				return 0; /* If we are using a different nick, then we need channel members to know that we joined since the user's nick is different */
#endif
			} else {
				/* The user has just left the channel, though we're still processing it.
				 * Returning 1 will suppress the PART/QUIT/KICK message for it,
				 * and even before that, we'll join the channel.
				 *
				 * Note that net_irc's JOIN handler is specifically modified
				 * to avoid deadlock when we do this, since net_irc
				 * holds a WRLOCK on the channels list when it calls this callback function. */
				start_bouncer_for_channel(bc);
				RWLIST_UNLOCK(&bouncer_users);
#ifdef USE_REAL_NICK_WHEN_POSSIBLE
				return 1;
#else
				return 0; /* If we are using a different nick, then we need channel members to know that we left since the user's nick is different */
#endif
			}
		}
	}
	RWLIST_UNLOCK(&bouncer_users);
	return 0;
}

static void disable_bouncer(struct bouncer_user *bu)
{
	bbs_debug(3, "Disabling bouncers for %s\n", bu->username);
	bbs_mutex_lock(&bu->lock);
	RWLIST_REMOVE_ALL(&bu->channels, entry, free_bouncer_channel);
	bbs_mutex_unlock(&bu->lock);
}

static int load_config(const char *filename, unsigned int userid)
{
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	struct bbs_config *cfg;
	int enabled = 1;
	int i = 0;
	int interactive = 1, email_digest_freq = 0;
	struct bouncer_user *bu = NULL;
	char username[64] = "";

	cfg = bbs_config_load(filename, 1);
	if (!cfg) {
		return -1; /* File should exist, so this shouldn't happen... */
	}

	bbs_config_val_set_true(cfg, "general", "enabled", &enabled);
	if (!enabled) {
		/* If any bouncers were previously enabled, disable them. */
		RWLIST_WRLOCK(&bouncer_users);
		RWLIST_TRAVERSE_SAFE_BEGIN(&bouncer_users, bu, entry) {
			if (bu->userid == userid) {
				RWLIST_REMOVE_CURRENT(entry);
				disable_bouncer(bu);
			}
		}
		RWLIST_TRAVERSE_SAFE_END;
		RWLIST_UNLOCK(&bouncer_users);
		goto cleanup;
	}

	if (bbs_username_from_userid(userid, username, sizeof(username))) {
		bbs_warning("No such user with user ID %u\n", userid);
		goto cleanup;
	}

	bbs_config_val_set_true(cfg, "general", "interactive_digest", &interactive);
	bbs_config_val_set_int(cfg, "general", "email_digest_freq", &email_digest_freq);
	if (email_digest_freq <= 0) {
		interactive = 1; /* At least one or the other needs to be enabled */
	}

	RWLIST_WRLOCK(&bouncer_users);
	bu = calloc(1, sizeof(*bu) + strlen(username) + 1);
	if (ALLOC_FAILURE(bu)) {
		RWLIST_UNLOCK(&bouncer_users);
		goto cleanup;
	}
	strcpy(bu->data, username); /* Safe */
	bu->username = bu->data;
	bu->userid = userid;
	bbs_mutex_init(&bu->lock, NULL);
	RWLIST_HEAD_INIT(&bu->channels);
	RWLIST_INSERT_TAIL(&bouncer_users, bu, entry);

	bbs_mutex_lock(&bu->lock);

	/* First, create a bouncer "channel" for all private messages. */
	bu->pmbc = create_bouncer_channel(bu, bu->username, (unsigned int) interactive, (unsigned int) email_digest_freq);
	if (!bu->pmbc) {
		RWLIST_REMOVE(&bouncer_users, bu, entry);
		free(bu);
		goto cleanup2;
	}

	while ((section = bbs_config_walk(cfg, section))) {
		if (strcmp(bbs_config_section_name(section), "channels")) {
			continue; /* Not a channel mapping section, skip */
		}
		while ((keyval = bbs_config_section_walk(section, keyval))) {
			struct bouncer_channel *bc;
			const char *channel = bbs_keyval_key(keyval), *option = bbs_keyval_val(keyval);

			if (i >= user_maxbouncers) {
				bbs_user_config_log(cfg, LOG_ERROR, LOG_NOTICE, "Max bouncer bouncers exceeded for user %s\n", bu->username);
				break;
			}

			if (!irc_valid_channel_name(channel)) {
				bbs_user_config_log(cfg, LOG_ERROR, LOG_NOTICE, "Invalid IRC channel name '%s'\n", channel);
				continue;
			}

			/* Ensure we haven't already added this channel, for this user */
			RWLIST_TRAVERSE(&bu->channels, bc, entry) {
				if (!strcasecmp(bc->channel, channel)) {
					break;
				}
			}
			if (bc) {
				bbs_user_config_log(cfg, LOG_WARNING, LOG_NOTICE, "Ignoring duplicate bouncer channel %s\n", channel);
				continue;
			}

			email_digest_freq = atoi(option);
			interactive = email_digest_freq >= 0; /* Includes 0 */
			if (email_digest_freq < 0) {
				email_digest_freq = -email_digest_freq; /* Invert */
			}

			bc = create_bouncer_channel(bu, channel, (unsigned int) interactive, (unsigned int) email_digest_freq);
			if (bc) {
				RWLIST_INSERT_TAIL(&bu->channels, bc, entry);
				i++;
			}
		}
	}
cleanup2:
	bbs_mutex_unlock(&bu->lock);
	RWLIST_UNLOCK(&bouncer_users);

cleanup:
	bbs_config_unlock(cfg);
	return 0;
}

static int config_callback(const char *dir_name, const char *filename, void *obj)
{
	unsigned int userid;
	char fullpath[1024];

	UNUSED(obj);

	snprintf(fullpath, sizeof(fullpath), "%s/%s/.config/.bouncer", dir_name, filename);

	/* At this point, we already know the file exists. */
	userid = (unsigned int) atoi(filename);
	return load_config(fullpath, userid);
}

static int scan_configs(void)
{
	struct bbs_transfer_traversal t = {
		.filename = ".config/.bouncer",
		.callback = config_callback,
		.obj = NULL,
	};
	if (bbs_transfer_traverse_home_directories(&t)) {
		return -1;
	}
	return 0;
}

static int load_and_start(void)
{
	/* We don't call scan_configs() until the BBS is fully started,
	 * because it calls bbs_username_from_userid(),
	 * which won't work until a user provider is registered. */

	/*! \todo FIXME What if a file is created while BBS is running? Need to re-scan periodically?
	 * Ideally, we would use inotify to watch user's .config directories for changes to
	 * the .bouncer file, and automatically re-process just that user's config at that point.
	 * The BBS needs to have an inotify API we can use to do this, with tests for this functionality. */
	return scan_configs() || start_bouncers();
}

static int cli_bouncers(struct bbs_cli_args *a)
{
	struct bouncer_user *bu;
	struct bouncer_channel *bc;

	bbs_dprintf(a->fdout, "%-20s %6s %s\n", "User", "Active", "Channel");
	RWLIST_RDLOCK(&bouncer_users);
	RWLIST_TRAVERSE(&bouncer_users, bu, entry) {
		RWLIST_TRAVERSE(&bu->channels, bc, entry) {
			bbs_dprintf(a->fdout, "%-20s %6s %s\n", bu->username, bc->fp ? "Yes" : "No", bc->channel);
		}
	}
	RWLIST_UNLOCK(&bouncer_users);
	return 0;
}

static struct bbs_cli_entry cli_commands_bouncer[] = {
	BBS_CLI_COMMAND(cli_bouncers, "irc bouncers", 2, "List all IRC bouncers", NULL),
};

struct irc_relay_callbacks relay_callbacks = {
	.away = away_cb,
	.join_leave = join_leave,
};

static int load_module(void)
{
	if (bbs_pthread_create(&email_thread, NULL, periodic_emailer, NULL)) {
		RWLIST_WRLOCK_REMOVE_ALL(&bouncer_users, entry, free_bouncer_user);
		return -1;
	}
	bbs_run_when_started(load_and_start, STARTUP_PRIORITY_DEPENDENT);
	irc_relay_register(&relay_callbacks);
	bbs_cli_register_multiple(cli_commands_bouncer);
	return 0;
}

static int unload_module(void)
{
	unloading = 1;
	bbs_cli_unregister_multiple(cli_commands_bouncer);
	irc_relay_unregister(&relay_callbacks);
	bbs_pthread_interrupt(email_thread);
	bbs_pthread_join(email_thread, NULL);
	RWLIST_WRLOCK_REMOVE_ALL(&bouncer_users, entry, free_bouncer_user);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("IRC Bouncer", "net_irc.so");
