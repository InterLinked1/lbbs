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
 * \brief MailScript Filtering Engine
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>
#include <float.h>

#include "include/module.h"
#include "include/system.h"
#include "include/stringlist.h"
#include "include/variables.h"
#include "include/utils.h"
#include "include/transfer.h"
#include "include/user.h"

#include "include/mod_mail.h"
#include "include/net_smtp.h"

#define REQUIRE_ARG(s) \
	if (strlen_zero(s)) { \
		bbs_warning("Incomplete condition on line %d (%s must be nonempty)\n", lineno, #s); \
		return 0; \
	}

static int numcmp(char *s, int num)
{
	int match = 0;
	int val, eq, lt, gt;
	lt = *s == '<';
	gt = *s == '>';
	s++;
	eq = *s == '=';
	if (eq) {
		s++;
	}
	ltrim(s);
	if (strlen_zero(s)) {
		return 0;
	}
	val = atoi(s);
	if (lt && !eq && num < val) {
		match = 1;
	} else if (lt && eq && num <= val) {
		match = 1;
	} else if (gt && !eq && num > val) {
		match = 1;
	} else if (gt && eq && num >= val) {
		match = 1;
	} else if (eq && num == val) {
		match = 1;
	}
	return match;
}

enum match_type {
	MATCH_STRICT = 0,
	MATCH_SUBSTR,
	MATCH_REGEX,
	MATCH_GTE,
	MATCH_GT,
	MATCH_LTE,
	MATCH_LT,
	MATCH_EQ,
};

/*! \brief retval -1 if no such header, 0 if not found, 1 if found */
static int header_match(struct smtp_msg_process *mproc, const char *header, const char *find, enum match_type matchtype)
{
	int found = -1;
	size_t findlen = 0;
	regex_t regexbuf;
	int regcompiled = 0;
	char headerval[1000];
	size_t headerlen;

	if (!mproc->fp) {
		mproc->fp = fopen(mproc->datafile, "r");
		if (!mproc->fp) {
			bbs_error("fopen(%s) failed: %s\n", mproc->datafile, strerror(errno));
			return 0;
		}
	} else {
		rewind(mproc->fp);
	}
	headerlen = strlen(header);
	while ((fgets(headerval, sizeof(headerval), mproc->fp))) {
		char *start;
		if (!strcmp(headerval, "\r\n")) {
			break; /* End of headers */
		}
		if (strncasecmp(headerval, header, headerlen)) { /* Header names are not case-sensitive */
			continue; /* It's not the right header. */
		}
		start = headerval + headerlen;
		if (*start != ':') {
			continue; /* Prefix of another header, I guess. Not actually the right header. */
		}
#ifdef EXTRA_DEBUG
		bbs_debug(8, "Found %s header\n", header);
#endif
		found = 0; /* At this point, we have found the header exists. But not sure yet if it's a match. */
		if (!find) {
			break; /* Just care if it exists, not what the value is */
		}
		start++;
		ltrim(start);
		bbs_strterm(start, '\r');
		/*! \todo BUGBUG FIXME Technically, header values could cross line boundaries for multi-line headers,
		 * but the logic here wouldn't match if a string is split by CR LF. */
		if (matchtype == MATCH_STRICT) {
			/* Exact match, easy */
			if (!findlen) {
				findlen = strlen(find);
			}
			/* This is relatively efficient since we don't do any copying to make comparisons. */
			found = !strncmp(start, find, findlen); /* Values are case-sensitive */
#ifdef EXTRA_DEBUG
			bbs_debug(7, "Comparison(%d) = %.*s with %s\n", found, (int) findlen, start, find);
#endif
			start += findlen;
			if (found && (!strlen_zero(start) && *start != '\r')) {
				bbs_debug(8, "Was just a prefix of something else\n");
				found = 0;
			} else {
				break;
			}
		} else if (matchtype == MATCH_SUBSTR) {
			/* Things like "CONTAINS" can be done with LIKE... (it's just a subset of it), technically even EQUALS could be, too...
			 * However, this is obviously more efficient. */
			found = strstr(start, find) ? 1 : 0;
			if (found) {
				break;
			}
		} else if (matchtype == MATCH_REGEX) {
			/* Use a regular expression for LIKE */
			if (!regcompiled) {
				int errcode;
				if ((errcode = regcomp(&regexbuf, find, REG_EXTENDED | REG_NOSUB))) {
					regerror(errcode, &regexbuf, headerval, sizeof(headerval)); /* steal headerval buf */
					bbs_warning("Malformed expression %s: %s\n", find, headerval);
					break; /* If the regex is invalid, we'll never be able to use it anyways */
				}
				regcompiled = 1;
			}
			bbs_debug(6, "Evaluating regex: '%s' %s\n", find, start);
			found = regexec(&regexbuf, start, 0, NULL, 0) ? 0 : 1;
			if (found) {
				break;
			}
		} else { /* numeric comparisons */
			double threshold, actual, diff;
			/* We don't use numcmp, since we need to support floating point numbers */
			if (sscanf(find, "%4lf", &threshold) != 1) {
				bbs_warning("Invalid numeric value: %s\n", start);
			} else {
				int count;
				actual = 0;
				count = sscanf(start, "%4lf", &actual);
				bbs_debug(5, "Found: %d, Threshold: %f, Actual: %f (%s)\n", found, threshold, actual, start);
				switch (matchtype) {
					case MATCH_GTE:
						found = count == 1 && actual >= (threshold - DBL_EPSILON);
						break;
					case MATCH_GT:
						found = count == 1 && actual > (threshold - DBL_EPSILON);
						break;
					case MATCH_LTE:
						found = count == 1 && actual <= (threshold + DBL_EPSILON);
						break;
					case MATCH_LT:
						found = count == 1 && actual < (threshold + DBL_EPSILON);
						break;
					case MATCH_EQ:
						diff = actual - threshold;
						if (diff < 0) {
							diff = -diff;
						}
						found = count == 1 && diff < DBL_EPSILON; /* Floating point equality comparison */
						break;
					default:
						bbs_soft_assert(0); /* Shouldn't be reached */
				}
			}
		}
	}
	if (regcompiled) {
		regfree(&regexbuf);
	}
	return found;
}

static void __attribute__ ((nonnull (2, 3, 4))) str_match(const char *matchtype, const char *a, const char *expr, int *restrict match)
{
	if (!strcasecmp(matchtype, "EQUALS")) {
		*match = !strcasecmp(a, expr);
	} else if (!strcasecmp(matchtype, "CONTAINS")) {
		*match = strcasestr(a, expr) ? 1 : 0;
	} else if (!strcasecmp(matchtype, "LIKE")) {
		regex_t regexbuf;
		int errcode;
		if ((errcode = regcomp(&regexbuf, expr, REG_EXTENDED | REG_NOSUB))) {
			char errbuf[256];
			regerror(errcode, &regexbuf, errbuf, sizeof(errbuf));
			bbs_warning("Malformed expression %s: %s\n", expr, errbuf);
		} else {
			bbs_debug(6, "Evaluating regex: '%s' %s\n", expr, a);
			*match = regexec(&regexbuf, a, 0, NULL, 0) ? 0 : 1;
			regfree(&regexbuf);
		}
	} else {
		bbs_warning("Invalid command match type: %s\n", matchtype);
	}
}

static int test_condition(struct smtp_msg_process *mproc, int lineno, int lastretval, const char *usermaildir, char *s)
{
	char *next;
	int match = 0;
	int negate = 0;

	REQUIRE_ARG(s);/* Empty match implicitly matches anything anyways */

#ifdef EXTRA_DEBUG
	bbs_debug(7, "Evaluating condition: %s\n", s);
#endif

	next = strsep(&s, " ");
	REQUIRE_ARG(s);
	if (!strcasecmp(next, "NOT")) {
		negate = 1;
		next = strsep(&s, " ");
		REQUIRE_ARG(s);
	}
	if (!strcasecmp(next, "DIRECTION")) {
		if (!strcasecmp(s, "IN")) {
			match = mproc->direction == SMTP_MSG_DIRECTION_IN;
		} else if (!strcasecmp(s, "OUT")) {
			match = mproc->direction == SMTP_MSG_DIRECTION_OUT;
		} else {
			bbs_warning("Invalid direction: %s\n", s);
		}
	} else if (!strcasecmp(next, "RETVAL")) {
		match = numcmp(s, lastretval);
	} else if (!strcasecmp(next, "SIZE")) {
		match = numcmp(s, mproc->size);
	} else if (!strcasecmp(next, "MAILFROM")) {
		const char *expr, *matchtype;
		matchtype = strsep(&s, " ");
		expr = s;
		REQUIRE_ARG(expr);
		REQUIRE_ARG(mproc->from);
		str_match(matchtype, mproc->from, expr, &match);
	} else if (!strcasecmp(next, "RECIPIENT")) {
		const char *expr, *matchtype;
		matchtype = strsep(&s, " ");
		expr = s;
		REQUIRE_ARG(expr);
		REQUIRE_ARG(mproc->recipient);
		str_match(matchtype, mproc->recipient, expr, &match);
	} else if (!strcasecmp(next, "HEADER")) {
		int found;
		const char *expr, *matchtype, *header;
		header = strsep(&s, " ");
		matchtype = strsep(&s, " ");
		expr = s;
		if (!strcasecmp(matchtype, "EXISTS")) {
			found = header_match(mproc, header, NULL, MATCH_STRICT);
			match = found >= 0;
		} else if (!strcasecmp(matchtype, "EQUALS")) {
			REQUIRE_ARG(expr);
			found = header_match(mproc, header, expr, MATCH_STRICT);
			match = found == 1;
		} else if (!strcasecmp(matchtype, "CONTAINS")) {
			REQUIRE_ARG(expr);
			found = header_match(mproc, header, expr, MATCH_SUBSTR);
			match = found == 1;
		} else if (!strcasecmp(matchtype, "LIKE")) {
			REQUIRE_ARG(expr);
			found = header_match(mproc, header, expr, MATCH_REGEX);
			match = found == 1;
		} else if (!strcmp(matchtype, ">=")) {
			REQUIRE_ARG(expr);
			found = header_match(mproc, header, expr, MATCH_GTE);
			match = found == 1;
		} else if (!strcmp(matchtype, ">")) {
			REQUIRE_ARG(expr);
			found = header_match(mproc, header, expr, MATCH_GT);
			match = found == 1;
		} else if (!strcmp(matchtype, "<=")) {
			REQUIRE_ARG(expr);
			found = header_match(mproc, header, expr, MATCH_LTE);
			match = found == 1;
		} else if (!strcmp(matchtype, "<")) {
			REQUIRE_ARG(expr);
			found = header_match(mproc, header, expr, MATCH_LT);
			match = found == 1;
		} else if (!strcmp(matchtype, "==")) {
			REQUIRE_ARG(expr);
			found = header_match(mproc, header, expr, MATCH_EQ);
			match = found == 1;
		} else {
			bbs_warning("Invalid HEADER command match type: %s\n", matchtype);
		}
	} else if (!strcasecmp(next, "FILE")) {
		char fullfile[1024];
		char *file = fullfile;
		REQUIRE_ARG(s);
		if (*s != '/') {
			if (usermaildir) {
				snprintf(fullfile, sizeof(fullfile), "%s/%s", usermaildir, s);
			} else {
				/* This is a system rule not associated with a particular mailbox,
				 * so we can't process this rule. */
				bbs_warning("Path '%s' is invalid in this context. Relative paths can only be used for mailbox-associated MailScript rules!\n", s);
				return 0; /* Not a match */
			}
		} else {
			file = s;
		}
		if (bbs_file_exists(file)) {
			match = 1;
		}
	} else {
		bbs_warning("Invalid condition: %s %s\n", next, S_IF(s));
	}
	match = negate ? !match : match;
#ifdef EXTRA_DEBUG
	/* Can't print condition since we mangled it with strsep */
	bbs_debug(7, "Evaluated condition => %s\n", match ? "1 (TRUE)" : "0 (FALSE)");
#endif
	return match;
}

static int exec_cmd(struct smtp_msg_process *mproc, char *s)
{
	int res;
	char subbuf[1024];
	char *argv[32];
	int argc;
	int wants_copy;
	char tmpfile[256];
	struct bbs_exec_params x;

	wants_copy = strstr(s, "${MAILFILE}") ? 1 : 0;

	if (wants_copy) { /* This rule wants the message as a file */
		if (mproc->iteration == FILTER_MAILBOX) {
			/* Since the container does not have access to any maildir, including the mailbox's,
			 * we need to copy the data file to a temp file inside the container for access.
			 * However, each container gets its own temporary environment, and thus its own /tmp.
			 * So, we create the temp copy in the user's home directory.
			 * Because of that limitation, EXEC can only be used for personal mailboxes,
			 * not shared mailboxes (mailboxes not associated with a user). However,
			 * global rules could be used to target those. */
			if (!mproc->userid) {
				bbs_warning("EXEC must be used from either a global rule or be associated with a personal mailbox\n");
				return 1;
			}

			/* First, ensure the .config directory exists. Thi function creates the .config subdirectory if needed. */
			if (bbs_transfer_home_config_dir(mproc->userid, tmpfile, sizeof(tmpfile))) { /* Ignore result, just reuse buffer */
				return 1;
			}

			/* Calculate the path of the temp file we are going to create */
			res = bbs_transfer_home_config_file(mproc->userid, basename(mproc->datafile), tmpfile, sizeof(tmpfile));
			if (res == -1) {
				return 1; /* Couldn't calculate path */
			} else if (res == 0) {
				/* The .config subdirectory of the user's home directory is intended to only
				 * hold config files that start with '.', and since mproc->datafile doesn't,
				 * it should be safe to create it in here. */
				bbs_warning("File %s already exists, skipping EXEC to avoid clobbering\n", tmpfile);
				return 1; /* File already exists */
			} /* else, res == 1, file does not exist (which is what we want) */

			if (bbs_copy_files(mproc->datafile, tmpfile, 0)) {
				return 1;
			}

			bbs_node_var_set_fmt(mproc->node, "MAILFILE", "~/.config/%s", basename(mproc->datafile));
		} else { /* FILTER_BEFORE_MAILBOX or FILTER_AFTER_MAILBOX */
			
			bbs_node_var_set(mproc->node, "MAILFILE", mproc->datafile);
		}
	}

	bbs_node_substitute_vars(mproc->node, s, subbuf, sizeof(subbuf));
	s = subbuf;
	argc = bbs_argv_from_str(argv, ARRAY_LEN(argv), s); /* Parse string into argv */
	if (argc < 1 || argc > (int) ARRAY_LEN(argv)) {
		bbs_warning("Invalid EXEC action\n");
		res = 1; /* Rules may rely on a return code of 0 for success, so don't return 0 if we didn't do anything */
		goto cleanup;
	}

	EXEC_PARAMS_INIT_HEADLESS(x);
	if (mproc->iteration == FILTER_MAILBOX) {
		/* While we allow users to use the EXEC command,
		 * the execution must be isolated (run in the container). */
		x.isolated = 1;
		/* We need to execute in the context of the user's environment,
		 * so override the execution user to the user. */
		if (mproc->userid) {
			x.user = bbs_user_from_userid(mproc->userid);
		}
	} /* else, global rule, since sysadmin has control over these, it's safe to allow execution of programs on host system */

	res = bbs_execvp(mproc->node, &x, argv[0], argv); /* Directly return the exit code */

	if (x.user) {
		bbs_user_destroy(x.user); /* Destroy the temporary user we created for execution */
	}

cleanup:
	if (wants_copy && mproc->iteration == FILTER_MAILBOX) {
		/* Delete the temp file we created */
		bbs_delete_file(tmpfile);
	}
	return res;
}

#undef REQUIRE_ARG
#define REQUIRE_ARG(s) \
	if (strlen_zero(s)) { \
		bbs_warning("Incomplete action on line %d\n", lineno); \
		return 0; \
	}

static int do_action(struct smtp_msg_process *mproc, int lineno, char *s)
{
	char *next;

	REQUIRE_ARG(s);

	next = strsep(&s, " ");
	if (!strcasecmp(next, "NOOP")) {
		return 0;
	} else if (!strcasecmp(next, "MOVETO")) {
		char newdir[512];
		REQUIRE_ARG(s);
		if (!STARTS_WITH(s, "imap:") && !STARTS_WITH(s, "imaps:")) {
			/* Doesn't support INBOX (and doesn't need to, that's the default) */
			if (mproc->userid) {
				snprintf(newdir, sizeof(newdir), "%s/%d/.%s", mailbox_maildir(NULL), mproc->userid, s);
			} else {
				snprintf(newdir, sizeof(newdir), "%s/.%s", mailbox_maildir(mproc->mbox), s);
			}
			if (eaccess(newdir, R_OK)) {
				bbs_warning("MOVETO failed: %s\n", strerror(errno));
				return 0;
			}
		}
		REPLACE(mproc->newdir, s);
	} else if (!strcasecmp(next, "BOUNCE") || !strcasecmp(next, "REJECT")) {
		mproc->bounce = 1;
		if (!strcasecmp(next, "REJECT")) {
			mproc->drop = 1;
		} /* for BOUNCE, reject at protocol level, but don't implicitly drop it */
		free_if(mproc->bouncemsg);
		if (s && *s == '"') {
			s++; /* Strip quotes */
		}
		if (!strlen_zero(s)) {
			mproc->bouncemsg = strdup(s);
			bbs_strterm(mproc->bouncemsg, '"'); /* Strip any trailing quotes */
		}
	} else if (!strcasecmp(next, "DISCARD")) {
		mproc->drop = 1;
	} else if (!strcasecmp(next, "EXEC")) {
		REQUIRE_ARG(s);
		return exec_cmd(mproc, s);
	} else if (!strcasecmp(next, "REDIRECT")) {
		REQUIRE_ARG(s);
		/* Don't allow forwarding to self, or that will create a loop (one that can't even be detected, since message is not modified) */
		if (!stringlist_contains(mproc->forward, s)) {
			stringlist_push(mproc->forward, s);
		}
	} else if (!strcasecmp(next, "RELAY")) {
		REQUIRE_ARG(s);
		/* Submit the message via a message submission agent (relay it through some other mail server) */
		REPLACE(mproc->relayroute, s);
	} else {
		bbs_warning("Invalid action: %s %s\n", next, S_IF(s));
	}
	return 0;
}

/*!
 * \brief Run rules using a given MailScript rules file
 * \param mproc
 * \param rulesfile Full path to MailScript to execute
 * \param usermaildir ull path to maildir of corresponding mailbox, if exists (could be NULL)
 * \retval 0 to continue, -1 to exit rule processing
 */
static int run_rules(struct smtp_msg_process *mproc, const char *rulesfile, const char *usermaildir)
{
	int res = 0;
	FILE *fp;
	char buf[512];
	char *s;
	int multilinecomment = 0;
	int in_rule = 0;
	int skip_rule = 0;
	int if_count = 0; /* Level of nested IF */
	int want_endif = 0; /* How many ENDIF's we need to encounter before we can start processing lines (we're skipping false blocks) */
	int retval = 0;
	int lineno = 0;

	if (!bbs_file_exists(rulesfile)) {
		bbs_debug(7, "MailScript %s doesn't exist\n", rulesfile);
		return 0;
	}

	fp = fopen(rulesfile, "r");
	if (!fp) {
		bbs_error("fopen(%s) failed: %s\n", rulesfile, strerror(errno));
		return 0;
	}

	bbs_debug(5, "Evaluating MailScript rules in %s\n", rulesfile);

	/* Single pass over the rules file */
	while (fgets(buf, sizeof(buf), fp)) {
		int was_skip = 0;
		s = buf;
		lineno++;
		bbs_term_line(s); /* Ignore line endings in a tolerant way (CR LF vs LF) */
		bbs_strterm(s, '#'); /* Ignore single line comments */
		trim(s);
		if (strlen_zero(s)) {
			continue;
		}
		was_skip = skip_rule;
		if (!strcasecmp(s, "ENDCOMMENT")) {
			if (multilinecomment > 0) {
				multilinecomment--;
			} else {
				bbs_warning("No multiline comment active at line %d\n", lineno);
			}
			continue;
		} else if (!strcasecmp(s, "COMMENT")) {
			multilinecomment++;
		} else if (multilinecomment) {
#ifdef EXTRA_DEBUG
			bbs_debug(10, "Skipping rest of multiline comment...\n");
#endif
			continue; /* Ignore multiline comments */
		} else if (!strcasecmp(s, "RULE")) {
			in_rule = 1;
		} else if (!in_rule) {
			bbs_warning("Ignoring directive outside of rule: %s\n", s);
		} else if (!strcasecmp(s, "ENDRULE")) {
			skip_rule = in_rule = 0;
		} else if (skip_rule) {
#ifdef EXTRA_DEBUG
			bbs_debug(10, "Skipping rest of rule...\n");
#endif
			continue;
		} else if (!strcasecmp(s, "ENDIF")) {
			if (if_count > 0) {
#ifdef EXTRA_DEBUG
				bbs_debug(6, "if_count=%d, want_endif=%d\n", if_count, want_endif);
#endif
				if (want_endif) {
					--want_endif;
				}
				if_count--;
			} else {
				bbs_warning("No IF block scope at line %d\n", lineno);
			}
		} else if (want_endif) {
			if (STARTS_WITH(s, "IF ")) {
				/* Don't care what condition is, or whether it's true or false,
				 * we just need to adjust if_count/want_endif,
				 * so that we properly handle nested IF blocks. */
				if_count++;
				want_endif++;
			}
#ifdef EXTRA_DEBUG
			bbs_debug(10, "Skipping rest of if condition...\n");
#endif
			continue;
		} else if (STARTS_WITH(s, "TEST ")) {
			s += STRLEN("TEST ");
			retval = test_condition(mproc, lineno, retval, usermaildir, s);
		} else if (STARTS_WITH(s, "MATCH ")) {
			s += STRLEN("MATCH ");
			retval = test_condition(mproc, lineno, retval, usermaildir, s);
			if (!retval) {
				skip_rule = 1; /* Didn't match, skip this rule */
			}
		} else if (STARTS_WITH(s, "ACTION ")) {
			s += STRLEN("ACTION ");
			if (strlen_zero(s)) {
				return 0;
			}
			bbs_debug(5, "Executing action: %s\n", s);
			if (STARTS_WITH(s, "BREAK")) {
				skip_rule = 1;
			} else if (STARTS_WITH(s, "RETURN")) {
				break;
			} else if (STARTS_WITH(s, "EXIT")) {
				if (mproc->iteration == FILTER_MAILBOX) {
					bbs_warning("EXIT not allowed for user mailbox rules, doing RETURN instead\n");
				} else {
					/* We only allow EXIT to abort global rules processing
					 * if this is a systemwide rule. Otherwise, that would
					 * allow a user to skip after.sieve and after.rules
					 * from being run, where some actions may be enforced system-wide. */
					res = 1; /* Return 1, not -1, since we don't want to abort the SMTP transaction, just rules processing */
				}
				break;
			} else {
				retval = do_action(mproc, lineno, s);
			}
		} else if (STARTS_WITH(s, "IF ")) {
			int cond, negate = 0;
			s += STRLEN("IF ");
			if_count++;
			/* Evaluate this condition */
			if (STARTS_WITH(s, "NOT ")) {
				negate = 1;
				s += STRLEN("NOT ");
			}
			cond = test_condition(mproc, lineno, retval, usermaildir, s);
			if (negate) {
				cond = !negate;
			}
			if (!cond) {
				want_endif++;
				bbs_debug(5, "Skipping IF conditional, condition at line %d is false\n", lineno);
			}
		} else {
			bbs_warning("Invalid command: %s\n", s);
		}

		if (!was_skip && skip_rule) { /* Rule statement just evaluated as false */
#ifdef EXTRA_DEBUG
			/* We butchered the rule statement with strsep so can't print it out again */
			bbs_debug(5, "Skipping rule, condition at line %d false\n", lineno);
#endif
		}
	}

	fclose(fp);
	return res;
}

static char before_rules[256];
static char after_rules[256];

static int mailscript(struct smtp_msg_process *mproc)
{
	char filepath[256];
	const char *mboxmaildir;

	/* COMBINED scope is only for outbound mail submissions */
	if (mproc->scope != SMTP_SCOPE_INDIVIDUAL && mproc->dir != SMTP_DIRECTION_SUBMIT) {
		return 0;
	}

	/* Calculate maildir path, if we have a mailbox */
	if (mproc->userid) {
		snprintf(filepath, sizeof(filepath), "%s/%d", mailbox_maildir(NULL), mproc->userid);
		mboxmaildir = filepath;
	} else if (mproc->mbox) {
		mboxmaildir = mailbox_maildir(mproc->mbox);
	} else {
		mboxmaildir = NULL;
	}

	if (mproc->iteration == FILTER_BEFORE_MAILBOX) {
		return run_rules(mproc, before_rules, mboxmaildir);
	} else if (mproc->iteration == FILTER_AFTER_MAILBOX) {
		return run_rules(mproc, after_rules, mboxmaildir);
	} else { /* FILTER_MAILBOX */
		int res;
		char script[263];
		if (!mboxmaildir) {
			return 0; /* Can't execute per-mailbox callback if there is no mailbox */
		}
		/* We execute up to 2 different script files, if they exist.
		 * First, the version in the maildir, which is always allowed to exist,
		 * but can only be modified by the sysop. This is most useful for public mailboxes.
		 * Second, the version in the user's home directory, which only exists
		 * for user mailboxes, but can be modified directly by them. */
		snprintf(script, sizeof(script), "%s/.rules", mboxmaildir);
		res = run_rules(mproc, script, mboxmaildir);
		if (res) {
			return res;
		}
		/* If this is a user's mailbox, also execute any rules in the user's home directory. */
		if (mproc->userid && !bbs_transfer_home_config_file(mproc->userid, ".rules", script, sizeof(script))) {
			res = run_rules(mproc, script, mboxmaildir);
		}
		return res;
	}
}

struct smtp_message_processor proc = {
	.callback = mailscript,
	.dir = SMTP_DIRECTION_ALL,
	/* Filters are typically only run for individual delivery.
	 * Even global rules should use SMTP_SCOPE_INDIVIDUAL,
	 * since they could manipulate the mailbox in some way,
	 * and we don't have a single mailbox if processing
	 * a message that will get delivered to multiple recipients.
	 * However, mail submissions do use COMBINED scope, as they are not run per-recipient,
	 * since in that case the mailbox belongs to the sender, not the recipient. */
	.scope = SMTP_SCOPE_INDIVIDUAL | SMTP_SCOPE_COMBINED,
	.iteration = FILTER_ALL_PASSES, /* We handle all passes, with more granular logic in the callback */
};

static int load_module(void)
{
	snprintf(before_rules, sizeof(before_rules), "%s/before.rules", mailbox_maildir(NULL));
	snprintf(after_rules, sizeof(after_rules), "%s/after.rules", mailbox_maildir(NULL));
	return smtp_register_processor(&proc);
}

static int unload_module(void)
{
	return smtp_unregister_processor(&proc);
}

BBS_MODULE_INFO_DEPENDENT("SMTP MailScript Engine", "net_smtp.so");
