/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2026, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Active group metadata file implementation
 */

#include "include/bbs.h"

#include <dirent.h>

#include "include/node.h"
#include "include/utils.h"

#include "nntp.h"
#include "nntp_active_file.h"

/* News server metadata file */
static char active_file[sizeof(newsdir) + STRLEN("/active")] = ""; /* active file (used for LIST ACTIVE) */

static int newsdir_has_subdirs = 0;

static int newsdir_contains_groups(const char *path)
{
	DIR *dir;
	struct dirent *entry;
	int res = 0;

	if (!(dir = opendir(path))) {
		bbs_error("Error opening directory - %s: %s\n", path, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) { /* Don't just bail out if errno becomes set, modules could set errno when we load them. */
		if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		} else if (entry->d_type == DT_DIR) {
			/* Exclude special directories, e.g. .backlog */
			if (entry->d_name[0] == '.') {
				continue;
			}
			res = 1;
			break;
		}
	}
	closedir(dir);
	return res;
}

int active_file_init(void)
{
	snprintf(active_file, sizeof(active_file), "%s/active", newsdir);

	/* Note that we aren't concerned here with what the directories themselves are
	 * or how they are organized (only the spool implementation is concerned with these details),
	 * but all implementations (as of now) will create subdirectories. */
	if (newsdir_contains_groups(newsdir)) {
		newsdir_has_subdirs = 1;
		if (!bbs_file_exists(active_file)) {
			/* We have groups in the spool, but no active file, that's not good... */
			bbs_error("Active file %s doesn't exist, but newsdir contains subdirectories?\n", active_file);
			return -1;
		}
	}
	return 0;
}

void active_file_cleanup(void)
{
	return;
}

/* As discussed in the mega-comment near the top of net_nntp,
 * here we use an "extended" format for the active file,
 * to reduce the number of files needed to store group metadata (to just 1, in this case).
 *
 * Format is (tab-separated):
 * <name> <last> <high> <low> <count> <status> <created> <creator> <description>
 */

#define active_strsep(s) (strsep(&s, "\t"))

#define PARSE_ACTIVE_NUM(var) \
	tmp = active_strsep(s); \
	if (unlikely(strlen_zero(tmp))) { \
		bbs_error("Active file line malformed, missing %s\n", #var); \
		return 1; /* Line malformed */ \
	} \
	var = atoi(tmp);

#define PARSE_ACTIVE_STR(var) \
	tmp = active_strsep(s); \
	if (unlikely(strlen_zero(tmp))) { \
		bbs_error("Active file line malformed, missing %s\n", #var); \
		return 1; /* Line malformed */ \
	} \
	var = tmp;

/*!
 * \internal
 * \brief Parse out group information from a line in the active file
 * \param s Line from active file for this newsgroup, excluding the group name, i.e. beginning with <last>
 * \param[out] g Group information
 * \retval 0 on success
 * \retval -1 on system error
 * \retval 1 if line was malformed
 */
static inline int parse_active_line(char *s, struct group_info *restrict g)
{
	char *tmp, *desc;
	PARSE_ACTIVE_NUM(g->last);
	PARSE_ACTIVE_NUM(g->high);
	PARSE_ACTIVE_NUM(g->low);
	PARSE_ACTIVE_NUM(g->count);
	PARSE_ACTIVE_STR(g->status);
	PARSE_ACTIVE_NUM(g->created);
	PARSE_ACTIVE_STR(g->creator);
	PARSE_ACTIVE_STR(desc);
	bbs_term_line(desc); /* Don't leave trailing LF in description */
	g->description = desc;
	return 0;
}

static inline void write_active_file_line(FILE *fp, struct group_info *g)
{
	/* We zero-pad any article numbers (last, high, low, count) to 10 digits so that the active file can be edited in place.
	 * The epoch is also inherently 10 digits (was < 9 digits prior to 2001-09-09 01:46:39) and will be 10 digits until 2286-11-20 17:46:39.
	 * Since the creator and description can have spaces, the whole line is tab-delimited. */
	fprintf(fp, "%s\t%010d\t%010d\t%010d\t%010d\t%s\t%10ld\t%s\t%s\n", g->name, g->last, g->high, g->low, g->count, g->status, g->created, g->creator, g->description);
}

enum group_mod_type {
	GROUP_CREATE,
	GROUP_DELETE,
	GROUP_MODIFY,
};

#define DEFAULT_VALUE(field, compval) if (g->field == compval) { g->field = oldgroup->field; }

static inline void update_and_set_group(struct group_info *g, struct group_info *oldgroup)
{
	/* Carry over existing values if necessary */
	DEFAULT_VALUE(last, -1);
	DEFAULT_VALUE(high, -1);
	DEFAULT_VALUE(low, -1);
	DEFAULT_VALUE(count, -1);
	DEFAULT_VALUE(status, NULL);
	g->created = oldgroup->created; /* Doesn't change */
	g->creator = oldgroup->creator; /* Doesn't change */
	DEFAULT_VALUE(description, NULL);
}

/*!
 * \brief Create or rewrite the active file, either to add or delete a group
 * \param[in] modtype Whether we are creating or deleting a group
 * \param[in] g Group information
 * \retval -1 system error occured
 * \retval 1 program/environment error occured
 * \retval 0 on success
 */
static int regenerate_active_file(enum group_mod_type modtype, struct group_info *g)
{
	FILE *oldfp, *newfp;
	char template[64] = "/tmp/nntp_activeXXXXXX";
	int inserted = 0;
	int error = 0;
	int found_group = 0;

	oldfp = fopen(active_file, "r");
	if (!oldfp) {
		int saved_errno = errno;
		/* Should only happen if there are no newsgroup directories at all */
		if (newsdir_has_subdirs) {
			bbs_error("Couldn't open active file '%s': %s\n", active_file, strerror(saved_errno));
			error = -1;
			goto cleanup;
		}
		/* Not an error, but this will only happen once, ever, so it's noteworthy: */
		bbs_debug(1, "Active file '%s' doesn't exist yet (no newsgroups exist yet), creating for first time\n", active_file);
	}
	newfp = bbs_mkftemp(template, 0644);
	if (!newfp) {
		if (oldfp) {
			fclose(oldfp);
		}
		error = -1;
		goto cleanup;
	}

	if (oldfp) {
		/* Copy over each line from the old file to the new, updating the line of interest when we find it.
		 * If we are inserting a new group, we make sure to keep the list sorted by group name.
		 * Traditionally, an active file is sorted by when groups were added (e.g. LIST ACTIVE.TIMES),
		 * which would make this operation easy (append at the end), but there don't seem to be any
		 * requirements on ordering for either LIST ACTIVE or LIST ACTIVE.TIMES, so keeping the groups
		 * sorted alphabetically seems more useful to a client... */
		char oldline[NNTP_MAX_LINE_LENGTH];
		char lastgrp[sizeof(oldline)];

		while ((fgets(oldline, sizeof(oldline), oldfp))) {
			char *restofline = oldline;
			char *thisgroup = active_strsep(restofline);
			if (unlikely(!thisgroup || !restofline)) {
				bbs_error("Active file is malformed (contains empty line or newsgroup without any metadata)\n");
				continue;
			}
			strcpy(lastgrp, thisgroup); /* Safe, since buffer sizes are the same. This function is on a hot path so we avoid bounds check as an optimization. */
			if (!strcmp(thisgroup, g->name)) {
				/* Found the group of interest */
				if (unlikely(modtype == GROUP_CREATE)) {
					bbs_error("Trying to add group '%s', but it already exists in active file?\n", g->name);
					error = 1;
				} else if (modtype == GROUP_MODIFY) {
					/* Update existing group */
					struct group_info oldgroup;
					if (parse_active_line(restofline, &oldgroup)) {
						error = 1;
					} else {
						update_and_set_group(g, &oldgroup);
						bbs_assert(g->low >= oldgroup.low); /* The low water mark can never decrease */
						write_active_file_line(newfp, g);
						found_group = 1;
						break;
					}
				} else {
					/* Delete existing group... simply by not copying it over. */
				}
			} else {
				/* Some other group. Carry it over, but first check if we need to insert the new group here first */
				if (!inserted && modtype == GROUP_CREATE) {
					/* If thisgroup would sort after the new group, it's time to insert */
					if (strcmp(thisgroup, g->name) > 0) {
						write_active_file_line(newfp, g);
						inserted = 1;
					}
				}
				/* No need to parse the rest of the line if we're just copying it over */
				fprintf(newfp, "%s\t%s", thisgroup, restofline); /* We don't include LF here because restofline already has it */
			}
		}

		/* Edge case... the new group sorts after all the existing groups (including file existed, but was empty) */
		if (!inserted && modtype == GROUP_CREATE) {
			write_active_file_line(newfp, g);
		}
		fclose(oldfp);
	} else {
		/* Easy case, which only occurs once... ever! Add the very first newsgroup: */
		write_active_file_line(newfp, g);
	}
	fclose(newfp);

	/* Now, rename the new file to the old one (replacing or creating the target) */
	if (rename(template, active_file)) {
		bbs_error("Failed to rename new active file %s -> %s: %s\n", template, active_file, strerror(errno));
		error = -1;
	}

cleanup:
	if (unlikely(modtype == GROUP_DELETE && !found_group)) {
		bbs_error("Wanted to delete group '%s' but couldn't find it?\n", g->name);
		error = 1;
	}
	return error;
}

/*!
 * \brief Update an existing group in the active file, modifying the active file in place
 * \param[in] g Group information
 * \retval -1 system error occured
 * \retval 1 program/environment error occured
 * \retval 0 on success
 */
static int update_active_file(struct group_info *g, int *incrlast)
{
	FILE *fp;
	int error = 0;
	char line[NNTP_MAX_LINE_LENGTH];
	int found_group = 0;
	fpos_t pos = { 0 };

	fp = fopen(active_file, "r+");
	if (!fp) {
		bbs_error("Attempt to update group with no existing active file?\n");
		error = 1;
		goto cleanup;
	}

	for (; (fgets(line, sizeof(line), fp)); fgetpos(fp, &pos)) {
		char *restofline = line;
		char *thisgroup = active_strsep(restofline);
		if (unlikely(!thisgroup || !restofline)) {
			bbs_error("Active file is malformed (contains empty line or newsgroup without any metadata)\n");
			continue;
		}
		if (!strcmp(thisgroup, g->name)) {
			/* Update existing group */
			struct group_info oldgroup;
			if (parse_active_line(restofline, &oldgroup)) {
				error = 1;
			} else {
				found_group = 1;
				update_and_set_group(g, &oldgroup);
				if (incrlast) {
					if (g->last >= NNTP_MAX_ARTICLE_NUMBER) {
						/* Uh oh, we're out of room */
						*incrlast = 0; /* Indicate we can't allocate any more article numbers in this group */
						bbs_warning("Newsgroup %s is full\n", g->name);
						break; /* Abort without making any changes */
					}
					*incrlast = ++g->last; /* Increment LAST and return it in the variable */
					/* If we're assigning a new article number, also increment count and high water mark while we're at it.
					 * There's always a slight chance that the article creation in the spool might fail afterwards,
					 * but in the common case where all goes well, we won't need to make another update here. */
					g->count++;
					g->high = g->last;
					if (g->count == 1) {
						/* If we are adding an article to a directory that was previously empty, this is our new low water mark as well */
						g->low = g->last;
					}
				}
				bbs_assert(g->low >= oldgroup.low); /* The low water mark can never decrease */
				fsetpos(fp, &pos); /* Need to rewind the file pointer to the position where the line started */
				write_active_file_line(fp, g);
				break;
			}
		}
	}
	fclose(fp);

cleanup:
	if (unlikely(!found_group)) {
		bbs_error("Wanted to update group '%s' but couldn't find it in active file?\n", g->name);
		error = 1;
	}
	return error;
}

int active_file_group_create(struct group_info *g)
{
	/* Last but really most importantly, add it to the active file.
	 * We do this at the end because we want to make sure the group is ready to go before we do this.
	 * If this operation fails, having stale data in the other files is not as big of a deal. */
	return regenerate_active_file(GROUP_CREATE, g);
}

int active_file_group_delete(const char *groupname)
{
	struct group_info g;
	g.name = groupname;
	/* None of the other fields will get used, no need to initialize them */
	return regenerate_active_file(GROUP_DELETE, &g);
}

int active_file_group_update(const char *groupname, int *incrlast, int last, int high, int low, int count, const char *status, const char *description)
{
	struct group_info g;
	/* Assume if the description changes, we'll need to rewrite out the file again.
	 * This may not be true if the length of the description is unchanged,
	 * but we won't know that without checking, which would require a pass over the file first. */
	int need_rewrite = description != NULL;

	if (!need_rewrite && status) {
		/* If the status has changed, we technically only need to rewrite the active file if the length of the status has changed,
		 * i.e. we go from a single letter status to =other.group or vice versa.
		 * At the moment, we just assume we always need to rewrite, but per the above note on description, this is not always true. */
		need_rewrite = 1;
	}

	g.name = groupname;
	g.last = last;
	g.high = high;
	g.low = low;
	g.count = count;
	g.status = status;
	g.description = description;
	/* Don't need to set created and creator, as those can't change and are just copied from the old on updates */

	if (need_rewrite) {
		return regenerate_active_file(GROUP_MODIFY, &g);
	} else {
		return update_active_file(&g, incrlast);
	}
}

int active_file_group_info(const char *groupname, int *last, int *high, int *low, int *count, char *status, size_t statuslen, time_t *created, char *creator, size_t creatorlen, char *description, size_t descriplen)
{
	char buf[NNTP_MAX_LINE_LENGTH + 1];
	FILE *fp;

	/*! \todo A worthwhile optimization here would be to add a hash table with an offset into the active file for each group.
	 * This way, we can have constant time access to the info in the active file, useful for GROUP, etc.
	 * We could also keep a persistent file handle to the active file open. Since right now we have to parse the whole
	 * file, each thread opening it on its own allows them to read the file in parallel (since a full scan may be needed);
	 * after implementing a hash table with offsets, "searches" for single groups should be quick,
	 * and it would be more worthwhile just having a single handle to it open, with the appropriate locking. */

	fp = fopen(active_file, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", active_file, strerror(errno));
		return -1;
	}
	while ((fgets(buf, sizeof(buf), fp))) {
		struct group_info g;
		char *restofline = buf;
		char *thisgroup = active_strsep(restofline);
		if (strcmp(thisgroup, groupname)) {
			continue;
		}
		/* Past here, we return immediately so close file now */
		fclose(fp);
		if (parse_active_line(restofline, &g)) {
			return 1;
		}
		/* For any strings, we need to copy the values to the caller (rather than just equating the pointer),
		 * because the pointers here won't be any good after we return from this function. */
		if (last) {
			*last = g.last;
		}
		if (high) {
			*high = g.high;
		}
		if (low) {
			*low = g.low;
		}
		if (count) {
			*count = g.count;
		}
		if (status) {
			safe_strncpy(status, g.status, statuslen);
		}
		if (created) {
			*created = g.created;
		}
		if (creator) {
			safe_strncpy(creator, g.creator, creatorlen);
		}
		if (description) {
			safe_strncpy(description, g.description, descriplen);
		}
		return 0;
	}
	fclose(fp);
	return 1;
}

static int active_file_group_list_full(struct nntp_session *nntp, enum list_category listcat, const char *wildmat, time_t newerthan, int newgroups)
{
	FILE *fp;
	char *group, buf[NNTP_MAX_LINE_LENGTH + 1];
	int lineno = 0;

	fp = fopen(active_file, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", active_file, strerror(errno));
		return 1;
	}

	switch (listcat) {
		case LIST_ACTIVE:
		case LIST_COUNTS:
			nntp_send(nntp, newgroups ? NNTP_OK_NEWGROUPS : NNTP_OK_LIST, "Newsgroup listing follows in form \"group high low status\"");
			break;
		case LIST_ACTIVE_TIMES:
			nntp_send(nntp, NNTP_OK_LIST, "Newsgroup creation times follow in form \"group time who\"");
			break;
		case LIST_NEWSGROUPS:
			nntp_send(nntp, NNTP_OK_LIST, "Newsgroup information follows in form \"group description\"");
			break;
		default:
			bbs_assert(0);
	}

	while ((fgets(buf, sizeof(buf), fp))) {
		struct group_info g;
		char *line = buf;
		lineno++;
		group = active_strsep(line);
		if (strlen_zero(line)) {
			bbs_error("Malformed line (%s:%d)\n", active_file, lineno);
			continue;
		}
		/* Check if the group matches any filters present */
		if (wildmat && !uwildmat(group, wildmat)) {
			continue; /* Didn't match wildmat */
		}
		/* Check if allowed by ACL */
		if (!ACL_ALLOWED_LOCKED(nntp, group, NNTP_ACL_READ)) {
			continue;
		}
		bbs_term_line(line);
		if (parse_active_line(line, &g)) {
			continue;
		}
		if (newgroups && g.created < newerthan) {
			continue;
		}
		/* This involves slightly more parsing than most news servers have to do.
		 * Traditional news servers use separate files for each of the LIST responses.
		 * Since we use one great big extended file for all of this,
		 * every response requires us to parse out what we need first
		 * and format it appropriately. */
		switch (listcat) {
			case LIST_ACTIVE:
				/* We can't use the raw low/high water marks from the active file as is,
				 * since if the group is empty, we need to adjust the high water mark
				 * to be lower than the low water mark. */
				FIX_EMPTY_GROUP_STATS(g.high, g.low, g.count);
				_nntp_send(nntp, "%s %d %d %s\r\n", group, g.high, g.low, g.status);
				break;
			case LIST_COUNTS:
				FIX_EMPTY_GROUP_STATS(g.high, g.low, g.count);
				_nntp_send(nntp, "%s %d %d %d %s\r\n", group, g.high, g.low, g.count, g.status);
				break;
			case LIST_ACTIVE_TIMES:
				_nntp_send(nntp, "%s %lu %s\r\n", group, g.created, g.creator);
				break;
			case LIST_NEWSGROUPS:
				_nntp_send(nntp, "%s\t%s\r\n", group, g.description); /* The RFC allows space or tab delimiter, but says tab is preferred */
				break;
			default:
				__builtin_unreachable(); /* We would have asserted in the switch at the top of the function */
		}
	}
	fclose(fp);
	_nntp_send(nntp, ".\r\n");
	return 0;
}

int active_file_group_list(struct nntp_session *nntp, enum list_category listcat, const char *wildmat)
{
	return active_file_group_list_full(nntp, listcat, wildmat, 0, 0);
}

int active_file_group_list_newgroups(struct nntp_session *nntp, time_t newerthan)
{
	return active_file_group_list_full(nntp, LIST_ACTIVE, NULL, newerthan, 1); /* LIST ACTIVE response lines for matching groups, with 231 response */
}
