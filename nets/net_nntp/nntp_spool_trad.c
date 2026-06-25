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
 * \brief Traditional file-based spool implementation (and overview)
 */

#include "include/bbs.h"

#include <dirent.h>
#include <sys/statvfs.h> /* use statvfs */

#include "include/node.h"
#include "include/utils.h"
#include "include/stringlist.h"
#include "include/system.h"

#include "nntp.h"
#include "nntp_history.h"
#include "nntp_spool_trad.h"

/* Use a large enough buffer to ensure even long lines in the overview file will fit, or weird things will happen */
#define OVERVIEW_BUFSIZ 4096

extern int spool_compression;

/* Each thread opens a group's overview file for reading/writing, so multiple readers can operate simultaneously.
 * Right now, we don't have any per-group data structures, so for simplicity, we have one rwlock_t globally,
 * even though overview file operations are PER GROUP; so if one group's overview file is being modified,
 * no other reads/writes can occur; but otherwise, all reading operations are unconstrained. */
static bbs_rwlock_t overviewlock = BBS_RWLOCK_INITIALIZER;

static unsigned long blocksize;

static int get_block_size(void)
{
	struct statvfs st;

	if (statvfs(newsdir, &st)) {
		bbs_error("stat(%s) failed: %s\n", newsdir, strerror(errno));
		return -1;
	}
	blocksize = st.f_bsize;

	bbs_debug(6, "Block size of %s: %lu\n", newsdir, blocksize);
	return 0;
}

int tradspool_init(void)
{
	if (get_block_size()) {
		return -1;
	}
	if (spool_compression) {
		BBS_REQUIRE_EXTERNAL_PROGRAM("zstd");
	}
	return 0;
}

void tradspool_cleanup(void)
{
	return;
}

static int build_newsgroup_path(const char *name, char *buf, size_t len)
{
	errno = 0;
	if (strstr(name, "..")) { /* Reject dangerous inputs */
		return -1;
	}
	snprintf(buf, len, "%s/%s", newsdir, name);

	/* Conventionally, the hierarchy itself is mirrored on disk,
	 * e.g. misc.news is misc/news on disk (a folder 'news' within a folder 'misc'), not
	 * just misc.news in the top-level newsdir.
	 *
	 * This differs from the IMAP convention of having a flatter directory structure.
	 * While I can't think of any performance advantages of this method (large
	 * directories may have been more problematic back in the day, but large groups
	 * would likely have more files inside of them with the tradspool method),
	 * this may have the slight advantage of allowing certain hierarchies to be easily
	 * stored on different disks. */
	bbs_strreplace(buf, '.', '/');

	if (eaccess(buf, R_OK)) {
		errno = ENOENT;
		return -1; /* Doesn't exist */
	}
	return 0;
}

#define COMPRESSED_SUFFIX ".zst"

static inline void build_compressed_path(const char *groupname, int article_num, char *buf, size_t len)
{
	int slen = snprintf(buf, len, "%s/%s/%d" COMPRESSED_SUFFIX, newsdir, groupname, article_num);
	bbs_strreplace(buf, '.', '/');
	buf[(size_t) slen - STRLEN(COMPRESSED_SUFFIX)] = '.'; /* Replace /zst with .zst */
}

static int build_nonexistent_path(const char *groupname, int article_num, char *buf, size_t len, int compressed)
{
	if (compressed) {
		build_compressed_path(groupname, article_num, buf, len);
	} else {
		snprintf(buf, len, "%s/%s/%d", newsdir, groupname, article_num);
		bbs_strreplace(buf, '.', '/');
	}
	if (bbs_file_exists(buf)) {
		bbs_warning("File '%s' already exists\n", buf);
		return 1;
	}
	return 0;
}

static int build_group_article_path(const char *groupname, int article_num, char *buf, size_t len, int *restrict is_compressed)
{
	if (strstr(groupname, "..")) { /* Reject dangerous inputs */
		*is_compressed = 0;
		errno = 0;
		return -1;
	}

	/* In theory, if we knew the article size and it was <= blocksize, we could skip this (or try it second)
	 * since we wouldn't have compressed this article. */
	if (spool_compression) {
		build_compressed_path(groupname, article_num, buf, len);
		if (bbs_file_exists(buf)) {
			*is_compressed = 1;
			return 0;
		}
	}

	*is_compressed = 0;
	snprintf(buf, len, "%s/%s/%d", newsdir, groupname, article_num);
	bbs_strreplace(buf, '.', '/');
	if (!bbs_file_exists(buf)) {
		errno = ENOENT;
		return -1; /* Doesn't exist */
	}
	return 0;
}

static int delete_article(const char *groupname, int article_num)
{
	char articlefile[NNTP_MAX_PATH_LENGTH + 32];
	int is_compressed;

	if (build_group_article_path(groupname, article_num, articlefile, sizeof(articlefile), &is_compressed)) {
		return -1;
	}
	if (unlink(articlefile)) {
		bbs_debug(1, "Attempt to delete nonexistent article %s:%d\n", groupname, article_num);
		return 1;
	}
	return 0;
}

/*! \todo Use the zstd library directly instead of the zstd program (for efficiency) */

static int compress_article(const char *path, size_t bytes, char *newpath, size_t newpathlen)
{
	struct bbs_exec_params x;
	struct stat st;
	size_t newsize, newblocks, oldblocks;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
	char *const argv[] = { "zstd", path, NULL };
#pragma GCC diagnostic pop

	/* If the article is small enough to fit within a single block, there is no point in compressing it...
	 * so only attempt to compress if this is larger than 1 block and will shave off at least one block. */
	if (bytes <= blocksize) {
		return 1;
	}

	/* Note: Using a custom dictionary trained on netnews would probably yield even greater compression.
	 * However, zstd on its own without a custom dictionary is still fairly effective at compressing articles
	 * (usually by about half), and custom dictionaries also come with the risk of overfitting if not
	 * trained properly, so at the moment, we do not use a custom dictionary. */

	EXEC_PARAMS_INIT_HEADLESS(x);
	if (bbs_execvp(NULL, &x, "zstd", argv)) {
		bbs_error("Failed to compress %s: %s\n", path, strerror(errno));
		if (eaccess("zstd", X_OK)) {
			/* If zstd isn't available for some reason then don't try this again */
			bbs_warning("Disabling spool compression since zstd is not available\n");
			spool_compression = 0;
		}
		return -1;
	}

	/* Check the size of the compressed file and make sure it's at least one block size less than the original,
	 * otherwise there's no point as we'll be doing extra work later for no gain in disk space. */
	snprintf(newpath, newpathlen, "%s" COMPRESSED_SUFFIX, path);
	if (stat(newpath, &st)) {
		bbs_error("stat(%s) failed: %s\n", newpath, strerror(errno));
		return -1;
	}
	newsize = (size_t) st.st_size;
	newblocks = (newsize / blocksize) + 1;
	oldblocks = (bytes / blocksize) + 1;
	if (!(newblocks < oldblocks)) {
		bbs_debug(6, "Not compressing %s, block usage is unchanged (%lu [%lu] -> %lu [%lu])\n", path, bytes, oldblocks, newsize, newblocks);
		bbs_delete_file(newpath);
		return 1;
	}

	/* If compression succeeded, remove the original file */
	bbs_delete_file(path);
	return 0;
}

static int uncompress_article(char *path)
{
	char template[TMPNAME_BUFSIZ];
	struct bbs_exec_params x;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdiscarded-qualifiers"
	char *const argv[] = { "zstd", "-d", path, "-o", template, NULL };
#pragma GCC diagnostic pop

	/* In theory, there may be efficiency gains of uncompressing a file to the normal uncompressed filename,
	 * so that multiple readers could reuse the same file.
	 * However, at some point these need to be pruned (deleted), or that defeats the point of compression,
	 * and if not careful, this could lead to a file being deleted while it's being used.
	 * Rather than renaming file.zst to just file, we use a unique tempname,
	 * so that concurrent article accesses + deletions don't step on each other.
	 * Since it's unique to use, after we're done using this file, it's then immediately deleted. */
	bbs_tempname("nntpart_decomp", template, sizeof(template));

	EXEC_PARAMS_INIT_HEADLESS(x);
	if (bbs_execvp(NULL, &x, "zstd", argv)) {
		bbs_error("Failed to compress %s: %s\n", path, strerror(errno));
		return -1;
	}

	safe_strncpy(path, template, NNTP_MAX_PATH_LENGTH);
	return 0;
}

static int remove_uncompressed_article(const char *path)
{
	return bbs_delete_file(path);
}

int tradspool_group_create(const char *groupname)
{
	char grouppath[NNTP_MAX_PATH_LENGTH];
	int res;

	/* Will return -1 since it doesn't exist yet, that's fine and expected in this case.
	 * In fact, if it returns 0, it already exists and we have a problem. */
	res = build_newsgroup_path(groupname, grouppath, sizeof(grouppath));
	if (!res) {
		bbs_error("Directory %s already exists, please delete it and manually synchronize metadata\n", grouppath);
		return 1; /* Directory already exists? */
	}
	if (errno != ENOENT) {
		return -1; /* Something else went wrong */
	}
	/* Create the directory, recursively creating any ancestors in the hierarchy as needed */
	if (bbs_ensure_directory_exists_recursive(grouppath)) {
		bbs_error("Failed to create %s: %s\n", grouppath, strerror(errno));
		return -1;
	}
	return 0;
}

int tradspool_group_delete(const char *groupname)
{
	char grouppath[NNTP_MAX_PATH_LENGTH];
	int res;

	res = build_newsgroup_path(groupname, grouppath, sizeof(grouppath));
	if (res) {
		return -1;
	}
	if (bbs_delete_directory(grouppath)) {
		return -1;
	}
	return 0;
}

int tradspool_group_exists(const char *groupname)
{
	char grouppath[NNTP_MAX_PATH_LENGTH];
	int res = build_newsgroup_path(groupname, grouppath, sizeof(grouppath));
	return res == 0;
}

static int build_overview_path(const char *groupname, char *buf, size_t len)
{
	size_t slen;
	if (strstr(groupname, "..")) { /* Reject dangerous inputs */
		return -1;
	}
	slen = (size_t) snprintf(buf, len, "%s/%s/%s", newsdir, groupname, ".overview");
	if (slen > len) {
		return -1;
	}
	buf[slen - STRLEN(".overview")] = '\0'; /* Don't change .overview to /overview */
	bbs_strreplace(buf, '.', '/');
	buf[slen - STRLEN(".overview")] = '.'; /* Change it back */
	return 0; /* Don't check for existence since we'll try to open it now */
}

static void overview_insert(FILE *fp, struct article_info *artinfo, int article_num)
{
	/* References is optional (not every article has one), the rest should be present: */
	fprintf(fp, "%d\t%s\t%s\t%s\t%s\t%s\t%lu\t%d\t%s\n",
		article_num, artinfo->subject, artinfo->from, artinfo->date, artinfo->messageid, S_IF(artinfo->references), artinfo->bytes, artinfo->lines,
		artinfo->xref);
}

/* Note: In theory, overview isn't coupled to the spool implementation.
 * However, the current overview uses a file inside each group's directory,
 * and some spool implementations (e.g. CNFS) may not entail a directory per each group,
 * so to that extent, the overview implementation is included here at the moment too
 * as it's not easily separable at the moment. */
static int overview_add(struct article_info *artinfo, const char *group, int article_num, int last, int xrefslave)
{
	int res;
	char overviewfile[NNTP_MAX_PATH_LENGTH];

	if (build_overview_path(group, overviewfile, sizeof(overviewfile))) {
		return -1;
	}

	bbs_rwlock_wrlock(&overviewlock);
	/* Even if we slaved the article number, if it was higher than any previously assigned article number, we can simply append.
	 * Only rewrite the overview file if we need to insert in the middle. */
	if (xrefslave && article_num != last) { /* if article_num == last, the latest article is the one we just assigned */
		char template[NNTP_MAX_PATH_LENGTH];
		char buf[OVERVIEW_BUFSIZ];
		FILE *oldfp, *newfp;
		/* With xref slave, the article number could be lower than the highest article number assigned thus far,
		 * so to keep the overview file ordered, we need to insert in the right place. */
		oldfp = fopen(overviewfile, "r");
		if (!oldfp) {
			bbs_error("Failed to open %s: %s\n", overviewfile, strerror(errno));
			res = -1;
			goto done;
		}
		bbs_renamable_tempname("nntp_overview", template, sizeof(template));
		newfp = bbs_mkftemp(template, 0644);
		if (!newfp) {
			fclose(oldfp);
			res = -1;
			goto done;
		}

		/* Copy the old overview to the new, inserting in the appropriate place */
		while ((fgets(buf, sizeof(buf), oldfp))) {
			int artnum = atoi(buf);
			if (artnum >= article_num) {
				if (unlikely(artnum == article_num)) {
					/* In tradspool_article_create, we already check for existence, so this should never happen */
					bbs_error("Can't insert duplicate overview entry %s:%d\n", group, article_num);
					res = -1;
					goto done;
				}
				overview_insert(newfp, artinfo, article_num);
				fwrite(buf, 1, strlen(buf), newfp); /* Already includes LF */
				break;
			}
			fwrite(buf, 1, strlen(buf), newfp); /* Already includes LF */
		}
		if (bbs_copy_rest_of_file(oldfp, newfp)) {
			fclose(oldfp);
			fclose(newfp);
			res = -1;
			goto done;
		}

		fclose(oldfp);
		fclose(newfp);
		if (bbs_rename(template, overviewfile)) {
			res = -1;
			goto done;
		}
	} else {
		/* If not slaved off xref, then we assigned the next unused article number, so we can just append to the end,
		 * since we know the article number should be higher than any currently assigned. */
		FILE *fp = fopen(overviewfile, "a");
		if (!fp) {
			bbs_error("Failed to open %s: %s\n", overviewfile, strerror(errno));
			res = -1;
			goto done;
		}
		overview_insert(fp, artinfo, article_num);
		fclose(fp);
		res = 0;
	}

done:
	bbs_rwlock_unlock(&overviewlock);
	return res;
}

static inline int parse_overview_line(struct article_info *artinfo, char *s)
{
	char *tmp;
	artinfo->subject = strsep(&s, "\t");
	artinfo->from = strsep(&s, "\t");
	artinfo->date = strsep(&s, "\t");
	artinfo->messageid = strsep(&s, "\t");
	artinfo->references = strsep(&s, "\t");
	tmp = strsep(&s, "\t");
	if (!tmp) {
		return -1;
	}
	artinfo->bytes = (size_t) atol(tmp);
	tmp = strsep(&s, "\t");
	if (!tmp) {
		return -1;
	}
	artinfo->lines = atoi(tmp);
	artinfo->xref = s; /* This is the last field */
	if (!s) {
		return -1;
	}
	bbs_term_line(s); /* Trim trailing LF */
	return 0;
}

static void scandir_free(struct dirent **entries, int count)
{
	int i = 0;
	struct dirent *entry;
	while (i < count && (entry = entries[i++])) {
		free(entry);
	}
	free(entries);
}

/*! \brief Numeric sort callback to scandir - alphasort is lexiographic, not numeric, so we use this */
static int numsort(const struct dirent **da, const struct dirent **db)
{
	const char *a = (*da)->d_name;
	const char *b = (*db)->d_name;
	int numa = atoi(a), numb = atoi(b);
	if (numa != numb) {
		return numa < numb ? -1 : 1;
	}
	return strcmp(a, b); /* If one or both are not numeric, fall back to normal comparison */
}

/*!
 * \brief Rebuild the overview file by removing entries for articles that no longer exist (done as soon as any article is removed from a group)
 * \param group Name of group
 * \param article_to_remove Article number if we just want to remove a single article and we know which one. Otherwise 0, to scan the spool for articles to remove (e.g. after nightly expire)
 *        0 is always an acceptable argument for this parameter; it's just more efficient to provide an article if you just want to remove that one.
 */
static int overview_rebuild(const char *group, int article_to_remove)
{
	FILE *oldfp, *newfp;
	int res = 0;
	char grouppath[NNTP_MAX_PATH_LENGTH];
	char template[TMPNAME_BUFSIZ];
	char overviewfile[NNTP_MAX_PATH_LENGTH];
	char buf[OVERVIEW_BUFSIZ];
	/* for scandir: */
	struct dirent **entries;
	int dirfiles = 0, fileindex = 0;

	res = build_newsgroup_path(group, grouppath, sizeof(grouppath));
	if (res) {
		return res;
	}

	if (build_overview_path(group, overviewfile, sizeof(overviewfile))) {
		return -1;
	}

	bbs_debug(5, "Rebuilding overview for %s\n", group);

	bbs_rwlock_wrlock(&overviewlock);
	oldfp = fopen(overviewfile, "r");
	if (!oldfp) {
		bbs_rwlock_unlock(&overviewlock);
		return 1; /* If an overview file doesn't already exist, there is nothing to rebuild */
	}
	bbs_renamable_tempname("nntp_overview", template, sizeof(template));
	newfp = bbs_mkftemp(template, 0644);
	if (!newfp) {
		fclose(oldfp);
		bbs_rwlock_unlock(&overviewlock);
		return -1;
	}
	if (!article_to_remove) {
		/* We're going to end up checking if every article still in overview still exists in the spool.
		 * For a single file, stat/access would be faster, but since we'll want to know this for all of them,
		 * it's worth it to use scandir + numsort once up front, and then we can check in memory
		 * for existence of the article we want. We sort the files so we don't need to do a linear scan. */
		dirfiles = scandir(grouppath, &entries, NULL, numsort);
		if (dirfiles < 0) {
			bbs_error("scandir(%s) failed: %s\n", newsdir, strerror(errno));
			bbs_rwlock_unlock(&overviewlock);
			return -1;
		}
	}
	while ((fgets(buf, sizeof(buf), oldfp))) {
		int artnum = atoi(buf); /* Should automatically stop at the tab */
		if (article_to_remove) {
			if (artnum == article_to_remove) {
				continue; /* We already know this article no longer exists, so don't copy it to the new file */
			}
		} else {
			int eartnum = 0;
			/* Look in entries to see if it exists.
			 * This should be ~constant time because the overview file and the list of entries are both sorted. */
			for (; fileindex < dirfiles; fileindex++) {
				struct dirent *entry = entries[fileindex];
				if (entry->d_name[0] == '.') { /* This covers . and .. for directories as well as .overview */
					continue;
				}
				eartnum = atoi(entry->d_name);
				if (eartnum >= artnum) {
					/* We found the article we want (or we're past it, so it doesn't exist) */
					break;
				}
			}
			if (eartnum != artnum) {
				continue; /* Article no longer exists, don't copy it to the new file */
			}
		}
		/* The article still exists, copy the whole line to the new file.
		 * For articles that were removed and are NOT copied over, we don't add them to the expire log now.
		 * They'll be added when the history log gets pruned. */
		fprintf(newfp, "%s", buf); /* Already includes LF */
	}
	fclose(oldfp);
	fclose(newfp);

	/* Replace the old overview file with the new one */
	if (bbs_rename(template, overviewfile)) {
		res = -1;
	}

	bbs_rwlock_unlock(&overviewlock);
	if (!article_to_remove) {
		scandir_free(entries, dirfiles);
	}
	return res;
}

static int overview_line_extract_messageid(char *s, char *buf, size_t len)
{
	char *msgid, *tmp = s;
	if (skipn(&tmp, '\t', 4) != 4 || !tmp) {
		bbs_error("Malformed overview line '%s'\n", s);
		return -1;
	}
	msgid = strsep(&tmp, "\t");
	safe_strncpy(buf, msgid, len);
	return 0;
}

static int overview_find_messageid(const char *group, int article_num, char *msgidbuf, size_t msgidlen)
{
	FILE *fp;
	char buf[OVERVIEW_BUFSIZ];
	char overviewfile[NNTP_MAX_PATH_LENGTH];

	if (build_overview_path(group, overviewfile, sizeof(overviewfile))) {
		return -1;
	}

	bbs_rwlock_rdlock(&overviewlock);
	fp = fopen(overviewfile, "r");
	if (!fp) {
		/* If the group is empty, the overview file may not exist yet */
		bbs_rwlock_unlock(&overviewlock);
		return 1;
	}
	while ((fgets(buf, sizeof(buf), fp))) {
		int artnum = atoi(buf); /* Should automatically stop at the tab */
		if (artnum != article_num) {
			continue;
		}
		/* Found the article, extract the Message-ID. It's the fifth element in the tab-delimited list. */
		fclose(fp);
		bbs_rwlock_unlock(&overviewlock);
		if (overview_line_extract_messageid(buf, msgidbuf, msgidlen)) {
			return -1;
		}
		return 0;
	}
	fclose(fp);
	bbs_rwlock_unlock(&overviewlock);
	return 1;
}

int tradspool_group_seek(const char *groupname, int cur_artnum, int *new_artnum, int direction, char *msgidbuf, size_t msgidlen)
{
	FILE *fp;
	long int lastoffset = 0, bestoffset = -1;
	char buf[OVERVIEW_BUFSIZ];
	char artpath[NNTP_MAX_PATH_LENGTH];
	char overviewfile[NNTP_MAX_PATH_LENGTH];
	int is_compressed;

	/* There are two logical ways to determine the NEXT or LAST articles in a group.
	 * The simplest way is simply to scan the directory and find the min/max article number as appropriate.
	 * However, this could require a lot of file system operations.
	 * A better way is to use the overview file, since it should reflect all the articles on disk,
	 * unless one was deleted and the overview file didn't get updated. */
	*new_artnum = cur_artnum;
	*msgidbuf = '\0';

	if (build_overview_path(groupname, overviewfile, sizeof(overviewfile))) {
		return -1;
	}
	bbs_rwlock_rdlock(&overviewlock);
	fp = fopen(overviewfile, "r");
	if (!fp) {
		/* If the group is empty, the overview file may not exist yet */
		bbs_rwlock_unlock(&overviewlock);
		return 1;
	}

	/* We need to find the article number, but we also need to return the Message-ID of the article.
	 * Rather than copying on every better match, which would involve a lot of copies,
	 * and rather than scanning a second time back to the right article,
	 * store the best match's offset in the file, so we can come back at the end to parse out the Message-ID.
	 * Of course, when we match, the file position will be the beginning of the next line, so we need to save
	 * the offset each time. */

	lastoffset = 0;
	while ((fgets(buf, sizeof(buf), fp))) {
		int artnum = atoi(buf); /* Should automatically stop at the tab */
		if (direction > 0) { /* +1 for NEXT */
			/* We want the smallest article number greater than cur_artnum */
			if (artnum > cur_artnum) {
				/* NEXT is slightly easier than LAST.
				 * Because the overview file is in ascending order of article numbers,
				 * we can stop as soon as we find our match. */
				*new_artnum = artnum;
				bestoffset = lastoffset;
				break;
			}
		} else { /* -1 for LAST */
			/* We want the largest article number smaller than cur_artnum */
			if (artnum < cur_artnum) {
				/* Either this is the first match, in which case it automatically wins, or it's a better match.
				 * In practice, all the articles will match until we get past cur_artnum. */
				if (*new_artnum == cur_artnum || artnum > *new_artnum) {
					*new_artnum = artnum;
					bestoffset = lastoffset;
				}
			} else {
				/* We've gone past cur_artnum, so we can stop scanning now */
				break;
			}
		}
		lastoffset = ftell(fp);
	}

	if (*new_artnum != cur_artnum) {
		/* If we succeeded, retrieve the Message-ID now */
		fseek(fp, bestoffset, SEEK_SET);
		if (fgets(buf, sizeof(buf), fp)) {
			int artnum = atoi(buf); /* Should automatically stop at the tab */
			if (artnum != *new_artnum) {
				bbs_error("Found article %d when seeking to article %d?\n", artnum, *new_artnum);
			} else {
				overview_line_extract_messageid(buf, msgidbuf, msgidlen);
			}
		}
	}

	fclose(fp);
	bbs_rwlock_unlock(&overviewlock);

	/* Go ahead and check if this article actually exists.
	 * It should, so if it doesn't, then the overview file is out of sync with the spool. */
	if (*new_artnum != cur_artnum && (build_group_article_path(groupname, *new_artnum, artpath, sizeof(artpath), &is_compressed))) {
		bbs_warning("Overview file %s is out of sync with the spool (%s doesn't exist)\n", overviewfile, artpath);
		/* Don't change our answer. Technically, even if the article doesn't exist,
		 * pretending it does here isn't quite "illegal", because it's always possible the article
		 * could have existed, but between our response to the client and when it tries to retrieve
		 * the article, it suddenly expired. */
	}

	return 0;
}

int tradspool_group_list_articles(struct nntp_session *nntp, const char *groupname, int min, int max)
{
	FILE *fp;
	char buf[OVERVIEW_BUFSIZ];
	char overviewfile[NNTP_MAX_PATH_LENGTH];
	int matches = 0;

	if (build_overview_path(groupname, overviewfile, sizeof(overviewfile))) {
		return -1;
	}

	bbs_rwlock_rdlock(&overviewlock);
	fp = fopen(overviewfile, "r");
	if (!fp) {
		/* If the group is empty, the overview file may not exist yet */
		bbs_rwlock_unlock(&overviewlock);
		return 1;
	}
	while ((fgets(buf, sizeof(buf), fp))) {
		int artnum = atoi(buf); /* Should automatically stop at the tab */
		if (artnum < min) {
			continue;
		} else if (artnum > max) {
			break; /* Since file is in ascending order of articles, there will be no more matches at this point */
		} else {
			_nntp_send(nntp, "%d\r\n", artnum);
			matches++;
		}
	}
	fclose(fp);
	bbs_rwlock_unlock(&overviewlock);
	if (!matches) {
		return 1;
	}
	_nntp_send(nntp, ".\r\n");
	return 0;
}

enum overview_field {
	OVERVIEW_UNSUPPORTED,
	OVERVIEW_ALL,
	OVERVIEW_SUBJECT,
	OVERVIEW_FROM,
	OVERVIEW_DATE,
	OVERVIEW_MESSAGEID,
	OVERVIEW_REFERENCES,
	OVERVIEW_METADATA_BYTES,
	OVERVIEW_METADATA_LINES,
	OVERVIEW_XREF,
};

static enum overview_field parse_overview_item(const char *s)
{
	if (!strcasecmp(s, "Subject")) {
		return OVERVIEW_SUBJECT;
	} else if (!strcasecmp(s, "From")) {
		return OVERVIEW_FROM;
	} else if (!strcasecmp(s, "Date")) {
		return OVERVIEW_DATE;
	} else if (!strcasecmp(s, "Message-ID")) {
		return OVERVIEW_MESSAGEID;
	} else if (!strcasecmp(s, "References")) {
		return OVERVIEW_REFERENCES;
	} else if (!strcasecmp(s, ":bytes")) {
		return OVERVIEW_METADATA_BYTES;
	} else if (!strcasecmp(s, ":lines")) {
		return OVERVIEW_METADATA_LINES;
	} else if (!strcasecmp(s, "Xref")) {
		return OVERVIEW_XREF;
	} else {
		return OVERVIEW_UNSUPPORTED;
	}
}

static int tradspool_group_overview_full(struct nntp_session *nntp, enum overview_field field, enum nntp_hdr_cmd cmd, const char *pattern, const char *messageid, const char *groupname, int min, int max)
{
	FILE *fp;
	char buf[OVERVIEW_BUFSIZ];
	char overviewfile[NNTP_MAX_PATH_LENGTH];
	char eff_group[NNTP_BUFSIZ];
	int eff_artnum = 0;
	int matches = 0;

	if (messageid) {
		/* First, we need to find some group that contains this article.
		 * (Preferably groupname, if it's non NULL and the article exists in that group.) */
		/* If we just have a Message-ID, we need to scan the history file to find a link to the message */
		if (history_find_article_by_messageid(nntp, messageid, groupname, eff_group, sizeof(eff_group), &eff_artnum)) {
			return 1; /* No such article */
		}
		if (build_overview_path(eff_group, overviewfile, sizeof(overviewfile))) {
			return -1;
		}
		if (!ACL_ALLOWED_LOCKED(nntp, eff_group, NNTP_ACL_READ)) {
			return -1;
		}
		min = max = eff_artnum;
		if (!nntp->currentgroup || strcmp(eff_group, groupname)) {
			eff_artnum = 0; /* If article exists in current group, use its article number; otherwise, 0 */
		}
	} else {
		if (build_overview_path(groupname, overviewfile, sizeof(overviewfile))) {
			return -1;
		}
	}

	bbs_rwlock_rdlock(&overviewlock);
	fp = fopen(overviewfile, "r");
	if (!fp) {
		/* If the group is empty, the overview file may not exist yet */
		bbs_rwlock_unlock(&overviewlock);
		return 1;
	}
	while ((fgets(buf, sizeof(buf), fp))) {
		int artnum = atoi(buf); /* Should automatically stop at the tab */
		if (artnum < min) {
			continue;
		} else if (artnum > max) {
			break; /* Since file is in ascending order of articles, there will be no more matches at this point */
		} else {
			/* It matches the range filter, dump the line */
			if (!matches++) {
				if (field == OVERVIEW_ALL) {
					nntp_send(nntp, NNTP_OK_OVER, "Overview information follows");
				} else {
					nntp_send(nntp, cmd == NNTP_HDR ? NNTP_OK_HDR : NNTP_OK_HEAD, "Header information follows");
				}
			}
			if (field != OVERVIEW_ALL) {
				/* HDR/XHDR/XPAT responses */
				const char *hdrval = NULL;
				struct article_info artinfo;
				char *rest = buf;
				int myartnum;
				strsep(&rest, "\t"); /* Eat article number */
				if (parse_overview_line(&artinfo, rest)) {
					continue;
				}
				myartnum = artnum;
				if (messageid && !eff_artnum) {
					myartnum = 0;
				}
				switch (field) {
					case OVERVIEW_SUBJECT:
						hdrval = artinfo.subject;
						break;
					case OVERVIEW_FROM:
						hdrval = artinfo.from;
						break;
					case OVERVIEW_DATE:
						hdrval = artinfo.date;
						break;
					case OVERVIEW_MESSAGEID:
						hdrval = artinfo.messageid;
						break;
					case OVERVIEW_REFERENCES:
						hdrval = artinfo.references;
						break;
					case OVERVIEW_XREF:
						hdrval = artinfo.xref;
						break;
					/* These last two only apply to HDR, not XHDR or XPAT
					 * We continue since we don't apply the string logic after the switch. */
					case OVERVIEW_METADATA_BYTES:
						_nntp_send(nntp, "%d %lu\r\n", myartnum, artinfo.bytes);
						continue;
					case OVERVIEW_METADATA_LINES:
						_nntp_send(nntp, "%d %d\r\n", myartnum, artinfo.lines);
						continue;
					default:
						bbs_assert(0);
				}
				hdrval = S_IF(hdrval);
				if (!pattern || uwildmat_simple(hdrval, pattern)) {
					/* RFC 3977 8.5.2: For HDR, even if the header is not present, so long as the article exists,
					 * we must still send a line for that article (space after article number is optional). */
					_nntp_send(nntp, "%d %s\r\n", myartnum, hdrval);
				}
			} else {
				/* OVER and XOVER responses */
				if (messageid && !eff_artnum) {
					/* Need to respond with article number 0 instead */
					char *rest = buf;
					strsep(&rest, "\t");
					_nntp_send(nntp, "%d\t%s", 0, rest); /* msgbuf already includes CR LF */
				} else {
					_nntp_send(nntp, "%s", buf); /* msgbuf already includes CR LF */
				}
			}
		}
	}
	fclose(fp);
	bbs_rwlock_unlock(&overviewlock);
	if (!matches) {
		return 1;
	}
	_nntp_send(nntp, ".\r\n");
	return 0;
}

int tradspool_group_overview(struct nntp_session *nntp, const char *messageid, const char *groupname, int min, int max)
{
	return tradspool_group_overview_full(nntp, OVERVIEW_ALL, NNTP_HDR, NULL, messageid, groupname, min, max);
}

int tradspool_group_overview_header(struct nntp_session *nntp, const char *field, const char *messageid, const char *groupname, int min, int max, enum nntp_hdr_cmd cmd, const char *pattern)
{
	enum overview_field fld = parse_overview_item(field);
	if (fld == OVERVIEW_UNSUPPORTED) {
		return 2;
	} else if (cmd != NNTP_HDR && (fld == OVERVIEW_METADATA_BYTES || fld == OVERVIEW_METADATA_LINES)) {
		return 2; /* Metadata only supported for HDR, not XHDR/XPAT */
	}
	/*! \todo Right now, only headers in overview are supported for HDR/XHDR/XPAT.
	 * While not required, we could be more flexible and also support any arbitrary header
	 * by pulling the header from the article itself if the header isn't in overview. */
	return tradspool_group_overview_full(nntp, fld, cmd, pattern, messageid, groupname, min, max);
}

int tradspool_overview_header_list(struct nntp_session *nntp, enum list_category listcat, const char *argument)
{
	if (listcat & LIST_HEADERS) {
		/* With LIST_HEADERS, type is either MSGID or RANGE or NULL.
		 * At the moment, we respond identically for all variants of the command, so we make no distinction. */
		UNUSED(argument);

		nntp_send(nntp, NNTP_OK_LIST, "Headers and metadata items supported");
		/* If we supported any arbitrary header, we would return ':' instead */
		_nntp_send(nntp, "Subject\r\n");
		_nntp_send(nntp, "From\r\n");
		_nntp_send(nntp, "Date\r\n");
		_nntp_send(nntp, "Message-ID\r\n");
		_nntp_send(nntp, "References\r\n");
		_nntp_send(nntp, ":bytes\r\n");
		_nntp_send(nntp, ":lines\r\n");
		_nntp_send(nntp, "Xref\r\n");
	} else { /* LIST_OVERVIEW_FMT */
		nntp_send(nntp, NNTP_OK_LIST, "Order of fields in overview database");
		_nntp_send(nntp, "Subject:\r\n");
		_nntp_send(nntp, "From:\r\n");
		_nntp_send(nntp, "Date:\r\n");
		_nntp_send(nntp, "Message-ID:\r\n");
		_nntp_send(nntp, "References:\r\n");
		_nntp_send(nntp, ":bytes:\r\n");
		_nntp_send(nntp, ":lines\r\n");
		_nntp_send(nntp, "Xref:full\r\n");
	}
	_nntp_send(nntp, ".\r\n");
	return 0;
}

static size_t construct_xref(struct article_groups *groups, char *buf, size_t len)
{
	char *xrefpos = buf;
	size_t xrefleft = len;
	size_t used_prev_lines = 0;
	size_t xreftotal = 0;
	struct article_group *g;

	SAFE_FAST_APPEND(buf, len, xrefpos, xrefleft, "Xref: %s", newsname); /* SAFE_FAST_APPEND automatically adds spaces between items */
	BBS_LIST_TRAVERSE(groups, g, entry) {
		if (!g->article_num) {
			continue; /* Group was skipped */
		}
		SAFE_FAST_APPEND(buf, len, xrefpos, xrefleft, "%s:%d", g->name, g->article_num);
		xreftotal = (size_t) (xrefpos - buf);
		/* If there are a lot of groups, it could be more than we'll fit in a single line. */
		if (xreftotal - used_prev_lines > NNTP_MAX_LINE_LENGTH - 11) {
			SAFE_FAST_APPEND_NOSPACE(buf, len, xrefpos, xrefleft, "\r\n");
			xreftotal += 2; /* CR LF */
			used_prev_lines = xreftotal;
		}
	}
	if (xreftotal - used_prev_lines > 0) {
		SAFE_FAST_APPEND_NOSPACE(buf, len, xrefpos, xrefleft, "\r\n");
		xreftotal += 2; /* CR LF */
	}
	return xreftotal;
}

/*! \brief Transform Xref header into format suitable for overview file */
static void xref_reformat(char *restrict xref)
{
	char *restrict s = xref;
	/* In case there are multiple lines, remove any line endings so it will all be on a single line */
	while (*s) {
		if (*s == '\r' || *s == '\n') {
			*s = ' ';
		}
		s++;
	}
	s--;
	/* Trim last two spaces (formerly the last line ending) */
	while (s > xref && *s == ' ') {
		*s-- = '\0';
	}
}

/*! \returns Article number in Xref header if group is contained in it, 0 otherwise */
static int get_xref_article_number(const char *xref, const char *groupname)
{
	const char *p = xref;
	size_t grouplen = strlen(groupname);

	for (;;) {
		if (!*p) {
			return 0; /* End of header */
		}
		p = strstr(p, groupname);
		if (!p) {
			return 0; /* No matches for substring */
		}
		if (p > xref && !(p[-1] == ' ' || p[-1] == ',')) {
			/* Found the substring, but it was a suffix of another group name */
			p += grouplen;
			continue;
		}
		p += grouplen;
		if (*p != ':') {
			/* Found the substring, but it was a prefix of another group name */
			p += grouplen;
			continue;
		}
		p++;
		return atoi(p);
	}
}

int tradspool_article_create(struct article_groups *groups, struct article_info *artinfo, int srcfd, size_t len)
{
	char hardpath[NNTP_MAX_PATH_LENGTH];
	char links[4 * NNTP_MAX_PATH_LENGTH];
	char xref[10 * NNTP_MAX_LINE_LENGTH]; /* If there are a lot of groups, it could be more than we'll fit in a single line */
	int xrefslave = 0;
	size_t xrefbytes;
	time_t expires = 0;
	char *linkspos = links;
	size_t linksleft = sizeof(links);
	struct article_group *g;
	int attempting = 0, delivered = 0;
	int actually_compressed = 0;
	time_t arrival_time;

	arrival_time = time(NULL);

	/* At this point, we've already verified the groups exist.
	 * First, assign the article numbers for all the groups. This way we can add the Xref header before actually adding the article to the spool. */
	BBS_LIST_TRAVERSE(groups, g, entry) {
		int artnum = 0;
		if (artinfo->xref) {
			xrefslave = 1;
			/* We are slaving article numbers off the received Xref header (from peer server or suck feed).
			 * If the group existed on that server, try to use its article number directly.
			 * If that article number is already assigned (which shouldn't happen normally), reject the article for this group.
			 * If a group is not present in the Xref header, then we assign our own header as usual. */
			artnum = get_xref_article_number(artinfo->xref, g->name);
			if (artnum) {
				/* Make sure the requested article number is available */
				if (tradspool_article_exists(g->name, artnum)) {
					/* This shouldn't happen unless 'xrefslave' is being used inappropriately (e.g. with multiple servers) */
					bbs_warning("Article %s:%d already exists, not assigning it for %s\n", g->name, artnum, artinfo->messageid);
					continue;
				}
				g->article_num = artnum;
			}
		}
		if (group_assign_article_number_locked(g->name, &g->article_num, &g->last) || !g->article_num) {
			if (artnum) {
				bbs_notice("Couldn't assign article number %d for group %s\n", artnum, g->name);
			} else {
				bbs_notice("Couldn't assign article number for group %s\n", g->name);
			}
			continue; /* Group is full, or requested article number cannot be assigned */
		}
		/* Since we assigned the article number in this group for this article,
		 * we sure hope that everything succeeds past this point for the article,
		 * there's no "undoing" the assignment... */
		attempting++;
	}

	if (!attempting) {
		errno = ERANGE; /* All groups are full (that is the only reason we would have failed at this point) */
		return 0;
	}

	/* If we retained the received Xref header so that we could use it for slaving article numbers, we're all done with that now.
	 * Free the received header so we can construct our own based on the actual article numbers. */
	free_if(artinfo->xref);

	/* Construct the Xref header. While not technically mandatory, this is standard practice. */
	xrefbytes = construct_xref(groups, xref, sizeof(xref));
	if (!xrefbytes) {
		return 0; /* Something went wrong if we had no groups to add to Xref header */
	}
	artinfo->bytes += xrefbytes;

	/*! \todo FIXME If we fail below, then we should decrement at least the count for the failed groups,
	 * otherwise the count will be out of sync with the spool */

	/* Finally, actually add the article to the spool.
	 * For the first group, we'll actually create a file in the spool;
	 * subsequent groups (cross-posts) will just get a link to the file, to save space. */
	BBS_LIST_TRAVERSE(groups, g, entry) {
		char articlepath[NNTP_MAX_PATH_LENGTH - STRLEN(COMPRESSED_SUFFIX)];
		if (!g->article_num) {
			continue;
		}
		/* Even if the article will be compressed, when it's first created, it's not compressed so this is always 0 for the first group.
		 * Subsequent links may point to the compressed version and be named appropriately. */
		if (build_nonexistent_path(g->name, g->article_num, articlepath, sizeof(articlepath), actually_compressed)) {
			continue;
		}
		if (delivered) {
			/* Subsequent groups link to the original file
			 *
			 * This is a hard link, so we won't be able to tell the difference between the two afterwards.
			 * All the links will point to the same inode, so we don't duplicate the article itself on disk.
			 * Only when all links are deleted is the original file deleted.
			 *
			 * A side effect that this has is that if the retention of articles differs wildly between two groups,
			 * an article may not get deleted in one group, even if it's expired there, because it's
			 * still being retained for another group. */
			if (link(hardpath, articlepath)) {
				bbs_error("Failed to symlink %s -> %s: %s\n", articlepath, hardpath, strerror(errno));
				/* We already delivered one article, so don't fail overall at this point */
				continue;
			}
		} else {
			/* First group gets the "real" file */
			int destfd = open(articlepath, O_CREAT | O_WRONLY, 0600);
			if (destfd < 0) {
				bbs_warning("open(%s) failed: %s\n", articlepath, strerror(errno));
				return -1; /* Caller will free the rest of the list */
			}

			/* Copy the entire article to the file.
			 * Would be nice to use iovec to reduce number of system calls,
			 * but we are combining write() with copy_file_range or sendfile, so not sure if that is possible. */
			if (artinfo->prepend) {
				if (bbs_write(destfd, artinfo->prepend, artinfo->prependlen) < 0) {
					return -1;
				}
			}
			if (bbs_copy_file(srcfd, destfd, 0, (int) artinfo->headerslen) < 0) { /* Copy original headers, not including empty line */
				return -1;
			}
			if (artinfo->append) {
				if (bbs_write(destfd, artinfo->append, artinfo->appendlen) < 0) {
					return -1;
				}
			}
			if (bbs_write(destfd, xref, xrefbytes) < 0) { /* Add the Xref header now so it's the very last header */
				return -1;
			}
			if (bbs_copy_file(srcfd, destfd, (int) artinfo->headerslen, (int) (len - artinfo->headerslen)) < 0) { /* Copy blank line and the body */
				return -1;
			}

			close(destfd);
			if (spool_compression) {
				if (compress_article(articlepath, artinfo->bytes, hardpath, sizeof(hardpath))) {
					safe_strncpy(hardpath, articlepath, sizeof(hardpath));
				} else {
					actually_compressed = 1;
				}
			} else {
				safe_strncpy(hardpath, articlepath, sizeof(hardpath)); /* Save the filename so we can create links to this for further groups */
			}
		}
		/* links are space-separated and relative to the root newsdir */
		SAFE_FAST_APPEND(links, sizeof(links), linkspos, linksleft, "%s/%d", g->name, g->article_num);
		/* Add article to overview */
		xref_reformat(xref + STRLEN("Xref: ")); /* xref has been written to the file so we can now mutate it; replace CR LF with spaces and rtrim */
		artinfo->xref = xref; /* We include the header name itself (Xref:), this is why LIST OVERVIEW.FMT returns Xref:full (includes header name itself) */
		overview_add(artinfo, g->name, g->article_num, g->last, xrefslave);
		artinfo->xref = NULL; /* We didn't allocate memory, so set to NULL for now */
		delivered++;
		bbs_debug(6, "Saved article as %s:%d\n", g->name, g->article_num);
		free_if(artinfo->xref);
	}

	if (delivered) {
		/* Since no allocation was done previously, we cannot have failed up to this point. Now, duplicate the stack-allocated string so propagation to sites can access.
		 * If allocation fails, at least only propagation will fail and not receiving the actual article itself and adding it to overview.
		 * Duplication is done here instead of after the call to overview_add because that is in a loop. */
		artinfo->xref = strdup(xref + STRLEN("Xref: "));

		/* Add the article to history, so we can keep track of message-IDs of articles we've already seen */
		if (artinfo->expires) {
			/* If article has Expires header, we store its UNIX timestamp in history so we know when to expire it */
			struct tm tm;
			memset(&tm, 0, sizeof(tm));
			if (!bbs_parse_rfc822_date(artinfo->expires, &tm)) {
				expires = mktime(&tm);
			}
		}
		history_add(artinfo->messageid, arrival_time, expires, artinfo->bytes, links);
		/* Save the file path (or a file path) for use when feeding the article.
		 * Note that here, we simply pick the first path (corresponding to the first newsgroup).
		 * However, we could be smarter about this. This is kept by the NNTP feeder in the backlog
		 * so that it can easily send the article. However, if the first group's article retention
		 * is much shorter than the other's, then this path may "go bad" before other paths
		 * pointing to the same article.
		 *
		 * Thus, it would be better if we kept track of (among the successful groups),
		 * which group has the longest retention policy, also considering any Expires header,
		 * and use THAT for this value, instead of just the first one.
		 *
		 * However, since even short retention periods are likely to be longer than the time it takes
		 * to feed articles to peer, this is unlikely to make much difference in practice. */
		REPLACE(artinfo->filepath, hardpath);
	} else {
		errno = 0;
	}
	return delivered;
}

/*! \brief Scan the files in a news directory to determine the water marks and article count (typically after articles expire) */
static int scan_for_marks_and_counts(const char *path, int *min, int *max, int *count)
{
	DIR *dir;
	struct dirent *entry;

	*count = *min = *max = 0;

	if (!(dir = opendir(path))) {
		bbs_error("Error opening directory - %s: %s\n", path, strerror(errno));
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		int articlenum;
		if (entry->d_type != DT_REG || !strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
			continue;
		}
		articlenum = atoi(entry->d_name);
		if (!articlenum) {
			continue; /* Probably the overview file or something that isn't an article */
		}
		*count += 1;
		if (articlenum > *max) {
			*max = articlenum;
		}
		if (!*min || articlenum < *min) {
			*min = articlenum;
		}
	}

	closedir(dir);
	return 0;
}

/*!
 * \brief Delete an article from a newsgroup
 * \param groupname Newsgroup name
 * \param article_num Article number
 * \retval 0 on success, 1 on nonexistent article, -1 on system error
 */
int tradspool_article_delete_by_number(const char *groupname, int article_num)
{
	int low, high, last, oldcount;
	int res;

	/* Low water mark is a lower bound, so we increment it after deleting article(s) */
	if (group_get_stats_locked(groupname, &last, &high, &low, &oldcount)) {
		return -1;
	}

	res = delete_article(groupname, article_num);
	if (res) {
		return res;
	}

	/* If we deleted either the low or high water mark article,
	 * then we need to recalculate at least one of the water marks. */
	if (article_num == low || article_num == high) {
		int curlow, curhigh, curcount;
		char grouppath[NNTP_MAX_PATH_LENGTH];
		if (build_newsgroup_path(groupname, grouppath, sizeof(grouppath))) {
			return -1;
		}
		/* At least one water mark will need adjusting, maybe both */
		if (!scan_for_marks_and_counts(grouppath, &curlow, &curhigh, &curcount)) {
			int newlow, newhigh;
			if (curcount) {
				/* Group has at least one article left */
				newlow = curlow; /* Should not have changed if article_num == high */
				newhigh = curhigh; /* Should not have changed if article_num == low */
			} else {
				/* Group is now empty.
				 * This is a special case, rather than assigning newlow = article_num,
				 * we instead assign newlow = "last", so that we can have the highest
				 * low water mark permissible, now that all older articles are deleted
				 * (and won't be reinstated).
				 *
				 * Note that here we set newlow = last. If MAXIMIZE_LOW_WATERMARK
				 * is defined, low will be returned as last + 1 to the client,
				 * but that is handled by FIX_EMPTY_GROUP_STATS, not here. */
				newlow = last;
				newhigh = newlow - 1;
			}
			/* Update the low water mark to next */
			group_update_counts_locked(groupname, newhigh, newlow, curcount);
		}
	} else {
		/* We deleted an article somewhere in the middle.
		 * Water marks stay the same, count decrements by 1.
		 * We could call scan_for_marks_and_counts for the most accurate count (in case the spool is out of sync with the active file),
		 * but just subtract 1 from the old count. */
		group_update_counts_locked(groupname, -1, -1, oldcount - 1);
	}

	/* Delete the article from overview immediately.
	 * It'll stay in history for a sufficient amount of time (at least until IHAVE would reject the same article for being too old). */
	overview_rebuild(groupname, article_num);
	return 0;
}

int tradspool_article_exists(const char *groupname, int article_num)
{
	char artpath[NNTP_MAX_PATH_LENGTH];
	int is_compressed;
	if (!build_group_article_path(groupname, article_num, artpath, sizeof(artpath), &is_compressed)) {
		return 1;
	}
	return 0;
}

int tradspool_article_stat(struct nntp_session *nntp, const char *messageid, const char *groupname, int article_num)
{
	if (messageid) {
		char eff_group[NNTP_BUFSIZ];
		int eff_artnum;
		/* Scan the history file for any messages matching this Message-ID */
		if (!history_find_article_by_messageid(nntp, messageid, groupname, eff_group, sizeof(eff_group), &eff_artnum)) {
			if (!nntp->currentgroup || strcmp(nntp->currentgroup, eff_group)) {
				eff_artnum = 0;
			}
			if (!ACL_ALLOWED_LOCKED(nntp, eff_group, NNTP_ACL_READ)) {
				return 1;
			}
			nntp_send(nntp, NNTP_OK_STAT, "%d %s", eff_artnum, messageid);
			return 0;
		}
	} else {
		char artpath[NNTP_MAX_PATH_LENGTH];
		char found_messageid[NNTP_BUFSIZ];
		int is_compressed;
		if (!build_group_article_path(groupname, article_num, artpath, sizeof(artpath), &is_compressed)) {
			/* Need to look up Message-ID from overview */
			if (!overview_find_messageid(groupname, article_num, found_messageid, sizeof(found_messageid))) {
				nntp_send(nntp, NNTP_OK_STAT, "%d %s", article_num, found_messageid);
				return 0;
			}
		}
	}
	return 1;
}

ssize_t tradspool_article_send_raw(struct bbs_tcp_client *tcpclient, const char *artpath)
{
	ssize_t res;
	char artpathbuf[NNTP_MAX_PATH_LENGTH];
	int is_compressed;

	is_compressed = bbs_str_ends_with(artpath, COMPRESSED_SUFFIX);
	if (is_compressed) {
		safe_strncpy(artpathbuf, artpath, sizeof(artpathbuf));
		if (uncompress_article(artpathbuf)) {
			return -1;
		}
		artpath = artpathbuf;
	}

	res = bbs_send_file(artpath, tcpclient->wfd);
	if (is_compressed) {
		remove_uncompressed_article(artpath);
	}
	if (res <= 0) {
		return -1;
	}
	return res;
}

ssize_t tradspool_article_send_raw_noxref(struct bbs_tcp_client *tcpclient, const char *artpath)
{
	ssize_t wres;
	size_t size;
	char artpathbuf[NNTP_MAX_PATH_LENGTH];
	char buf[NNTP_MAX_LINE_LENGTH + 1];
	int is_compressed;
	size_t headerlen = 0;
	int skipping_header = 0;
	FILE *fp;
	off_t offset;

	is_compressed = bbs_str_ends_with(artpath, COMPRESSED_SUFFIX);
	if (is_compressed) {
		safe_strncpy(artpathbuf, artpath, sizeof(artpathbuf));
		if (uncompress_article(artpathbuf)) {
			return -1;
		}
		artpath = artpathbuf;
	}

	fp = fopen(artpath, "r");
	if (!fp) {
		bbs_error("Failed to open %s: %s\n", artpath, strerror(errno));
		return 0;
	}

	/* Parse the headers and send all of them except the few we MUST NOT send */
	bbs_cork_fd(tcpclient->fd, 1); /* Cork file descriptor so calling bbs_write for each header won't result in a burst of packets */
	while ((fgets(buf, sizeof(buf), fp))) {
		size_t linelen;
		if (!strcmp(buf, "\r\n")) {
			break;
		}
		linelen = strlen(buf);
		headerlen += linelen;
		if (buf[0] == ' ' || buf[0] == '\t') {
			/* Continuation */
			if (skipping_header) {
				continue;
			}
		} else {
			/* New header */
			skipping_header = 0;
			/* Injection-Info and Xref MUST NOT be present (RFC 5537 3.4.1)
			 * Multiple injection: We MUST NOT add an Injection-Date header if it is missing (RFC 5537 3.4.2)
			 * We MUST retain unmodified any existing Message-ID, Date, and Injection-Date;
			 * the Message-ID is what other sites will rely on to filter out duplicates. */
			if (STARTS_WITH(buf, "Injection-Info:") || STARTS_WITH(buf, "Xref:")) {
				skipping_header = 1;
				continue;
			}
			/* Path SHOULD NOT contain a "POSTED" keyword (RFC 5537 3.4.1)
			 * Technically, we could alter the header to remove the .POSTED and everything after it
			 * (or even just the .POSTED), but this is generally even more frowned upon.
			 * We could also rename the header, e.g. to X-Path, but the limited trace info
			 * that exists at this point is unlikely to be of much interest to anyone on the other side. */
			if (STARTS_WITH(buf, "Path:")) {
				skipping_header = 1;
				continue;
			}
		}
		bbs_write(tcpclient->wfd, buf, linelen); /* Send it */
	}
	bbs_cork_fd(tcpclient->fd, 0); /* Flush anything remaining */

	/* Now, send the rest of the article, i.e. the body. We can use sendfile for the rest,
	 * since we kept track of our offset into the file. */
	offset = (off_t) headerlen;
	size = (size_t) lseek(fileno(fp), 0, SEEK_END); /* Seek to end to get size. lseek returns the pos, fseek does not, so we use lseek even though we have a FILE* */
	fseek(fp, offset, SEEK_SET); /* Rewind to where we want to begin */

	wres = bbs_sendfile(tcpclient->wfd, fileno(fp), &offset, size - (size_t) offset); /* Send remainder of article */
	fclose(fp);

	if (is_compressed) {
		remove_uncompressed_article(artpath);
	}
	if (wres < 0) {
		return -1; /* If something went wrong, abort before finalizing article */
	}
	return (ssize_t) size;
}

int tradspool_article_send(struct nntp_session *nntp, enum article_part_filter filter, const char *messageid, const char *groupname, int article_num)
{
	int is_compressed;
	char artpath[NNTP_MAX_PATH_LENGTH];
	char eff_group[NNTP_BUFSIZ];
	char buf[NNTP_BUFSIZ];
	int eff_artnum;
	char found_messageid[NNTP_BUFSIZ];
	int resp_artnum = 0; /* can't be used uninitialized, but silence older versions of gcc */
	int res;

	/* First, find the article, if it even exists */
	if (messageid) {
		/* If we just have a Message-ID, we need to scan the history file to find a link to the message */
		res = history_find_article_by_messageid(nntp, messageid, groupname, eff_group, sizeof(eff_group), &eff_artnum);
		if (res) {
			return 1;
		}
		if (!res) {
			res = build_group_article_path(eff_group, eff_artnum, artpath, sizeof(artpath), &is_compressed);
			/* If article is not in this group, we MUST send an article number of 0 */
			resp_artnum = nntp->currentgroup && !strcmp(nntp->currentgroup, eff_group) ? eff_artnum : 0;
		}
		if (!ACL_ALLOWED_LOCKED(nntp, eff_group, NNTP_ACL_READ)) {
			return 1;
		}
	} else {
		res = build_group_article_path(groupname, article_num, artpath, sizeof(artpath), &is_compressed);
		resp_artnum = article_num;
		/* In this case, we weren't provided the Message-ID, so we need to look that up.
		 * Use the overview file in this case, since we know the group, and it'll be smaller than the history file. */
		if (!res) {
			if (overview_find_messageid(groupname, article_num, found_messageid, sizeof(found_messageid))) {
				return 1;
			}
		}
	}
	if (res) {
		return res;
	}

	/* spoolcompression could be disabled to stop compressing articles, but we still need to decompress existing compressed articles. */
	if (is_compressed && uncompress_article(artpath)) {
		return -1;
	}

	/* If we found it, send the parts requested */
	if ((filter & SEND_HEADERS) && (filter & SEND_BODY)) {
		/* Send the whole file (ARTICLE) */
		if (!bbs_file_exists(artpath)) {
			return 1;
		}
		nntp_send(nntp, NNTP_OK_ARTICLE, "%d %s", resp_artnum, S_OR(messageid, found_messageid));
		bbs_send_file(artpath, nntp->node->wfd);
	} else {
		FILE *fp = fopen(artpath, "r");
		if (!fp) {
			if (errno == ENOENT) {
				if (messageid) {
					/* If we searched by Message-ID and the history file said such an article exists, then shouldn't it? */
					bbs_error("Failed to open %s: %s\n", artpath, strerror(errno));
				}
				return 1; /* Article doesn't exist */
			}
			bbs_error("Failed to open %s: %s\n", artpath, strerror(errno));
			return -1;
		}

		if (filter & SEND_HEADERS) {
			/* HEAD command - send just headers, without empty line at end */
			nntp_send(nntp, NNTP_OK_HEAD, "%d %s", resp_artnum, S_OR(messageid, found_messageid));
			while ((fgets(buf, sizeof(buf), fp))) {
				if (!strcmp(buf, "\r\n")) {
					break;
				} else if (!strcmp(buf, "\n")) { /* Broken line endings */
					bbs_error("File %s using LF line endings instead of CR LF?\n", artpath);
					break;
				}
				_nntp_send(nntp, "%s", buf); /* buf already includes CR LF */
			}
		} else { /* SEND_BODY only */
			long int start, end;
			off_t startoffset;
			nntp_send(nntp, NNTP_OK_BODY, "%d %s", resp_artnum, S_OR(messageid, found_messageid));
			while ((fgets(buf, sizeof(buf), fp))) {
				if (!strcmp(buf, "\r\n")) {
					break;
				} else if (!strcmp(buf, "\n")) { /* Broken line endings */
					bbs_error("File %s using LF line endings instead of CR LF?\n", artpath);
					break;
				}
			}
			/* End of headers, now send body
			 * So we don't have to send the body line by line, get the current offset,
			 * then determine how many bytes we need to send. */
			start = startoffset = ftell(fp);
			fseek(fp, 0, SEEK_END);
			end = ftell(fp);
			bbs_sendfile(nntp->node->wfd, fileno(fp), &startoffset, (size_t) (end - start));
		}
		fclose(fp);
	}
	_nntp_send(nntp, ".\r\n"); /* Termination character. */
	if (is_compressed && remove_uncompressed_article(artpath)) {
		return -1;
	}
	return 0;
}
