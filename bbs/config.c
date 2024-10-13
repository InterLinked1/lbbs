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
 * \brief Config parser
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h> /* use PATH_MAX */

#include "include/linkedlists.h"
#include "include/config.h"
#include "include/utils.h"

struct bbs_keyval {
	char *key;
	char *value;
	/* Next entry */
	RWLIST_ENTRY(bbs_keyval) entry;
};

RWLIST_HEAD(bbs_keyvals, bbs_keyval);

struct bbs_config_section {
	char *name;
	/* List of key/value pairs */
	struct bbs_keyvals keyvals;
	/* Next entry */
	RWLIST_ENTRY(bbs_config_section) entry;
};

RWLIST_HEAD(bbs_config_sections, bbs_config_section);

struct bbs_config {
	char *name;
	time_t parsetime;
	/* List of sections */
	struct bbs_config_sections sections;
	/* Next entry */
	RWLIST_ENTRY(bbs_config) entry;
};

static RWLIST_HEAD_STATIC(configs, bbs_config);

const char *bbs_config_val(struct bbs_config *cfg, const char *section_name, const char *key)
{
	struct bbs_config_section *section;

	RWLIST_TRAVERSE(&cfg->sections, section, entry) {
		if (!strcmp(section->name, section_name)) {
			break;
		}
	}
	if (!section) {
		return NULL;
	}
	return bbs_config_sect_val(section, key);
}

const char *bbs_config_sect_val(struct bbs_config_section *section, const char *key)
{
	struct bbs_keyval *keyval;

	RWLIST_TRAVERSE(&section->keyvals, keyval, entry) {
		if (!strcmp(keyval->key, key)) {
			break;
		}
	}
	if (!keyval) {
		return NULL;
	}
	return keyval->value;
}

int bbs_config_val_set_str(struct bbs_config *cfg, const char *section_name, const char *key, char *buf, size_t len)
{
	const char *s = bbs_config_val(cfg, section_name, key);
	if (!strlen_zero(s)) {
		safe_strncpy(buf, s, len);
		return 0;
	}
	return -1;
}

int bbs_config_val_set_path(struct bbs_config *cfg, const char *section_name, const char *key, char *buf, size_t len)
{
	char *tmp;
	int res = bbs_config_val_set_str(cfg, section_name, key, buf, len);
	if (res) {
		return res;
	}
	/* Paths must not contain trailing slash */
	tmp = strrchr(buf, '/');
	if (tmp && !*(tmp + 1)) {
		*tmp = '\0';
	}
	/* Check that the directory exists (it needs to be executable as well) */
	if (eaccess(buf, X_OK)) {
		bbs_warning("Cannot read directory %s\n", buf);
		return -1;
	}
	return 0;
}

int bbs_config_val_set_dstr(struct bbs_config *cfg, const char *section_name, const char *key, char **str)
{
	const char *s = bbs_config_val(cfg, section_name, key);
	if (!strlen_zero(s)) {
		char *dup = strdup(s);
		if (ALLOC_FAILURE(dup)) {
			return -1;
		}
		*str = dup;
		return 0;
	}
	return -1;
}

int bbs_config_val_set_int(struct bbs_config *cfg, const char *section_name, const char *key, int *var)
{
	const char *s = bbs_config_val(cfg, section_name, key);
	if (!strlen_zero(s)) {
		*var = atoi(s);
		return 0;
	}
	return -1;
}

int bbs_config_val_set_uint(struct bbs_config *cfg, const char *section_name, const char *key, unsigned int *var)
{
	const char *s = bbs_config_val(cfg, section_name, key);
	if (!strlen_zero(s)) {
		*var = (unsigned int) atoi(s); /* Explicitly set to an unsigned int, so we lose the negative */
		return 0;
	}
	return -1;
}

int bbs_config_val_set_port(struct bbs_config *cfg, const char *section_name, const char *key, int *var)
{
	const char *s = bbs_config_val(cfg, section_name, key);
	if (!strlen_zero(s)) {
		int tmp = atoi(s);
		if (PORT_VALID(tmp)) {
			*var = tmp;
		} else {
			bbs_warning("Invalid port number: %s\n", s);
		}
		return 0;
	}
	return -1;
}

int bbs_config_val_set_true(struct bbs_config *cfg, const char *section_name, const char *key, int *var)
{
	const char *s = bbs_config_val(cfg, section_name, key);
	if (!strlen_zero(s)) {
		*var = S_TRUE(s);
		return 0;
	}
	return -1;
}

struct bbs_config_section *bbs_config_section_get(struct bbs_config *cfg, const char *name)
{
	struct bbs_config_section *sect;
	RWLIST_TRAVERSE(&cfg->sections, sect, entry) {
		if (!strcmp(sect->name, name)) {
			break;
		}
	}
	return sect;
}

struct bbs_keyval *bbs_config_section_walk(struct bbs_config_section *section, struct bbs_keyval *keyval)
{
	if (!keyval) {
		/* Return first keyval */
		return RWLIST_FIRST(&section->keyvals);
	}
	return RWLIST_NEXT(keyval, entry); /* Return next keyval. */
}

struct bbs_config_section *bbs_config_walk(struct bbs_config *cfg, struct bbs_config_section *section)
{
	if (!section) {
		/* Return first section */
		return RWLIST_FIRST(&cfg->sections);
	}
	return RWLIST_NEXT(section, entry); /* Return next section. */
}

const char *bbs_keyval_key(struct bbs_keyval *keyval)
{
	return keyval->key;
}

const char *bbs_keyval_val(struct bbs_keyval *keyval)
{
	return keyval->value;
}

const char *bbs_config_section_name(struct bbs_config_section *section)
{
	return section->name;
}

static struct bbs_config *config_get(const char *name)
{
	struct bbs_config *cfg;

	RWLIST_RDLOCK(&configs);
	RWLIST_TRAVERSE(&configs, cfg, entry) {
		if (!strcmp(cfg->name, name)) {
			break;
		}
	}
	RWLIST_UNLOCK(&configs);

	return cfg;
}

static void config_keyval_free(struct bbs_keyval *keyval)
{
	free(keyval->key);
	free(keyval->value);
	free(keyval);
}

static void config_section_free(struct bbs_config_section *section)
{
	/* No need to bother locking individual config sections */
	RWLIST_REMOVE_ALL(&section->keyvals, entry, config_keyval_free);
	RWLIST_HEAD_DESTROY(&section->keyvals);
	free(section->name);
	free(section);
}

static void config_free(struct bbs_config *cfg)
{
	struct bbs_config_section *section;

	bbs_debug(5, "Destroying config %s\n", cfg->name);
	while ((section = RWLIST_REMOVE_HEAD(&cfg->sections, entry))) {
		config_section_free(section);
	}
	RWLIST_HEAD_DESTROY(&cfg->sections);
	free(cfg->name);
	free(cfg);
}

void bbs_configs_free_all(void)
{
	struct bbs_config *cfg;

	RWLIST_WRLOCK(&configs);
	while ((cfg = RWLIST_REMOVE_HEAD(&configs, entry))) {
		config_free(cfg);
	}
	RWLIST_UNLOCK(&configs);
}

int bbs_config_free(struct bbs_config *c)
{
	struct bbs_config *cfg;

	RWLIST_WRLOCK(&configs);
	cfg = RWLIST_REMOVE(&configs, c, entry);
	RWLIST_UNLOCK(&configs);

	if (!cfg) {
		bbs_error("Couldn't find config\n"); /* c->name might not be valid here so don't print it? */
		bbs_log_backtrace(); /* So we can see what module this was for */
	} else {
		config_free(cfg);
	}

	return cfg ? 0 : -1;
}

#define BEGINS_SECTION(s) (*s == '[')

/*! \brief Parse a config file, and optionally write a setting to it */
static struct bbs_config *config_parse_or_write(const char *name, FILE **restrict write_fp_ptr, const char *write_section, const char *write_key, const char *write_value)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval;
	FILE *fp;
	char *line = NULL;
	char *dupline = NULL;
	const char *endl = NULL;
	int has_line_ending = 0;
	size_t len = 0;
    ssize_t bytes_read;
	char *key, *value;
	int lineno = 0;
	char fullname[PATH_MAX];

	if (strstr(name, "..")) {
		bbs_warning("Config name '%s' contains unsafe characters\n", name);
		return NULL;
	}

	if (*name == '/') { /* Full path */
		safe_strncpy(fullname, name, sizeof(fullname));
	} else { /* Path relative to config dir */
		snprintf(fullname, sizeof(fullname), "%s/%s", bbs_config_dir(), name);
	}
	if (access(fullname, R_OK)) {
		/* Config files are optional, not mandatory, so this is a warning only, not an error. */
		bbs_notice("Config file %s does not exist\n", fullname);
		return NULL;
	}
	fp = fopen(fullname, "r");
	if (!fp) {
		/* Okay, at this point the file should exist, so emit an error. */
		bbs_error("Failed to open config file %s\n", fullname);
		return NULL;
	}

	cfg = calloc(1, sizeof(*cfg));
	if (ALLOC_FAILURE(cfg)) {
		fclose(fp);
		return NULL;
	}
	cfg->parsetime = time(NULL);
	cfg->name = strdup(name);
	if (ALLOC_FAILURE(cfg->name)) {
		free(cfg);
		fclose(fp);
		return NULL;
	}
	RWLIST_HEAD_INIT(&cfg->sections);

	bbs_debug(3, "Parsing config %s\n", fullname);

#define COPY_EXISTING_LINE() fprintf(*write_fp_ptr, "%s", dupline);

	while ((bytes_read = getline(&line, &len, fp)) != -1) {
		lineno++;
		if (strlen_zero(line)) {
			continue;
		}
		if (write_fp_ptr) {
			has_line_ending = strchr(line, '\n') ? 1 : 0; /* Whether CR or LF, it has an LF */
			if (!endl) {
				/* Preserve whichever line endings this file uses. */
				endl = strchr(line, '\r') ? "\r\n" : "\n";
			}
			/* Handle previous line */
			if (dupline) {
				COPY_EXISTING_LINE();
				free(dupline);
			}
			dupline = strdup(line);
			if (ALLOC_FAILURE(dupline)) {
				/* Exit cleanly, but fail. */
				fclose(*write_fp_ptr);
				*write_fp_ptr = NULL;
			}
		}
		rtrim(line);
		if (*line == '\r' || *line == '\n') {
			continue; /* Skip blank/empty lines */
		}
		bbs_strterm(line, ';'); /* Ignore comments */
		if (strlen_zero(line)) {
			continue; /* Skip blank/empty lines (such as lines solely consisting of comments) */
		}

		if (BEGINS_SECTION(line)) {
			char *section_name, *end;

			end = strchr(line, ']');
			section_name = line + 1;

			if (!end) {
				bbs_warning("Config section begun but not ended (%s:%d): %s\n", name, lineno, line);
			} else {
				*end++ = '\0';
				if (end && *end && !isspace(*end)) {
					bbs_warning("Config section name contains trailing content (%s:%d): %s (starting with %c/%d)\n", name, lineno, end, isalpha(*end) ? *end : ' ', *end);
				}
			}
			if (strlen_zero(section_name)) {
				bbs_warning("Empty config section name (%s:%d)\n", name, lineno);
				continue;
			}
#ifdef DEBUG_CONFIG_PARSING
			bbs_debug(7, "New section: %s\n", section_name);
#endif

			if (write_fp_ptr && write_section && section && !strcmp(section->name, write_section)) {
				/* Append keyval to previous section since it was not already present.
				 * The only downside of this logic is in a file formatted like this:
				 * [section]
				 * keyA=valA
				 * keyB=valB
				 *
				 * [section2]
				 * ...
				 * If we append, it will be on the line immediately before [section2],
				 * which is correct, but it will be AFTER the blank line.
				 * This issue doesn't come up when the value is being replaced, rather than added.
				 * There's nothing incorrect about this, it just looks weird,
				 * but it's not worth the added overhead to work around that to me... */
				fprintf(*write_fp_ptr, "%s = %s%s", write_key, write_value, endl);
				bbs_verb(5, "Adding setting '%s' in existing config\n", write_key);
			}

			section = calloc(1, sizeof(*section));
			if (ALLOC_FAILURE(section)) {
				continue;
			}
			section->name = strdup(section_name);
			if (ALLOC_FAILURE(section->name)) {
				free(section);
				section = NULL;
				continue;
			}
			RWLIST_HEAD_INIT(&section->keyvals);
			RWLIST_INSERT_TAIL(&cfg->sections, section, entry);
			bbs_assert(RWLIST_FIRST(&cfg->sections) != NULL);
			continue;
		}

		value = NULL;
		key = line; /* Must not modify line pointer for free() */

		ltrim(key); /* Eat leading whitespace: maybe the line has a comment later on and that's it */
		if (strlen_zero(key)) {
			continue;
		}

		value = strchr(key, '=');
		if (!value) {
			bbs_warning("Config directive does not begin section and missing '=', ignoring! (%s:%d): %s\n", name, lineno, line);
			continue;
		}
		*value++ = '\0';
		trim(key);
		trim(value);

		if (!section) {
			bbs_warning("Failed to process %s=%s, not in a section (%s:%d)\n", key, value, name, lineno);
			continue;
		}

		if (write_fp_ptr && write_section) {
			/* At this point, we know if this key should be updated.
			 * Furthermore, keys cannot have empty values, so we are replacing some value. */
			if (!strcmp(key, write_key) && !strcmp(section->name, write_section)) {
				char *tmp = strchr(dupline, '=');
				bbs_assert_exists(tmp); /* We duplicated a string which contains '=', so it must exist */
				tmp++; /* There must be a value, so tmp must be nonempty at this point */
				tmp = strstr(dupline, value);
				bbs_assert_exists(value);
				tmp += strlen(value);
				/* Copy remainder of line from tmp onwards,
				 * then free dupline since we already handled this line. */
				fprintf(*write_fp_ptr, "%s = %s%s", key, write_value, S_IF(tmp)); /* tmp also includes the line ending */
				bbs_verb(5, "Updating setting '%s' in existing config\n", write_key);
				FREE(dupline); /* free and set to NULL */
				write_section = NULL; /* Do not do any further replacements/additions */
			}
		}

		keyval = calloc(1, sizeof(*keyval));
		if (ALLOC_FAILURE(keyval)) {
			continue;
		}
		keyval->key = strdup(key);
		if (ALLOC_FAILURE(keyval->key)) {
			free(keyval);
			continue;
		}
		keyval->value = strdup(value);
		if (ALLOC_FAILURE(keyval->value)) {
			free(keyval->key);
			free(keyval);
			continue;
		}
#ifdef DEBUG_CONFIG_PARSING
		bbs_debug(8, "New key-value pair in %s: %s => %s=%s\n", name, section->name, keyval->key, keyval->value);
#endif
		RWLIST_INSERT_TAIL(&section->keyvals, keyval, entry);
		bbs_assert(RWLIST_FIRST(&section->keyvals) != NULL);
	}

	if (line) {
		free(line); /* Free only once at the end */
	}
	if (write_fp_ptr && dupline) {
		COPY_EXISTING_LINE();
		FREE(dupline);
	}
	if (write_fp_ptr && write_section && section && !strcmp(section->name, write_section)) {
		/* If the last line did not originally end with a newline, don't add one at the end now */
		fprintf(*write_fp_ptr, "%s = %s%s", write_key, write_value, has_line_ending ? endl : "");
		bbs_verb(5, "Adding setting '%s' in existing config\n", write_key);
	}
	fclose(fp);

	/* Only at the end should we insert the config into the list. */
	if (!write_key) {
		RWLIST_WRLOCK(&configs);
		RWLIST_INSERT_TAIL(&configs, cfg, entry);
		RWLIST_UNLOCK(&configs);
	}

	bbs_verb(5, "Parsed config %s\n", fullname);

	return cfg;
}

static struct bbs_config *config_parse(const char *name)
{
	return config_parse_or_write(name, NULL, NULL, NULL, NULL);
}

int bbs_config_set_keyval(const char *filename, const char *section, const char *key, const char *value)
{
	FILE *oldfp, *newfp;
	struct bbs_config *cfg;
	size_t fsize;
	struct stat st;
	char tmpfile[256] = "/tmp/bbs_config_XXXXXX";

	/* Unlike Asterisk, we do not parse the entire config into memory,
	 * modify config objects, and then serialize it back to disk.
	 * Instead, we just work with the INI config file directly.
	 * This avoids having to worry about preserving comments and formatting verbatim,
	 * resulting in "dumber" (less semantic/powerful) but ultimately much simpler code.
	 * This would be very inefficient for updating multiple key-value pairs,
	 * but for updating a single setting in a file, it is fairly efficient. */

	/* The GNU and BSD versions of sed use different syntax,
	 * and we may want to either set or replace the config value
	 * (and may not know or care what the old value is).
	 * So, do a brute force copy and update/add/replace. */

	oldfp = fopen(filename, "r");
	if (!oldfp) {
		bbs_warning("Existing config file '%s' does not exist\n", filename);
		/* If config file doesn't exist, we could create it,
		 * but more than likely something is wrong and we should just abort. */
		return -1;
	}
	newfp = bbs_mkftemp(tmpfile, 0660);
	if (!newfp) {
		fclose(oldfp);
		return -1;
	}

	cfg = config_parse_or_write(filename, &newfp, section, key, value);

	/* Finalize and cleanup */
	fclose(oldfp);
	if (!newfp) {
		/* Failure occured, and newfp has already been closed. */
		if (cfg) {
			config_free(cfg);
			bbs_delete_file(tmpfile);
		}
		return -1;
	}
	fflush(newfp);
	fsize = (size_t) ftell(newfp);
	fclose(newfp);

	/* We parsed the config, but don't want to keep it.
	 * For one, it's now outdated, and it may be duplicating the stale version already in the linked list. */
	if (!cfg) {
		bbs_delete_file(tmpfile);
		return -1;
	}
	config_free(cfg); /* Wasn't inserted into list, so don't use bbs_config_free */

	/* Edge case, but check if the disk was full and we weren't actually able to write the file to disk. */
	if (stat(tmpfile, &st)) {
		bbs_error("Failed to stat %s: %s\n", tmpfile, strerror(errno));
		bbs_delete_file(tmpfile);
		return -1;
	}
	if ((size_t) st.st_size != fsize) {
		bbs_error("File size mismatch: %lu != %lu\n", st.st_size, fsize);
		bbs_delete_file(tmpfile);
		return -1;
	}

	/* Okay, now do the atomic rename, since we are confident file truncation did not occur. */
	if (rename(tmpfile, filename)) {
		bbs_error("Failed to rename %s -> %s: %s\n", tmpfile, filename, strerror(errno));
		bbs_delete_file(tmpfile);
		return -1;
	}

	return 0;
}

static int __bbs_cached_config_outdated(struct bbs_config *cfg, const char *name)
{
	/* Check if the config has changed since we parsed it. */
	char fullname[PATH_MAX];
	const char *filename;
	struct stat st;

	/* If not an absolute path, prefix BBS config dir */
	if (*name == '/') {
		filename = name;
	} else {
		snprintf(fullname, sizeof(fullname), "%s/%s", bbs_config_dir(), name);
		filename = fullname;
	}

	if (stat(filename, &st)) {
		bbs_warning("stat(%s) failed: %s\n", filename, strerror(errno));
	} else {
		time_t modified = st.st_mtime;
		if (modified < cfg->parsetime) {
			/* File hasn't been modified since we last parsed it. */
			/* We're not refcounting or returning cfg locked in any way.
			 * Our assumption is that bbs_config_free will only be called
			 * when nobody is using cfg anymore.
			 * Reasonable assumption if each config is only used by one module or file,
			 * and that module can ensure this invariant is obeyed. */
			return 0;
		}
	}
	return 1;
}

int bbs_cached_config_outdated(const char *name)
{
	struct bbs_config *cfg = config_get(name);
	if (!cfg) {
		return -1;
	}
	return __bbs_cached_config_outdated(cfg, name);
}

struct bbs_config *bbs_config_load(const char *name, int usecache)
{
	struct bbs_config *cfg;

	cfg = config_get(name);
	if (cfg) {
		if (usecache) {
			if (!__bbs_cached_config_outdated(cfg, name)) {
				bbs_debug(5, "Config %s has not been modified since it was last parsed. Returning cached version.\n", name);
				return cfg;
			}
			bbs_debug(5, "Reparsing config %s again since it has changed\n", name);
		} else {
			bbs_debug(5, "Reparsing config %s again since caching is disabled\n", name);
		}
		/* We're reparsing the config. Destroy the existing copy. */
		if (bbs_config_free(cfg)) {
			return NULL;
		}
	}

	return config_parse(name);
}
