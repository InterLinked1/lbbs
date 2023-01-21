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
#include <linux/limits.h> /* use PATH_MAX */

#include "include/linkedlists.h"
#include "include/config.h"

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

int bbs_config_val_set_dstr(struct bbs_config *cfg, const char *section_name, const char *key, char **str)
{
	const char *s = bbs_config_val(cfg, section_name, key);
	if (!strlen_zero(s)) {
		char *dup = strdup(s);
		if (!dup) {
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
		*var = atoi(s); /* Explicitly set to an unsigned int, so we lose the negative */
		return 0;
	}
	return -1;
}

int bbs_config_val_set_port(struct bbs_config *cfg, const char *section_name, const char *key, int *var)
{
	int tmp;
	const char *s = bbs_config_val(cfg, section_name, key);
	if (!strlen_zero(s)) {
		tmp = atoi(s);
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
	struct bbs_keyval *keyval;

	/* No need to bother locking individual config sections */
	while ((keyval = RWLIST_REMOVE_HEAD(&section->keyvals, entry))) {
		config_keyval_free(keyval);
	}
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
	RWLIST_TRAVERSE_SAFE_BEGIN(&configs, cfg, entry) {
		if (cfg == c) {
			RWLIST_REMOVE_CURRENT(entry);
			config_free(cfg);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&configs);

	if (!cfg) {
		bbs_error("Couldn't find config %s\n", c->name);
	}

	return cfg ? 0  : -1;
}

#define BEGINS_SECTION(s) (*s == '[')

static struct bbs_config *config_parse(const char *name)
{
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval;
	FILE *fp;
	char *line = NULL;
	size_t len = 0;
    ssize_t bytes_read;
	char *key, *value;
	int lineno = 0;
	char fullname[PATH_MAX];

	if (strstr(name, "..")) {
		bbs_warning("Config name '%s' contains unsafe characters\n", name);
		return NULL;
	}

	snprintf(fullname, sizeof(fullname), "%s/%s", BBS_CONFIG_DIR, name);
	if (access(fullname, R_OK)) {
		/* Config files are optional, not mandatory, so this is a warning only, not an error. */
		bbs_warning("Config file %s does not exist\n", fullname);
		return NULL;
	}
	fp = fopen(fullname, "r");
	if (!fp) {
		/* Okay, at this point the file should exist, so emit an error. */
		bbs_error("Failed to open config file %s\n", fullname);
		return NULL;
	}

	cfg = calloc(1, sizeof(*cfg));
	if (!cfg) {
		fclose(fp);
		return NULL;
	}

	cfg->parsetime = time(NULL);
	cfg->name = strdup(name);

	bbs_debug(3, "Parsing config %s\n", fullname);

	while ((bytes_read = getline(&line, &len, fp)) != -1) {
		lineno++;
		rtrim(line);
		if (strlen_zero(line)) {
			continue; /* Skip blank/empty lines */
		}
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
			section = calloc(1, sizeof(*section));
			if (!section) {
				bbs_error("calloc failed\n");
				continue;
			}
			section->name = strdup(section_name);
			RWLIST_INSERT_TAIL(&cfg->sections, section, entry);
			bbs_assert(RWLIST_FIRST(&cfg->sections) != NULL);
			continue;
		}

		key = value = NULL;
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

		keyval = calloc(1, sizeof(*keyval));
		if (!keyval) {
			bbs_error("calloc failure\n");
			continue;
		}
		keyval->key = strdup(key);
		if (!keyval->key) {
			bbs_error("strdup failed\n");
			free(keyval);
			continue;
		}
		keyval->value = strdup(value);
		if (!keyval->value) {
			bbs_error("strdup failed\n");
			free(keyval->key);
			free(keyval);
			continue;
		}
#ifdef DEBUG_CONFIG_PARSING
		bbs_debug(8, "New key-value pair in %s: %s=%s\n", section->name, keyval->key, keyval->value);
#endif
		RWLIST_INSERT_TAIL(&section->keyvals, keyval, entry);
		bbs_assert(RWLIST_FIRST(&section->keyvals) != NULL);
	}

	if (line) {
		free(line); /* Free only once at the end */
	}
	fclose(fp);

	/* Only at the end should we insert the config into the list. */
	RWLIST_WRLOCK(&configs);
	RWLIST_INSERT_TAIL(&configs, cfg, entry);
	RWLIST_UNLOCK(&configs);

	bbs_verb(5, "Parsed config %s\n", fullname);

	return cfg;
}

struct bbs_config *bbs_config_load(const char *name, int usecache)
{
	struct bbs_config *cfg;

	cfg = config_get(name);
	if (cfg) {
		if (usecache) {
			/* Check if the config has changed since we parsed it. */
			char fullname[PATH_MAX];
			struct stat st;

			snprintf(fullname, sizeof(fullname), "%s/%s", BBS_CONFIG_DIR, name);

			if (stat(fullname, &st)) {
				bbs_error("stat failed: %s\n", strerror(errno));
			} else {
				time_t modified = st.st_mtime;
				if (modified < cfg->parsetime) {
					/* File hasn't been modified since we last parsed it. */
					/* We're not refcounting or returning cfg locked in any way.
					 * Our assumption is that bbs_config_free will only be called
					 * when nobody is using cfg anymore.
					 * Reasonable assumption if each config is only used by one module or file,
					 * and that module can ensure this invariant is obeyed. */
					bbs_debug(5, "Config %s has not been modified since it was last parsed. Returning cached version.\n", name);
					return cfg;
				}
			}
		}
		bbs_debug(5, "Reparsing config %s again since it has changed\n", name);
		/* We're reparsing the config. Destroy the existing copy. */
		if (bbs_config_free(cfg)) {
			return NULL;
		}
	}

	return config_parse(name);
}
