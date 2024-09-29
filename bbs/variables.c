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
 * \brief BBS (node and global) variables
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h> /* use free, calloc */
#include <stdarg.h>
#include <string.h>

#include "include/linkedlists.h"
#include "include/variables.h"
#include "include/node.h"
#include "include/user.h"
#include "include/config.h"
#include "include/utils.h"
#include "include/cli.h"
#include "include/reload.h"

/*! \brief Opaque structure for a variable (really, a list of variables) */
struct bbs_var {
	RWLIST_ENTRY(bbs_var) entry;
	/* Pointers to memory in the FSM */
	char *key;
	char *value;
	/* Key is stored in the FSM. Var is allocated separately so that we can easily update it */
	char s[0];
};

/* static RWLIST_HEAD_STATIC(global_vars, bbs_var); */
static struct bbs_vars global_vars;

static inline void bbs_var_destroy(struct bbs_var *var)
{
	free(var->value); /* Free variable */
	free(var); /* Free key and the struct itself */
}

void bbs_vars_destroy(struct bbs_vars *vars)
{
	RWLIST_WRLOCK_REMOVE_ALL(vars, entry, bbs_var_destroy);
	RWLIST_HEAD_DESTROY(vars);
}

void bbs_vars_remove_first(struct bbs_vars *vars)
{
	struct bbs_var *var;
	RWLIST_WRLOCK(vars);
	var = RWLIST_REMOVE_HEAD(vars, entry);
	if (var) {
		bbs_var_destroy(var);
	}
	RWLIST_UNLOCK(vars);
}

const char *bbs_vars_peek_head(struct bbs_vars *vars, char **value)
{
	struct bbs_var *var = RWLIST_FIRST(vars);
	if (var) {
		*value = var->value;
		return var->key;
	}
	return NULL;
}

const char *bbs_varlist_next(struct bbs_vars *vars, struct bbs_var **v, const char **key)
{
	struct bbs_var *vnext;
	if (!*v) {
		vnext = RWLIST_FIRST(vars);
	} else {
		vnext = RWLIST_NEXT(*v, entry);
	}
	*v = vnext; /* Set iterator to next item */
	if (*v) {
		*key = vnext->key;
		return vnext->value;
	}
	return NULL;
}

static int load_config(void)
{
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	struct bbs_config *cfg = bbs_config_load("variables.conf", 1);

	/* Predefine colors for user convenience in menus.conf, since they contain escape sequences */
	bbs_var_set_user("TERM_COLOR_BLACK", COLOR(TERM_COLOR_BLACK));
	bbs_var_set_user("TERM_COLOR_RED", COLOR(TERM_COLOR_RED));
	bbs_var_set_user("TERM_COLOR_GREEN", COLOR(TERM_COLOR_GREEN));
	bbs_var_set_user("TERM_COLOR_BLUE", COLOR(TERM_COLOR_BLUE));
	bbs_var_set_user("TERM_COLOR_MAGENTA", COLOR(TERM_COLOR_MAGENTA));
	bbs_var_set_user("TERM_COLOR_CYAN", COLOR(TERM_COLOR_CYAN));
	bbs_var_set_user("TERM_COLOR_WHITE", COLOR(TERM_COLOR_WHITE));
	bbs_var_set_user("COLOR_NONE", COLOR_RESET);

	bbs_var_set_user("COLOR_PRIMARY", COLOR(COLOR_PRIMARY));
	bbs_var_set_user("COLOR_SECONDARY", COLOR(COLOR_SECONDARY));

	/* Predefine other useful formatting sequences for menus.conf */
	bbs_var_set_user("TAB", "\t");
	bbs_var_set_user("CRLF", "\r\n");

	if (!cfg) {
		return 0;
	}

	while ((section = bbs_config_walk(cfg, section))) {
		if (strcmp(bbs_config_section_name(section), "variables")) {
			/* [variables] contains global variables
			 * Don't load anything else into memory directly. */
			continue;
		}
		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
			bbs_var_set_user(key, value);
		}
	}
	/* Don't free the config, since we'll reference it whenever users log in. */
	return 0;
}

static int vars_reload(int fd)
{
	RWLIST_WRLOCK_REMOVE_ALL(&global_vars, entry, bbs_var_destroy);
	load_config();
	bbs_dprintf(fd, "Reloaded variables\n");
	return 0;
}

static int vars_dump(int fd, struct bbs_vars *vars)
{
	if (vars) {
		int c = 0;
		struct bbs_var *v;

		RWLIST_RDLOCK(vars);
		RWLIST_TRAVERSE(vars, v, entry) {
			char safebuf[256];
			if (!c++) {
				bbs_dprintf(fd, "== %sVariables ==\n", vars == &global_vars ? "Global " : "Node ");
				if (vars == &global_vars) {
					/* Include pseudo globals (builtins) */
					bbs_dprintf(fd, "%-20s : %s\n", "BBS_TIME", "<DYNAMIC> e.g. 01/01 01:01pm");
					bbs_dprintf(fd, "%-20s : %s\n", "BBS_TIME_LONG", "<DYNAMIC> e.g. Sat Dec 31 2000 09:45 am EST");
				}
			}
			if (!bbs_str_safe_print(v->value, safebuf, sizeof(safebuf))) {
				bbs_dprintf(fd, "%-20s : %s\n", v->key, safebuf);
			} else {
				/* Print only the name */
				bbs_dprintf(fd, "%-20s : <UNPRINTABLE>\n", v->key);
			}
		}
		RWLIST_UNLOCK(vars);
		bbs_dprintf(fd, "%d variable%s\n", c, ESS(c));
	} else {
		bbs_dprintf(fd, "No variables\n");
	}
	return 0;
}

int bbs_node_vars_dump(int fd, struct bbs_node *node)
{
	/* If there are vars for a node, print them (vars_dump handles NULL) */
	return vars_dump(fd, node->vars);
}

static int cli_variables(struct bbs_cli_args *a)
{
	return vars_dump(a->fdout, &global_vars); /* Dump globals */
}

static struct bbs_cli_entry cli_commands_variables[] = {
	BBS_CLI_COMMAND(cli_variables, "variables", 1, "List global variables", NULL),
};

void bbs_vars_cleanup(void)
{
	bbs_cli_unregister_multiple(cli_commands_variables);
	/* Destroy any global variables that remain */
	bbs_vars_destroy(&global_vars);
}

int bbs_vars_init(void)
{
	RWLIST_HEAD_INIT(&global_vars);
	return load_config() || bbs_register_reload_handler("variables", "Reload global and per-user variables", vars_reload) || bbs_cli_register_multiple(cli_commands_variables);
}

/*! \note Could use a callback for this (allowing NULL modules in event.c),
 * but just make this callable directly from node.c */
int bbs_user_init_vars(struct bbs_node *node)
{
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	struct bbs_config *cfg = bbs_config_load("variables.conf", 1);

	if (!cfg) {
		return 0;
	}

	while ((section = bbs_config_walk(cfg, section))) {
		if (strcasecmp(bbs_config_section_name(section), bbs_username(node->user))) {
			continue;
		}
		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
			bbs_node_var_set(node, key, value);
		}
	}
	return 0;
}

int bbs_varlist_last_var_append(struct bbs_vars *vars, const char *s)
{
	struct bbs_var *v;

	RWLIST_WRLOCK(vars);
	v = RWLIST_LAST(vars);
	if (v) {
		char *newval;
		size_t oldlen = strlen(v->value);
		size_t addlen = strlen(s);
		bbs_debug(6, "Updating value of %s from %s to %s%s\n", v->key, v->value, v->value, s);
		newval = realloc(v->value, oldlen + addlen + 1);
		if (ALLOC_SUCCESS(newval)) {
			strcpy(newval + oldlen, s); /* Safe */
			v->value = newval;
		}
	}
	RWLIST_UNLOCK(vars);
	return v ? 0 : -1;
}

int bbs_varlist_append(struct bbs_vars *vars, const char *key, const char *value)
{
	struct bbs_var *v;
	size_t keylen = strlen(key);
	char *dupedvalue;

	RWLIST_WRLOCK(vars);
	/* Check if variable already exists.
	 * If it does and value is NULL, delete it.
	 * Otherwise, update it.
	 */
	RWLIST_TRAVERSE_SAFE_BEGIN(vars, v, entry) {
		if (!strcmp(v->key, key)) {
			if (value) {
				/* Update to new value. */
				if (strcmp(v->value, value)) {
					bbs_debug(6, "Updating value of %s from %s to %s\n", key, v->value, value);
					REPLACE(v->value, value);
				} else {
					bbs_debug(6, "Value of %s (%s) has not changed\n", key, value);
				}
			} else {
				/* value is NULL (not merely the empty string). Delete the existing variable. */
				RWLIST_REMOVE_CURRENT(entry);
				bbs_debug(6, "Deleting variable %s with value %s\n", key, v->value);
				bbs_var_destroy(v);
			}
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;

	if (v) { /* Did something with an existing var */
		RWLIST_UNLOCK(vars);
		return 0;
	} else if (!value) {
		RWLIST_UNLOCK(vars);
		bbs_warning("Attempted to set variable %s to NULL, but it doesn't already exist\n", key);
		return -1;
	}

	/* Variable didn't already exist. Create a new variable */
	dupedvalue = strdup(value);
	if (ALLOC_FAILURE(dupedvalue)) {
		RWLIST_UNLOCK(vars);
		return -1;
	}

	v = calloc(1, sizeof(*v) + keylen + 1); /* NUL */
	if (ALLOC_FAILURE(v)) {
		free(dupedvalue);
		RWLIST_UNLOCK(vars);
		return -1;
	}
	v->key = v->s;
	strcpy(v->key, key); /* Safe */
	v->value = dupedvalue;
	RWLIST_INSERT_TAIL(vars, v, entry);
	RWLIST_UNLOCK(vars);
	bbs_debug(6, "Set variable %s to '%s'%s\n", key, value, strchr(value, 27) ? COLOR_RESET : ""); /* Zoinks, contained an escape sequence! */
	return 0;
}

int bbs_node_var_set(struct bbs_node *node, const char *key, const char *value)
{
	/* The bbs_node struct contains a pointer to bbs_vars, not a bbs_var itself.
	 * This prevents having to expose bbs_var internally to node.h, we just need
	 * to forward declare bbs_vars.
	 * The downside of this is we have to allocate a bbs_vars list if one doesn't already exist.
	 * The upside of this is if we never need to set vars for a node, we never allocate a list.
	 */
	if (node) {
		struct bbs_vars *vars;

		/* Make sure a race condition doesn't result in creating a duplicate var list */
		bbs_node_lock(node);
		if (!node->vars) {
			vars = calloc(1, sizeof(*vars));
			if (ALLOC_FAILURE(vars)) {
				bbs_node_unlock(node);
				return -1;
			}
			bbs_debug(5, "Allocated variable list for node %d\n", node->id);
			RWLIST_HEAD_INIT(vars);
			node->vars = vars;
		}
		bbs_node_unlock(node);

		return bbs_varlist_append(node->vars, key, value);
	} else {
		/* "Global" var */
		return bbs_varlist_append(&global_vars, key, value);
	}
}

int bbs_var_set_user(const char *key, const char *value)
{
	if (STARTS_WITH(key, "BBS_")) {
		bbs_warning("Variable name '%s' is reserved\n", key);
		return -1;
	}
	return bbs_node_var_set(NULL, key, value); /* Set a global var */
}

int __attribute__ ((format (gnu_printf, 3, 4))) bbs_node_var_set_fmt(struct bbs_node *node, const char *key, const char *fmt, ...)
{
	char *buf;
	int len, res;
	va_list ap;

	if (!strchr(fmt, '%')) {
		/* No format characters, just call it directly to avoid an unnecessary allocation */
		return bbs_node_var_set(node, key, fmt);
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}
	res = bbs_node_var_set(node, key, buf);
	free(buf);
	return res;
}

const char *bbs_var_find(struct bbs_vars *vars, const char *key)
{
	struct bbs_var *v;

	RWLIST_RDLOCK(vars);
	RWLIST_TRAVERSE(vars, v, entry) {
		if (!strcmp(v->key, key)) {
			break;
		}
	}
	RWLIST_UNLOCK(vars);
	return v ? v->value : NULL;
}

const char *bbs_var_find_case(struct bbs_vars *vars, const char *key)
{
	struct bbs_var *v;

	RWLIST_RDLOCK(vars);
	RWLIST_TRAVERSE(vars, v, entry) {
		if (!strcasecmp(v->key, key)) {
			break;
		}
	}
	RWLIST_UNLOCK(vars);
	return v ? v->value : NULL;
}

/*! \note This function is only compatible with a buffer. We cannot return const char data since some of these vars are dynamic. */
static int builtin_var_expand(struct bbs_node *node, const char *name, char *buf, size_t len)
{
	UNUSED(node); /* This argument is currently not used, but may be in the future. */
	if (!strcmp(name, "BBS_TIME")) {
		if (!buf) {
			bbs_error("Cannot substitute variable '%s' because no buffer is available\n", name);
			return -1;
		}
		return bbs_time_friendly_short_now(buf, len) < 0 ? -1 : 0;
	} else if (!strcmp(name, "BBS_TIME_LONG")) {
		if (!buf) {
			bbs_error("Cannot substitute variable '%s' because no buffer is available\n", name);
			return -1;
		}
		return bbs_time_friendly_now(buf, len) < 0 ? -1 : 0;
	} else {
		return 1; /* Not applicable */
	}
}

const char *bbs_node_var_get(struct bbs_node *node, const char *key)
{
	const char *value = NULL;

	/* Since this function returns a direct reference to the variable,
	 * we don't check global variables, only node variables,
	 * so we can require that the node be locked.
	 * This avoids the caller having to acquire a global variable read lock,
	 * and manually unlock afterwards, just in case the variable returned
	 * is global. */

	/* If node has vars, check there */
	if (node->vars) {
		value = bbs_var_find(node->vars, key);
	}
	return value;
}

int bbs_node_var_get_buf(struct bbs_node *node, const char *key, char *restrict buf, size_t len)
{
	const char *s = NULL;

	/* Built-in vars that aren't really true variables, but treated as such. */
	if (!builtin_var_expand(node, key, buf, len)) {
		return 0;
	}

	RWLIST_RDLOCK(&global_vars); /* Guarantee thread safety for globals. In case the variable is global, RDLOCK it here. We may RDLOCK again in bbs_var_find, but that's okay. */

	/* Check if it's a global variable. */
	s = bbs_var_find(&global_vars, key);
	if (s) {
		safe_strncpy(buf, s, len);
		RWLIST_UNLOCK(&global_vars);
		return 0;
	}

	if (node) {
		bbs_node_lock(node); /* Guarantee thread safety for node variables. */
		s = bbs_node_var_get(node, key);
		if (s) {
			safe_strncpy(buf, s, len);
		} else {
			*buf = '\0'; /* Be nice and at least null terminate, in case the caller doesn't check the return value. */
		}
		bbs_node_unlock(node);
	}
	RWLIST_UNLOCK(&global_vars);
	return s ? 0 : -1;
}

static int substitute_vars(struct bbs_node *node, struct bbs_vars *vars, const char *sub, char *restrict buf, size_t len)
{
	char varname[64];
	char *bufstart = buf;
	const char *s = sub;

	/* Don't think we can optimize by returning early if !strchr(sub, '$'). The while loop below does no extra work in that case anyways */
	if (strlen_zero(sub)) {
		*buf = '\0';
		return 0;
	}

	while (*s) {
		const char *end;
		int starts_var;

		if (len <= 1) {
			*buf = '\0';
			bbs_warning("Truncation occured when substituting variables for '%s'\n", sub);
			return -1;
		}

		starts_var = *s == '$' && *(s + 1) == '{';
		if (!starts_var) {
			/* Just copy and go to the next one */
			*buf++ = *s;
			--len;
			s++;
			continue;
		}
		s += 2; /* Skip ${ */
		/* Find the end */
		end = strchr(s, '}');
		if (!end) {
			bbs_warning("Variable expression is malformed, missing end brace: '%s'\n", sub);
			/* Just treat it as normal text, what else can ya do? */
			s -= 2; /* Undo the advancement */
			*buf++ = *s;
			--len;
			s++;
			continue;
		}
		/* Find a variable */
		if ((end - s) >= (long int) sizeof(varname)) {
			bbs_warning("Variable name '%.*s' is too long for substitution\n", (int) (end - s), varname);
			/* Just treat it as normal text, what else can ya do? */
			s -= 2; /* Undo the advancement */
			*buf++ = *s;
			--len;
			s++;
			continue;
		}
		/* sub is const char, so we can't just null terminate at } and use that.
		 * This isn't just about style, the sub might directly be from the config,
		 * so we must be able to deal with const char.
		 * So, copy the variable name into a buffer and null terminate it there.
		 *
		 * Say we copy "test".
		 * We should copy 4 characters and then add a null termination after.
		 * end - s = 4, or the length of the varname.
		 * Add 1 because we need room for the null termination, and safe_strncpy will
		 * automatically null terminate.
		 *
		 * Truncation shouldn't occur because we already checked for that.
		 */
		safe_strncpy(varname, s, (size_t) MIN((int) sizeof(varname), end - s + 1));
		bbs_debug(9, "Substituting variable '%s' (using %s)\n", varname, node ? "node" : "varlist");
		if (vars) {
			const char *val = bbs_var_find(vars, varname);
			if (val) {
				int bytes = snprintf(buf, len, "%s", val);
				buf += bytes;
				len -= (size_t) bytes;
			}
		} else {
			/* node can be NULL, that's fine */
			bbs_node_var_get_buf(node, varname, buf, len);
		}
		/* After substitution occurs, find the null termination and update our pointers. */
		while (*buf) {
			if (len <= 1) {
				*buf = '\0';
				bbs_warning("Truncation occured when substituting variables for '%s'\n", sub);
				return -1;
			}
			buf++;
			len--;
		}
		s = end + 1;
	}
	*buf = '\0'; /* Null terminate */
	bbs_debug(8, "Substituted '%s' to '%s'\n", sub, bufstart);
	return 0;
}

int bbs_varlist_substitute_vars(struct bbs_vars *vars, const char *sub, char *restrict buf, size_t len)
{
	return substitute_vars(NULL, vars, sub, buf, len);
}

int bbs_node_substitute_vars(struct bbs_node *node, const char *sub, char *restrict buf, size_t len)
{
	return substitute_vars(node, NULL, sub, buf, len);
}
