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
 * \brief Module loader and unloader
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h> /* use usleep */
#include <poll.h>
#include <limits.h> /* use PATH_MAX */

#include "include/linkedlists.h"
#include "include/dlinkedlists.h"
#include "include/stringlist.h"
#include "include/module.h"
#include "include/reload.h"
#include "include/config.h"
#include "include/utils.h" /* use bbs_dir_traverse */
#include "include/node.h"
#include "include/cli.h"
#include "include/event.h"

#define BBS_MODULE_DIR DIRCAT("/usr/lib", DIRCAT(BBS_NAME, "modules"))

struct bbs_module_reference {
	int pair;
	void *refmod;
	const char *file;
	const char *func;
	int line;
	RWLIST_ENTRY(bbs_module_reference) entry;
	char data[];
};

RWLIST_HEAD(module_refs, bbs_module_reference);

struct bbs_module {
	const struct bbs_module_info *info;
	/*! The shared lib. */
	void *lib;
	/*! Number of 'users' and other references currently holding the module. */
	int usecount;
	struct {
		/*! This module is awaiting a reload. */
		unsigned int reloadpending:1;
#if 0
		/* This wasn't being used, if we need it, we can bring it back */
		/*! Actively being unloaded. */
		unsigned int unloading:1;
#endif
#ifdef DLOPEN_ONLY_ONCE
		/*! Module has been unloaded. Useful if DLOPEN_ONLY_ONCE, since the module destructor doesn't run, we need to know we unloaded it */
		unsigned int unloaded:1;
#endif
	} flags;
	/*! Load order */
	int loadorder;
	/*! Load time */
	time_t loadtime;
	/* Module references */
	struct module_refs refs;
	/* Next entry */
	RWLIST_ENTRY(bbs_module) entry;
	/*! The name of the module. */
	char name[];
};

static RWLIST_HEAD_STATIC(modules, bbs_module);

struct autoload_module {
	RWDLLIST_ENTRY(autoload_module) entry;
	/* Plan for autoloading */
	unsigned int preload:1; /* Whether to preload module */
	unsigned int required:1; /* Required, normal load (unless preloaded also). Load failure will cause startup to abort. */
	unsigned int load:1; /* Load module? */
	unsigned int noload:1; /* Don't load? */
	/* Results */
	unsigned int attempted:1; /* Attempted to load? */
	unsigned int failed:1; /* Failed to load? */
	unsigned int loaded:1; /* Loaded successfully */
	char name[]; /* Module name */
};

static RWDLLIST_HEAD_STATIC(autoload_modules, autoload_module);

static int total_modules = 0; /* Total number of modules in module dir */

/*! \brief Autoload all modules by default */
#define DEFAULT_AUTOLOAD_SETTING 1

static int autoload_setting = DEFAULT_AUTOLOAD_SETTING;

static int really_register = 0;

/*! \brief Number of modules we plan to autoload */
static int autoload_planned = 0;

/*! \brief Number of modules successfully autoloaded */
static int autoload_loaded = 0;

/*!
 * \internal
 *
 * This variable is set by load_dynamic_module so bbs_module_register
 * can know what pointer is being registered.
 *
 * This is protected by the module list lock.
 */
static struct bbs_module * volatile resource_being_loaded;

static void free_module(struct bbs_module *mod)
{
	RWLIST_HEAD_DESTROY(&mod->refs);
	free(mod);
}

void bbs_module_register(const struct bbs_module_info *info)
{
	struct bbs_module *mod;

	mod = resource_being_loaded;
	if (unlikely(!mod)) {
		bbs_error("No module being loaded while registering %s?\n", info->name);
		return;
	}

	if (really_register) {
		bbs_verb(2, "Registering module %s\n", info->name);
	}

	/* This tells load_dynamic_module that we're registered. */
	resource_being_loaded = NULL;
	mod->info = info;

	/* Give the module a copy of its own handle, for later use in registrations and the like */
#pragma GCC diagnostic ignored "-Wcast-qual"
	*((struct bbs_module **) &(info->self)) = mod;
#pragma GCC diagnostic pop
	return;
}

void bbs_module_unregister(const struct bbs_module_info *info)
{
	char *curname;
	struct bbs_module *mod = NULL;
	size_t len = strlen(info->name);
	char buf[256]; /* Avoid using len + 4, for -Wstack-protector */

	if (!really_register) {
		return; /* If this is prior to really registering modules, then we never called start_resource, so it won't be in the list. */
	}

	buf[0] = '\0';
	if (len >= 3 && info->name[len - 3] != '.') {
		snprintf(buf, sizeof(buf), "%s.so", info->name);
	}

	RWLIST_TRAVERSE_SAFE_BEGIN(&modules, mod, entry) {
		curname = mod->name;
		if (!strcasecmp(curname, info->name) || (*buf && !strcasecmp(curname, buf))) {
			RWLIST_REMOVE_CURRENT(entry);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;

	if (mod) {
		bbs_verb(2, "Unregistering module %s\n", info->name);
		free_module(mod);
	} else {
#ifndef DLOPEN_ONLY_ONCE
		/* This happens with DLOPEN_ONLY_ONCE if we tried to load a module
		 * and the load_module callback returned nonzero.
		 * In that case, we unloaded the module and freed the module structure.
		 * However, since on these platforms, the module is still in memory,
		 * its destructor will run when the BBS exits, and it will call
		 * bbs_module_unregister. However, at this point, we don't have
		 * any record of this module ourself, so this warning isn't appropriate. */
		bbs_debug(1, "Unable to unregister module %s\n", info->name);
#endif
	}
}

static int log_module_ref(struct bbs_module *mod, int pair, void *refmod, const char *file, int line, const char *func, int diff)
{
	struct bbs_module_reference *r;

	/* refmod can't disappear while we're in this function since it called us.
	 * However, it could be NULL; it's only non-NULL for modules. */
	RWLIST_WRLOCK(&mod->refs);
	if (diff == 1) { /* Ref */
		size_t filelen = strlen(file);
		size_t fflen = filelen + strlen(func) + 2;

		r = calloc(1, sizeof(*r) + fflen);
		if (ALLOC_FAILURE(r)) {
			/* Allocation of the module reference structure failed.
			 * It's still being used regardless, so we won't decrement usecount in response. */
			RWLIST_UNLOCK(&mod->refs);
			return -1;
		}
		strcpy(r->data, file); /* Safe */
		r->file = r->data;
		strcpy(r->data + filelen + 1, func); /* Safe */
		r->func = r->data + filelen + 1;
		r->line = line;
		r->refmod = refmod;
		r->pair = pair;
		RWLIST_INSERT_HEAD(&mod->refs, r, entry); /* Head insert absolutely makes perfect sense */
	} else { /* Unref */
		RWLIST_TRAVERSE_SAFE_BEGIN(&mod->refs, r, entry) {
			if (r->pair == pair && !strcmp(r->file, file)) { /* Pair IDs are only unique within a source file */
				RWLIST_REMOVE_CURRENT(entry);
				free(r);
				break;
			}
		}
		RWLIST_TRAVERSE_SAFE_END;
		if (!r) { /* Should only happen legitimately if allocation failed during ref */
			bbs_error("Failed to find existing reference for %s with pair ID %d\n", mod->name, pair - 1);
			RWLIST_UNLOCK(&mod->refs);
			return -1;
		}
	}
	RWLIST_UNLOCK(&mod->refs);
	return 0;
}

struct bbs_module *__bbs_module_ref(struct bbs_module *mod, int pair, void *refmod, const char *file, int line, const char *func)
{
	bbs_atomic_fetchadd_int(&mod->usecount, +1);
	bbs_assert(mod->usecount > 0);
	log_module_ref(mod, pair, refmod, file, line, func, +1);
	return mod;
}

void __bbs_module_unref(struct bbs_module *mod, int pair, void *refmod, const char *file, int line, const char *func)
{
	int res;
	bbs_soft_assert(pair >= 0);
	res = log_module_ref(mod, pair, refmod, file, line, func, -1); /* Do this first, since module can't disappear while it has a positive refcount */
	if (pair <= 0) {
		/* Observed in one stack trace where the pair ID was 0.
		 * In this case, the assertion below failed, suggesting
		 * that that the refcount was never bumped for the module
		 * in the first place.
		 * Thus, this is likely to be invalid and we should just return.
		 * Worst that can happen is this was a false positive and
		 * now mod can never be unloaded while the BBS is running. */
		bbs_error("Not decrementing refcount of %s (pair ID: %d, decref %s)\n", bbs_module_name(mod), pair, res ? "failed" : "succeeded");
		return;
	}
	bbs_atomic_fetchadd_int(&mod->usecount, -1);
	bbs_assert(mod->usecount >= 0);

	/* If a reload was pending, reload the module now */
	if (mod->usecount == 0 && mod->flags.reloadpending) {
		/* No guarantees that we're not trying to reload the module that called us here,
		 * so have the main thread do it instead. */
		bbs_debug(3, "Requesting reload of module '%s', now that use count is 0\n", mod->name);
		bbs_request_module_unload(mod->name, 1);
	}
}

/*! \note modules list must be locked */
static struct bbs_module *find_resource(const char *resource)
{
	struct bbs_module *mod = NULL;
	size_t len = strlen(resource);
	char buf[256]; /* Avoid using len + 4, for -Wstack-protector */

	buf[0] = '\0';
	if (len >= 3 && resource[len - 3] != '.') {
		snprintf(buf, sizeof(buf), "%s.so", resource);
	}

	RWLIST_TRAVERSE(&modules, mod, entry) {
		char *curname = mod->name;
		if (!strcasecmp(curname, resource) || (*buf && !strcasecmp(curname, buf))) {
			break;
		}
	}

	return mod;
}

struct bbs_module *__bbs_require_module(const char *module, void *refmod)
{
	struct bbs_module *reffing_mod = refmod;
	struct bbs_module *mod = find_resource(module);
	if (mod) {
		bbs_debug(5, "Module dependency '%s' is satisfied (required by %s)\n", module, reffing_mod->name);
		__bbs_module_ref(mod, 1, refmod, __FILE__, __LINE__, __func__);
	} else {
		bbs_error("Module %s dependency is not satisfied (required by %s)\n", module, reffing_mod->name);
	}
	return mod;
}

void __bbs_unrequire_module(struct bbs_module *mod, void *refmod)
{
	__bbs_module_unref(mod, 1, refmod, __FILE__, __LINE__, __func__);
}

static int queue_reload(const char *resource)
{
	int res = -1;
	struct bbs_module *mod;

	RWLIST_RDLOCK(&modules);
	mod = find_resource(resource);
	if (mod) {
		res = 0;
		mod->flags.reloadpending = 1;
	}
	RWLIST_UNLOCK(&modules);
	return res;
}

/*! \brief dlclose(), with failure logging. */
static int logged_dlclose(const char *name, void *lib)
{
	if (!lib) {
		bbs_debug(5, "No lib passed, skipping dlclose for %s\n", name);
		return -1;
	}
	dlerror(); /* Clear any existing error */
	if (really_register) {
		bbs_debug(5, "dlclose: %s\n", name);
	}
	if (dlclose(lib)) {
		char *error = dlerror();
		bbs_error("Failure in dlclose for module '%s': %s\n", name ? name : "unknown", error ? error : "Unknown error");
		return -1;
	}
	return 0;
}

/*!
 * \internal
 * \brief Attempt to dlopen a module.
 *
 * \param resource_in The module name to load.
 * \param so_ext ".so" or blank if ".so" is already part of resource_in.
 * \param filename Passed directly to dlopen.
 * \param flags Passed directly to dlopen.
 * \param suppress_logging Do not log any error from dlopen.
 *
 * \return Pointer to opened module, NULL on error.
 *
 * \warning module_list must be locked before calling this function.
 */
static struct bbs_module *load_dlopen(const char *resource_in, const char *so_ext, const char *filename, int flags, unsigned int suppress_logging)
{
	struct bbs_module *mod;
	size_t bytes;

	bbs_assert(!resource_being_loaded);

	bytes = sizeof(*mod) + strlen(resource_in) + strlen(so_ext) + 1; /* + just enough for resource name + null term. */

	mod = calloc(1, bytes);
	if (ALLOC_FAILURE(mod)) {
		return NULL;
	}

	bbs_assert_exists(mod->name);
	snprintf(mod->name, bytes, "%s%s", resource_in, so_ext); /* safe */

	RWLIST_HEAD_INIT(&mod->refs);

	resource_being_loaded = mod;
	mod->lib = dlopen(filename, flags);

	if (resource_being_loaded) {
		const char *dlerror_msg = S_IF(dlerror());

		/* Module didn't register itself during load, failure! */

		resource_being_loaded = NULL;
		if (mod->lib) {
			if (!suppress_logging) {
				bbs_error("Module '%s' did not register itself during load\n", resource_in);
			}
			logged_dlclose(resource_in, mod->lib);
		} else if (!suppress_logging) {
			bbs_error("Error %sloading module '%s': %s\n", flags & RTLD_LAZY ? "lazy " : "", resource_in, dlerror_msg);
		}

		free_module(mod);
		return NULL;
	}

	return mod;
}

static struct autoload_module *find_autoload_module(const char *module)
{
	struct autoload_module *a;
	RWDLLIST_TRAVERSE(&autoload_modules, a, entry) {
		if (!strcmp(a->name, module)) {
			return a;
		}
	}
	return NULL;
}

/* Forward declaration */
static int load_resource(struct autoload_module *a, const char *restrict resource_name, unsigned int suppress_logging);

/*! \note a can be NULL */
static struct bbs_module *load_dynamic_module(struct autoload_module *a, const char *resource_in, unsigned int suppress_logging)
{
	char fn[PATH_MAX];
	size_t resource_in_len = strlen(resource_in);
	const char *so_ext = "";
	struct bbs_module *mod;
	int retry;

	if (resource_in_len < 4 || strcasecmp(resource_in + resource_in_len - 3, ".so")) {
		so_ext = ".so";
	}

	snprintf(fn, sizeof(fn), "%s/%s%s", BBS_MODULE_DIR, resource_in, so_ext);

	/* If we're going to try loading dependencies and then call load_dlopen again,
	 * any warnings can be ignored the first time, since they were probably due
	 * to missing symbols (and if not, we'll try again anyways, and log that time). */
	retry = a && a->preload;
	retry = 1; /* Actually we need to always retry... not sure why we wouldn't? */

#ifdef DLOPEN_ONLY_ONCE
	/* If we only have one shot, we have no choice but to make everything global... yuck */
	mod = load_dlopen(resource_in, so_ext, fn, RTLD_NOW | RTLD_GLOBAL, suppress_logging || retry);
	if (!mod) {
		/* Can't resolve dependencies automatically, since that would involve another load_dlopen with RTLD_LAZY, and then yet another one with RTLD_NOW again */
		bbs_error("Module %s has dependencies that cannot be autoloaded on this platform. Mark it for preload in modules.conf and try again.\n", resource_in);
	}
#else
	mod = load_dlopen(resource_in, so_ext, fn, RTLD_NOW | RTLD_LOCAL, suppress_logging || retry);
	if (!mod) {
		/* XXX. Here, we consider the case of modules that are both depended on by other modules
		 * and themselves depend on yet other modules.
		 * In other words, they both export symbols globally, and they also require the symbols of other modules.
		 * This means that among the modules to preload, order will matter,
		 * because if C depends on B and B depends on A, then B and A will both be marked for preload,
		 * but A *MUST* be loaded before B, or B will fail to load (cascading to C, etc.)
		 *
		 * In the case of autoload, we already ordered the modules with dependencies taken into account,
		 * so the branch below to preload on the fly should never be taken in that case,
		 * only for modules loaded after the BBS is fully started.
		 *
		 * In the meantime, if we're NOT autoloading modules, and a load fails, it's probably because symbols
		 * failed to resolve, and probably due to unresolved dependencies. Try to resolve those on the fly, for now.
		 *
		 * XXX This is no longer safe from accidental infinte recursion. We will crash (stack overflow) if there is a dependency loop here.
		 * If we have a better way of handling this in the future, this hack can be removed:
		 */
		if (retry) {
			/* At this point, we'll have to do a lazy open again. If that fails, then really give up. */
			mod = load_dlopen(resource_in, so_ext, fn, RTLD_LAZY | RTLD_LOCAL, suppress_logging);
			if (mod && mod->info->dependencies) {
				int res = 0;
				char dependencies_buf[256];
				char *dependency, *dependencies = dependencies_buf;
				safe_strncpy(dependencies_buf, mod->info->dependencies, sizeof(dependencies_buf));
				logged_dlclose(resource_in, mod->lib);
				free_module(mod);
				while ((dependency = strsep(&dependencies, ","))) {
					if (!find_resource(dependency)) { /* It's not loaded already. */
						int mres;
						struct autoload_module *d = NULL;
						if (a) {
							/* If we're autoloading, need to pass the dependency's autoload object,
							 * not that of the module dependent on it. */
							d = find_autoload_module(dependency);
							/* If !d, load_resource will fail, but we'll let it handle it there */
							if (d && d->failed) {
								/* We already tried loading the dependency earlier in the autoload sequence, and it failed.
								 * No point in trying to load it again now. */
								bbs_error("Module %s is dependent on %s, which failed to load\n", a->name, d->name);
								res = -1;
								break;
							}
						}
						bbs_debug(1, "Preloading %s on the fly since it's required by %s\n", dependency, resource_in);
						/* Since we automatically reorder modules with dependencies for autoload,
						 * the only time this logic should be hit is while the BBS is already running.
						 * We shouldn't need to have to preload something on the fly during autoload,
						 * breaking from the presorted module ordering. */
						bbs_soft_assert(a == NULL);
						mres = load_resource(d, dependency, suppress_logging);
						/* Since dependency will have loaded bit set now, we won't try to load it another time in the future. */
						if (!mres) {
							autoload_loaded++;
						}
						res |= mres;
					}
				}
				/* Try again for real. */
				if (!res) {
					/* Try again, now that dependencies are loaded (and possibly recursively) */
					mod = load_dlopen(resource_in, so_ext, fn, RTLD_NOW | RTLD_LOCAL, suppress_logging);
				} else {
					mod = NULL;
				}
			}
		}
	}
	if (mod && mod->info->flags & MODFLAG_GLOBAL_SYMBOLS) {
		/* Close the module so we can reopen with correct flags. */
		bbs_debug(3, "Module '%s' contains global symbols, reopening\n", resource_in);
		really_register = 0;
		logged_dlclose(resource_in, mod->lib);
		free_module(mod);
		/* At this point, we've already loaded any dependencies needed, so we're only going to load a single module,
		 * hence we can safely defer re-enabling really_register until after load_dlopen.
		 * This suppresses log messages for dlclose and registering module when we reopen it. */
		mod = load_dlopen(resource_in, so_ext, fn, RTLD_NOW | RTLD_GLOBAL, 0);
		really_register = 1;
	}
#endif /* DLOPEN_ONLY_ONCE */
	return mod;
}

#define SHOULD_LOAD_MODULE(m) (!m->noload && (autoload_setting || m->load || m->preload || m->required))

#ifndef DLOPEN_ONLY_ONCE
static struct autoload_module *find_first_autoload_in_list(struct autoload_module *a, struct autoload_module *b)
{
	struct autoload_module *first = a;

	/* We assume a != b. Even if it is, it doesn't matter which one we return anyways. */
	while ((first = RWDLLIST_NEXT(first, entry))) {
		if (first == b) {
			/* By following next pointers from a, we got to b, so a is first */
			return a;
		}
	}

	return b;
}

static void check_dependencies(struct autoload_module *a)
{
	char fn[PATH_MAX];
	size_t resource_in_len = strlen(a->name);
	const char *so_ext = "";
	struct bbs_module *mod;

	if (resource_in_len < 4 || strcasecmp(a->name + resource_in_len - 3, ".so")) {
		so_ext = ".so";
	}

	snprintf(fn, sizeof(fn), "%s/%s%s", BBS_MODULE_DIR, a->name, so_ext);

	/* Lazy load won't perform symbol resolution, so we can successfully load a module that is missing dependencies */
	mod = load_dlopen(a->name, so_ext, fn, RTLD_LAZY | RTLD_LOCAL, 0);
	if (!mod) {
		bbs_error("Failed to check dependencies for %s\n", a->name);
		return;
	}

	if (autoload_setting && mod->info->flags & MODFLAG_ALWAYS_PRELOAD) {
		/* The module wants to be loaded as early as possible during startup,
		 * so load it first.
		 * Do this first, since then we can avoid checking if it has any dependents.
		 *
		 * To be clear, here we are not concerned with dependency chains,
		 * that is handled without MODFLAG_ALWAYS_PRELOAD. The purpose of this flag
		 * is to explicitly move a module to the very front of the load order.
		 * An example of this is io_tls. No module has a direct dependency on this module,
		 * but ssl_available() will return 1 only after io_tls has loaded.
		 * Therefore, it should load before other modules, even though it is not "strictly"
		 * a dependency (it's not *required* for anything to load),
		 * it still needs to be loaded early for the desired behavior.
		 *
		 * XXX This is not foolproof; ideally, we would have store a "load priority"
		 * for all modules, and ensure that the priority of this module
		 * is before anything that might try to use it (or behave differently if not loaded). */
		bbs_debug(4, "Module %s requested to be preloaded\n", a->name);
		a->preload = 1;
		/* Move to beginning of list */
		RWDLLIST_REMOVE(&autoload_modules, a, entry);
		RWDLLIST_INSERT_HEAD(&autoload_modules, a, entry);
	} else if (!strlen_zero(mod->info->dependencies)) {
		char dependencies_buf[256];
		char *dependencies, *dependency;
		safe_strncpy(dependencies_buf, mod->info->dependencies, sizeof(dependencies_buf));
		dependencies = dependencies_buf;
		while ((dependency = strsep(&dependencies, ","))) {
			struct autoload_module *first, *d = find_autoload_module(dependency);
			if (!d) {
				bbs_warning("Module %s has a dependency on unknown module %s\n", a->name, dependency);
				a->noload = 1;
			} else if (d->noload) {
				/* The module might try to load later (if autoload or explicitly loaded),
				 * but if it's dependent on a module that's noloaded, it WILL fail anyways, so just also noload it now. */
				bbs_error("Module %s depends on noloaded module %s\n", a->name, dependency);
				a->noload = 1;
			} else if (SHOULD_LOAD_MODULE(a)) {
				bbs_debug(4, "Marking %s for loading since %s depends on it\n", dependency, a->name);
				/* Just mark for regular load, not preload. Preload should be reserved for exceptional cases
				 * where a module really needs to load first (or close to it).
				 * In this case, we just want to move it up earlier in the load sequence,
				 * i.e. move d before a. Setting preload or load doesn't do that, it's the
				 * remove/insert before operation below that does that. */
				d->load = 1;
				/* Also adjust the ordering such that the dependency precedes the thing that depends on it */
				first = find_first_autoload_in_list(a, d);
				/* If d is first, that's what we want, since it needs to load first.
				 * If a is first, we need to swap the two to correct the ordering.
				 * Since we only do this when we encounter a dependency, it's
				 * sort of like an efficient subset of bubble sort. */
				if (a == first) {
					/* Since d comes later in the list, we want to remove it from wherever it is now,
					 * and reinsert it just before a. But that requires a doubly linked list.
					 * An alternative is to instead remove a and insert it after d,
					 * which changes the ordering respective to these 2 elements (only) properly.
					 * However, it doesn't preserve other desired invariants. Consider this scenario:
					 *
					 *
					 * Initial relative ordering: C ... B ... A1 ... A2 (other elements are inbetween)
					 * C depends on B, B depends on both A1 and A2
					 *
					 * If we make a pass and swap elements such that the
					 * one that is too early is moved after its dependency,
					 * e.g. move C after B, B after A1, B after A2, we end up:
					 *
					 * C ... B ... A1 ... A2
					 * B ... C ... A1 ... A2
					 * C ... A1 ... B ... A2
					 * C ... A1 ... A2 ... B
					 *
					 * B is ordered after everything it depends on, so B's ordering is okay.
					 * However, C should be ordered after B, and now it's not.
					 *
					 * If we do the related operation of moving something that is a dependency
					 * before its dependents, that solves this issue:
					 *
					 * C ... B ... A1 ... A2
					 * B ... C ... A1 ... A2
					 * A1 ... B ... C ... A2
					 * A2 ... A1 ... B ... C
					 *
					 *
					 * So, we have to use a doubly linked list, since we need to access
					 * the element BEFORE a, so we can insert d before it.
					 *
					 * TL;DR Inserting a after d is not correct.
					 * We need to insert d before a instead. */
#ifdef DEBUG_LOAD_ORDER
					bbs_debug(7, "  -- Moved %s after %s in load order\n", a->name, d->name);
#endif
					RWDLLIST_REMOVE(&autoload_modules, d, entry);
					RWDLLIST_INSERT_BEFORE(&autoload_modules, a, d, entry);
				}
			}
		}
	}

	logged_dlclose(a->name, mod->lib);
	free_module(mod);
	return;
}
#endif /* DLOPEN_ONLY_ONCE */

const char *bbs_module_name(const struct bbs_module *mod)
{
	if (!mod || !mod->info) {
		return NULL;
	}

	return mod->info->name;
}

/*!
 * \brief Check to see if the given resource is loaded.
 *
 * \param resource_name Name of the resource, including .so suffix.
 * \return False (0) if module is not loaded.
 * \return True (non-zero) if module is loaded.
 */
static int is_module_loaded(const char *resource_name)
{
	char fn[PATH_MAX] = "";
	void *lib;

	snprintf(fn, sizeof(fn), "%s/%s", BBS_MODULE_DIR, resource_name);
	lib = dlopen(fn, RTLD_LAZY | RTLD_NOLOAD);

	if (lib) {
		logged_dlclose(resource_name, lib);
		return 1;
	}

	return 0;
}

static void unload_dynamic_module(struct bbs_module *mod)
{
	char name[256]; /* Avoid strdupa for gcc -Wstack-protector */
	void *lib = mod->lib;

	safe_strncpy(name, bbs_module_name(mod), sizeof(name)); /* Save a copy of the module name */

	/* WARNING: the structure pointed to by mod is going to
	 * disappear when this operation succeeds, so we can't
	 * dereference it */
	if (logged_dlclose(bbs_module_name(mod), lib)) {
		if (is_module_loaded(name)) {
			bbs_error("Module '%s' failed to unload\n", name);
		} else {
			bbs_error("Module '%s' failed to unload, but it's not currently loaded?\n", name);
		}
		return;
	}

	/* There are several situations where the module might still be resident
	 * in memory.
	 *
	 * If somehow there was another dlopen() on the same module (unlikely,
	 * since that all is supposed to happen in module.c).
	 *
	 * Avoid the temptation of repeating the dlclose(). The other code that
	 * dlopened the module still has its module reference, and should close
	 * it itself. In other situations, dlclose() will happily return success
	 * for as many times as you wish to call it.
	 */
	if (is_module_loaded(name)) {
		bbs_error("Module '%s' could not be completely unloaded\n", name);
	}
#ifndef DLOPEN_ONLY_ONCE
	/* If it's actually unloaded from memory but somehow still registered,
	 * then something is wrong as that means dlclose didn't trigger
	 * the module's destructor to run. */
	if (find_resource(name)) {
		bbs_error("Module '%s' unloaded but still registered?\n", name);
	}
#endif
}

static int loadindex = 0;

/*! \note modules list must be locked */
static int start_resource(struct bbs_module *mod)
{
	int res;

	if (unlikely(!mod->info->load)) {
		bbs_error("Module %s contains no load function?\n", mod->name);
		return -1;
	}

	res = mod->info->load();
	if (res) {
		return res;
	}

	mod->loadorder = ++loadindex; /* This is atomic since list is locked. This is strictly increasing, not decremented when a module unloads. */

	/* Insert alphabetically */
	RWLIST_INSERT_SORTALPHA(&modules, mod, entry, name);
	return 0;
}

/*!
 * \brief loads a resource based upon resource_name.
 * \note a can be NULL
 */
static int load_resource(struct autoload_module *a, const char *restrict resource_name, unsigned int suppress_logging)
{
	int res;
	struct bbs_module *mod;

	if ((mod = find_resource(resource_name))) {
		bbs_warning("Module '%s' already loaded and running.\n", resource_name);
		return -1;
	}

	if (a) {
		a->attempted = 1;
	}
	mod = load_dynamic_module(a, resource_name, suppress_logging);
	if (!mod) {
		if (a) {
			a->failed = 1;
		}
		bbs_error("Failed to load module %s\n", resource_name);
		return -1;
	}

	res = start_resource(mod);

	if (res) {
		/* If success, log in start_resource, otherwise, log here */
		bbs_error("Module '%s' could not be loaded.\n", resource_name);
		if (a) {
			a->failed = 1;
		}
		/* If start_resource returned failure, that means
		 * the module was not inserted into the modules list.
		 * Therefore, we set really_register false temporarily,
		 * to ensure bbs_module_unregister doesn't try to remove it from the list,
		 * since it's not there. */
		really_register = 0;
		unload_dynamic_module(mod);
		really_register = 1;
		free_module(mod); /* bbs_module_unregister isn't called if the module declined to load, so free to avoid a leak */
		return -1;
	} else {
		/* Bump the ref count of any modules upon which we depend. */
		if (a) {
			a->loaded = 1;
		}
		if (!strlen_zero(mod->info->dependencies)) {
			char dependencies_buf[256];
			char *dependencies, *dependency;
			safe_strncpy(dependencies_buf, mod->info->dependencies, sizeof(dependencies_buf));
			dependencies = dependencies_buf;
			while ((dependency = strsep(&dependencies, ","))) {
				__bbs_require_module(dependency, mod);
			}
		}
	}
	return res;
}

/* Forward declaration */
static struct bbs_module *unload_resource_nolock(struct bbs_module *mod, int force, int *usecount, struct stringlist *removed);

struct bbs_module_ref {
	struct bbs_module *m;
	const char *name;
	RWLIST_ENTRY(bbs_module_ref) entry;
	char data[0];
};

RWLIST_HEAD(module_list, bbs_module_ref);

/*! \note modules list must be locked when calling */
static int unload_dependencies(struct bbs_module *mod, int force, struct stringlist *restrict removed)
{
	struct bbs_module *m;
	int res = 0;
	struct module_list list;
	struct bbs_module_ref *r;

	/* Make a list of modules to unload upfront */
	RWLIST_HEAD_INIT(&list);

	/* I thought about perhaps checking how many dependencies exist,
	 * and only going ahead with unloading them if the number of dependencies
	 * is equal to the use count (the logic being, if the use count is greater
	 * than the number of dependencies, than even if we unload all the dependencies,
	 * other stuff will still be using the module (e.g. nodes, etc.) and then parent
	 * unload operation will fail anyways, so why bother unloading other stuff
	 * and then potentially leaving the system in an undesirable state if we meant
	 * to reload rather than merely unload?
	 *
	 * But, ideally we should be able to boot nodes from a module if we really
	 * want to unload it, and I'm not sure at this time if adding the logic
	 * described above would be good or bad. */

	/* One reason we require each module's dependency strings to contain the full module name
	 * (i.e. including the .so extension), is so that we can just make direct comparisons
	 * with the module names as they exist in the list. No need to build the full name
	 * in a buffer each time. */

	RWLIST_TRAVERSE(&modules, m, entry) {
		if (mod == m) {
			continue; /* Skip ourself, we're already working on it... (and if it happened to specify itself, for whatever reason, that would result in infinite recursion) */
		}
		if (strlen_zero(m->info->dependencies)) {
			continue; /* Module doesn't have any dependencies, let alone on the relevant module. */
		}
		/* Because all module names end in .so, this (correctly) won't erroneously
		 * include module names that are otherwise prefixes of another module. */
		if (!strstr(m->info->dependencies, mod->name)) {
			continue;
		}
		bbs_debug(6, "Adding %s to unload list, since it depends on %s\n", m->name, mod->name);
		r = calloc(1, sizeof(*r) + strlen(m->name) + 1);
		if (ALLOC_FAILURE(r)) {
			/* If we can't unload a dependency, this is all going to fail */
			RWLIST_REMOVE_ALL(&list, entry, free);
			return -1;
		}
		strcpy(r->data, m->name); /* Safe */
		r->name = r->data;
		r->m = m;
		RWLIST_INSERT_HEAD(&list, r, entry);
	}

	while ((r = RWLIST_REMOVE_HEAD(&list, entry))) {
		int usecount;
		/* The module MAY have already been unloaded, in which case m is no longer valid memory.
		 * Check to see if it's in the list. */
		if (removed && stringlist_contains_locked(removed, r->name)) {
			free(r);
			continue;
		}
		/* m is still valid memory since module has not been unloaded */
		m = r->m;
		free(r);
		bbs_verb(5, "Unloading %s, since it depends on %s\n", m->name, mod->name);
		if (!unload_resource_nolock(m, force, &usecount, removed)) {
			res = -1;
			bbs_warning("Failed to unload module %s, which depends on %s\n", m->name, mod->name);
			continue;
		}
		/* Keep track of any modules that were removed. */
		if (removed) {
			stringlist_push(removed, m->name);
		}
		/* Actually unload the dependent. */
		unload_dynamic_module(m);
	}

	RWLIST_HEAD_DESTROY(&list);
	return res;
}

static void dec_refcounts(struct bbs_module *mod)
{
	/* Decrement the ref count of any modules upon which we depend. */
	if (!strlen_zero(mod->info->dependencies)) {
		char dependencies_buf[256];
		char *dependencies, *dependency;
		safe_strncpy(dependencies_buf, mod->info->dependencies, sizeof(dependencies_buf));
		dependencies = dependencies_buf;
		while ((dependency = strsep(&dependencies, ","))) {
			struct bbs_module *m = find_resource(dependency);
			bbs_debug(9, "%s no longer depends on module %s\n", bbs_module_name(mod), dependency);
			if (m) {
				__bbs_unrequire_module(m, mod);
			} else {
				bbs_error("Dependency %s not currently loaded?\n", dependency);
			}
		}
	}
}

int __bbs_module_is_unloading(struct bbs_module *mod)
{
	bbs_assert_exists(mod);
	return mod->flags.reloadpending;
}

int __bbs_module_is_shutting_down(struct bbs_module *mod)
{
	bbs_assert_exists(mod);
	return mod->flags.reloadpending || bbs_is_shutting_down();
}

time_t __bbs_module_load_time(struct bbs_module *mod)
{
	bbs_assert_exists(mod);
	return mod->loadtime;
}

static inline int __unload_module(struct bbs_module *mod)
{
	int res;
	mod->flags.reloadpending = 1;
	res = mod->info->unload();
	mod->flags.reloadpending = 0;
	return res;
}

static struct bbs_module *unload_resource_nolock(struct bbs_module *mod, int force, int *usecount, struct stringlist *restrict removed)
{
	int res;

	bbs_debug(2, "Module %s has use count %d (force: %d)\n", mod->name, mod->usecount, force);
	*usecount = mod->usecount;

	/* Automatically unload any other modules that may depend on this module. */
	if (mod->usecount) {
		if (force) {
			unsigned int nodes_usecount = bbs_node_mod_count(mod);
			/* Kick any nodes that were registered using this module, or otherwise unload will fail.
			 * This increases the chances that an unload operation actually succeeds while it's in use.
			 * Note that this only applies to network modules (e.g. modules in the nets directory).
			 * If a node is executing a door, for example, that won't apply: the module will have
			 * a refcount due to the usage, but we won't be able to kick the node in this manner here. */
			if (nodes_usecount > 0) {
				unsigned int removed_nodes = bbs_node_shutdown_mod(mod); /* Kick all the nodes created by this module. */
				if (removed_nodes != nodes_usecount) {
					bbs_warning("Wanted to kick %u nodes but only removed %u?\n", nodes_usecount, removed_nodes);
				} else if (removed_nodes) {
					usleep(10000); /* Wait for actual node exits to complete, to increase chance of success */
					bbs_debug(3, "Removed %d node%s from module %s\n", removed_nodes, ESS(removed_nodes), bbs_module_name(mod));
				}
			}
		}
		unload_dependencies(mod, force, removed);
	}

	if (mod->usecount > 0) {
		if (force > 1) {
			bbs_warning("Warning: Forcing removal of module '%s' with use count %d\n", mod->name, mod->usecount);
		} else {
			if (RWLIST_EMPTY(&mod->refs)) {
				/* The integer count is positive, but our list is empty?
				 * Critical lack of synchronization! (Probably a bug) */
				bbs_error("Module '%s' supposedly has use count %d, but refcount list is empty?\n", mod->name, mod->usecount);
			}
			bbs_warning("Soft unload failed, '%s' has use count %d\n", mod->name, mod->usecount);
			return NULL;
		}
	}

	bbs_debug(1, "Unloading %s\n", mod->name);
	res = __unload_module(mod);
	if (res) {
		bbs_warning("Firm unload failed for %s\n", mod->name);
		if (force <= 2) {
			return NULL;
		} else {
			bbs_warning("** Dangerous **: Unloading resource anyway, at user request\n");
		}
	} else {
		/* Decrement the ref count of any modules upon which we depend. */
		if (!strlen_zero(mod->info->dependencies)) {
			dec_refcounts(mod);
		}
	}

	return mod;
}

static int unload_resource(const char *resource_name, int force, struct stringlist *restrict removed)
{
	struct bbs_module *mod;
	int usecount = 0;

	RWLIST_WRLOCK(&modules);
	if (!(mod = find_resource(resource_name))) {
		bbs_warning("Unload failed, '%s' could not be found\n", resource_name);
		RWLIST_UNLOCK(&modules);
		return -1;
	}
	mod = unload_resource_nolock(mod, force, &usecount, removed);
	RWLIST_UNLOCK(&modules);

	if (!mod) {
		return usecount;
	}

	unload_dynamic_module(mod);
	return 0;
}

static int on_module(const char *dir_name, const char *filename, void *obj)
{
	struct autoload_module *a;

	UNUSED(dir_name);
	UNUSED(obj);

#ifdef EXTRA_DEBUG
	bbs_debug(7, "Detected dynamic module %s\n", filename);
#endif
	a = calloc(1, sizeof(*a) + strlen(filename) + 1);
	if (ALLOC_FAILURE(a)) {
		return -1;
	}

	strcpy(a->name, filename); /* Safe */
	RWDLLIST_INSERT_HEAD(&autoload_modules, a, entry);
	total_modules++;
	return 0;
}

static int do_autoload_module(struct autoload_module *a)
{
	struct bbs_module *mod;
	const char *filename = a->name;

	if (a->loaded) {
		/* Module already loaded, don't load it again. */
		bbs_debug(5, "Module %s already loaded\n", a->name);
		return 0;
	}
	if (a->failed) {
		bbs_debug(5, "Failed to load %s earlier, skipping\n", a->name);
		return 0;
	}
	if (a->noload) {
		if (a->preload) {
			bbs_warning("Conflicting directives 'noload' and 'preload' for %s, not preloading\n", filename);
		}
		autoload_planned--;
		return 0;
	}

	mod = find_resource(a->name);
	if (mod) {
		bbs_warning("Module %s is already loaded?\n", a->name);
		return 0;
	}

	if (!autoload_setting) {
		if (!(a->required || a->preload || a->load)) {
#ifdef EXTRA_DEBUG
			bbs_debug(5, "Not loading dynamic module %s, not explicitly loaded and autoload=no\n", filename);
#endif
			autoload_planned--;
			return 0;
		}
		bbs_debug(5, "Autoloading dynamic module %s, since explicitly %s\n", filename, a->required ? "required" : "loaded");
	} else {
		bbs_debug(5, "Autoloading dynamic module %s (autoload=yes)\n", filename);
	}

	if (load_resource(a, filename, 0)) {
		/* load_resource already logs an error on failure, no need to logic individual module load failure here */
		if (a->required) {
			bbs_error("Aborting startup due to failing to load required module %s\n", filename);
			return 1;
		}
	} else {
		autoload_loaded++;
	}

	return bbs_abort_startup() ? 1 : 0; /* Always return 0 or otherwise we'd abort the entire autoloading process */
}

static int load_config(void)
{
	/* modules.conf is only used on startup. */
	struct bbs_config_section *section = NULL;
	struct bbs_keyval *keyval = NULL;
	struct bbs_config *cfg = bbs_config_load("modules.conf", 0);

	if (!cfg) {
		return 0;
	}

	bbs_config_val_set_true(cfg, "general", "autoload", &autoload_setting);

	while ((section = bbs_config_walk(cfg, section))) {
		if (!strcmp(bbs_config_section_name(section), "general")) {
			continue; /* Skip general, already handled */
		} else if (strcmp(bbs_config_section_name(section), "modules")) {
			bbs_warning("Unknown section name '%s', skipping\n", bbs_config_section_name(section));
			continue;
		}
		/* [modules] section */
		while ((keyval = bbs_config_section_walk(section, keyval))) {
			struct autoload_module *a;
			const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
			a = find_autoload_module(value);
			if (!a) {
				/* Couldn't find the module... */
				bbs_warning("Unknown module name '%s' with directive '%s'\n", value, key);
				continue;
			}
			if (!strcmp(key, "load")) {
				bbs_debug(7, "Explicitly planning to load '%s'\n", value);
				a->load = 1;
			} else if (!strcmp(key, "noload")) {
				bbs_debug(7, "Explicitly planning to not load '%s'\n", value);
				a->noload = 1;
			} else if (!strcmp(key, "preload")) {
				bbs_debug(7, "Explicitly planning to preload '%s'\n", value);
				a->preload = 1;
				/* For now, just move to the beginning of the list.
				 * This way, all preloads are before all the non-preloads. */
				RWDLLIST_REMOVE(&autoload_modules, a, entry);
				RWDLLIST_INSERT_HEAD(&autoload_modules, a, entry);
			} else if (!strcmp(key, "require")) {
				bbs_debug(7, "Explicitly planning to require '%s'\n", value);
				a->required = 1;
			} else {
				bbs_warning("Invalid directive %s=%s, ignoring\n", key, value);
			}
		}
	}
	bbs_config_free(cfg); /* Destroy the config now, rather than waiting until shutdown, since it will NEVER be used again for anything. */
	return 0;
}

static int try_autoload_modules(void)
{
	struct autoload_module *a, **alist;
	int c = 0;
	int abort = 0;
	int res = -1;

	bbs_debug(1, "Autoloading modules\n");

	RWDLLIST_WRLOCK(&autoload_modules);
	bbs_dir_traverse(BBS_MODULE_DIR, on_module, NULL, -1); /* Initialize autoload_modules with an object for each module in the modules directory */

	/* Now, check config for settings */
	if (load_config()) {
		goto cleanup;
	}

	/* Now, initialize the objects themselves by lazy loading each module. This will also partially sort the list.
	 * Since we need to be able to swap elements in the list during traversal, but the actual order of the traversal doesn't matter,
	 * allocate a temporary array for traversing all the elements. Even RWLIST_TRAVERSE_SAFE_BEGIN doesn't help here. */
	alist = malloc((size_t) total_modules * sizeof(*a));
	if (ALLOC_FAILURE(alist)) {
		goto cleanup;
	}
	RWDLLIST_TRAVERSE(&autoload_modules, a, entry) {
		alist[c++] = a;
	}
#ifdef DLOPEN_ONLY_ONCE
	bbs_debug(1, "Skipping module dependency checks\n");
#else
	for (c = 0; c < total_modules; c++) {
		if (SHOULD_LOAD_MODULE(alist[c])) {
			check_dependencies(alist[c]); /* Check if we need to load any dependencies for this module. */
		}
	}
#endif
	free(alist);

	/* Okay, we made a plan for what we're going to do, now execute it. */
	autoload_planned = total_modules;
	bbs_debug(1, "Detected %d dynamic module%s\n", autoload_planned, ESS(autoload_planned));
	really_register = 1;

	/* Now, actually try to load them. */
#ifdef DEBUG_LOAD_ORDER
	c = 0;
	RWDLLIST_TRAVERSE(&autoload_modules, a, entry) {
		if (autoload_setting) {
			bbs_debug(3, "Load order %d/%d: %s\n", ++c, total_modules, a->name);
		} else {
			bbs_debug(3, "Load order %d/%d: %s%s\n", ++c, total_modules, a->name, a->noload ? "" : a->preload ? "\t\t(PRELOAD)" : a->required ? "\t\t(REQUIRE)" : a->load ? "\t\t(LOAD)" : "");
		}
	}
#endif
	RWDLLIST_TRAVERSE(&autoload_modules, a, entry) {
		/* If a required module fails to load, we will stop loading modules thenceforth.
		 * However, when autoload=no, in order to ensure that autoload_planned is correct,
		 * we want to finish the traversal and continue decrementing based on module properties. */
		if (abort) {
			/* abort is only true if !autoload_modules (autoload=no), so it wouldn't be loaded
			 * unless it's explicitly going to be loaded. */
			if (!SHOULD_LOAD_MODULE(a)) {
				autoload_planned--;
			}
		} else if (do_autoload_module(a)) {
			if (!autoload_setting) {
				abort = 1;
			} else {
				/* We still abort, but we do it immediately by breaking, so no need to set the flag */
				break;
			}
		}
	}

	if (autoload_planned != autoload_loaded) {
		/* Some modules failed to autoload */
		bbs_warning("Planned to autoload %d module%s, but only loaded %d\n", autoload_planned, ESS(autoload_planned), autoload_loaded);
	} else {
		bbs_debug(1, "Successfully autoloaded %d module%s\n", autoload_planned, ESS(autoload_planned));
	}

	res = 0;
	/* Do a final pass to see if we're good to go. */
	RWDLLIST_TRAVERSE(&autoload_modules, a, entry) {
		if (!a->loaded) {
			/* Enumerate any modules which failed to load before we abort, so it's all in one place. */
			if (a->required) {
				bbs_error("Required module '%s' failed to load\n", a->name);
				res = -1;
			} else if (!a->noload && !a->loaded && a->attempted && (a->load || autoload_setting)) {
				/* For all other modules that failed to load:
				 * - Ignore if noload
				 * - Ignore if we never attempted to load it because we aborted due to a required module failing to load
				 * - Ignore if autoload=no, and don't have a load=yes */
				bbs_warning("Module '%s' failed to load\n", a->name);
			}
		}
	}

cleanup:
	RWDLLIST_REMOVE_ALL(&autoload_modules, entry, free);
	RWDLLIST_UNLOCK(&autoload_modules);
	return res;
}

int bbs_module_load(const char *name)
{
	int res;
	RWLIST_WRLOCK(&modules);
	res = load_resource(NULL, name, 0);
	RWLIST_UNLOCK(&modules);
	return res;
}

int bbs_module_unload(const char *name)
{
	int res;

#ifdef DLOPEN_ONLY_ONCE
	if (!bbs_is_shutting_down()) {
		bbs_error("This platform does not support hot-swapping modules during runtime. Modules can only be unloaded at shutdown.\n");
		return -1;
	}
#endif

	res = unload_resource(name, 0, NULL);
	return res ? -1 : 0;
}

int bbs_module_reload(const char *name, int try_delayed)
{
	struct stringlist unloaded;
	int res;

#ifdef DLOPEN_ONLY_ONCE
	bbs_error("This platform does not support hot-swapping modules during runtime. BBS must be restarted for new module to take effect.\n");
	return -1;
#endif

	stringlist_init(&unloaded);

	/* On a reload, also kick any nodes registered by this module, if the reload isn't delayed.
	 * XXX Maybe this should be a separate sysop command? Could be confusing that reload will
	 * autokick nodes created by the module, whereas unload won't try to do that and will fail immediately. */
	res = unload_resource(name, !try_delayed, &unloaded);
	if (!res) {
		res = bbs_module_load(name);
		if (!res) {
			int lres = 0;
			char *module;
			/* Load any modules that we automatically unloaded so that we could do the unload.
			 * Note that unloaded was filled recursively, if certain modules were unloaded
			 * as a result of unloads, those are also included.
			 * Normal pop operations will remove the element most recently added to the list.
			 * The most recently added modules are modules that may have unloaded after their dependents.
			 * Therefore, this is the correct order to use since the most recently unloaded modules
			 * also need to be loaded again first to guarantee that any modules dependent on them
			 * can load properly when we try to load them afterwards.
			 */
			while ((module = stringlist_pop(&unloaded))) {
				lres |= load_resource(NULL, module, 0);
				free(module);
			}
			if (lres) {
				bbs_warning("Not all automatically unloaded modules could be successfully loaded again\n");
			}
		}
	} else if (try_delayed) {
		/* XXX If we do this, then any automatically unloaded modules will not get automatically loaded again. */
		if (!queue_reload(name)) { /* Can't reload now, queue for reload when possible */
			bbs_verb(4, "Queued reload of module '%s'\n", name);
		}
	}
	stringlist_empty_destroy(&unloaded);
	return res;
}

/*! \brief Whether a module exists in the module directory on disk (regardless of whether it's active or running) */
static int bbs_module_exists(const char *name)
{
	char fn[PATH_MAX];
	size_t resource_in_len = strlen(name);
	const char *so_ext = "";

	if (resource_in_len < 4 || strcasecmp(name + resource_in_len - 3, ".so")) {
		so_ext = ".so";
	}

	snprintf(fn, sizeof(fn), "%s/%s%s", BBS_MODULE_DIR, name, so_ext);
	return bbs_file_exists(fn);
}

int bbs_module_running(const char *name)
{
	struct bbs_module *mod;
	RWLIST_RDLOCK(&modules);
	mod = find_resource(name);
	RWLIST_UNLOCK(&modules);
	return mod ? 1 : 0;
}

static int list_modules(int fd)
{
	int c = 0;
	struct bbs_module *mod;

	bbs_dprintf(fd, "%6s %-35s %3s %s\n", "Load #", "Module Name", "Use", "Description");

	RWLIST_RDLOCK(&modules);
	RWLIST_TRAVERSE(&modules, mod, entry) {
		bbs_dprintf(fd, "%6d %-35s %3d %s\n", mod->loadorder, mod->name, mod->usecount, mod->info->description);
		c++;
	}
	RWLIST_UNLOCK(&modules);
	bbs_dprintf(fd, "%d module%s loaded\n", c, ESS(c));
	return 0;
}

/*! \note Modules list must be locked */
static int list_modulerefs(int fd, const char *name)
{
	struct bbs_module *mod;
	int i = 0;
	size_t compchars = 0;

	bbs_dprintf(fd, "%-30s %3s %2s %-30s %s\n", "Module", "#", "PR", "Reffing Module", "Ref Location");

	/* Allow comparison without the .so suffix. */
	if (!strlen_zero(name)) {
		char *period = strchr(name, '.');
		if (period) {
			compchars = (size_t) (period - name);
		} else {
			compchars = strlen(name);
		}
	}

	RWLIST_TRAVERSE(&modules, mod, entry) {
		if (!name || !strncasecmp(name, mod->name, compchars)) {
			int c = 0;
			struct bbs_module_reference *r;
			/* Dump refs */
			RWLIST_RDLOCK(&mod->refs);
			RWLIST_TRAVERSE(&mod->refs, r, entry) {
				struct bbs_module *refmod = r->refmod;
				c++;
				i++;
				/* Safe to dereference r->refmod (if not NULL), since it can't be removed while modules list is locked */
				bbs_dprintf(fd, "%-30s %3d %2d %-30s %s:%d %s\n", mod->name, c,
					r->pair, refmod ? refmod->name : "", r->file, r->line, r->func);
			}
			RWLIST_UNLOCK(&mod->refs);
			if (name) {
				bbs_dprintf(fd, "Module %s has %d reference%s\n", mod->name, c, ESS(c));
				break;
			}
		}
	}
	if (name && !mod) {
		bbs_dprintf(fd, "No module references found for '%s'\n", name);
		return -1;
	} else if (!name) {
		bbs_dprintf(fd, "%d total reference%s\n", i, ESS(i));
	}
	return 0;
}

static int cli_modules(struct bbs_cli_args *a)
{
	return list_modules(a->fdout);
}

static int cli_modulerefs(struct bbs_cli_args *a)
{
	int res;
	RWLIST_RDLOCK(&modules);
	res = list_modulerefs(a->fdout, a->argc >= 2 ? a->argv[1] : NULL);
	RWLIST_UNLOCK(&modules);
	return res;
}

static int cli_load(struct bbs_cli_args *a)
{
	bbs_cli_set_stdout_logging(a->fdout, 1); /* We want to be able to see the logging */
	return bbs_module_load(a->argv[1]);
}

static int cli_loadwait(struct bbs_cli_args *a)
{
	int res;
	struct pollfd pfd;
	const char *s = a->argv[1];

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = a->fdin;
	pfd.events = POLLIN;

	/* Since the terminal is in canonical mode, we need a newline for poll() to wake up.
	 * That's fine, just say so. */

	if (!bbs_module_exists(s)) {
		bbs_dprintf(a->fdout, "Module '%s' does not exist\n", s);
		return -1;
	} else if (bbs_module_running(s)) {
		bbs_dprintf(a->fdout, "Module '%s' is already running\n", s);
		return -1;
	}

	/* Technically, a small race condition is possible here.
	 * The module might not be running when we check above, but be running before we call bbs_module_load.
	 * In that case, we'd just sit here. Very unlikely though, and not really possible unless the user is manipulating modules. */
	bbs_dprintf(a->fdout, "Waiting until module '%s' loads. Press ENTER to cancel retry: ", s); /* No newline */
	do {
		res = bbs_module_load(s);
		/* Allow the call to be interrupted. */
	} while (res && poll(&pfd, 1, 500) == 0);
	if (res) {
		bbs_dprintf(a->fdout, TERM_RESET_LINE "Load retry cancelled\n");
		return 1;
	}
	bbs_dprintf(a->fdout, TERM_RESET_LINE "Module loaded\n");
	return 0;
}

static int has_dependency_on(struct bbs_module *requestor, struct bbs_module *dependent, struct bbs_module *target)
{
	if (dependent == target) {
		return 1;
	}
	if (!strlen_zero(dependent->info->dependencies)) {
		char dependencies_buf[256];
		char *dependencies, *dependency;
		safe_strncpy(dependencies_buf, dependent->info->dependencies, sizeof(dependencies_buf));
		dependencies = dependencies_buf;
		while ((dependency = strsep(&dependencies, ","))) {
			struct bbs_module *m = find_resource(dependency);
			if (m) {
				if (has_dependency_on(requestor, m, target)) {
					bbs_debug(1, "%s has recursive dependency on %s (via %s)\n", bbs_module_name(requestor), bbs_module_name(target), bbs_module_name(m));
					return 1;
				}
			} else {
				bbs_warning("Dependency %s not currently loaded?\n", dependency);
			}
		}
	}
	return 0;
}

static int module_has_dependency_on(const char *dependent, const char *dependency)
{
	int res;
	struct bbs_module *requestor, *target;

	/* The unload process already has to process dependencies,
	 * so it'd be slightly more efficient to just do that upfront,
	 * and switch on the fly to an async unload if we found we need to.
	 * But that would add a lot more complexity, so we check beforehand for now. */
	RWLIST_RDLOCK(&modules);
	requestor = find_resource(dependent);
	target = find_resource(dependency);
	if (!requestor) {
		bbs_error("Could not find requesting module %s?\n", dependent);
		res = -1; /* Fail safe (do async reload), return nonzero */
	} else if (!dependency) {
		bbs_error("Could not find target module %s?\n", dependency);
		res = -1; /* Fail safe (do async reload), return nonzero */
	} else {
		res = has_dependency_on(requestor, requestor, target);
	}
	RWLIST_UNLOCK(&modules);

	return res;
}

static int need_async_unload(const char *s)
{
	/* Example: The sysop can't unload the sysop module directly in the same thread.
	 * We need to have another thread do it for us, asynchronously.
	 * The same is true for any module for which mod_sysop is a dependency, e.g. mod_history.
	 *
	 * If a module were to request itself also be unloaded, the same thing also applies.
	 *
	 * So, first, we need to check to see if the calling module is the same as
	 * the module to be unloaded, or if the calling module has a dependency (recursively)
	 * on the module to be unloaded. */

	/*! \note Since CLI commands can only be triggered by mod_sysop, this is hardcoded for now.
	 * Otherwise, we would need to know the module that called this function,
	 * or really, for that matter, any modules above us in the call stack. */
#define SYSOP_CLI_MOD_NAME "mod_sysop"
	if (module_has_dependency_on(SYSOP_CLI_MOD_NAME, s)) {
		return 1;
	}
	return 0;
}

static int threadsafe_unload(const char *s)
{
	if (need_async_unload(s)) {
		bbs_request_module_unload(s, 0);
		return 0;
	}
	return bbs_module_unload(s);
}

static int threadsafe_reload(const char *s, int queued)
{
	if (need_async_unload(s)) {
		bbs_request_module_unload(s, 1);
		return 0;
	}
	return bbs_module_reload(s, queued);
}

static int cli_unload(struct bbs_cli_args *a)
{
	const char *s = a->argv[1];
	bbs_cli_set_stdout_logging(a->fdout, 1); /* We want to be able to see the logging */
	return threadsafe_unload(s);
}

static int cli_unloadwait(struct bbs_cli_args *a)
{
	int res;
	struct pollfd pfd;
	const char *s = a->argv[1];

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = a->fdin;
	pfd.events = POLLIN;

	/* Since the terminal is in canonical mode, we need a newline for poll() to wake up.
	 * That's fine, just say so. */

	if (!bbs_module_running(s)) {
		bbs_dprintf(a->fdout, "Module '%s' is not currently running\n", s);
		return -1;
	}

	bbs_dprintf(a->fdout, "Waiting until module '%s' unloads. Press ENTER to cancel retry: ", s); /* No newline */
	do {
		res = threadsafe_unload(s);
		/* Allow the call to be interrupted. */
	} while (res && poll(&pfd, 1, 500) == 0);
	if (res) {
		bbs_dprintf(a->fdout, TERM_RESET_LINE "Unload retry cancelled\n");
		return 1;
	}
	bbs_dprintf(a->fdout, TERM_RESET_LINE "Module unloaded\n");
	return 0;
}

struct reload_handler {
	const char *name;
	const char *description;
	int (*reloader)(int fd);
	RWLIST_ENTRY(reload_handler) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(reload_handlers, reload_handler);

int bbs_register_reload_handler(const char *name, const char *description, int (*reloader)(int fd))
{
	struct reload_handler *r;
	size_t namelen;

	if (strchr(name, '_')) {
		bbs_warning("Reload handler '%s' contains forbidden character\n", name);
		return -1;
	}

	namelen = strlen(name);

	RWLIST_WRLOCK(&reload_handlers);
	RWLIST_TRAVERSE(&reload_handlers, r, entry) {
		if (!strcmp(name, r->name)) {
			RWLIST_UNLOCK(&reload_handlers);
			bbs_error("Reload handler '%s' already registered\n", name);
			return -1;
		}
	}

	r = calloc(1, sizeof(*r) + namelen + strlen(description) + 2);
	if (ALLOC_FAILURE(r)) {
		RWLIST_UNLOCK(&reload_handlers);
		return -1;
	}

	r->reloader = reloader;
	strcpy(r->data, name); /* Safe */
	strcpy(r->data + namelen + 1, description);
	r->name = r->data;
	r->description = r->data + namelen + 1;
	RWLIST_INSERT_TAIL(&reload_handlers, r, entry);
	RWLIST_UNLOCK(&reload_handlers);
	return 0;
}

static int cli_reloadhandlers(struct bbs_cli_args *a)
{
	struct reload_handler *r;

	bbs_dprintf(a->fdout, "%-20s %s\n", "Name", "Description");
	RWLIST_RDLOCK(&reload_handlers);
	RWLIST_TRAVERSE(&reload_handlers, r, entry) {
		bbs_dprintf(a->fdout, "%-20s %s\n", r->name, r->description);
	}
	RWLIST_UNLOCK(&reload_handlers);
	return 0;
}

int bbs_reload(const char *name, int fd)
{
	int res = 0;
	int reloaded = 0;
	struct reload_handler *r;

	/* If the reload was triggered by the main thread,
	 * (as opposed to a reload initiated by a console),
	 * then there isn't anywhere the output needs to (or should) go.
	 * We can send it to STDOUT, even if we are daemonized,
	 * that will just get safely discarded. */
	if (fd == -1) {
		fd = STDOUT_FILENO;
	}

	if (bbs_is_shutting_down()) {
		/* Can't reload if shutting down, particularly as
		 * some stuff in the core will start unregistering
		 * and cleaning up, past a certain point of shutdown. */
		return -1;
	}

	/* There should never be more than one reload happening at a time,
	 * so just write lock, even though we're not changing the list. */
	RWLIST_WRLOCK(&reload_handlers);
	RWLIST_TRAVERSE(&reload_handlers, r, entry) {
		if (!name || !strcmp(name, r->name)) {
			int rres;
			/* These are all in the core, so no need to ref/unref a module.
			 * Just execute the callback. */
			rres = r->reloader(fd);
			if (!res) {
				reloaded++;
			}
			res |= rres;
		}
	}
	RWLIST_UNLOCK(&reload_handlers);
	if (reloaded) {
		/* Emit a reload event as long as we reloaded something successfully,
		 * even if there were also some failures. */
		bbs_event_dispatch(NULL, EVENT_RELOAD);
		if (!res) {
			/* We reloaded at least one thing, and everything reloaded successfully */
			return 0;
		}
	}
	return 1;
}

static int reload_core(const char *name, int fd)
{
	int res = bbs_reload(name, fd);
	if (res) {
		/* Handler(s) failed to reload */
		bbs_dprintf(fd, "%s\n", name ? "Reload failed" : "Full or partial reload failure");
		return res;
	}
	/* Either something failed to reload, or we didn't actually reload anything (typo in target) */
	bbs_dprintf(fd, "No such component to reload: '%s'\n", name);
	return 1;
}

static int cli_reload(struct bbs_cli_args *a)
{
	bbs_cli_set_stdout_logging(a->fdout, 1); /* We want to be able to see the logging */

	/* Request to reload a specific module */
	if (a->argc >= 2) {
		const char *s = a->argv[1];
		/* If it's a module name, it contains an underscore */
		if (strchr(s, '_')) {
			return threadsafe_reload(s, 0);
		} else {
			return reload_core(s, a->fdout);
		}
	}

	/* Reload all core components */
	return reload_core(NULL, a->fdout);
}

static int cli_reloadwait(struct bbs_cli_args *a)
{
	int res;
	struct pollfd pfd;
	const char *s = a->argv[1];

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = a->fdin;
	pfd.events = POLLIN;

	/* Since the terminal is in canonical mode, we need a newline for poll() to wake up.
	 * That's fine, just say so. */

	if (!bbs_module_running(s)) {
		bbs_dprintf(a->fdout, "Module '%s' is not currently running\n", s);
		return -1;
	}

	bbs_dprintf(a->fdout, "Waiting until module '%s' reloads. Press ENTER to cancel retry: ", s); /* No newline */
	do {
		res = threadsafe_reload(s, 0);
		/* Allow the call to be interrupted. */
	} while (res && poll(&pfd, 1, 500) == 0);
	if (res) {
		bbs_dprintf(a->fdout, TERM_RESET_LINE "Reload retry cancelled\n");
		return 1;
	}
	bbs_dprintf(a->fdout, TERM_RESET_LINE "Module reloaded\n");
	return 0;
}

static int cli_reloadqueue(struct bbs_cli_args *a)
{
	const char *s = a->argv[1];
	bbs_cli_set_stdout_logging(a->fdout, 1); /* We want to be able to see the logging */
	/* Nothing increments the ref count of mod_sysop currently,
	 * so reloads will always succeed anyways, not get queued */
	return threadsafe_reload(s, 1);
}

static struct bbs_cli_entry cli_commands_modules[] = {
	BBS_CLI_COMMAND(cli_modules, "modules", 1, "List loaded modules", NULL),
	BBS_CLI_COMMAND(cli_modulerefs, "modulerefs", 1, "List references on a module", "modulerefs [<module>]"),
	BBS_CLI_COMMAND(cli_load, "load", 2, "Load dynamic module", "load <module>"),
	BBS_CLI_COMMAND(cli_loadwait, "loadwait", 2, "Keep retrying load of dynamic module until it successfully loads", "loadwait <module>"),
	BBS_CLI_COMMAND(cli_unload, "unload", 2, "Unload dynamic module", "unload <module>"),
	BBS_CLI_COMMAND(cli_unloadwait, "unloadwait", 2, "Keep retrying load of dynamic module until it successfully unloads", "unloadwait <module>"),
	BBS_CLI_COMMAND(cli_reload, "reload", 1, "Hotswap (unload and load) dynamic module or run a specific (or all) core reload handler(s)", "reload [<module>]"),
	BBS_CLI_COMMAND(cli_reloadhandlers, "reloadhandlers", 1, "List all core reload handlers", NULL),
	BBS_CLI_COMMAND(cli_reloadwait, "reloadwait", 2, "Keep retrying hotswap reload of dynamic module until successful", "reloadwait <module>"),
	BBS_CLI_COMMAND(cli_reloadqueue, "reloadqueue", 2, "Unload and load dynamic module, queuing if necessary", "reloadqueue <module>"),
};

static int loaded_modules = 0;
static int really_loaded_modules = 0;

int load_modules(void)
{
	int res, c = 0; /* XXX If this is not uninitialized, gcc does not throw a warning, why not??? */
	struct bbs_module *mod;

	/* No modules should be registered on startup. */
	RWLIST_WRLOCK(&modules);

	bbs_assert(RWLIST_EMPTY(&modules));
	loaded_modules = 1;
	res = try_autoload_modules();
	c = RWLIST_SIZE(&modules, mod, entry);

	RWLIST_UNLOCK(&modules);

	bbs_assert(c == autoload_loaded);
	if (!res) {
		bbs_cli_register_multiple(cli_commands_modules);
		really_loaded_modules = 1;
	}
	return res;
}

/*! \brief Cleanly unload everything we can */
static void unload_modules_helper(void)
{
	int passes, skipped = 0;

	bbs_debug(3, "Auto unloading modules\n");

/* Try 51 times * 0.2 seconds = up to 10.2 seconds to unload everything cleanly (which means that in the test suite, the alarm should go off and trigger a backtrace dump) */
#define MAX_PASSES 51

	RWLIST_WRLOCK(&modules);
	/* Run the loop a max of 5 times. Always do it at least once, but then only if there are still skipped modules remaining.
	 * We really try our best here to unload all modules cleanly, but we can't try forever in case a module is just not unloading. */
	for (passes = 0 ; (passes == 0 || skipped) && passes < MAX_PASSES ; passes++) {
		unsigned int nodecount = bbs_node_count();
		struct bbs_module *mod, *lastmod = NULL; /* If passes > 0, do this so we don't try dlclosing a module twice */
		RWLIST_TRAVERSE(&modules, mod, entry) {
#ifdef DLOPEN_ONLY_ONCE
			if (mod->flags.unloaded) {
				continue;
			}
#endif
			if (lastmod) {
				/* Because we're using a singly linked list, instead of a doubly linked list,
				 * we must advance to the next item in the list before actually calling
				 * unload_dynamic_module on it, since that will result in calling
				 * bbs_module_unregister, which will remove the module completely from the list,
				 * such that trying to advance to the next element at that point is an invalid
				 * memory access.
				 *
				 * Traversing a doubly linked list in a reverse would also work.
				 *
				 * Note that bbs_module_unregister doesn't WRLOCK the module list again so this is safe.
				 */
				if (!strlen_zero(lastmod->info->dependencies)) {
					dec_refcounts(lastmod);
				}
				unload_dynamic_module(lastmod);
			}
			lastmod = NULL; /* If we call continue in the loop, make sure this is NULL so we don't process a module twice. */
			if (mod->usecount) {
				/* Pass # when printed out is 1-indexed for sanity */
				if (nodecount) {
					bbs_debug(2, "Skipping unload of %s with use count %d on pass %d (%d total nodes active)\n", mod->name, mod->usecount, passes + 1, nodecount);
				} else {
					bbs_debug(2, "Skipping unload of %s with use count %d on pass %d\n", mod->name, mod->usecount, passes + 1);
				}
				if (passes == 0) {
					skipped++; /* Only add to our count the first time. */
				}
				continue;
			}
			/* Module doesn't appear to still be in use (though internally it may be), so try to unload the module. */
			bbs_debug(2, "Attempting to unload %s\n", mod->name);
			if (__unload_module(mod)) {
				/* Could actually still be cleaning up. Skip on this pass. */
				bbs_debug(2, "Module %s declined to unload, skipping on pass %d\n", mod->name, passes + 1);
				if (passes == 0) {
					skipped++; /* Only add to our count the first time. */
				}
				continue; /* Don't actually dlclose a module that refused to unload. */
			}
#ifdef DLOPEN_ONLY_ONCE
			mod->flags.unloaded = 1;
#endif
			lastmod = mod; /* Actually go ahead and dlclose the module. */
			if (passes > 0) {
				/* We previously skipped the module because it had a positive use count, but now we're good. */
				bbs_debug(2, "Module %s previously was in use but unloaded on pass %d\n", mod->name, passes + 1);
				skipped--;
			}
		}
		if (lastmod) {
			/* Don't forget to unload the last module. See comment above. */
			if (!strlen_zero(lastmod->info->dependencies)) {
				dec_refcounts(lastmod);
			}
			unload_dynamic_module(lastmod);
		}
		if (passes > 0) {
			/* The first 2 passes (between 1st and 2nd), don't sleep.
			 * Modules may just have needed a teeny bit more time.
			 * Afterwards, sleep a bit to increase the chances of successful unload. */
			if (passes == MAX_PASSES / 2 || passes == MAX_PASSES - 1) {
				unsigned int numnodes;
				/* Dump module refs to aid debugging, since something is probably stuck.
				 * The test suite will kill the BBS before we get to MAX_PASSES,
				 * so dump it halfway through for that case and at the end for running interactively. */
				list_modulerefs(STDOUT_FILENO, NULL);
				numnodes = bbs_node_count();
				if (numnodes) {
					bbs_warning("%u node%s still registered\n", numnodes, ESS(numnodes));
				} else {
					/* Nodes are removed from the node list prior to node_shutdown being called.
					 * However, they don't actually exit (and unref the module) until node_free is called.
					 * Thus, there can still be a delay in that case. */
					bbs_debug(2, "All nodes have been unregistered (but haven't necessarily exited)\n");
				}
			}
			usleep(200000); /* Wait 200 ms and try again */
		}
	}
	RWLIST_UNLOCK(&modules);
	if (skipped) {
		bbs_error("%d module%s could not be unloaded after %d passes\n", skipped, ESS(skipped), passes);
	}
}

int unload_modules(void)
{
#ifndef DLOPEN_ONLY_ONCE
	struct bbs_module *mod;
#endif

	unload_modules_helper();

#ifndef DLOPEN_ONLY_ONCE
	/* Check for any modules still registered. */
	RWLIST_WRLOCK(&modules);
	RWLIST_TRAVERSE(&modules, mod, entry) {
		bbs_warning("Module %s still registered during BBS shutdown\n", mod->name);
	}
	RWLIST_UNLOCK(&modules);
#endif

	/* If startup aborts due to a required module failing to load,
	 * the CLI commands were never registered, so don't attempt to unregister them. */
	if (really_loaded_modules) {
		bbs_cli_unregister_multiple(cli_commands_modules);
	}

	RWLIST_WRLOCK_REMOVE_ALL(&reload_handlers, entry, free);
	return 0;
}
