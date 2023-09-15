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
#include <linux/limits.h> /* use PATH_MAX */
#include <unistd.h> /* use usleep */
#include <poll.h>

#include "include/linkedlists.h"
#include "include/stringlist.h"
#include "include/module.h"
#include "include/config.h"
#include "include/utils.h" /* use bbs_dir_traverse */
#include "include/node.h"
#include "include/cli.h"

#define BBS_MODULE_DIR DIRCAT("/usr/lib", DIRCAT(BBS_NAME, "modules"))

struct bbs_module {
	const struct bbs_module_info *info;
	/*! The shared lib. */
	void *lib;
	/*! Number of 'users' and other references currently holding the module. */
	int usecount;
	struct {
		/*! This module is awaiting a reload. */
		unsigned int reloadpending:1;
	} flags;
	/*! Load order */
	int loadorder;
	/* Next entry */
	RWLIST_ENTRY(bbs_module) entry;
	/*! The name of the module. */
	char name[0];
};

static RWLIST_HEAD_STATIC(modules, bbs_module);

/*! \brief Autoload all modules by default */
#define DEFAULT_AUTOLOAD_SETTING 1

static int autoload_setting = DEFAULT_AUTOLOAD_SETTING;

static int really_register = 0;

struct stringlist modules_preload;
struct stringlist modules_load;
struct stringlist modules_noload;

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
		free(mod);
	} else {
		bbs_debug(1, "Unable to unregister module %s\n", info->name);
	}
}

struct bbs_module *bbs_module_ref(struct bbs_module *mod)
{
	bbs_atomic_fetchadd_int(&mod->usecount, +1);
	bbs_assert(mod->usecount > 0);
	return mod;
}

void bbs_module_unref(struct bbs_module *mod)
{
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

struct bbs_module *bbs_require_module(const char *module)
{
	struct bbs_module *mod = find_resource(module);
	if (mod) {
		bbs_debug(5, "Module dependency '%s' is satisfied\n", module);
		bbs_module_ref(mod);
	} else {
		bbs_warning("Module %s dependency is not satisfied\n", module);
	}
	return mod;
}

void bbs_unrequire_module(struct bbs_module *mod)
{
	bbs_module_unref(mod);
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
static void logged_dlclose(const char *name, void *lib)
{
	if (!lib) {
		return;
	}
	dlerror(); /* Clear any existing error */
	if (really_register) {
		bbs_debug(5, "dlclose: %s\n", name);
	}
	if (dlclose(lib)) {
		char *error = dlerror();
		bbs_error("Failure in dlclose for module '%s': %s\n", name ? name : "unknown", error ? error : "Unknown error");
	}
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

	resource_being_loaded = mod;
	mod->lib = dlopen(filename, flags);

	if (resource_being_loaded) {
		const char *dlerror_msg = S_IF(dlerror());

		bbs_warning("Module %s didn't register itself during load?\n", resource_in);

		resource_being_loaded = NULL;
		if (mod->lib) {
			bbs_error("Module '%s' did not register itself during load\n", resource_in);
			logged_dlclose(resource_in, mod->lib);
		} else if (!suppress_logging) {
			bbs_error("Error loading module '%s': %s\n", resource_in, dlerror_msg);
		}

		free(mod);
		return NULL;
	}

	return mod;
}

/* Forward declaration */
static int load_resource(const char *restrict resource_name, unsigned int suppress_logging);

static struct bbs_module *load_dynamic_module(const char *resource_in, unsigned int suppress_logging)
{
	char fn[PATH_MAX];
	size_t resource_in_len = strlen(resource_in);
	const char *so_ext = "";
	struct bbs_module *mod;

	if (resource_in_len < 4 || strcasecmp(resource_in + resource_in_len - 3, ".so")) {
		so_ext = ".so";
	}

	snprintf(fn, sizeof(fn), "%s/%s%s", BBS_MODULE_DIR, resource_in, so_ext);

	mod = load_dlopen(resource_in, so_ext, fn, RTLD_NOW | RTLD_LOCAL, suppress_logging);
	if (!mod) {
		/* XXX. Here, we consider the case of modules that are both depended on by other modules
		 * and themselves depend on yet other modules.
		 * In other words, they both export symbols globally,
		 * and they also require the symbols of other modules.
		 * This means that among the modules to preload, order will matter,
		 * because if C depends on B and B depends on A, then B and A will both be marked for preload,
		 * but A *MUST* be loaded before B, or B will fail to load (cascading to C, etc.)
		 *
		 * When scanning the list of modules, at some point, we will discover that B requires A and C requires B.
		 * It could be in either order.
		 * And besides that, we use directory order, not stringlist order, for the purposes of autoloading.
		 * That could be changed for preload, but we would need to store more state to detect these deeper dependencies
		 * than we do now.
		 *
		 * In the meantime, if we're autoloading modules, and a load fails, it's probably because symbols
		 * failed to resolve, and probably due to unresolved dependencies. Try to resolve those on the fly, for now.
		 *
		 * XXX This is really not elegant, it would be better to make a properly ordered list of all modules from the get go.
		 * Also, this is no longer safe from accidental infinte recursion. We will crash (stack overflow) if there is a dependency loop here.
		 * If we have a better way of handling this in the future, this hack can be removed:
		 */
		if (stringlist_contains(&modules_preload, resource_in)) {
			/* Only bother checking if it's a preload module.
			 * Otherwise, checking dependencies now isn't going to do anything for us.
			 * Also only do this during autoload (the preload list will be emptied once autoload finishes).
			 */

			/* At this point, we'll have to do a lazy open again. If that fails, then really give up. */
			mod = load_dlopen(resource_in, so_ext, fn, RTLD_LAZY | RTLD_LOCAL, suppress_logging);
			if (mod && mod->info->dependencies) {
				int res = 0;
				char dependencies_buf[256];
				char *dependency, *dependencies = dependencies_buf;
				safe_strncpy(dependencies_buf, mod->info->dependencies, sizeof(dependencies_buf));
				logged_dlclose(resource_in, mod->lib);
				free(mod);
				while ((dependency = strsep(&dependencies, ","))) {
					if (!find_resource(dependency)) { /* It's not loaded already. */
						int mres;
						bbs_debug(1, "Preloading %s on the fly since it's required by %s\n", dependency, resource_in);
						mres = load_resource(dependency, suppress_logging);
						if (!mres) {
							/* Prevent it from being loaded again in the future */
							stringlist_push(&modules_noload, dependency);
							stringlist_remove(&modules_preload, dependency);
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
		} else {
			bbs_debug(3, "Failure appears to be genuine: %s cannot be loaded\n", resource_in);
		}
	}
	if (mod && mod->info->flags & MODFLAG_GLOBAL_SYMBOLS) {
		/* Close the module so we can reopen with correct flags. */
		logged_dlclose(resource_in, mod->lib);
		free(mod);
		bbs_debug(3, "Module '%s' contains global symbols, reopening\n", resource_in);
		mod = load_dlopen(resource_in, so_ext, fn, RTLD_NOW | RTLD_GLOBAL, 0);
	}

	return mod;
}

static void check_dependencies(const char *restrict resource_in, unsigned int suppress_logging)
{
	char fn[PATH_MAX];
	size_t resource_in_len = strlen(resource_in);
	const char *so_ext = "";
	struct bbs_module *mod;

	/* Module isn't going to load anyways, so who cares? */
	if (stringlist_contains(&modules_noload, resource_in)) {
		return;
	}

	if (resource_in_len < 4 || strcasecmp(resource_in + resource_in_len - 3, ".so")) {
		so_ext = ".so";
	}

	snprintf(fn, sizeof(fn), "%s/%s%s", BBS_MODULE_DIR, resource_in, so_ext);

	/* Lazy load won't perform symbol resolution, so we can successfully load a module that is missing dependencies */
	mod = load_dlopen(resource_in, so_ext, fn, RTLD_LAZY | RTLD_LOCAL, suppress_logging);
	if (!mod) {
		bbs_error("Failed to check dependencies for %s\n", resource_in);
		return;
	}

	if (!strlen_zero(mod->info->dependencies)) {
		char dependencies_buf[256];
		char *dependencies, *dependency;
		safe_strncpy(dependencies_buf, mod->info->dependencies, sizeof(dependencies_buf));
		dependencies = dependencies_buf;
		while ((dependency = strsep(&dependencies, ","))) {
			if (stringlist_contains(&modules_noload, dependency)) {
				/* The module might try to load later (if autoload or explicitly loaded),
				 * but if it does, it WILL fail anyways, so just noload it now. */
				if (!stringlist_contains(&modules_noload, resource_in)) {
					bbs_error("Module %s depends on noloaded module %s\n", resource_in, dependency);
					stringlist_push(&modules_noload, resource_in);
				}
				continue;
			}
			if (autoload_setting) {
				if (!stringlist_contains(&modules_preload, dependency)) {
					bbs_debug(2, "Marking %s for preload since %s depends on it\n", dependency, resource_in);
					stringlist_push(&modules_preload, dependency);
				} else {
					bbs_debug(4, "Module %s is already marked for preload\n", dependency);
				}
			}
		}
	}

	logged_dlclose(resource_in, mod->lib);
	free(mod);
	return;
}

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
	   disappear when this operation succeeds, so we can't
	   dereference it */
	logged_dlclose(bbs_module_name(mod), lib);

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

/*! \brief loads a resource based upon resource_name. */
static int load_resource(const char *restrict resource_name, unsigned int suppress_logging)
{
	int res;
	struct bbs_module *mod;

	if ((mod = find_resource(resource_name))) {
		bbs_warning("Module '%s' already loaded and running.\n", resource_name);
		return -1;
	}

	mod = load_dynamic_module(resource_name, suppress_logging);
	if (!mod) {
		bbs_warning("Could not load dynamic module %s\n", resource_name);
		return -1;
	}

	res = start_resource(mod);

	if (res) {
		/* If success, log in start_resource, otherwise, log here */
		bbs_error("Module '%s' could not be loaded.\n", resource_name);
		unload_dynamic_module(mod);
		free(mod); /* bbs_module_unregister isn't called if the module declined to load, so free to avoid a leak */
		return -1;
	} else {
		/* Bump the ref count of any modules upon which we depend. */
		if (!strlen_zero(mod->info->dependencies)) {
			char dependencies_buf[256];
			char *dependencies, *dependency;
			safe_strncpy(dependencies_buf, mod->info->dependencies, sizeof(dependencies_buf));
			dependencies = dependencies_buf;
			while ((dependency = strsep(&dependencies, ","))) {
				bbs_debug(9, "%s requires module %s\n", mod->name, dependency);
				bbs_require_module(dependency);
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
static int unload_dependencies(struct bbs_module *mod, struct stringlist *restrict removed)
{
	struct bbs_module *m;
	int res = 0;
	struct module_list list;
	struct bbs_module_ref *r;

	/* Make a list of modules to unload upfront */
	memset(&list, 0, sizeof(list));

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
		if (removed && stringlist_contains(removed, r->name)) {
			free(r);
			continue;
		}
		/* m is still valid memory since module has not been unloaded */
		m = r->m;
		free(r);
		bbs_verb(5, "Unloading %s, since it depends on %s\n", m->name, mod->name);
		if (!unload_resource_nolock(m, 0, &usecount, removed)) {
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
			bbs_debug(9, "No longer depend on module %s\n", dependency);
			if (m) {
				bbs_unrequire_module(m);
			} else {
				bbs_warning("Dependency %s not currently loaded?\n", dependency);
			}
		}
	}
}

static struct bbs_module *unload_resource_nolock(struct bbs_module *mod, int force, int *usecount, struct stringlist *restrict removed)
{
	int res;

	bbs_debug(2, "Module %s has use count %d\n", mod->name, mod->usecount);
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
				unsigned int kicked = bbs_node_shutdown_mod(mod); /* Kick all the nodes created by this module. */
				if (kicked != nodes_usecount) {
					bbs_warning("Wanted to kick %u nodes but only kicked %u?\n", nodes_usecount, kicked);
				} else if (kicked) {
					usleep(10000); /* Wait for actual node exits to complete, to increase chance of success */
					bbs_debug(3, "Kicked %d node%s\n", kicked, ESS(kicked));
				}
			}
		}
		unload_dependencies(mod, removed);
	}

	if (mod->usecount > 0) {
		if (force > 1) {
			bbs_warning("Warning:  Forcing removal of module '%s' with use count %d\n", mod->name, mod->usecount);
		} else {
			bbs_warning("Soft unload failed, '%s' has use count %d\n", mod->name, mod->usecount);
			return NULL;
		}
	}

	bbs_debug(1, "Unloading %s\n", mod->name);
	res = mod->info->unload();
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

static int on_file_plan(const char *dir_name, const char *filename, void *obj)
{
	UNUSED(dir_name);
	UNUSED(obj);

	autoload_planned++;
	bbs_debug(7, "Detected dynamic module %s\n", filename);
	check_dependencies(filename, 0); /* Check if we need to load any dependencies for this module. */
	return 0;
}

static int on_file_preload(const char *dir_name, const char *filename, void *obj)
{
	struct bbs_module *mod = find_resource(filename);

	UNUSED(dir_name);
	UNUSED(obj);

	if (mod) {
		bbs_error("Module %s is already loaded\n", filename);
		return 0; /* Always return 0 or otherwise we'd abort the entire autoloading process */
	}

	/* noload trumps preload if both are present */
	if (stringlist_contains(&modules_noload, filename)) {
		bbs_warning("Conflicting directives 'noload' and 'preload' for %s, not preloading\n", filename);
		return 0;
	}

	/* Only load if it's a preload module */
	if (!stringlist_contains(&modules_preload, filename)) {
		return 0;
	}

	bbs_debug(5, "Preloading dynamic module %s (autoload=yes or dependency)\n", filename);

	if (load_resource(filename, 0)) {
		bbs_error("Failed to autoload %s\n", filename);
	} else {
		autoload_loaded++;
	}

	return bbs_abort_startup() ? 1 : 0; /* Always return 0 or otherwise we'd abort the entire autoloading process */
}

static int on_file_autoload(const char *dir_name, const char *filename, void *obj)
{
	struct bbs_module *mod = find_resource(filename);

	UNUSED(dir_name);
	UNUSED(obj);

	if (mod) {
		if (!stringlist_contains(&modules_preload, filename)) { /* If it was preloaded, then it's legitimate */
			bbs_error("Module %s is already loaded\n", filename);
		}
		return 0; /* Always return 0 or otherwise we'd abort the entire autoloading process */
	}

	/* If explicit noload, bail now */
	if (stringlist_contains(&modules_noload, filename)) {
		bbs_debug(5, "Not loading dynamic module %s, since it's explicitly noloaded\n", filename);
		autoload_planned--;
		return 0;
	} else if (!autoload_setting) {
		if (!stringlist_contains(&modules_load, filename)) {
			bbs_debug(5, "Not loading dynamic module %s, not explicitly loaded and autoload=no\n", filename);
			autoload_planned--;
			return 0;
		}
		bbs_debug(5, "Autoloading dynamic module %s, since explicitly loaded\n", filename);
	} else {
		/* If autoload=yes and not in the noload list, then don't even bother checking the load list. Just load it. */
		bbs_debug(5, "Autoloading dynamic module %s (autoload=yes)\n", filename);
	}

	if (load_resource(filename, 0)) {
		bbs_error("Failed to autoload %s\n", filename);
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

	RWLIST_WRLOCK(&modules_load);
	RWLIST_WRLOCK(&modules_noload);
	RWLIST_WRLOCK(&modules_preload);
	while ((section = bbs_config_walk(cfg, section))) {
		if (!strcmp(bbs_config_section_name(section), "general")) {
			continue; /* Skip general, already handled */
		} else if (strcmp(bbs_config_section_name(section), "modules")) {
			bbs_warning("Unknown section name '%s', skipping\n", bbs_config_section_name(section));
			continue;
		}
		/* [modules] section */
		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
			if (!strcmp(key, "load")) {
				bbs_debug(7, "Explicitly planning to load '%s'\n", value);
				stringlist_push(&modules_load, value);
			} else if (!strcmp(key, "noload")) {
				bbs_debug(7, "Explicitly planning to not load '%s'\n", value);
				stringlist_push(&modules_noload, value);
			} else if (!strcmp(key, "preload")) {
				bbs_debug(7, "Explicitly planning to preload '%s'\n", value);
				stringlist_push(&modules_preload, value);
			} else {
				bbs_warning("Invalid directive %s=%s, ignoring\n", key, value);
			}
		}
	}
	RWLIST_UNLOCK(&modules_load);
	RWLIST_UNLOCK(&modules_noload);
	RWLIST_UNLOCK(&modules_preload);
	bbs_config_free(cfg); /* Destroy the config now, rather than waiting until shutdown, since it will NEVER be used again for anything. */
	return 0;
}

static int autoload_modules(void)
{
	bbs_debug(1, "Autoloading modules\n");

	/* Check config for load settings. */
	load_config();

	RWLIST_WRLOCK(&modules);
	/* Check what modules exist in the first place. Additionally, check for dependencies. */
	bbs_dir_traverse(BBS_MODULE_DIR, on_file_plan, NULL, -1);

	bbs_debug(1, "Detected %d dynamic module%s\n", autoload_planned, ESS(autoload_planned));
	really_register = 1;

	/* Now, actually try to load them. */
	bbs_dir_traverse(BBS_MODULE_DIR, on_file_preload, NULL, -1);
	bbs_dir_traverse(BBS_MODULE_DIR, on_file_autoload, NULL, -1);

	if (autoload_planned != autoload_loaded) {
		/* Some modules failed to autoload */
		bbs_warning("Planned to autoload %d module%s, but only loaded %d\n", autoload_planned, ESS(autoload_planned), autoload_loaded);
	} else {
		bbs_debug(1, "Successfully autoloaded %d module%s\n", autoload_planned, ESS(autoload_planned));
	}

	stringlist_empty(&modules_load);
	stringlist_empty(&modules_noload);
	stringlist_empty(&modules_preload);

	RWLIST_UNLOCK(&modules);
	return 0;
}

int bbs_module_load(const char *name)
{
	int res;
	RWLIST_WRLOCK(&modules);
	res = load_resource(name, 0);
	RWLIST_UNLOCK(&modules);
	return res;
}

int bbs_module_unload(const char *name)
{
	int res;

	res = unload_resource(name, 0, NULL);
	return res ? -1 : 0;
}

int bbs_module_reload(const char *name, int try_delayed)
{
	struct stringlist unloaded;
	int res;

	memset(&unloaded, 0, sizeof(unloaded));
	RWLIST_WRLOCK(&unloaded);
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
				lres |= load_resource(module, 0);
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
	RWLIST_UNLOCK(&unloaded);
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

/*! \brief Whether a module is currently running or not */
static int bbs_module_running(const char *name)
{
	struct bbs_module *mod = find_resource(name);
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

static int cli_modules(struct bbs_cli_args *a)
{
	return list_modules(a->fdout);
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

#define SYSOP_CLI_MOD_NAME "mod_sysop"

static int threadsafe_unload(const char *s)
{
	if (!strncasecmp(s, SYSOP_CLI_MOD_NAME, strlen(SYSOP_CLI_MOD_NAME))) {
		/* The sysop can't unload the sysop module directly in the same thread.
		 * We need to have another thread do it for us, asynchronously. */
		bbs_request_module_unload(s, 0);
		return 0;
	}
	return bbs_module_unload(s);
}

static int threadsafe_reload(const char *s, int queued)
{
	if (!strncasecmp(s, SYSOP_CLI_MOD_NAME, strlen(SYSOP_CLI_MOD_NAME))) {
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

static int cli_reload(struct bbs_cli_args *a)
{
	const char *s = a->argv[1];
	bbs_cli_set_stdout_logging(a->fdout, 1); /* We want to be able to see the logging */
	return threadsafe_reload(s, 0);
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
	BBS_CLI_COMMAND(cli_load, "load", 2, "Load dynamic module", "load <module>"),
	BBS_CLI_COMMAND(cli_loadwait, "loadwait", 2, "Keep retrying load of dynamic module until it successfully loads", "loadwait <module>"),
	BBS_CLI_COMMAND(cli_unload, "unload", 2, "Unload dynamic module", "unload <module>"),
	BBS_CLI_COMMAND(cli_unloadwait, "unloadwait", 2, "Keep retrying load of dynamic module until it successfully unloads", "unloadwait <module>"),
	BBS_CLI_COMMAND(cli_reload, "reload", 2, "Hotswap (unload and load) dynamic module", "reload <module>"),
	BBS_CLI_COMMAND(cli_reloadwait, "reloadwait", 2, "Keep retrying hotswap reload of dynamic module until successful", "reloadwait <module>"),
	BBS_CLI_COMMAND(cli_reloadqueue, "reloadqueue", 2, "Unload and load dynamic module, queuing if necessary", "reloadqueue <module>"),
};

int load_modules(void)
{
	int res, c = 0; /* XXX If this is not uninitialized, gcc does not throw a warning, why not??? */
	struct bbs_module *mod;

	/* No modules should be registered on startup. */
	RWLIST_WRLOCK(&modules);
	RWLIST_TRAVERSE(&modules, mod, entry) {
		bbs_assert(0);
	}
	RWLIST_UNLOCK(&modules);

	res = autoload_modules();

	RWLIST_WRLOCK(&modules);
	RWLIST_TRAVERSE(&modules, mod, entry) {
		c++;
	}
	RWLIST_UNLOCK(&modules);

	bbs_assert(c == autoload_loaded);
	bbs_cli_register_multiple(cli_commands_modules);
	return res;
}

/*! \brief Cleanly unload everything we can */
static void unload_modules_helper(void)
{
	int passes, skipped = 0;

	bbs_debug(3, "Auto unloading modules\n");

/* Try 15 times * 0.2 seconds = up to 3 seconds to unload everything cleanly */
#define MAX_PASSES 15

	RWLIST_WRLOCK(&modules);
	/* Run the loop a max of 5 times. Always do it at least once, but then only if there are still skipped modules remaining.
	 * We really try our best here to unload all modules cleanly, but we can't try forever in case a module is just not unloading. */
	for (passes = 0 ; (passes == 0 || skipped) && passes < MAX_PASSES ; passes++) {
		unsigned int nodecount = bbs_node_count();
		struct bbs_module *mod, *lastmod = NULL; /* If passes > 0, do this so we don't try dlclosing a module twice */
		RWLIST_TRAVERSE(&modules, mod, entry) {
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
			if (mod->info->unload()) {
				/* Could actually still be cleaning up. Skip on this pass. */
				bbs_debug(2, "Module %s declined to unload, skipping on pass %d\n", mod->name, passes + 1);
				if (passes == 0) {
					skipped++; /* Only add to our count the first time. */
				}
				continue; /* Don't actually dlclose a module that refused to unload. */
			}
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
	struct bbs_module *mod;

	unload_modules_helper();

	/* Check for any modules still registered. */
	RWLIST_WRLOCK(&modules);
	RWLIST_TRAVERSE(&modules, mod, entry) {
		bbs_warning("Module %s still registered during BBS shutdown\n", mod->name);
	}
	RWLIST_UNLOCK(&modules);

	bbs_cli_unregister_multiple(cli_commands_modules);
	return 0;
}
