/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 */

/*! \file
 *
 * \brief Module loader and unloader
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

enum bbs_module_flags {
	MODFLAG_DEFAULT = 0,
	MODFLAG_GLOBAL_SYMBOLS = (1 << 0), /* Module exports global symbols */
};

struct bbs_module_info {
	/*!
	 * The 'self' pointer for a module; it will be set by the loader before
	 * it calls the module's load_module() entrypoint, and used by various
	 * other macros that need to identify the module.
	 */
	struct bbs_module *self;
	/*! Register stuff etc. Optional. */
	int (*load)(void);
	/*! Config etc. Optional. */
	int (*reload)(void);
	/*! Unload. called with the module locked */
	int (*unload)(void);
	/*! Name of the module for loader reference and CLI commands */
	const char *name;
	/*! User friendly description of the module. */
	const char *description;
	/*! Module dependencies */
	const char *dependencies;
	/*! Module loading flags */
	unsigned int flags;
};

/*! \brief Get name of a module */
const char *bbs_module_name(const struct bbs_module *mod);

/*!
 * \brief Whether this module is currently being unloaded
 * \retval 1 if unload actively being attempted
 * \retval 0 if not
 */
#define bbs_module_is_unloading() __bbs_module_is_unloading(BBS_MODULE_SELF)

int __bbs_module_is_unloading(struct bbs_module *mod);

/*!
 * \brief Whether this module is currently being unloaded and/or the BBS is shutting down
 * \retval 1 if unload or shutdown actively being attempted
 * \retval 0 if not
 */
#define bbs_module_is_shutting_down() __bbs_module_is_shutting_down(BBS_MODULE_SELF)

int __bbs_module_is_shutting_down(struct bbs_module *mod);

/*!
 * \brief Get load time of this module
 * \return Module load time in epoch time
 */
#define bbs_module_load_time() __bbs_module_load_time(BBS_MODULE_SELF)

time_t __bbs_module_load_time(struct bbs_module *mod);

/*!
 * \brief Increment ref count of a module
 * \param mod
 * \param pairid A positive unique ID only used once in a source file for a corresponding ref/unref sequence.
 */
#define bbs_module_ref(mod, pairid) __bbs_module_ref(mod, pairid, BBS_MODULE_SELF, __FILE__, __LINE__, __func__)

struct bbs_module *__bbs_module_ref(struct bbs_module *mod, int pair, void *refmod, const char *file, int line, const char *func);

/*!
 * \brief Decrement ref count of a module
 * \param mod
 * \param pairid A positive unique ID only used once in a source file for a corresponding ref/unref sequence.
 */
#define bbs_module_unref(mod, pairid) __bbs_module_unref(mod, pairid, BBS_MODULE_SELF, __FILE__, __LINE__, __func__)

void __bbs_module_unref(struct bbs_module *mod, int pair, void *refmod, const char *file, int line, const char *func);

/*!
 * \brief Indicate that the calling module is dependent on the specified module.
 * \retval module reference on success, NULL on failure
 * \note On module close, you must call bbs_unrequire_module with the returned reference
 */
#define bbs_require_module(module) __bbs_require_module(module, BBS_MODULE_SELF)

struct bbs_module *__bbs_require_module(const char *module, void *refmod);

/*! \brief Indicate that this module is no longer dependent on the specified module. */
void __bbs_unrequire_module(struct bbs_module *mod, void *refmod);

/*! \brief Register a module */
void bbs_module_register(const struct bbs_module_info *modinfo);

/*! \brief Unregister a module */
void bbs_module_unregister(const struct bbs_module_info *modinfo);

/*!
 * \brief Load a dynamic module by name
 * \param name Module name, with or without .so extension
 * \retval 0 on success, -1 on failure
 */
int bbs_module_load(const char *name);

/*!
 * \brief Unload a dynamic module by name
 * \param name Module name, with or without .so extension
 * \retval 0 on success, -1 on failure
 */
int bbs_module_unload(const char *name);

/*!
 * \brief Unload and load again a dynamic module by name
 * \param name Module name with or without .so extension
 * \param try_delayed Whether to queue a delayed reload if a reload cannot be completed now.
 *        The reload will be processed once the ref count of the module hits 0.
 * \retval 0 on success
 * \retval -1 on failure (including if a reload was queued)
 */
int bbs_module_reload(const char *name, int try_delayed);

/*! \brief Autoload all modules */
int load_modules(void);

/*! \brief Auto unload all modules */
int unload_modules(void);

#define REQUIRE_FULL_LOAD(res) if (unlikely(res)) { unload_module(); } return res;

/* forward declare this pointer in modules, so that macro/function
	calls that need it can get it, since it will actually be declared
   and populated at the end of the module's source file... */
#if !defined(BBS_IN_CORE)
static const __attribute__((unused)) struct bbs_module_info *bbs_module_info;
#endif

#define BBS_MODULE_INFO(flags_to_set, desc, ...)	\
	static struct bbs_module_info 				\
		__mod_info = {					\
		.name = BBS_MODULE,				\
		.flags = flags_to_set,				\
		.description = desc,				\
		__VA_ARGS__						\
	};						\
	static void  __attribute__((constructor)) __reg_module(void) \
	{ \
		bbs_module_register(&__mod_info); \
	} \
	static void  __attribute__((destructor)) __unreg_module(void) \
	{ \
		bbs_module_unregister(&__mod_info); \
	}                                                             \
	struct bbs_module *BBS_MODULE_SELF_SYM(void)                       \
	{                                                                  \
		return __mod_info.self;                                        \
	}                                                                  \
	static const struct bbs_module_info *bbs_module_info = &__mod_info

/* In theory, the 2 dependency cases are not mutually exclusive.
 * For example, a module could have a dependency on another module,
 * and itself also have dependents (other modules depend on it).
 * But so far, that case hasn't happened, so this simplifies things for now. */

/* For most modules */
#define BBS_MODULE_INFO_STANDARD(desc)	 \
	BBS_MODULE_INFO(0, desc,   			\
		.load = load_module,			\
		.unload = unload_module,		\
		.dependencies = NULL,			\
	)

/* For modules that depend on other modules */
#define BBS_MODULE_INFO_DEPENDENT(desc, dependencylist)	 \
	BBS_MODULE_INFO(0, desc,   				\
		.load = load_module,				\
		.unload = unload_module,			\
		.dependencies = dependencylist,		\
	)

#define BBS_MODULE_INFO_FLAGS_DEPENDENT(desc, flags, dependencylist)	 \
	BBS_MODULE_INFO(flags, desc,   				\
		.load = load_module,				\
		.unload = unload_module,			\
		.dependencies = dependencylist,		\
	)

/* For modules that are depended upon by other modules */
#define BBS_MODULE_INFO_FLAGS(desc, flags)	 \
	BBS_MODULE_INFO(flags, desc,   			\
		.load = load_module,				\
		.unload = unload_module,			\
		.dependencies = NULL,				\
	)
