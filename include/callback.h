/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief Module Callbacks
 *
 */

/* Needed for pthread_rwlock_t */
#include <pthread.h>

struct bbs_singular_callback {
	pthread_rwlock_t lock;	/*!< Read/write lock for callback function */
	void *mod;				/*!< Module that registered the callback */
	/* It's temping to just use void * as the type for the callback function,
	 * and store it here - and this works for all usage of this API itself.
	 * However, this poses a problem when trying to execute the callback,
	 * and we also want type checking for the right number (and correct type)
	 * of arguments. We could cast the void pointer back to the type
	 * of the function, but that's rather messy to use in practice.
	 * Therefore, we actually store the callback function pointer
	 * in the calling source file, and store the pointer to the pointer in this struct,
	 * but make this indirection transparent to callers using some macros. */
	void *func_pointer_ptr;	/*!< Callback function */
	unsigned int initialized:1;
};

/*! \note We cannot use memset with the above struct, to avoid overwriting scb->func_pointer_ptr,
 * which is already set at this point, thanks to BBS_SINGULAR_CALLBACK_DECLARE.
 * Thus, we explicitly initialize each member in the below macro.
 *
 * To make the interface as simple as possible, we statically initialize the rwlock.
 */

/* == Function variants == */

/*!
 * \brief Declare a singularly provided callback function and its interface
 * \param name Unique variable name
 * \param returntype The return type of the callback function
 * \param ... Variadic arguments for each callback function parameter
 */
#define BBS_SINGULAR_CALLBACK_DECLARE(name, returntype, ...) \
	static returntype (*__ ## name ## _cb_func)(__VA_ARGS__) = NULL; \
	static struct bbs_singular_callback name = { \
		.func_pointer_ptr = &__ ## name ## _cb_func, \
		.mod = NULL, \
		.lock = PTHREAD_RWLOCK_INITIALIZER \
	};

/*!
 * \brief Get the pointer to the callback function
 * \param name Same name provided to BBS_SINGULAR_CALLBACK_DECLARE
 * \return Function pointer
 */
#define BBS_SINGULAR_CALLBACK_EXECUTE(name) __ ## name ## _cb_func

/* == Struct variants (struct pointer, instead of function pointer (the dereferenced struct contains function pointers)) == */
/* Since we're storing the function pointer as void, we can just store the struct pointer there instead */

#define BBS_SINGULAR_STRUCT_CALLBACK_DECLARE(name, structtype) \
	static struct structtype (*__ ## name ## _cb_struct) = NULL; \
	static struct bbs_singular_callback name = { \
		.func_pointer_ptr = &__ ## name ## _cb_struct, \
		.mod = NULL, \
		.lock = PTHREAD_RWLOCK_INITIALIZER \
	};

/*!
 * \brief Get the pointer to the struct of callbacks
 * \param name Same name provided to BBS_SINGULAR_STRUCT_CALLBACK_DECLARE
 * \return Function pointer
 */
#define BBS_SINGULAR_STRUCT_CALLBACK_EXECUTE(name) __ ## name ## _cb_struct

/*!
 * \brief Destroy a bbs_singular_callback
 * \param scb
 * \retval 0 on success, -1 on failure
 * \note There is no corresponding initialize function, since initialization is static.
 *       To be "correct", this function SHOULD be called, particularly from dynamic modules,
 *       but this interface was designed such that not calling this from core files won't matter.
 */
int bbs_singular_callback_destroy(struct bbs_singular_callback *scb) __attribute__((nonnull (1)));

int __bbs_singular_callback_register(struct bbs_singular_callback *scb, void *cbptr, void *mod, const char *file, int line, const char *func) __attribute__((nonnull (1,2)));;

/*!
 * \brief Register a singularly provided callback
 * \param scb
 * \param cbptr Callback function
 * \param mod Providing module
 * \retval 0 if callback registered
 * \retval -1 callback not registered (already another callback registered)
 * \warning Because this API uses a void pointer to allow any function pointer, the function prototype
 *          MUST be validated by the calling function, to prevent ABI hanky panky.
 */
#define bbs_singular_callback_register(scb, cbptr, mod) __bbs_singular_callback_register(scb, cbptr, mod, __FILE__, __LINE__, __func__)

int __bbs_singular_callback_unregister(struct bbs_singular_callback *scb, void *cbptr, const char *file, int line, const char *func) __attribute__((nonnull (1,2)));

/*!
 * \brief Unregister a singularly provided callback
 * \param scb
 * \param cbptr Callback function to unregister
 */
#define bbs_singular_callback_unregister(scb, cbptr) __bbs_singular_callback_unregister(scb, cbptr, __FILE__, __LINE__, __func__)

/*!
 * \brief Check whether a callback function is registered
 * \param scb
 * \retval 1 if callback function currently registered
 * \retval 0 if no callback function currently registered
 */
int bbs_singular_callback_registered(struct bbs_singular_callback *scb);

int __bbs_singular_callback_execute_pre(struct bbs_singular_callback *scb, void *refmod, const char *file, int line, const char *func);

/*!
 * \param Begin executing a singularly provided callback function
 * \param scb
 * \retval 0 on success (okay to execute callback function)
 * \retval -1 on failure
 * \warning UNDER NO CIRCUMSTANCES should the callback function be executed if this function returns failure
 */
#define bbs_singular_callback_execute_pre(scb) __bbs_singular_callback_execute_pre(scb, BBS_MODULE_SELF, __FILE__, __LINE__, __func__)

int __bbs_singular_callback_execute_post(struct bbs_singular_callback *scb, void *refmod, const char *file, int line, const char *func);

/*!
 * \param Stop executing a singularly provided callback function
 * \param scb
 * \retval 0 on success, -1 on failure
 * \warning This function MUST be called after finish execution of the callback
 */
#define bbs_singular_callback_execute_post(scb) __bbs_singular_callback_execute_post(scb, BBS_MODULE_SELF, __FILE__, __LINE__, __func__)
