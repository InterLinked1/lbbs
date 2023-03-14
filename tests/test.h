/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 */

/*! \file
 *
 * \brief Test Framework Modules
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#define BBS_TEST_FRAMEWORK

#if defined(TEST_IN_CORE) || (!defined(TEST_MODULE_SELF_SYM) && (defined(STANDALONE) || defined(STANDALONE2) || defined(TEST_NOT_MODULE)))
#define TEST_MODULE_SELF NULL
#elif defined(TEST_MODULE_SELF_SYM)
/*! Retrieve the 'struct test_module *' for the current module. */
#define TEST_MODULE_SELF TEST_MODULE_SELF_SYM()
struct test_module;
/* Internal/forward declaration, TEST_MODULE_SELF should be used instead. */
struct test_module *TEST_MODULE_SELF_SYM(void);
#else
#error "Externally compiled modules must declare TEST_MODULE_SELF_SYM."
#endif

/* Don't be fooled.
 * This program is not linked to the main BBS binary,
 * so arbitrarily including headers for the BBS
 * generally won't be useful.
 * However, bbs.h contains lots of convenience macros
 * that we can certainly use here as well. */
#include "include/bbs.h"

/* Allow the use of dprintf */
#undef dprintf
#undef pthread_create
#undef pthread_join
#undef strcat

/* Don't allow bbs_verb */
#undef bbs_verb

#define LBBS_BINARY "/usr/sbin/lbbs"
#define TEST_CONFIG_DIR "/tmp/test_lbbs_etc"

/* Yuck, but why reinvent the wheel */
#define TEST_ADD_CONFIG(filename) system("cp " filename " " TEST_CONFIG_DIR)

#define TEST_HOSTNAME "bbs.example.com"

#define TEST_EMAIL_UNAUTHORIZED "unauthorized" "@" TEST_HOSTNAME

#define TEST_USER "testuser"
#define TEST_PASS "P@ssw0rd"
#define TEST_HASH "$2y$10$1vtttulZgw5Sz.Ks8PePFumnPCztHfp0YzgHLnuIQ1vAb0mSQpv2q"
#define TEST_SASL "dGVzdHVzZXIAdGVzdHVzZXIAUEBzc3cwcmQ="
#define TEST_EMAIL TEST_USER "@" TEST_HOSTNAME

#define TEST_USER2 "testuser2"
#define TEST_PASS2 "P@ssw0rD"
#define TEST_HASH2 "$2y$10$0hcFFDyIUBkNcqMPw9G0t.vR.c8oBArJJOE1tK1atcPWkk9XBhvzK"
#define TEST_SASL2 "dGVzdHVzZXIyAHRlc3R1c2VyMgBQQHNzdzByRA=="
#define TEST_EMAIL2 TEST_USER2 "@" TEST_HOSTNAME

#define ENDL "\r\n"

int test_bbs_expect(const char *s, int ms);

int test_add_module(const char *module);

int test_make_socket(int port);

int test_client_expect(int fd, int ms, const char *s, int line);
int test_client_expect_eventually(int fd, int ms, const char *s, int line);

#define CLIENT_EXPECT(fd, s) if (test_client_expect(fd, SEC_MS(1), s, __LINE__)) { goto cleanup; }
#define CLIENT_EXPECT_EVENTUALLY(fd, s) if (test_client_expect_eventually(fd, SEC_MS(1), s, __LINE__)) { goto cleanup; }

struct test_module_info {
	struct test_module *self;
	int (*pre)(void);
	int (*run)(void);
	const char *name;
	const char *description;
	unsigned int flags;
};

void test_module_register(const struct test_module_info *modinfo);

void test_module_unregister(const struct test_module_info *modinfo);

#if !defined(TEST_IN_CORE)
static const __attribute__((unused)) struct test_module_info *test_module_info;
#endif

#define TEST_MODULE_INFO(flags_to_set, desc, fields...)	\
	static struct test_module_info 				\
		__mod_info = {					\
		.name = TEST_MODULE,				\
		.flags = flags_to_set,				\
		.description = desc,				\
		fields						\
	};						\
	static void  __attribute__((constructor)) __reg_module(void) \
	{ \
		test_module_register(&__mod_info); \
	} \
	static void  __attribute__((destructor)) __unreg_module(void) \
	{ \
		test_module_unregister(&__mod_info); \
	}                                                             \
	struct test_module *TEST_MODULE_SELF_SYM(void)                       \
	{                                                                  \
		return __mod_info.self;                                        \
	}                                                                  \
	static const struct test_module_info *test_module_info = &__mod_info

/* In theory, the 2 dependency cases are not mutually exclusive.
 * For example, a module could have a dependency on another module,
 * and itself also have dependents (other modules depend on it).
 * But so far, that case hasn't happened, so this simplifies things for now. */

/* For most modules */
#define TEST_MODULE_INFO_STANDARD(desc)	 \
	TEST_MODULE_INFO(0, desc,   			\
		.pre = pre,			\
		.run = run,			\
	)
