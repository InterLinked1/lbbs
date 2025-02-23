/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2025, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief UUID support
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#ifdef __linux__
#include <uuid/uuid.h> /* use uuid_generate, uuid_unparse */
#endif

#include "include/module.h"

#include "include/mod_uuid.h"

char *bbs_uuid(void)
{
#ifdef UUID_STR_LEN
	char *uuid;
	uuid_t binary_uuid;

	uuid_generate_random(binary_uuid);
	uuid = malloc(UUID_STR_LEN + 1);
	if (ALLOC_FAILURE(uuid)) {
		return NULL;
	}
	uuid_unparse_lower(binary_uuid, uuid);
	return uuid;
#else
	bbs_error("uuid not supported on this platform\n");
	return NULL;
#endif
}

static int unload_module(void)
{
	return 0;
}

static int load_module(void)
{
	return 0;
}

BBS_MODULE_INFO_FLAGS("UUID Support", MODFLAG_GLOBAL_SYMBOLS);
