/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief JSON
 *
 */

#include <jansson.h>

#define json_object_string_value(json, key) (json_string_value(json_object_get(json, key)))
#define json_object_number_value(json, key) (json_number_value(json_object_get(json, key)))
#define json_object_int_value(json, key) ((int) json_object_number_value(json, key))
