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
 * \brief Config parser
 *
 */

/* Forward declarations of opaque structs */
struct bbs_config;
struct bbs_config_section;
struct bbs_keyval;

/*!
 * \brief Log a log-message that pertains to a user's config file. This will log normally but may in the future also notify the user via a non-logging mechanism (e.g. email)
 * \param userid The user ID of the user whose config file this is, or 0 if this is not a user-facing error message
 * \param cfg The config file
 * \param userlevel Same as level, but the level to use for the end user as opposed to the BBS system logs.
 * \param level Log level. Can be any level except debug level, since debug levels would not be appropriate for an end-user anyways.
 * \param fmt printf-style format string
 */
#define bbs_user_config_log(userid, cfg, userlevel, level, fmt, ...) __bbs_user_config_log(__FILE__, __LINE__, __func__, userid, bbs_config_filename(cfg), userlevel, level, fmt, ## __VA_ARGS__)

/*! \brief Same as bbs_user_config_log, but operate directly on a config filename */
#define bbs_user_file_log(userid, file, userlevel, level, fmt, ...) __bbs_user_config_log(__FILE__, __LINE__, __func__, userid, file, userlevel, level, fmt, ## __VA_ARGS__)

void __attribute__ ((format (gnu_printf, 8, 9))) __bbs_user_config_log(const char *file, int line, const char *func, unsigned int userid, const char *filename, enum bbs_log_level userlevel, enum bbs_log_level level, const char *fmt, ...);

/*!
 * \brief Retrieve filename of config
 * \param cfg
 * \returns Config filename. May be relative or absolute depending on if it's a BBS system-wide or per-user config
 */
const char *bbs_config_filename(struct bbs_config *cfg);

/*!
 * \brief Retrieve a config setting
 * \param cfg
 * \param section_name Name of section
 * \param key Name of key
 * \retval value on success, NULL if section or key not found
 */
const char *bbs_config_val(struct bbs_config *cfg, const char *section_name, const char *key);

/*!
 * \brief Retrieve a config setting
 * \param section
 * \param key Name of key
 * \retval value on success, NULL if section or key not found
 */
const char *bbs_config_sect_val(struct bbs_config_section *section, const char *key);

/*!
 * \brief Set a string buffer with a value from a config setting
 * \param cfg
 * \param section_name Name of section
 * \param key Name of key
 * \param buf Buffer to fill
 * \param len Size of buffer
 * \retval 0 if set, -1 if not set (config value not found)
 */
int bbs_config_val_set_str(struct bbs_config *cfg, const char *section_name, const char *key, char *buf, size_t len);

/*!
 * \brief Set a string buffer with a directory path from a config setting
 * \param cfg
 * \param section_name Name of section
 * \param key Name of key
 * \param buf Buffer to fill
 * \param len Size of buffer
 * \retval 0 if set, -1 if not set (config value not found)
 * \note Trailing slash, if present, will be trimmed
 */
int bbs_config_val_set_path(struct bbs_config *cfg, const char *section_name, const char *key, char *buf, size_t len);

/*!
 * \brief Allocate a string with a value from a config setting
 * \param cfg
 * \param section_name Name of section
 * \param key Name of key
 * \param str Pointer to string variable to allocate if key exists
 * \retval 0 if set, -1 if not set (config value not found)
 */
int bbs_config_val_set_dstr(struct bbs_config *cfg, const char *section_name, const char *key, char **str);

/*!
 * \brief Set an integer with a value from a config setting
 * \param cfg
 * \param section_name Name of section
 * \param key Name of key
 * \param var int variable to set
 * \retval 0 if set, -1 if not set (config value not found)
 */
int bbs_config_val_set_int(struct bbs_config *cfg, const char *section_name, const char *key, int *var);

/*!
 * \brief Set an integer with an unsigned value from a config setting
 * \param cfg
 * \param section_name Name of section
 * \param key Name of key
 * \param var int variable to set
 * \retval 0 if set, -1 if not set (config value not found)
 */
int bbs_config_val_set_uint(struct bbs_config *cfg, const char *section_name, const char *key, unsigned int *var);

/*!
 * \brief Set a TCP/UDP port number from a config setting
 * \param cfg
 * \param section_name Name of section
 * \param key Name of key
 * \param var int variable to set
 * \retval 0 if set, -1 if not set (config value not found)
 */
int bbs_config_val_set_port(struct bbs_config *cfg, const char *section_name, const char *key, int *var);

/*!
 * \brief Set a true/false integer flag with a value from a config setting
 * \param cfg
 * \param section_name Name of section
 * \param key Name of key
 * \param var Pointer to integer
 * \retval 0 if set, -1 if not set (config value not found)
 */
int bbs_config_val_set_true(struct bbs_config *cfg, const char *section_name, const char *key, int *var);

/*!
 * \brief Get a specific config section by name
 * \param cfg
 * \param name Name of section
 * \return section if found
 * \param NULL if not found
 */
struct bbs_config_section *bbs_config_section_get(struct bbs_config *cfg, const char *name);

/*!
 * \brief Traverse a config section
 * \param section
 * \param keyval Previous key value pair. NULL to start at beginning.
 * \returns Next config key value pair
 */
struct bbs_keyval *bbs_config_section_walk(struct bbs_config_section *section, struct bbs_keyval *keyval);

/*!
 * \brief Traverse a config
 * \param cfg
 * \param section Previous config section. NULL to start at beginning.
 * \returns Next config section
 */
struct bbs_config_section *bbs_config_walk(struct bbs_config *cfg, struct bbs_config_section *section);

/*! \brief Get the key of a config key value pair */
const char *bbs_keyval_key(struct bbs_keyval *keyval);

/*! \brief Get the value of a config key value pair */
const char *bbs_keyval_val(struct bbs_keyval *keyval);

/*! \brief Get a config section's name */
const char *bbs_config_section_name(struct bbs_config_section *section);

/*!
 * \brief Destroy (free) a BBS config
 * \param cfg
 * \retval 0 on success, -1 on failure
 */
int bbs_config_free(struct bbs_config *cfg);

/*! \brief Destroy all existing configs (used at shutdown) */
void bbs_configs_free_all(void);

/*!
 * \brief Write a single particular key-value setting to a config file, adding if not present and overwriting existing value if already present
 * \param filename Config fil name
 * \param section Config section name in which to add or update setting
 * \param key Key name of setting to add or update
 * \param value Setting value to add or update
 * \retval 0 on success, -1 on failure
 */
int bbs_config_set_keyval(const char *filename, const char *section, const char *key, const char *value) __attribute__((nonnull (1, 2, 3, 4)));

/*!
 * \brief Check whether a config file has been updated since it was last parsed
 * \param name Config filename
 * \retval -1 if config file is not cached at all
 * \retval 0 if not modified since last parse
 * \retval 1 if modified since last parse
 */
int bbs_cached_config_outdated(const char *name);

/*!
 * \brief Return a BBS config object, parsing the config if necessary
 * \param name Config file name
 * \param usecache If config object exists, use cached version.
 *                 Configs that have not been parsed yet will always be parsed.
 *                 Specify 0 to always reparse configs.
 * \retval config on success, NULL on failure
 * \note The config is returned locked and must be unlocked with bbs_config_unlock
 */
struct bbs_config *bbs_config_load(const char *name, int usecache);

/*!
 * \brief Unlock a config when done with it
 */
int bbs_config_unlock(struct bbs_config *cfg);
