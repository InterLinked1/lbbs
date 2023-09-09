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
 * \brief BBS doors
 *
 */

/* Forward declarations */
struct bbs_node;
struct bbs_module;

#define DOOR_PARAMS struct bbs_node *node, const char *args

/*! \brief Registers a door
 * \param name Name of door (must be unique globally)
 * \param exec Function
 * \retval 0 on success
 * \retval -1 on failure
 */
#define bbs_register_door(name, exec) __bbs_register_door(name, exec, BBS_MODULE_SELF)

int __bbs_register_door(const char *name, int (*execute)(DOOR_PARAMS), void *mod);

/*! \brief Unregister a door */
int bbs_unregister_door(const char *name);

/*!
 * \brief Execute a named door
 * \param node
 * \param name Name of door
 * \param args Optional door arguments
 * \retval 0 on success, -1 on failure
 */
int bbs_door_exec(struct bbs_node *node, const char *name, const char *args);

/*! \brief Initialize doors */
int bbs_init_doors(void);
