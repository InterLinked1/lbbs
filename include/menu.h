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
 * \brief BBS menus
 *
 */

/*! \brief Default menu name is main */
#define DEFAULT_MENU "main"

/*! \brief Maximum number of times menus can recurse */
#define BBS_MAX_MENUSTACK 12

/*! \note We don't use 1-26 to save those for easy CTRL key shortcuts. This is ^^ */
#define MENU_REFRESH_KEY 30

/* Forward declaration for bbs_menu_run */
struct bbs_node;

/*!
 * \brief Run the BBS on a node
 * \param node
 * \retval -1 on error, 0 on successful user exit of the BBS main menu
 */
int bbs_node_menuexec(struct bbs_node *node);

/*! \brief Destroy all menus */
void bbs_free_menus(void);

/*! \brief Load or reload menus */
int bbs_load_menus(int reload);
