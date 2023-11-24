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
 * \brief Graphical text menus
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#define MAX_NCURSES_MENU_OPTIONS 64

struct bbs_ncurses_menu {
	const char *title;
	const char *subtitle;
	const char *keybindings;
	char keybind[MAX_NCURSES_MENU_OPTIONS];
	char *options[MAX_NCURSES_MENU_OPTIONS];
	char *optvals[MAX_NCURSES_MENU_OPTIONS];
	int num_options;
};

/*!
 * \brief Initialize a menu. You must call this before using it in any way.
 */
void bbs_ncurses_menu_init(struct bbs_ncurses_menu *menu);

/*! \brief Destroy a menu when done with it */
void bbs_ncurses_menu_destroy(struct bbs_ncurses_menu *menu);

/*!
 * \brief Set the title of a menu
 * \param menu
 * \param title Menu title. Must remain valid throughout the lifetime of menu.
 */
void bbs_ncurses_menu_set_title(struct bbs_ncurses_menu *menu, const char *title);

/*!
 * \brief Set the subtitle of a menu
 * \param menu
 * \param subtitle Menu subtitle. Must remain valid throughout the lifetime of menu.
 */
void bbs_ncurses_menu_set_subtitle(struct bbs_ncurses_menu *menu, const char *subtitle);

/*!
 * \brief Disable custom key bindings. A default 'q' option will still be added to quit.
 * \param menu
 */
void bbs_ncurses_menu_disable_keybindings(struct bbs_ncurses_menu *menu);

/*!
 * \brief Add an option to a menu
 * \param menu
 * \param key Key binding. Specify 0 for no key binding.
 * \param opt Will be duplicated.
 * \param value Will be duplicated.
 * \retval -1 on failure, 0 on success
 */
int bbs_ncurses_menu_addopt(struct bbs_ncurses_menu *menu, char key, const char *opt, const char *value)  __attribute__ ((nonnull (1, 3)));

/*!
 * \brief Get the option value of a menu item at a particular index
 * \param menu
 * \param index
 * \return NULL on failure or invalid index
 * \return Option value
 */
const char *bbs_ncurses_menu_getopt_name(struct bbs_ncurses_menu *menu, int index);

/*!
 * \brief Get the keybinding of a menu item at a particular index
 * \param menu
 * \param index
 * \return 0 on failure or invalid index
 * \return Key binding
 */
char bbs_ncurses_menu_getopt_key(struct bbs_ncurses_menu *menu, int index);

/*!
 * \brief Get an option using a menu (pass to bbs_ncurses_menu_getopt_name for the text value)
 * \param node
 * \param menu
 * \retval -1 on failure, option index otherwise
 */
int bbs_ncurses_menu_getopt(struct bbs_node *node, struct bbs_ncurses_menu *menu);

/*!
 * \brief Run a menu and return the keybinding for the chosen option.
 *        This is a convenience wrapper that calls bbs_ncurses_menu_getopt
 *        and then calls bbs_ncurses_menu_getopt_key on the result, if there is one.
 * \param node
 * \param menu
 * \return Same as bbs_ncurses_menu_getopt_key
 */
char bbs_ncurses_menu_getopt_selection(struct bbs_node *node, struct bbs_ncurses_menu *menu);
