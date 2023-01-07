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
 * \brief Key definitions
 *
 */

#define KEY_ESC 27

/*
 * These are taken directly from ncurses.h.
 * We don't include <ncurses.h>, even for these key definitions,
 * because some of the macros we use (e.g. COLOR_RED) conflict
 * with macros ncurses uses, in different ways than we use them. */
#define KEY_DOWN    0402        /* down-arrow key */
#define KEY_UP      0403        /* up-arrow key */
#define KEY_LEFT    0404        /* left-arrow key */
#define KEY_RIGHT   0405        /* right-arrow key */
#define KEY_HOME    0406        /* home key */
#define KEY_BACKSPACE   0407        /* backspace key */
#define KEY_F0      0410        /* Function keys.  Space for 64 */
#define KEY_F(n)    (KEY_F0+(n))    /* Value of function key n */
#define KEY_DL      0510        /* delete-line key */
#define KEY_IL      0511        /* insert-line key */
#define KEY_DC      0512        /* delete-character key */
#define KEY_IC      0513        /* insert-character key */
#define KEY_NPAGE   0522        /* next-page key */
#define KEY_PPAGE   0523        /* previous-page key */
#define KEY_ENTER   0527        /* enter/send key */
#define KEY_PRINT   0532        /* print key */
#define KEY_END     0550        /* end key */
