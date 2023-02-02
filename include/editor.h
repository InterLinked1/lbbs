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
 * \brief Terminal editor: editor, paging, navigation, etc.
 *
 */

/* Forward declarations */
struct bbs_node;

/*!
 * \brief Invoke the BBS line editor. This is a primitive line editor that allows
 *        composition of a multiline message, but only allows editing the current line.
 *        Previous lines cannot be edited.
 *        The user can choose to process, abort, or continue at any time.
 * \param node
 * \param instr If non-NULL, a line of instructions to be displayed to the user. Do not terminate with LF.
 * \param buf Buffer in which input will be stored. Should be sufficiently large for its purpose.
 * \param line Size of buf
 * \retval -1 on disconnect, 0 on success (continue processing), 1 on abort (discard buffer)
 */
int bbs_line_editor(struct bbs_node *node, const char *instr, char *buf, size_t len);

struct pager_info {
	int line;
	int want;
	char *header;
	char *footer;
};

/*!
 * \brief Page through lines
 * \param node BBS node
 * \param pginfo pginfo struct
 * \param ms poll timeout
 * \param s Single line of output to display. Should not contain a new line. NULL if end of file.
 * \param len Length of s
 * \retval 2 on quit, 1 on timeout, 0 if input received, -1 on failure
 * \note The return values from this function are non-standard, please pay attention!
 */
int bbs_pager(struct bbs_node *node, struct pager_info *pginfo, int ms, const char *s, int len);

/*! \brief Display a file to a node */
int bbs_node_term_browse(struct bbs_node *node, const char *filename);
