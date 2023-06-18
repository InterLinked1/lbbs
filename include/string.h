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
 * \brief String utility functions
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/*!
 * \brief Get the printable length of a string (how many columns it would take up on a terminal)
 * \param s String
 * \returns Number of columns the string will occupy on a terminal
 * \warning This function cannot be accurate for all possible characters, e.g. TAB, whose number of cols occupied depends entirely on location on the terminal.
 */
int bbs_printable_strlen(const char *restrict s);

/*!
 * \brief Process backspaces and deletes in a stream of characters and output the new result
 * \note Mainly needed because not all terminal emulators behave the same way, some like SyncTERM are more broken when it comes to backspace handling. PuTTY/KiTTY don't need this.
 * \param s Original input string
 * \param buf Output buffer
 * \param len Size of buf. Should be exactly as large as the original length of s, but larger is unnecessary
 * \retval 0 on success, -1 on failure (truncation)
 */
int bbs_str_process_backspaces(const char *restrict s, char *restrict buf, size_t len);

/*!
 * \brief Create a safely printable representation of a string (for debugging or dumping).
 *        The string created, when printed, will not contain any escape sequences or formatting.
 * \param s Original string (containing potentially "unsafe" characters, e.g. CR, LF, ESC, and other formatting or control chars)
 * \param buf Buffer
 * \param len Size of buf
 * \retval 0 on success, -1 on failure/truncation
 */
int bbs_str_safe_print(const char *restrict s, char *restrict buf, size_t len);

/*! \brief Dump an ASCII representation of a string to the BBS debug log level */
void bbs_dump_string(const char *restrict s);

/*! \brief Dump an hex representation of a buffer to the BBS debug log level */
void bbs_dump_mem(unsigned const char *restrict s, size_t len);

/*!
 * \brief Get the number of instances of a character in a NUL-terminated string
 * \param s String
 * \param c Character of interest
 * \return Number of instances
 */
int bbs_str_count(const char *restrict s, char c);

/*!
 * \brief Get the number of instances of a character in a region of memory
 * \param s String
 * \param len Number of bytes to search
 * \param c Character of interest
 * \return Number of instances
 */
int bbs_strncount(const char *restrict s, size_t len, char c);

/*!
 * \brief Terminate a string at the end of the first line (first CR or LF character)
 * \param c
 * \return New string length
 * \note This is equivalent to calling bbs_strterm(c, '\r'); bbs_strterm(c, '\n'); return strlen(c);
 */
int bbs_term_line(char *restrict c);

/*!
 * \brief Size-limited null-terminating string copy.
 * \param dst The destination buffer.
 * \param src The source string
 * \param size The size of the destination buffer
 * This is similar to \a strncpy, with two important differences:
 * - the destination buffer will \b always be null-terminated
 * - the destination buffer is not filled with zeros past the copied string length
 * These differences make it slightly more efficient, and safer to use since it will
 * not leave the destination buffer unterminated. There is no need to pass an artificially
 * reduced buffer size to this function (unlike \a strncpy), and the buffer does not need
 * to be initialized to zeroes prior to calling this function.
 */
void safe_strncpy(char *restrict dst, const char *restrict src, size_t size) __attribute__((nonnull (1,2)));

/*!
 * \brief Copy s into buf, except for any whitespace characters
 * \param s Original string
 * \param[out] buf
 * \param len Length of bug
 * \retval 0 on success, -1 on failure (truncation)
 */
int bbs_strcpy_nospaces(const char *restrict s, char *restrict buf, size_t len);

/*!
 * \brief Remove a substring from a string in place
 * \param s String to modify
 * \param word Substring of which instances will be removed
 * \param wordlen Length of word
 */
void bbs_str_remove_substring(char *restrict s, const char *word, size_t wordlen);

/*!
 * \brief Replace all instances of character in a string with another character
 * \param s String in which to perform replacements
 * \param find Character that should be replaced
 * \param repl Character that will replace any matched characters
 */
void bbs_strreplace(char *restrict s, char find, char repl);

/*!
 * \brief Whether all characters in a string are printable (spaces are included)
 * \param s String to check
 * \retval 1 if yes, 0 if no
 */
int bbs_str_isprint(const char *restrict s);

/*!
 * \brief Whether a string contains some non-space printable character
 * \param s String to check
 * \retval 1 if yes, 0 if no
 */
int bbs_str_anyprint(const char *restrict s);

/*! \brief Convert a string to all lowercase */
void str_tolower(char *restrict s);

/*!
 * \brief Skip a number of occurences of a character in a string
 * \param str
 * \param c Character of interest
 * \param n Number of times to skip
 * \retval Number of instances of character skipped
 */
int skipn(char **str, char c, int n);

/*! \brief Same as skipn, but don't include spaces inside a parenthesized list */
int skipn_noparen(char **str, char c, int n);

/*!
 * \brief strsep-like tokenizer that returns the contents of the next substring inside parentheses (handling nested parentheses)
 * \param str
 * \return Substring inside the next outer set of parentheses. str will point to the next unparsed character.
 */
char *parensep(char **str);

/*!
 * \brief strsep-like tokenizer that returns the contents of the next substring inside quotes
 * \param str
 * \return Substring inside the next outer set of double quotes. str will point to the next unparsed character.
 * \note Nested quotes are not supported
 */
char *quotesep(char **str);
