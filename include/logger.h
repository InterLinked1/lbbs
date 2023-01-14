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
 * \brief Top level header file for LBBS
 *
 */

/*! \brief Initialize logging */
int bbs_log_init(int nofork);

/*! \brief Shut down logging */
int bbs_log_close(void);

enum bbs_log_level {
	LOG_ERROR,
	LOG_WARNING,
	LOG_NOTICE,
	LOG_AUTH,
	LOG_VERBOSE,
	LOG_DEBUG,
};

#define bbs_auth(fmt, ...) __bbs_log(LOG_AUTH, 0, __FILE__, __LINE__, __FUNCTION__, fmt, ## __VA_ARGS__);
#define bbs_error(fmt, ...) __bbs_log(LOG_ERROR, 0, __FILE__, __LINE__, __FUNCTION__, fmt, ## __VA_ARGS__);
#define bbs_warning(fmt, ...) __bbs_log(LOG_WARNING, 0, __FILE__, __LINE__, __FUNCTION__, fmt, ## __VA_ARGS__);
#define bbs_notice(fmt, ...) __bbs_log(LOG_NOTICE, 0, __FILE__, __LINE__, __FUNCTION__, fmt, ## __VA_ARGS__);
#define bbs_verb(level, fmt, ...) __bbs_log(LOG_VERBOSE, level, __FILE__, __LINE__, __FUNCTION__, fmt, ## __VA_ARGS__);
#define bbs_debug(level, fmt, ...) __bbs_log(LOG_DEBUG, level, __FILE__, __LINE__, __FUNCTION__, fmt, ## __VA_ARGS__);

/*!
 * \brief Set BBS verbose level
 * \param newlevel Level between 0 and 10
 * \retval -1 on failure, non-negative old verbose level on success
 */
int bbs_set_verbose(int newlevel);

/*!
 * \brief Set BBS debug level
 * \param newlevel Level between 0 and 10
 * \retval -1 on failure, non-negative old debug level on success
 */
int bbs_set_debug(int newlevel);

/*!
 * \brief Enable or disable logging to STDOUT
 * \param enabled 1 to enable, 0 to disable
 * \note This only has an effect when BBS is started with -c option
 * \retval 0 on success, -1 on failure
 */
int bbs_set_stdout_logging(int enabled);

/*!
 * \brief Thread-safe printf wrapper
 * \note This will always flush stdout if fd == STDOUT_FILENO
 */
void __attribute__ ((format (gnu_printf, 1, 2))) bbs_printf(const char *fmt, ...);

/*!
 * \brief Thread-safe dprintf wrapper
 * \note This will always flush stdout if fd == STDOUT_FILENO
 */
void __attribute__ ((format (gnu_printf, 2, 3))) bbs_dprintf(int fd, const char *fmt, ...);

void __attribute__ ((format (gnu_printf, 6, 7))) __bbs_log(enum bbs_log_level loglevel, int level, const char *file, int lineno, const char *func, const char *fmt, ...);

/*! \brief Clear screen */
#define TERM_CLEAR "\e[1;1H\e[2J"

#define TERM_ERASE_LINE "\33[2K"

/*! \brief Clear and reset cursor to beginning of current line */
#define TERM_RESET_LINE TERM_ERASE_LINE "\r"

#define TERM_TITLE_FMT "\033]2;%s\007"

/*! \brief Ring the bell on the TTY/terminal */
#define TERM_BELL "\a"

/*! \brief Format string for a specified color, that can be used directly as a string argument to a printf-style function */
#define COLOR(color) COLOR_START color COLOR_BEGIN

#define COLOR_START "\033[1;"
#define COLOR_BEGIN "m"
#define COLOR_RESET "\033[0m"

/*! \name Terminal Colors
 *
 * @{
 */
#define COLOR_BLACK     "30"
#define COLOR_RED       "31"
#define COLOR_GREEN     "32"
#define COLOR_BROWN     "33"
#define COLOR_BLUE      "34"
#define COLOR_MAGENTA   "35"
#define COLOR_CYAN      "36"
#define COLOR_WHITE     "37"
