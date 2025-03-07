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
 * \brief Sysop CLI commands
 *
 */

/* Forward declarations */
struct bbs_module;

/* Only for use by mod_sysop and cli.c */
#define bbs_cli_set_stdout_logging(fdout, setting) if (fdout == STDOUT_FILENO) { bbs_set_stdout_logging(setting); } else { bbs_set_fd_logging(fdout, setting); }

struct bbs_cli_args {
	int fdin;			/*!< Console input file descriptor */
	int fdout;			/*!< Console output file descriptor */
	int argc;			/*!< Number of arguments, including command name */
	const char *command;	/* Entire command as a single string */
	const char **argv;	/*!< Actual arguments */
};

struct bbs_cli_entry {
	int (*handler)(struct bbs_cli_args *a);								/*!< Command handler */
	const char *command;												/*!< Command name. Must be prefix-free amongst all CLI commands. */
	int minargc;														/*!< Minimum number of arguments required. */
	const char *description;											/*!< Command description */
	const char *usage;													/*!< Command usage */
};

#define BBS_CLI_COMMAND_SINGLE(handler, command, minfds, description, usage) \
	static struct bbs_cli_entry cli_command = { \
		handler, command, minfds, description, usage \
	};

#define BBS_CLI_COMMAND(handler, command, minfds, description, usage) { handler, command, minfds, description, usage }

int __bbs_cli_register(struct bbs_cli_entry *e, struct bbs_module *mod);

int __bbs_cli_register_multiple(struct bbs_cli_entry *e, size_t len, struct bbs_module *mod);

/*!
 * \brief Register a sysop CLI command
 * \param cmd
 * \retval 0 on success, -1 on failure
 */
#define bbs_cli_register(cmd) __bbs_cli_register(cmd, BBS_MODULE_SELF)

/*!
 * \brief Register multiple sysop CLI commands
 * \param cmds
 * \retval 0 on success, -1 on failure
 */
#define bbs_cli_register_multiple(cmds) __bbs_cli_register_multiple(cmds, ARRAY_LEN(cmds), BBS_MODULE_SELF)

/*!
 * \brief Unregister a sysop CLI command
 * \param cmd
 * \retval 0 on success, -1 on failure
 */
int bbs_cli_unregister(struct bbs_cli_entry *e);

/*!
 * \brief Unregister multiple sysop CLI commands
 * \param cmds
 * \retval 0 on success, -1 on failure
 */
#define bbs_cli_unregister_multiple(cmds) __bbs_cli_unregister_multiple(cmds, ARRAY_LEN(cmds))

int __bbs_cli_unregister_multiple(struct bbs_cli_entry *e, size_t len);

/*!
 * \brief Initialize CLI
 * \retval 0 on success, -1 on failure
 */
int bbs_cli_load(void);

/*!
 * \brief Unregister remaining core CLI commands at shutdown
 * \retval 0
 */
int bbs_cli_unregister_remaining(void);

/*!
 * \brief Execute a CLI command
 * \param fdin Input file descriptor of sysop console.
 * \param fdout Output file descriptor of sysop console.
 * \param s Command to execute.
 * \retval 0 if CLI command returns 0 (success)
 * \retval -1 if CLI command returns -1 (failure)
 * \retval EINVAL if s is empty
 * \retval ENOENT if no such CLI command exists
 */
int bbs_cli_exec(int fdin, int fdout, const char *s);
