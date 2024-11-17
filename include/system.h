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
 * \brief System and shell stuff
 *
 */

/* Forward declarations */
struct bbs_node;

/* Execution settings */
struct bbs_exec_params {
	/* File descriptor priority is as follows, independently for STDIN/STDOUT:
	 * 1. If custom file descriptor provided (not -1), use that
	 * 2. If usenode is TRUE, use node file descriptor
	 * 3. Create pipes to discard STDIN/STDOUT, akin to /dev/null. */
	int fdin;					/* Custom file descriptor for STDIN to created process, node->fdin or -1 otherwise */
	int fdout;					/* Custom file descriptor for STDOUT from created process, node->fdout or -1 otherwise */
	int priority;				/* CPU priority */
	unsigned int usenode:1;		/* Whether to use the node for I/O. If FALSE, node will not be used for I/O */
	unsigned int isolated:1;	/* Whether to create the process in an isolated container */
	/* Container parameters */
	unsigned int net:1;			/* Retain network connectivity through the host, inside the container. Only applicable if isolated is TRUE. */
};

/* _HEADLESS suffix = Don't use node for I/O
 * _FD suffix = Use custom file descriptors for I/O */

/* Normal init, use node for I/O */
#define EXEC_PARAMS_INIT(x) \
	memset(&x, 0, sizeof(struct bbs_exec_params)); \
	x.usenode = 1; \
	x.fdin = -1; \
	x.fdout = -1; \

/* Running on a node, but use custom file descriptors for I/O */
#define EXEC_PARAMS_INIT_FD(x, in, out) \
	EXEC_PARAMS_INIT(x); \
	x.usenode = 0; /* Setting to 0 is still important, since if fdin or fdout is -1, we don't want to default to using node->fdin or node->fdout */ \
	x.fdin = in; \
	x.fdout = out;

/* No I/O whatsoever (effectively equivalent to > /dev/null < /dev/null) */
#define EXEC_PARAMS_INIT_HEADLESS(x) \
	EXEC_PARAMS_INIT(x); \
	x.usenode = 0;

/*! \brief Same as bbs_execvpe, but with no custom envp */
#define bbs_execvp(node, e, filename, argv) bbs_execvpe(node, e, filename, argv, NULL)

/*!
 * \brief Wrapper around execvpe(). This will fork(), then call execvp(), then wait for the child to exit.
 * \param node Node to use for I/O. If NULL, output will be written to a temporary pipe and logged, but otherwise discarded
 * \param e Execution parameters
 * \param filename Filename of program to execute (path is optional)
 * \param argv
 * \param envp Custom environment (optional)
 * \retval 0 on success, -1 on failure
 * \warning Do not call bbs_execvp from a node thread with NULL for node. Provide the node but set e->usenode to 0.
 */
#define bbs_execvpe(node, e, filename, argv, envp) __bbs_execvpe(node, e, filename, argv, envp, __FILE__, __LINE__, __func__)

int __bbs_execvpe(struct bbs_node *node, struct bbs_exec_params *e, const char *filename, char *const argv[], char *const envp[], const char *file, int lineno, const char *func)  __attribute__((nonnull (2, 3)));

/*!
 * \brief Parse a string into an argv. Similar to wordexp, but without the unnecessary (and insecure?) shell expansion overhead
 *        This function will separate on spaces, but keep a quoted argument together as a single argument.
 * \param[out] argv
 * \param argc Size of argv
 * \param s String to parse
 * \retval Value of argc (new argc + 1)
 */
int bbs_argv_from_str(char **argv, int argc, char *s);

/*! \brief Load system.conf config at startup */
int bbs_init_system(void);
