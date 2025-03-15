/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Abstract I/O transformations interface
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <sys/ioctl.h> /* use FIONREAD, TIOCOUTQ */

#include "include/linkedlists.h"
#include "include/module.h"
#include "include/io.h"
#include "include/cli.h"
#include "include/utils.h" /* use print_time_elapsed */

#include "include/node.h" /* for setting node->rfd and node->wfd */

/* Unlike most I/O stream abstractions, such as OpenSSL's BIO,
 * Dovecot's read/write streams, and libetpan's "low" interface,
 * this is not a truly abstract I/O interface.
 * It is an interface that is highly coupled to file descriptors,
 * since much of the I/O in the BBS is currently written to depend on that.
 * While it would be more performant to be able to call I/O callback functions
 * that could, for example, call SSL_write directly under the hood,
 * rather than first writing to a pipe which is then drained in another
 * thread and passed to SSL_write, at this point, it would require
 * substantial work to refactor everything not to use file descriptors directly,
 * since initially it was only needed for TLS and nothing else.
 *
 * This abstraction is still useful, since instead of keeping track
 * of multiple read/write file descriptors, we can continue to only
 * use one and I/O modules will be responsible for setting up their
 * own intermediate layer. This also allows for modularity since
 * dependencies for particular kinds of I/O transformations (e.g. TLS, compression)
 * need not be embedded in the core, but can be implemented in their own modules.
 */

struct bbs_io_transformer {
	const char *name;
	enum bbs_io_transform_type type;
	enum bbs_io_transform_dir dir;
	struct bbs_io_transformer_functions *funcs;
	void *module;
	RWLIST_ENTRY(bbs_io_transformer) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(transformers, bbs_io_transformer);

/* Linked list of struct bbs_io_transformations (every active I/O session) */
struct io_session {
	struct bbs_io_transformations *s;
	unsigned int id;
	time_t start;
	enum bbs_io_session_type type;
	void *owner;
	RWLIST_ENTRY(io_session) entry;
};

static const char *session_type_name(enum bbs_io_session_type type)
{
	switch (type) {
		case TRANSFORM_SESSION_NODE: return "Node";
		case TRANSFORM_SESSION_TCPCLIENT: return "TCP Client";
	}
	__builtin_unreachable();
}

static RWLIST_HEAD_STATIC(sessions, io_session);
static unsigned int io_session_io = 0;

int bbs_io_session_register(struct bbs_io_transformations *s, enum bbs_io_session_type type, void *owner)
{
	struct io_session *i;

	RWLIST_WRLOCK(&sessions);
	RWLIST_TRAVERSE(&sessions, i, entry) {
		if (i->s == s) {
			/* Session already exists in linked list, already registered */
			bbs_warning("Session %u is already registered\n", i->id);
			RWLIST_UNLOCK(&sessions);
			return -1;
		}
	}
	/* Need to add to list */
	i = calloc(1, sizeof(*i));
	if (ALLOC_SUCCESS(i)) {
		i->s = s;
		i->id = ++io_session_io; /* This is an abitrary unique ID assigned so we can identify it from the CLI */
		i->start = time(NULL);
		i->type = type;
		i->owner = owner;
		RWLIST_INSERT_TAIL(&sessions, i, entry);
	}
	RWLIST_UNLOCK(&sessions);
	return i ? 0 : -1;
}

int bbs_io_session_unregister(struct bbs_io_transformations *s)
{
	struct io_session *i;
	int total = 0;

	RWLIST_WRLOCK(&sessions);
	RWLIST_TRAVERSE_SAFE_BEGIN(&sessions, i, entry) {
		total++;
		if (i->s == s) {
			RWLIST_REMOVE_CURRENT(entry);
			free(i);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&sessions);
	if (!i) {
		/* We traversed the entire list, so this count is accurate */
		bbs_warning("Transformation %p does not have an active session (%d total active)\n", s, total);
	}
	return i ? 0 : -1;
}

int __bbs_io_transformer_register(const char *name, struct bbs_io_transformer_functions *funcs, enum bbs_io_transform_type type, enum bbs_io_transform_dir dir, void *module)
{
	struct bbs_io_transformer *t;

	if (!funcs->setup || !funcs->cleanup) {
		bbs_error("Transformer missing mandatory function callbacks\n");
		return -1;
	}

	RWLIST_WRLOCK(&transformers);
	RWLIST_TRAVERSE(&transformers, t, entry) {
		if (!strcasecmp(name, t->name)) {
			RWLIST_UNLOCK(&transformers);
			bbs_error("I/O transformer '%s' already registered\n", name);
			return -1;
		}
	}
	t = calloc(1, sizeof(*t) + strlen(name) + 1);
	if (ALLOC_FAILURE(t)) {
		RWLIST_UNLOCK(&transformers);
		return -1;
	}
	strcpy(t->data, name); /* Safe */
	t->name = t->data;
	t->module = module;
	t->funcs = funcs;
	t->type = type;
	t->dir = dir;
	RWLIST_INSERT_TAIL(&transformers, t, entry);
	RWLIST_UNLOCK(&transformers);

	return 0;
}

int bbs_io_transformer_unregister(const char *name)
{
	struct bbs_io_transformer *t;

	RWLIST_WRLOCK(&transformers);
	RWLIST_TRAVERSE_SAFE_BEGIN(&transformers, t, entry) {
		if (!strcasecmp(name, t->name)) {
			RWLIST_REMOVE_CURRENT(entry);
			free(t);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&transformers);

	return t ? 0 : -1;
}

int bbs_io_named_transformer_available(const char *name)
{
	struct bbs_io_transformer *t;

	RWLIST_RDLOCK(&transformers);
	RWLIST_TRAVERSE(&transformers, t, entry) {
		if (!strcmp(name, t->name)) {
			break;
		}
	}
	RWLIST_UNLOCK(&transformers);

	if (!t) {
		bbs_debug(3, "No such transformer named '%s'\n", name);
	}

	return t ? 1 : 0;
}

static int transform_type_from_name(const char *name, enum bbs_io_transform_type *restrict type)
{
	struct bbs_io_transformer *t;

	RWLIST_RDLOCK(&transformers);
	RWLIST_TRAVERSE(&transformers, t, entry) {
		if (!strcmp(name, t->name)) {
			*type = t->type;
			break;
		}
	}
	RWLIST_UNLOCK(&transformers);

	return t ? 0 : -1;
}

int bbs_io_transformer_available(enum bbs_io_transform_type transform_type)
{
	struct bbs_io_transformer *t;

	RWLIST_RDLOCK(&transformers);
	RWLIST_TRAVERSE(&transformers, t, entry) {
		if (t->type == transform_type) {
			break;
		}
	}
	RWLIST_UNLOCK(&transformers);

	if (!t) {
		bbs_debug(3, "No such transformer of type %d\n", transform_type);
	}

	return t ? 1 : 0;
}

static int io_transform_slots_free(struct bbs_io_transformations *trans)
{
	int i;

	for (i = 0; i < MAX_IO_TRANSFORMS; i++) {
		if (!trans->transformations[i].transformer) {
			/* Not in use */
			return 1;
		}
	}
	return 0;
}

static struct bbs_io_transformation *io_transform_store(struct bbs_io_transformations *trans, struct bbs_io_transformer *t, void *data)
{
	int i;

	for (i = 0; i < MAX_IO_TRANSFORMS; i++) {
		if (!trans->transformations[i].transformer) {
			trans->transformations[i].data = data;
			trans->transformations[i].transformer = t;
			bbs_debug(7, "Set up node I/O transformer at index %d\n", i);
			return &trans->transformations[i];
		}
	}
	/* Shouldn't happen since only one thread is really handling a node's I/O at a time */
	bbs_error("Failed to store transformation\n");
	return NULL;
}

static int __bbs_io_transform_possible(struct bbs_io_transformations *trans, enum bbs_io_transform_type type, int warn)
{
	if (bbs_io_transform_active(trans, type)) {
		if (warn) {
			bbs_error("Transformation %d already active, declining to set up duplicate transformation\n", type);
		}
		return 0;
	}

	/* TLS compression is disabled, so we don't need to worry about rejecting TRANSFORM_DEFLATE_COMPRESSION
	 * if that were already to be active (as normally, that would conflict). */

	/* XXX Ideally, ordering constraints would be specified in the modules themselves,
	 * but since this involves both of them, just put it here for now: */
	if (type == TRANSFORM_TLS_ENCRYPTION) {
		if (bbs_io_transform_active(trans, TRANSFORM_DEFLATE_COMPRESSION)) {
			/* Since I/O transformations are pushed onto a stack of file descriptors, effectively,
			 * but TLS must happen after compression, it is too late to begin encryption.
			 * The current I/O transformation architecture doesn't really us to add transformations
			 * underneath existing ones. */
			if (warn) {
				bbs_warning("Can't enable encryption after compression has already been enabled, enable encryption prior to compression instead\n");
			}
			return 0;
		}
	}
	return 1;
}

int bbs_io_transform_possible(struct bbs_io_transformations *trans, enum bbs_io_transform_type type)
{
	return __bbs_io_transform_possible(trans, type, 0);
}

int bbs_io_transform_setup(struct bbs_io_transformations *trans, enum bbs_io_transform_type type, enum bbs_io_transform_dir direction, int *rfd, int *wfd, const void *arg)
{
	int res;
	void *data = NULL;
	int orig_rfd, orig_wfd;
	struct bbs_io_transformer *t;

	if (!__bbs_io_transform_possible(trans, type, 1)) {
		return -1;
	}

	RWLIST_RDLOCK(&transformers);
	if (!io_transform_slots_free(trans)) {
		RWLIST_UNLOCK(&transformers);
		bbs_error("Already at max transformations (%d)\n", MAX_IO_TRANSFORMS);
		return -1;
	}
	RWLIST_TRAVERSE(&transformers, t, entry) {
		if (!(t->dir & direction)) {
			continue;
		}
		if (t->type == type) {
			break;
		}
	}

	if (!t) {
		/* Should use bbs_io_transformer_available before to check.
		 * Yes, that is TOCTOU, but this should happen infrequently,
		 * although it is possible, hence a warning, not an error: */
		RWLIST_UNLOCK(&transformers);
		bbs_warning("No suitable transformer found (type %d)\n", type);
		return -1;
	}

	orig_rfd = *rfd;
	orig_wfd = *wfd;
	res = t->funcs->setup(rfd, wfd, direction, &data, arg);

	/* Store transform private data on node */
	if (!res) {
		struct bbs_io_transformation *tran = io_transform_store(trans, t, data);
		if (!tran) {
			/* Failure! */
			struct bbs_io_transformation dummy_tran;
			dummy_tran.transformer = t;
			dummy_tran.data = data;
			t->funcs->cleanup(&dummy_tran);
			res = 1;
		} else {
			/* These are used by bbs_io_drain: */
			tran->outer_rfd = orig_rfd;
			tran->outer_wfd = orig_wfd;
			tran->inner_rfd = *rfd;
			tran->inner_wfd = *wfd;

			bbs_module_ref(t->module, 1);
		}
	}
	RWLIST_UNLOCK(&transformers);

	return res;
}

int bbs_io_transform_active(struct bbs_io_transformations *trans, enum bbs_io_transform_type type)
{
	int i, active = 0;

	RWLIST_RDLOCK(&transformers);
	for (i = 0; i < MAX_IO_TRANSFORMS; i++) {
		if (trans->transformations[i].data) {
			struct bbs_io_transformer *t = trans->transformations[i].transformer;
			if (t->type == type) {
				active = 1;
				break;
			}
		}
	}
	RWLIST_UNLOCK(&transformers);

	return active;
}

int bbs_io_transform_query(struct bbs_io_transformations *trans, enum bbs_io_transform_type type, int query, void *data)
{
	int i;
	int res = -1;

	RWLIST_RDLOCK(&transformers);
	for (i = 0; i < MAX_IO_TRANSFORMS; i++) {
		if (trans->transformations[i].data) {
			struct bbs_io_transformer *t = trans->transformations[i].transformer;
			if (t->type == type) {
				if (t->funcs->query) {
					res = t->funcs->query(&trans->transformations[i], query, data);
				} else {
					res = 1;
				}
				break;
			}
		}
	}
	RWLIST_UNLOCK(&transformers);

	return res;
}

static int num_bytes_waiting_read(int fd)
{
	int res, bytes;
	res = ioctl(fd, FIONREAD, &bytes);
	if (res) {
		bbs_error("FIONREAD(%d) failed: %s\n", fd, strerror(errno));
		return -1;
	}
	return bytes;
}

static int num_bytes_waiting_write(int fd)
{
	int res, bytes;
	res = ioctl(fd, TIOCOUTQ, &bytes);
	if (res) {
		bbs_error("TIOCOUTQ(%d) failed: %s\n", fd, strerror(errno));
		return -1;
	}
	return bytes;
}

static int __do_drain(struct bbs_io_transformations *trans)
{
	int i, drained = 0;

	/* We want to start at the end of the list and work our way to the front,
	 * since transformations are added starting at the beginning.
	 * i.e. the outermost one would be at the beginning,
	 * and the last active transformation in the array is the one
	 * closest to the application layer. */
	RWLIST_RDLOCK(&transformers);
	for (i = MAX_IO_TRANSFORMS - 1; i >= 0; i--) {
		if (trans->transformations[i].data) {
			struct bbs_io_transformation *tran = &trans->transformations[i];
			int bytes;
			/*
			 *             1          2               3
			 * APPLICATION <-- read --< transformer A <-- read --< transformer B <-- ...
			 * APPLICATION >-- write -> transformer A >-- write -> transformer B --> ...
			 *             4          5               6
			 * Assuming tran is transformer A:
			 * 2 = tran->inner_wfd
			 * 3 = tran->outer_rfd
			 * 5 = tran->inner_rfd
			 * 6 = tran->outer_wfd
			*
			* Starting from the left and going right (transformer A, B, etc.)
			* we want to ensure that:
			* 1. There is no more data pending to read on 5
			* 2. All data has been written to 6.
			*/
			bytes = num_bytes_waiting_read(tran->inner_rfd);
			if (bytes > 0) {
				bbs_debug(3, "Still %d bytes that need to be read on fd %d\n", bytes, tran->inner_rfd);
			}
			if ((bytes = num_bytes_waiting_write(tran->outer_wfd))) {
				bbs_debug(3, "Still %d bytes that need to be written on fd %d\n", bytes, tran->outer_wfd);
				drained = 1;
				bbs_safe_sleep(30);
				while ((bytes = num_bytes_waiting_write(tran->outer_wfd)) > 0) {
					/* We can't use tcdrain, since that's only for terminal devices, and we're dealing with pipes. */
					if (bbs_safe_sleep(10)) {
						break;
					}
				}
			}
		}
	}
	RWLIST_UNLOCK(&transformers);
	return drained;
}

int bbs_io_drain(struct bbs_io_transformations *trans)
{
	int drained;

	/* Make sure all output has been flushed.
	 * This allows a sender to wait for all output to actually
	 * be sent out before closing its file descriptor,
	 * which can percolate through and close everything while data
	 * is still being processed in one of the transformers. */
	do {
		/* If we end up draining during an iteration,
		 * keep iterating until we have a full pass
		 * with no drains. */
		drained = __do_drain(trans);
	} while (drained > 0);
	return drained == -1 ? -1 : 0;
}

static void teardown_transformation(struct bbs_io_transformation *tran)
{
	struct bbs_io_transformer *t = tran->transformer;
	t->funcs->cleanup(tran);
	tran->data = NULL;
	tran->transformer = NULL;
	bbs_module_unref(t->module, 1);
}

void bbs_io_teardown_all_transformers(struct bbs_io_transformations *trans)
{
	int i;

	RWLIST_RDLOCK(&transformers);
	for (i = 0; i < MAX_IO_TRANSFORMS; i++) {
		if (trans->transformations[i].data) {
			bbs_debug(7, "Removing I/O transformer at index %d\n", i);
			teardown_transformation(&trans->transformations[i]);
		}
	}
	RWLIST_UNLOCK(&transformers);
}

static int cli_io_transformers(struct bbs_cli_args *a)
{
	struct bbs_io_transformer *t;

	RWLIST_RDLOCK(&transformers);
	RWLIST_TRAVERSE(&transformers, t, entry) {
		bbs_dprintf(a->fdout, "%s\n", t->name);
	}
	RWLIST_UNLOCK(&transformers);
	return 0;
}

static int cli_io_sessions(struct bbs_cli_args *a)
{
	struct io_session *i;
	int c = 0;
	time_t now = time(NULL);

	/* There isn't much more we can say about these sessions,
	 * since io.c has very limited visibility into them,
	 * apart from adding and removing a transformation.
	 * The data doesn't flow through this file, so we can't
	 * even speak to how many bytes have been sent/received
	 * (though an I/O transformation module can).
	 * Thus, we print the address of the owner/session to hopefully add some context. */
	bbs_dprintf(a->fdout, "%9s %-10s %12s %-16s %s\n", "ID", "Type", "Elapsed", "Owner", "Trans I/O");
	RWLIST_RDLOCK(&sessions);
	RWLIST_TRAVERSE(&sessions, i, entry) {
		char elapsed[24];
		print_time_elapsed(i->start, now, elapsed, sizeof(elapsed));
		bbs_dprintf(a->fdout, "%9u %-10s %12s %-16p %p\n", i->id, session_type_name(i->type), elapsed, i->owner, i->s);
		c++;
	}
	RWLIST_UNLOCK(&sessions);
	bbs_dprintf(a->fdout, "%d active I/O session%s\n", c, ESS(c));
	return 0;
}

/*! \note sessions must be locked when calling */
static struct io_session *find_io_session(unsigned int id)
{
	struct io_session *i;
	RWLIST_TRAVERSE(&sessions, i, entry) {
		if (i->id == id) {
			return i;
		}
	}
	return NULL;
}

static int cli_io_session(struct bbs_cli_args *a)
{
	struct io_session *io;
	int i, active = 0;

	RWLIST_RDLOCK(&sessions);
	io = find_io_session((unsigned int) atoi(a->argv[2]));
	if (!io) {
		RWLIST_UNLOCK(&sessions);
		bbs_dprintf(a->fdout, "No such I/O session: %s\n", a->argv[2]);
		return -1;
	}

	bbs_dprintf(a->fdout, "Active Transformations:\n");
	RWLIST_RDLOCK(&transformers);
	for (i = 0; i < MAX_IO_TRANSFORMS; i++) {
		if (io->s->transformations[i].data) {
			struct bbs_io_transformer *t = io->s->transformations[i].transformer;
			bbs_dprintf(a->fdout, "%s\n", t->name);
			active++;
		}
	}
	RWLIST_UNLOCK(&transformers);
	bbs_dprintf(a->fdout, "# Active Transformations: %d\n", active);

	RWLIST_UNLOCK(&sessions);
	return 0;
}

static int cli_io_session_transformation_add(struct bbs_cli_args *a)
{
	struct io_session *i;
	enum bbs_io_transform_type type;
	struct bbs_node *node;
	struct bbs_tcp_client *tcpclient;
	int res;
	const char *transformer = a->argv[4];

	if (!bbs_io_named_transformer_available(transformer)) {
		bbs_dprintf(a->fdout, "Transformer '%s' not available\n", transformer);
		return -1;
	}

	/* Note: This command is only intended for adding the TRANSFORM_SESSION_LOGGING transformer
	 * to an existing session. Adding TLS or compression outside of a protocol's
	 * mechanisms for doing so (e.g. STARTTLS) will likely just corrupt the entire session
	 * and break it. */

	RWLIST_RDLOCK(&sessions);
	i = find_io_session((unsigned int) atoi(a->argv[3]));
	if (!i) {
		RWLIST_UNLOCK(&sessions);
		bbs_dprintf(a->fdout, "No such I/O session: %s\n", a->argv[4]);
		return -1;
	} else if (transform_type_from_name(transformer, &type)) {
		RWLIST_UNLOCK(&sessions);
		return -1;
	}

	switch (i->type) {
	case TRANSFORM_SESSION_NODE:
		node = i->owner;
		res = bbs_io_transform_setup(i->s, type, TRANSFORM_SERVER_CLIENT_TX_RX, &node->rfd, &node->wfd, NULL);
		break;
	case TRANSFORM_SESSION_TCPCLIENT:
		tcpclient = i->owner;
		res = bbs_io_transform_setup(i->s, type, TRANSFORM_SERVER_CLIENT_TX_RX, &tcpclient->rfd, &tcpclient->wfd, NULL);
		break;
	default:
		__builtin_unreachable();
	}

	RWLIST_UNLOCK(&sessions);
	bbs_dprintf(a->fdout, "%s transformation %s\n", res ? "Failed to enable" : "Enabled", transformer);
	return res;
}

static struct bbs_cli_entry cli_commands_io[] = {
	BBS_CLI_COMMAND(cli_io_transformers, "io transformers", 2, "List all registered I/O transformers", NULL),
	BBS_CLI_COMMAND(cli_io_sessions, "io sessions", 2, "List all active I/O sessions", NULL),
	BBS_CLI_COMMAND(cli_io_session, "io session", 3, "List transformations active on an I/O session", "io session <session ID>"),
	BBS_CLI_COMMAND(cli_io_session_transformation_add, "io transformation add", 5, "Add I/O transformation to an I/O session", "io transformation add <session ID> <transformation name>"),
};

int bbs_io_init(void)
{
	return bbs_cli_register_multiple(cli_commands_io);
}
