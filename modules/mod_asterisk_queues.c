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
 * \brief Asterisk Queue Position System
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <ctype.h>
#include <stdarg.h>

#include <cami/cami.h>

#include "include/module.h"
#include "include/config.h"
#include "include/linkedlists.h"
#include "include/node.h"
#include "include/term.h"
#include "include/user.h"
#include "include/door.h"
#include "include/variables.h"
#include "include/cli.h"
#include "include/socket.h" /* use bbs_tcp_wait_max_unacked, don't need full utils.h */

#include "include/mod_asterisk_ami.h"
#include "include/mod_asterisk_queues.h"
#include "include/mod_ncurses.h"

struct queue;

struct queue_call {
	int id;					/*!< Queue call ID */
	const char *channel;	/*!< Channel name */
	struct queue *queue;	/*!< Parent queue to which this call belongs */
	int ani2;				/*!< ANI II */
	unsigned long ani;		/*!< ANI */
	unsigned long dnis;		/*!< DNIS, which unlike ConnectedLine, doesn't come for free (need to use Getvar) */
	const char *cnam;		/*!< CNAM */
	time_t added;			/*!< Time added to queue */
	int refcount;			/*!< Reference Count */
	unsigned int dead:1;	/*!< Dead? */
	RWLIST_ENTRY(queue_call) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(calls, queue_call);

struct agent {
	int id;						/*!< Agent ID */
	struct bbs_node *node;		/*!< Agent's node */
	unsigned int idle:1;		/*!< Currently idle? */
	unsigned int gotwritten:1;	/*!< Another thread wrote onto our terminal while we were idle */
	unsigned int stale:1;		/*!< Needs stats update */
	RWLIST_ENTRY(agent) entry;
};

static RWLIST_HEAD_STATIC(agents, agent);

/*! \brief Information about an agent for a specific queue */
struct member {
	struct queue *queue;
	struct agent *agent;
	int calls_taken;
	RWLIST_ENTRY(member) entry;
};

RWLIST_HEAD(members, member);

struct queue {
	const char *name;
	const char *title;
	const char *handler;
	/* By storing membership by queue, rather than agent,
	 * we make queue operations linear time but
	 * agent operations can by polynomial in the worst case.
	 * We choose this tradeoff since agent operations are limited in number,
	 * but queue operations can be more common.
	 * They could both be linear if we kept a list per agent of queues of which
	 * that agent is a member, but the linked list API we use does not make
	 * that feasible. */
	struct members members;	/*!< Queue members */
	int ringing;			/*!< # of calls currently ringing in the system */
	int calls;				/*!< Total # calls */
	int completed;			/*!< # completed calls */
	int abandoned;			/*!< # abandoned calls */
	unsigned int stale:1;	/*!< Needs stats initialization or update */
	RWLIST_ENTRY(queue) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(queues, queue);

struct queue_call_handler {
	const char *name;
	int (*handler)(struct queue_call_handle *qch);
	void *mod;
	RWLIST_ENTRY(queue_call_handler) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(handlers, queue_call_handler);

int __bbs_queue_call_handler_register(const char *name, int (*handler)(struct queue_call_handle *qch), void *mod)
{
	struct queue_call_handler *qch;

	RWLIST_WRLOCK(&handlers);
	RWLIST_TRAVERSE(&handlers, qch, entry) {
		if (!strcmp(qch->name, name)) {
			RWLIST_UNLOCK(&handlers);
			bbs_error("Queue call handler with name '%s' already registered\n", name);
			return -1;
		}
	};

	qch = calloc(1, sizeof(*qch) + strlen(name) + 1);
	if (ALLOC_FAILURE(qch)) {
		RWLIST_UNLOCK(&handlers);
		return -1;
	}

	strcpy(qch->data, name); /* Safe */
	qch->name = qch->data;
	qch->mod = mod;
	qch->handler = handler;
	RWLIST_INSERT_HEAD(&handlers, qch, entry);
	RWLIST_UNLOCK(&handlers);
	return 0;
}

int bbs_queue_call_handler_unregister(const char *name)
{
	struct queue_call_handler *qch;

	RWLIST_WRLOCK(&handlers);
	qch = RWLIST_REMOVE_BY_STRING_FIELD(&handlers, name, name, entry);
	RWLIST_UNLOCK(&handlers);

	if (!qch) {
		bbs_error("Queue call handler '%s' was not registered\n", name);
		return -1;
	}

	free(qch);
	return 0;
}

static char system_title[42];
static char call_menu_title[48];
static char queue_id_var[64];

static struct agent *new_agent(struct bbs_node *node, int agentid)
{
	struct agent *agent;

	agent = calloc(1, sizeof(*agent));
	if (ALLOC_FAILURE(agent)) {
		return NULL;
	}
	agent->idle = 0;
	agent->node = node;
	agent->id = agentid;

	RWLIST_WRLOCK(&agents);
	RWLIST_INSERT_HEAD(&agents, agent, entry);
	RWLIST_UNLOCK(&agents);
	return agent;
}

static void del_agent(struct agent *agent)
{
	struct queue *queue;
	struct member *member;

	RWLIST_WRLOCK(&queues);
	RWLIST_TRAVERSE(&queues, queue, entry) {
		/* Remove membership in all queues */
		RWLIST_WRLOCK(&queue->members);
		RWLIST_TRAVERSE_SAFE_BEGIN(&queue->members, member, entry) {
			if (member->agent == agent) {
				RWLIST_REMOVE_CURRENT(entry);
				free(member);
				/* Don't break, since an agent can be a member of multiple queues. */
			}
		}
		RWLIST_TRAVERSE_SAFE_END;
		RWLIST_UNLOCK(&queue->members);
	}
	RWLIST_UNLOCK(&queues);

	/* Finally, remove the agent itself, now that there are no longer any references to it,
	 * besides ours. */
	RWLIST_WRLOCK_REMOVE_BY_FIELD(&agents, id, agent->id, entry);

	free(agent);
}

/*! \brief queues must be locked when calling */
/*! \note This returns member unlocked, but this is fine if the calling thread "owns" the member.
 * If not, then do not use this function. */
static struct member *queue_member(struct queue *queue, struct agent *agent)
{
	struct member *member;
	RWLIST_RDLOCK(&queue->members);
	RWLIST_TRAVERSE(&queue->members, member, entry) {
		if (member->agent == agent) {
			RWLIST_UNLOCK(&queue->members);
			return member;
		}
	}
	RWLIST_UNLOCK(&queue->members);
	return NULL;
}

/*! \brief Must be called with queues locked */
static struct queue *find_queue(const char *name)
{
	struct queue *queue;
	RWLIST_TRAVERSE(&queues, queue, entry) {
		if (!strcmp(queue->name, name)) {
			return queue;
		}
	}
	return NULL;
}

static int update_queue_stats(void)
{
	int i;
	struct queue *q, *lastq;
	int stale_queues = 0;
	struct ami_response *resp;

	/* Initially (and as needed), get all stats for all queues. */
	RWLIST_RDLOCK(&queues);
	RWLIST_TRAVERSE(&queues, q, entry) {
		if (q->stale) {
			/* As long as at least one queue needs to have stats refreshed, make an AMI request.
			 * If none do, we can avoid making a request altogether.
			 * We need to update periodically to update global queue stats
			 * (and similarly for each queue agent), since these change whenever calls are processed.
			 * We could manually update these stats ourselves based on events,
			 * but this is probably the easiest way to keep in sync, albeit somewhat wasteful. */
			stale_queues++;
			lastq = q;
		}
	}
	if (!stale_queues) {
		/* No queues are stale right now, skip update. */
		RWLIST_UNLOCK(&queues);
		return 0;
	}

	/* If only one queue needs to be refreshed, then just ask for that one by name. */
	resp = ami_action(bbs_ami_session(), "QueueStatus", stale_queues == 1 ? lastq->name : "");

	if (!resp || !resp->success) {
		RWLIST_UNLOCK(&queues);
		if (resp) {
			ami_resp_free(resp);
		}
		bbs_error("Failed to get queue stats\n");
		return -1;
	}

	for (i = 1; i < resp->size - 1; i++) {
		struct ami_event *e = resp->events[i];
		const char *event = ami_keyvalue(e, "Event");
		if (!strcmp(event, "QueueParams")) {
			const char *numcalls, *completed, *abandoned;
			const char *queue_name = ami_keyvalue(e, "Queue");
			struct queue *queue = find_queue(queue_name);
			if (!queue) {
				bbs_debug(5, "Skipping irrelevant queue '%s'\n", queue_name);
				continue; /* Not one of our queues that we care about */
			}
			if (!queue->stale) {
				continue; /* Queue is already up to date, don't care */
			}
			numcalls = ami_keyvalue(e, "Calls");
			completed = ami_keyvalue(e, "Completed");
			abandoned = ami_keyvalue(e, "Abandoned");
			if (strlen_zero(numcalls) || strlen_zero(completed) || strlen_zero(abandoned)) {
				bbs_error("Empty mandatory fields?\n");
				continue;
			}
			/* Store stats for the queue, semipermanently, so we can reference them until the next update. */
			queue->calls = atoi(numcalls);
			queue->completed = atoi(completed);
			queue->abandoned = atoi(abandoned);
			bbs_debug(1, "Updated stats for queue %s\n", queue->name);
			queue->stale = 0;
		}
	}
	RWLIST_UNLOCK(&queues);
	ami_resp_free(resp); /* Free response when done with it */
	return 0;
}

static int cli_asterisk_queues(struct bbs_cli_args *a)
{
	struct queue *queue;
	bbs_dprintf(a->fdout, "%-30s %-15s %5s %9s %9s\n", "Name", "Handler", "Calls", "Completed", "Abandoned");
	RWLIST_RDLOCK(&queues);
	RWLIST_TRAVERSE(&queues, queue, entry) {
		struct queue_call_handler *qch;
		bbs_dprintf(a->fdout, "%-30s %-15s %5d %9d %9d\n", queue->name, queue->handler, queue->calls, queue->completed, queue->abandoned);
		/* Check that a handler actually exists.
		 * We can't do this when the module loads,
		 * because the handler modules are dependent on us,
		 * so they can't even load until we finish loading.
		 * However, during runtime, those modules should be loaded,
		 * and we should be able to go ahead and check. */
		RWLIST_RDLOCK(&handlers);
		RWLIST_TRAVERSE(&handlers, qch, entry) {
			if (!strcmp(qch->name, queue->handler)) {
				break;
			}
		}
		RWLIST_UNLOCK(&handlers);
		if (!qch) {
			bbs_warning("No queue call handler named '%s' appears to be registered currently\n", queue->handler);
		}
	}
	RWLIST_UNLOCK(&queues);
	return 0;
}

static int cli_asterisk_agents(struct bbs_cli_args *a)
{
	struct agent *agent;

	bbs_dprintf(a->fdout, "%4s %8s\n", "Node", "Agent ID");
	RWLIST_RDLOCK(&agents);
	RWLIST_TRAVERSE(&agents, agent, entry) {
		bbs_dprintf(a->fdout, "%4d %8d\n", agent->node->id, agent->id);
	}
	RWLIST_UNLOCK(&agents);
	return 0;
}

static void __mark_dead(struct queue_call *call)
{
	bbs_debug(3, "Marking queue call %d as dead: %s\n", call->id, call->channel);
	call->dead = 1;
}

static void mark_dead(const char *channel)
{
	struct queue_call *call;

	RWLIST_RDLOCK(&calls);
	RWLIST_TRAVERSE(&calls, call, entry) {
		if (call->dead) {
			continue;
		}
		if (!strcmp(call->channel, channel)) {
			__mark_dead(call);
			break;
		}
	}
	RWLIST_UNLOCK(&calls);
}

static int call_is_dead(struct queue_call *call)
{
	char *val;
	if (call->dead) {
		return -1;
	}
	val = ami_action_getvar(bbs_ami_session(), "queueuniq", call->channel);
	if (!val) {
		__mark_dead(call);
		return 1;
	}
	if (strlen_zero(val)) {
		__mark_dead(call);
		free(val);
		return 1;
	}
	free(val);
	return 0;
}

static void prune_dead_calls(int querydead)
{
	struct queue_call *call;

	if (querydead) {
		/* Only hold a RDLOCK while we're making AMI calls. */
		RWLIST_RDLOCK(&calls);
		RWLIST_TRAVERSE(&calls, call, entry) {
			call_is_dead(call);
		}
		RWLIST_UNLOCK(&calls);
	}

	/* Now purge any dead calls */
	RWLIST_WRLOCK(&calls);
	RWLIST_TRAVERSE_SAFE_BEGIN(&calls, call, entry) {
		/* If a call is dead but has a positive refcount,
		 * an agent is handling it, so don't remove it yet. */
		if (call->dead && !call->refcount) {
			RWLIST_REMOVE_CURRENT(entry);
			bbs_debug(3, "Pruning dead queue call %d (%s)\n", call->id, call->channel);
			free(call);
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	RWLIST_UNLOCK(&calls);
}

static int cli_asterisk_calls(struct bbs_cli_args *a)
{
	struct queue_call *call;

	prune_dead_calls(1);

	bbs_dprintf(a->fdout, "%4s %-25s %4s %4s %2s %15s %s\n", "ID", "Queue", "Dead", "Refs", "II", "ANI", "CNAM");
	RWLIST_RDLOCK(&calls);
	RWLIST_TRAVERSE(&calls, call, entry) {
		bbs_dprintf(a->fdout, "%4d %-25s %4s %4d %02d %15lu %s\n", call->id, call->queue->name, BBS_YN(call->dead), call->refcount, call->ani2, call->ani, call->cnam);
	}
	RWLIST_UNLOCK(&calls);
	return 0;
}

/*! \note 4 and 6 should also be nonnull, but SET_FSM_STRING_VAR does a strlen_zero check, so we can't include them in the attribute */
static __nonnull ((1, 5)) struct queue_call *new_call(struct queue *queue, int queueid, int ani2, const char *channel, const char *ani, const char *cnam, const char *dnis)
{
	struct queue_call *call;
	char *data;
	size_t chanlen, cnamlen;

	chanlen = strlen(channel) + 1;
	cnamlen = strlen(cnam) + 1;

	RWLIST_WRLOCK(&calls);

	/* First, make sure this call isn't already in the list.
	 * If it is, we don't want to add it again. */
	RWLIST_TRAVERSE(&calls, call, entry) {
		if (call->id == queueid) {
			/* If it's already in the list, but dead, mark it as dead and replace it. */
			if (!call_is_dead(call)) {
				bbs_debug(2, "Queue call %d already in call list, declining to duplicate\n", queueid);
				RWLIST_UNLOCK(&calls);
				return NULL;
			}
		}
	}

	call = calloc(1, sizeof(*call) + chanlen + cnamlen);
	if (ALLOC_FAILURE(call)) {
		RWLIST_UNLOCK(&calls);
		return NULL;
	}

	while (*ani && !isalnum(*ani)) {
		ani++;
	}

	call->added = time(NULL);
	call->id = queueid;
	call->queue = queue;
	call->ani2 = ani2;
	call->ani = (unsigned long) atol(ani);
	if (!strlen_zero(dnis)) {
		call->dnis = (unsigned long) atol(dnis);
	}
	data = call->data;
	SET_FSM_STRING_VAR(call, data, channel, channel, chanlen);
	SET_FSM_STRING_VAR(call, data, cnam, cnam, cnamlen);

	RWLIST_INSERT_TAIL(&calls, call, entry);
	RWLIST_UNLOCK(&calls);

	bbs_debug(4, "Added call from '%s' (%s) to queue '%s' as call %d\n", S_IF(ani), channel, queue->name, queueid);
	return call;
}

static void __attribute__ ((format (gnu_printf, 3, 4))) agent_printf(struct queue *queue, const char *member_name, const char *fmt, ...)
{
	char *buf;
	int len;
	va_list ap;
	struct agent *agent;
	int agent_id = !strlen_zero(member_name) ? atoi(member_name) : -1;

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return;
	}

	RWLIST_RDLOCK(&agents);
	RWLIST_TRAVERSE(&agents, agent, entry) {
		/* The chance that it's not idle because it's updating the time is unlikely:
		 * literally just 1 in 1000 */
		if (!agent->idle) {
			continue; /* Terminal is busy, don't interfere */
		}
		if (agent_id == -1) {
			/* Applies to all relevant members */
			if (!queue_member(queue, agent)) {
				continue; /* Not a member of this queue, doesn't pertain */
			}
		} else {
			if (agent_id != agent->id) {
				continue; /* Not the right agent */
			}
		}
		agent->gotwritten = 1; /* Let the poor TTY know we just did something to it, so it can plan accordingly the next time it writes */
		bbs_node_any_write(agent->node, buf, len);
	}
	RWLIST_UNLOCK(&agents);
	free(buf);
}

static int ami_callback(struct ami_event *e, const char *eventname)
{
	const char *queue_name;
	struct queue *queue;

	if (strncmp(eventname, "Queue", STRLEN("Queue")) && strncmp(eventname, "Agent", STRLEN("Agent"))) {
		return -1; /* If it doesn't start with Queue or Agent, not relevant to us. */
	}

	queue_name = ami_keyvalue(e, "Queue");
	if (strlen_zero(queue_name)) {
		return -1;
	}

	/* Is it one of our queues that we care about? */
	queue = find_queue(queue_name);
	if (!queue) {
		return -1; /* Nope, it's not. */
	}

	/* Events that print to agents' terminals use \r instead of \n
	 * to overwrite the current timestamp */

	queue->stale = 1; /* The stats are now stale, and will need to be updated at the next convenient opportunity. */

	bbs_debug(7, "Processing queue event '%s'\n", eventname);

	if (!strcmp(eventname, "QueueCallerJoin")) {
		char *queueid, *ani2, *dnis;
		const char *callerid, *channel, *callername;
		callerid = ami_keyvalue(e, "CallerIDNum");
		channel = ami_keyvalue(e, "Channel");
		callername = ami_keyvalue(e, "CallerIDName");
		if (strlen_zero(callerid) || strlen_zero(channel) || strlen_zero(callername)) {
			bbs_error("Missing mandatory fields\n");
			return -1;
		}
		queueid = ami_action_getvar(bbs_ami_session(), queue_id_var, channel);
		if (strlen_zero(queueid)) {
			return -1;
		}
		ani2 = ami_action_getvar(bbs_ami_session(), "CALLERID(ani2)", channel);
		dnis = ami_action_getvar(bbs_ami_session(), "CALLERID(DNID)", channel);
		new_call(queue, atoi(queueid), atoi(S_IF(ani2)), channel, callerid, callername, dnis);
		free_if(queueid);
		free_if(ani2);
		free_if(dnis);
	} else if (!strcmp(eventname, "QueueMemberStatus") || !strcmp(eventname, "AgentComplete")) {
		return -1; /* Don't care */
	} else if (!strcmp(eventname, "AgentCalled")) {
		const char *callerid = ami_keyvalue(e, "CallerIDNum");
		const char *member_name = ami_keyvalue(e, "MemberName");
		if (strlen_zero(member_name)) {
			return -1;
		}
		agent_printf(queue, member_name, "%s\r%s%-15s %-22s %15s\n", COLOR_RESET, TERM_BELL, "ACD RING", queue->title, S_OR(callerid, ""));
	} else if (!strcmp(eventname, "QueueCallerAbandon")) {
		const char *originalpos, *pos, *holdtime, *channel, *callerid;
		originalpos = ami_keyvalue(e, "OriginalPosition");
		pos = ami_keyvalue(e, "Position");
		holdtime = ami_keyvalue(e, "HoldTime");
		channel = ami_keyvalue(e, "Channel");
		callerid = ami_keyvalue(e, "CallerIDNum");
		/* This is the actual "caller hung up before agent answered" event */
		agent_printf(queue, NULL, "%s\r%s%-15s %-22s %15s %s>%s [%s]\n", COLOR_RESET, TERM_BELL, "ACD DC", queue->title, S_OR(callerid, ""), S_OR(originalpos, ""), S_OR(pos, ""), S_OR(holdtime, ""));
		mark_dead(channel); /* Probably safe to unregister directly if we wanted to, but just mark as dead for now */
	} else if (!strcmp(eventname, "QueueCallerLeave")) {
		const char *count, *pos, *callerid;
		pos	= ami_keyvalue(e, "Position");
		count = ami_keyvalue(e, "Count");
		callerid = ami_keyvalue(e, "CallerIDNum");
		/* This happens when an agent answers a call as well as when a caller hangs up. */
		agent_printf(queue, NULL, "%s\r%-15s %-20s %15s P%s %s@\n", COLOR_RESET, "ACD DD", queue->title, S_OR(callerid, ""), S_OR(pos, ""), S_OR(count, ""));
#if 0
		/* Actually, because this happens when an agent answers a call as well, we can't assume the call is dead here */
		/* Don't unregister the call now, since an agent might be handling it.
		 * However, we can go ahead and mark it as dead, to save an AMI request later. */
		mark_dead(channel);
#endif
	} else if (!strcmp(eventname, "AgentConnect")) {
		const char *holdtime, *ringtime, *member_name, *callerid;
		struct agent *agent;
		int agentid;
		member_name = ami_keyvalue(e, "MemberName");
		holdtime = ami_keyvalue(e, "HoldTime");
		ringtime = ami_keyvalue(e, "RingTime");
		callerid = ami_keyvalue(e, "CallerIDNum");
		agent_printf(queue, member_name, "%s\r%-15s %-20s %15s [%s/%s]\n", COLOR_RESET, "ACD ANS", queue->title, S_OR(callerid, ""), S_OR(holdtime, ""), S_OR(ringtime, ""));

		/* Since this agent has taken a call, this means the agent's statistics
		 * will need to be updated to reflect having answered this call. */
		agentid = atoi(member_name);
		RWLIST_RDLOCK(&agents);
		RWLIST_TRAVERSE(&agents, agent, entry) {
			if (agent->id == agentid) {
				agent->stale = 1;
			}
		}
		RWLIST_UNLOCK(&agents);
	} else {
		bbs_debug(6, "Ignoring queue event: %s\n", eventname); /* We know it's queue related since it contains a Queue key */
		return -1;
	}

	return 0;
}

static int update_member_stats(struct agent *agent)
{
	int i;
	struct ami_response *resp = ami_action(bbs_ami_session(), "QueueStatus", "Member:%d", agent->id);

	/* We still need to initialize the agent-specific stats for all queues.
	 * This response will be smaller (maybe much smaller) than asking for everything. */
	if (!resp || !resp->success) {
		if (resp) {
			ami_resp_free(resp);
		}
		bbs_error("Failed to get queue status for agent %d\n", agent->id);
		return -1;
	}

	/* Loop through each of the queue events and populate our structures if they apply. */
	RWLIST_RDLOCK(&queues);
	for (i = 1; i < resp->size - 1; i++) {
		struct queue *queue;
		struct member *member;
		const char *event, *queue_name, *name, *calls_taken;
		struct ami_event *e = resp->events[i];
		/* Slightly faster to loop through each field in the response.
		 * Faster than requesting each of the event fields individually (O(n) as opposed to O(n^2)), but, meh... */
		event = ami_keyvalue(e, "Event");
		if (strcmp(event, "QueueMember")) {
			continue; /* Skip QueueParams event */
		}
		queue_name = ami_keyvalue(e, "Queue");
		name = ami_keyvalue(e, "Name");
		calls_taken = ami_keyvalue(e, "CallsTaken");
		/* It's a QueueMember event */
		if (strlen_zero(event)) {
			bbs_error("Missing event name?\n"); /* Shouldn't ever happen */
			continue;
		}
		if (strlen_zero(queue_name)) {
			bbs_error("Missing queue name?\n");
			continue;
		}
		if (strlen_zero(calls_taken)) {
			bbs_error("Missing calls taken?\n");
			continue;
		}
		queue = find_queue(queue_name);
		if (!queue) {
			bbs_debug(5, "Agent '%s' not a member of queue '%s'\n", name, queue_name);
			continue; /* Not a queue that concerns us */
		}
		bbs_debug(4, "Agent '%s' member of queue '%s'\n", name, queue_name);
		member = calloc(1, sizeof(*member));
		if (ALLOC_FAILURE(member)) {
			continue;
		}
		member->agent = agent;
		member->queue = queue;
		if (calls_taken && name && agent->id == atoi(name)) {
			member->calls_taken = atoi(calls_taken);
		}
		RWLIST_WRLOCK(&queue->members);
		RWLIST_INSERT_HEAD(&queue->members, member, entry);
		RWLIST_UNLOCK(&queue->members);
	}
	RWLIST_UNLOCK(&queues);
	ami_resp_free(resp);
	return 0;
}

/*! \brief Draw the agent "home screen" showing all queues and their details */
static int queues_status(struct agent *agent)
{
	struct queue *queue;

	update_queue_stats();
	if (agent->stale) {
		update_member_stats(agent);
		agent->stale = 0;
	}

	bbs_node_writef(agent->node, "%-22s %6s\t%6s\t%6s\t%6s\n", "===== ACD QUEUE =====", "!!", "+", "-", "@");
	RWLIST_RDLOCK(&queues);
	RWLIST_TRAVERSE(&queues, queue, entry) {
		struct member *member = queue_member(queue, agent);
		if (!member) {
			continue;
		}
		bbs_node_writef(agent->node, "%-22s %6d\t%6d\t%6d\t%6d\n", queue->title, queue->ringing, queue->completed, queue->abandoned, member->calls_taken);
	}
	RWLIST_UNLOCK(&queues);
	return 0;
}

static int handle_call(struct agent *agent, struct queue_call *call)
{
	int res;
	struct queue_call_handler *qch;
	struct queue_call_handle qch_info;

	/* While this function is executing, call cannot disappear,
	 * since we've bumped its refcount. */

	RWLIST_RDLOCK(&handlers);
	RWLIST_TRAVERSE(&handlers, qch, entry) {
		if (!strcmp(qch->name, call->queue->handler)) {
			/* Increment refcount before breaking loop,
			 * to ensure it sticks around until we unref it. */
			bbs_module_ref(qch->mod, 1);
			break;
		}
	}
	RWLIST_UNLOCK(&handlers);

	if (!qch) {
		bbs_warning("No queue call handler exists for queue '%s'\n", call->queue->name);
		return -1;
	}

	/* Pass the call off to handling to a queue call handler
	 * for this particular queue.
	 * This is architected this way to keep the general queue handling logic
	 * in this module and anything queue-specific in its own module,
	 * which end users can focus on writing and customizing themselves as needed. */

	memset(&qch_info, 0, sizeof(qch_info));
	qch_info.node = agent->node;
	qch_info.agentid = agent->id;
	qch_info.queuetitle = call->queue->title;
	qch_info.id = call->id;
	qch_info.channel = call->channel;
	qch_info.ani = call->ani;
	qch_info.ani2 = call->ani2;
	qch_info.dnis = call->dnis;
	qch_info.cnam = call->cnam;

	/* At this point, there is junk left in the input buffer,
	 * probably from running the ncurses menu.
	 * Flush anything out so stray input isn't consumed in
	 * the next poll/read operation. */
	bbs_node_flush_input(agent->node);

	res = qch->handler(&qch_info);
	bbs_module_unref(qch->mod, 1);

	return res;
}

static int select_call(struct agent *agent)
{
	struct queue_call *call;
	int callid;
	int res;
	struct bbs_ncurses_menu menu;
	int call_count = 0;
	const char *optval;
	char subtitle[116];

	bbs_ncurses_menu_init(&menu);

	/* We're notified about calls when they arrive,
	 * but some channels may no longer exist or may be in the queue system.
	 * We can be notified about channel hangups but not necessarily if the channel
	 * exists and is no longer in the queue system.
	 * Manually check all channels in our list and see if any have gone bad. */
	prune_dead_calls(1);

	RWLIST_RDLOCK(&calls);
	RWLIST_TRAVERSE(&calls, call, entry) {
		char optkey[5];
		char optvalbuf[128];
		snprintf(optkey, sizeof(optkey), "%4d", call->id);
		snprintf(optvalbuf, sizeof(optvalbuf), "%4d   %-20s %02d %15lu   %-15s", call->id, call->queue->title, call->ani2, call->ani, call->cnam);
		bbs_ncurses_menu_addopt(&menu, 0, optkey, optvalbuf);
		call_count++;
	}
	RWLIST_UNLOCK(&calls);

	bbs_debug(4, "Currently %d call%s in all queues\n", call_count, ESS(call_count));
	if (!call_count) {
		/* No calls currently active. Abort. */
		bbs_node_ring_bell(agent->node);
		return 0;
	}

	/* Clear the agent's terminal.
	 * This is a subtle optimization. ncurses saves the previous window and restores it
	 * afterwards. Right now, the previous window is the main queue page showing all queues' status.
	 * Because bbs_ncurses_menu_getopt triggers a single run of ncurses, returns,
	 * and then based on the chosen option, potentially another run of ncurses is triggered,
	 * this would result in the main queue page briefly displaying again before being replaced by another menu.
	 * This is distracting and, on slower terminals, will waste time.
	 * Clearing the screen here ensures there is nothing to restore when the menu returns.
	 * When we need to display the queue screen again, we're going to print it again explicitly anyways. */
	bbs_node_clear_screen(agent->node);

	bbs_ncurses_menu_set_title(&menu, call_menu_title);
	snprintf(subtitle, sizeof(subtitle), "%4s   %-20s %2s %15s   %-15s", "ID #", "ACD QUEUE", "II", "ANI", "NAME");
	bbs_ncurses_menu_set_subtitle(&menu, subtitle);

	res = bbs_ncurses_menu_getopt(agent->node, &menu);
	if (res < 0) {
		bbs_ncurses_menu_destroy(&menu);
		return 0;
	}

	optval = bbs_ncurses_menu_getopt_name(&menu, res);
	if (!optval) {
		bbs_ncurses_menu_destroy(&menu);
		return 0;
	}

	/* The queue call ID is at the beginning of the string. atoi will exactly extract it for us. */
	callid = atoi(optval);
	bbs_ncurses_menu_destroy(&menu); /* No longer needed at this point */

	/* Look for this call in the list. */
	RWLIST_WRLOCK(&calls);
	RWLIST_TRAVERSE(&calls, call, entry) {
		if (call->id == callid) {
			if (call_is_dead(call)) {
				bbs_debug(3, "Call %d became dead before agent could handle it\n", call->id);
				call = NULL; /* Don't handle this call. It's dead. */
				break;
			}
			/* Prevent call from disappearing, while an agent is handling it. */
			call->refcount++;
			break;
		}
	}
	RWLIST_UNLOCK(&calls);

	if (!call) {
		bbs_debug(3, "Call %d disappeared before agent could handle it\n", callid);
		return 0;
	}

	res = handle_call(agent, call);
	RWLIST_WRLOCK(&calls);
	call->refcount--;
	RWLIST_UNLOCK(&calls);

	prune_dead_calls(0); /* We might be able to remove the call we just handled, if it no longer exists. */

	return res;
}

static void print_full_time(struct agent *agent)
{
	char str_date[256];
	time_t now = time(NULL);
	strftime(str_date, sizeof(str_date), "%Y/%m/%d %I:%M:%S %p", localtime(&now));
	bbs_node_writef(agent->node, "%s%s", COLOR(COLOR_MAGENTA), str_date);
}

#define BACKSPACE_BUF "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b"

static void print_full_time_update(struct agent *agent, int forcefull)
{
	time_t now;
	char str_date[32];
	now = time(NULL);
	strftime(str_date, sizeof(str_date), "%Y/%m/%d %I:%M:%S %p", localtime(&now));
	/* e.g. 2023/01/01 12:00:00 AM */
	if (forcefull) {
		bbs_node_writef(agent->node, "\r%s", str_date); /* Fully rewrite entire line */
	} else if (str_date[18] != '0') {
		/* If the last digit of the second is non-0, then nothing else could have changed from before.
		 * Only rewrite that.
		 * There are escape sequences to move to the exact column we want,
		 * but this is probably the simplest way to do it: back up a few and then overwrite the tail end. */
		bbs_node_writef(agent->node, "%.*s%s", 4, BACKSPACE_BUF, str_date + 18);
		/* Trust me, when you're the one accessing this at 300 baud,
		 * you will thank me for the added responsiveness! */
	} else {
		char last_date[32];
		const char *a, *b;
		int diff;
		now--;
		strftime(last_date, sizeof(last_date), "%Y/%m/%d %I:%M:%S %p", localtime(&now));
		/* Whenever the seconds digit is 0, then at least one previous character must also have changed.
		 * To determine how many, print the time a second ago into a buffer,
		 * and then see how similar the two strings are. */
		a = last_date;
		b = str_date;
		while (*a == *b) { /* It's guaranteed they differ in at least the digit, so no need to check for NUL terminator */
			a++;
			b++;
		}
		/* For example, say we transition thus:
		 * 2023/01/01 12:00:49 AM
		 * 2023/01/01 12:00:50 AM
		 *                  ^-- a/b after loop.
		 * diff = 17 after the loop.
		 * The entire string is 22 characters.
		 * We need to therefore print 5 backspaces, and then print str_date + 17.
		 *
		 * Now, if the change is drastic enough, say diff < X, for some X,
		 * then it'll be a smaller data transmission to either:
		 * - explicitly set the character using the "Set Cursor to Col" escape sequence. (X = length of the set column escape sequence)
		 * - print \r and rewrite the entire line. (X = ~width/2 = 22/2 = 11)
		 *
		 * Currently, we just fallback to the latter if needed.
		 */
		diff = (int) (a - last_date);
		if (diff > 12) {
			bbs_node_writef(agent->node, "%.*s%s", 22 - diff, BACKSPACE_BUF, str_date + diff);
		} else {
			bbs_node_writef(agent->node, "\r%s", str_date); /* Fully rewrite entire line */
		}
	}
}

static int agent_exec(struct bbs_node *node, const char *args)
{
	int agentid;
	struct agent *agent;
	const char *tmp;

	UNUSED(args);

	/* The agent's ID correlates into queues.conf in Asterisk.
	 * Right now these are set manually per user from variables.conf */

	bbs_node_lock(node);
	tmp = bbs_node_var_get(node, "ASTERISK_AGENT_ID");
	if (!tmp) {
		bbs_warning("Rejecting unauthorized queue agent '%s'\n", bbs_username(node->user));
		bbs_node_unlock(node);
		return 0;
	}
	agentid = atoi(tmp);
	bbs_node_unlock(node);

	agent = new_agent(node, agentid);
	if (!agent) {
		return 0;
	}

	if (update_member_stats(agent)) {
		goto cleanup;
	}

	/* Agent loop */
	for (;;) {
		unsigned int speed;
start:
		bbs_node_clear_screen(node);
		bbs_node_writef(node, "*** %s%-42s %s%d%s ***\n", COLOR(COLOR_MAGENTA), system_title, COLOR(COLOR_GREEN), agent->id, COLOR_RESET);
		queues_status(agent); /* Display current status of all relevant queues */

		/* On slow connections, it can take several seconds to print the entire queue list,
		 * and so we should wait to start printing the time until most of the data has been sent,
		 * or we'll end up quickly printing and erasing the time a bunch of times at the end. */
		speed = bbs_node_speed(node);
		if (speed && speed <= 1200 && bbs_node_wait_until_output_sent(node) < 0) {
			goto cleanup;
		}

		print_full_time(agent);
		bbs_node_unbuffer(node); /* Uncook the terminal. */

		/* Wait for something interesting to happen. */
		for (;;) {
			ssize_t res;
			char c;
			agent->idle = 1;
			res = bbs_node_poll(node, SEC_MS(1));
			agent->idle = 0;
			if (res < 0) {
				goto cleanup;
			}
			if (!res) {
				/* Nothing happened. Update the time and repeat. */
				if (agent->gotwritten) {
					/* Color was reset, so set it back */
					bbs_node_writef(node, "%s", COLOR(COLOR_MAGENTA));
				}
				print_full_time_update(agent, agent->gotwritten); /* Update the current time */
				agent->gotwritten = 0; /* If we were, we handled it, and are no more */
				continue;
			}
			/* else, got input from the node */
			res = bbs_node_read(node, &c, 1);
			if (res != 1) {
				goto cleanup;
			}
			if (!isalnum(c)) {
				bbs_debug(3, "Ignoring non-alphanumeric input: %d\n", c);
				continue;
			}
			bbs_debug(3, "Handling agent input '%c'\n", c);
			bbs_node_writef(node, "%s", COLOR_RESET);
			switch (c) {
				case 'l': /* Load (handle) call(s) */
					res = select_call(agent);
					if (res < 0) {
						bbs_debug(4, "Aborting queue system\n");
						goto cleanup;
					}
					goto start;
				case 'r': /* Refresh table */
				case '\n':
					goto start;
				case 'x':
				case 'q':
					goto cleanup;
				default: /* Ignore */
					bbs_node_writef(node, "%s", COLOR(COLOR_MAGENTA));
			}
		}
	}

cleanup:
	del_agent(agent);
	return 0;
}

static struct bbs_cli_entry cli_commands_queues[] = {
	BBS_CLI_COMMAND(cli_asterisk_queues, "asterisk queues", 2, "List Asterisk queues", NULL),
	BBS_CLI_COMMAND(cli_asterisk_agents, "asterisk agents", 2, "List Asterisk queue agents", NULL),
	BBS_CLI_COMMAND(cli_asterisk_calls, "asterisk calls", 2, "List Asterisk queue calls", NULL),
};

static int load_config(void)
{
	int res = 0;
	struct bbs_config *cfg;
	struct bbs_config_section *section = NULL;

	cfg = bbs_config_load("mod_asterisk_queues.conf", 1);
	if (!cfg) {
		return -1;
	}

	res |= bbs_config_val_set_str(cfg, "general", "title", system_title, sizeof(system_title));
	res |= bbs_config_val_set_str(cfg, "general", "callmenutitle", call_menu_title, sizeof(call_menu_title));
	res |= bbs_config_val_set_str(cfg, "general", "queueidvar", queue_id_var, sizeof(queue_id_var));

	if (res) {
		bbs_warning("Missing required settings in [general]\n");
		return -1;
	}

	RWLIST_WRLOCK(&queues);
	while ((section = bbs_config_walk(cfg, section))) {
		struct queue *queue;
		struct bbs_keyval *keyval = NULL;
		const char *name = NULL, *title = NULL, *handler = NULL; /* Mandatory */
		size_t datalen, namelen, titlelen, handlerlen; /* Mandatory */
		char *data;
		if (!strcmp(bbs_config_section_name(section), "general")) {
			continue; /* Not a queue, skip */
		}
		if (find_queue(bbs_config_section_name(section))) {
			bbs_warning("Queue '%s' already exists\n", bbs_config_section_name(section));
			continue;
		}

		while ((keyval = bbs_config_section_walk(section, keyval))) {
			const char *key = bbs_keyval_key(keyval), *value = bbs_keyval_val(keyval);
			if (!strcasecmp(key, "title")) {
				title = value;
				titlelen = strlen(value) + 1;
			} else if (!strcasecmp(key, "handler")) {
				handler = value;
				handlerlen = strlen(value) + 1;
			} else {
				bbs_warning("Unknown directive: %s\n", key);
			}
		}

		name = bbs_config_section_name(section);
		namelen = strlen(name) + 1;

		if (!title) {
			bbs_warning("Missing mandatory field 'title' for '%s'\n", name);
			continue;
		} else if (!handler) {
			bbs_warning("Missing mandatory field 'handler' for '%s'\n", name);
			continue;
		}

		datalen = namelen + titlelen + handlerlen;
		queue = calloc(1, sizeof(*queue) + datalen);
		if (ALLOC_FAILURE(queue)) {
			continue;
		}
		data = queue->data;
		SET_FSM_STRING_VAR(queue, data, name, name, namelen);
		SET_FSM_STRING_VAR(queue, data, title, title, titlelen);
		SET_FSM_STRING_VAR(queue, data, handler, handler, handlerlen);
		queue->stale = 1; /* Needs to be initialized with queue stats */
		RWLIST_HEAD_INIT(&queue->members);
		RWLIST_INSERT_TAIL(&queues, queue, entry);
		bbs_debug(4, "Added queue '%s'\n", name);
	}
	RWLIST_UNLOCK(&queues);

	return 0;
}

static void queue_free(struct queue *queue)
{
	RWLIST_HEAD_DESTROY(&queue->members);
	free(queue);
}

static int unload_module(void)
{
	bbs_cli_unregister_multiple(cli_commands_queues);
	bbs_ami_callback_unregister(ami_callback);
	bbs_unregister_door("astqueue");
	/* Agents and queue members will all be gone if the module is being unloaded, only queues are persistent */
	RWLIST_REMOVE_ALL(&queues, entry, queue_free);
	RWLIST_REMOVE_ALL(&calls, entry, free);
	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		RWLIST_REMOVE_ALL(&queues, entry, free);
		return -1;
	}
	/* Once we're ready to go, add the callback */
	if (bbs_ami_callback_register(ami_callback)) {
		RWLIST_REMOVE_ALL(&queues, entry, free);
		return -1;
	}
	if (update_queue_stats()) {
		RWLIST_REMOVE_ALL(&queues, entry, free);
		RWLIST_REMOVE_ALL(&calls, entry, free);
		return -1;
	}
	if (bbs_register_door("astqueue", agent_exec)) {
		bbs_ami_callback_unregister(ami_callback);
		RWLIST_REMOVE_ALL(&queues, entry, free);
		RWLIST_REMOVE_ALL(&calls, entry, free);
		return -1;
	}
	bbs_cli_register_multiple(cli_commands_queues);
	return 0;
}

BBS_MODULE_INFO_FLAGS_DEPENDENT("Asterisk Queues", MODFLAG_GLOBAL_SYMBOLS, "mod_asterisk_ami.so,mod_ncurses.so");
