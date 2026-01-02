/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2023-2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Operator Position System
 *
 * \note This is the queue handling logic for a basic operator position system
 *
 * While this module has been written in a generic manner, it has been tailored
 * to a particular application.
 * It is not intended to be used on any system other than the one running this system.
 *
 * I have open sourced this for two reasons:
 * - To provide an example of queue call handler implementation
 * - To allow other collaborators to update and improve this module, if needed
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <ctype.h>

#include <cami/cami.h>

#include "include/module.h"
#include "include/config.h"
#include "include/node.h"
#include "include/term.h"
#include "include/variables.h"
#include "include/json.h"
#include "include/string.h"
#include "include/cli.h"

#include "include/mod_curl.h"

#include "include/mod_asterisk_ami.h"
#include "include/mod_asterisk_queues.h"
#include "include/mod_ncurses.h"

/* Operator */
static char url_time_of_day[256] = "";
static char url_local_exchanges[256] = "";
static char url_rate_quote[256] = "";
static char url_reverse_lookup[256] = "";
static char context_operator_xfer[84] = "";
static char variable_cvs[64] = "";

/* Intercept */
static char variable_intercepted_num[32] = "";
static char url_intercept_lookup[256] = "";

/* Directory */
static char url_directory_location[256] = "";
static char url_directory_lookup[512] = "";

/* Coin Zone */
static char variable_amount_required[32] = "";

/* ONI */
static char channel_queue_inject[128] = "";
static char context_oni_digits[64] = "";
static char variable_queue_channel[32] = ""; /* W/O */
static char variable_supervisor_channel[32] = ""; /* R/O */
static char context_oni_eval[64] = "";
static char variable_oni_set[64] = "";

/* TRS */
static char variable_queuechannelout[128] = "";
static char relay_greeting[24] = "";
static char context_trs_transfer[64] = "";

/* Emergency */
static char url_emergency_caller_info[128] = "";
static char variable_n11translations[64] = "";

static bbs_mutex_t timelock = BBS_MUTEX_INITIALIZER;

/* Based on https://stackoverflow.com/a/15301457/ */
static void nonlocaltime(const char *tzname, char *buf, size_t len)
{
	char *tz;
    time_t now;

	now = time(NULL);

	bbs_mutex_lock(&timelock);

    tz = getenv("TZ");
    if (tz) {
        tz = strdup(tz);
	}
	/* Override TZ */
    setenv("TZ", tzname, 1);
    tzset();

	/* Use TZ */
    strftime(buf, len, "%Y/%m/%d %I:%M:%S %p", localtime(&now));

	/* Restore original TZ */
    if (tz) {
        setenv("TZ", tz, 1);
        free(tz);
    } else {
        unsetenv("TZ");
	}
    tzset();

	bbs_mutex_unlock(&timelock);
}

static int node_read_variable(struct bbs_node *node, const char *key)
{
	char buf[84];
	int res;

	/* First, flush any pending output,
	 * since otherwise a previous keystroke
	 * might still be here and cause us to return immediately. */
	bbs_node_flush_input(node);

	bbs_node_buffer(node);
	res = bbs_node_read_line(node, MIN_MS(5), buf, sizeof(buf));
	bbs_node_unbuffer(node);

	if (res <= 0) {
		return res;
	} else if (strlen(buf) >= sizeof(buf)) {
		bbs_warning("Truncation reading into buffer for variable '%s'\n", key);
		return 0;
	}

	bbs_node_var_set(node, key, buf);
	return res;
}

/*! \brief Reverse lookup of a number */
static int reverse_lookup(struct queue_call_handle *qch)
{
	char subbuf[256];
	int res;
	struct bbs_curl c = {
		.forcefail = 1,
	};

	bbs_node_writef(qch->node, "REV LOOKUP: ");

	if (qch->ani) {
		/* Prepopulate the buffer with the caller's phone number, if available.
		 * To do so, spoof the input as if received from the node on the master,
		 * so that it will appear on the slave. */
		bbs_debug(3, "Call associated, prepopulating '%lu' as default response\n", qch->ani);

		/* Do these before node_read_variable does, or we'll lose it */
		bbs_node_flush_input(qch->node);
		bbs_node_buffer(qch->node);

		bbs_dprintf(qch->node->amaster, "%lu", qch->ani);
	}

	res = node_read_variable(qch->node, "QUEUE_OTHER_NUMBER");

	if (res <= 0) {
		return res;
	}
	bbs_node_substitute_vars(qch->node, url_reverse_lookup, subbuf, sizeof(subbuf));
	memset(&c, 0, sizeof(c));
	c.url = subbuf;
	if (bbs_curl_get(&c)) {
		bbs_node_writef(qch->node, "Reverse Lookup unavailable\n");
	} else {
		json_error_t err;
		json_t *json = json_loads(c.response, 0, &err);
		bbs_curl_free(&c);
		if (json) {
			bbs_node_writef(qch->node, "*** REVERSE LOOKUP ***\n%-10s %s\n%-10s %s\n", "CNAM", json_object_string_value(json, "cnam"), "NBR OWNER", json_object_string_value(json, "owner"));
			json_decref(json);
		}
	}

	bbs_node_wait_key(qch->node, MIN_MS(2));
	return 0;
}

/*! \brief Default handler with general options that apply to most calls */
static int handle_default(struct queue_call_handle *qch)
{
	struct bbs_ncurses_menu menu;
	char subtitle[96];
	char opt;
	struct bbs_curl c = {
		.forcefail = 1,
	};

	bbs_node_clear_screen(qch->node);
	bbs_ncurses_menu_init(&menu);
	bbs_ncurses_menu_set_title(&menu, "OPERATOR POSITION SYSTEM");

	/* Private network CVS (Caller Verification Status/Score) code */
	if (!s_strlen_zero(variable_cvs)) {
		int cvs;
		char *val;
		/* It would be more efficient to just get this once, when we request the other channel variables in mod_asterisk_queues,
		 * but this promotes better modularity since this is a queue-specific (or queue group specific) variable.
		 * XXX Maybe we can define variables we should request in mod_asterisk_queues? */
		val = bbs_ami_action_getvar(NULL, variable_cvs, qch->channel);
		cvs = atoi(S_IF(val));
		free_if(val);
		snprintf(subtitle, sizeof(subtitle), "%s\tII %02d [CVS %02d] (%s) %lu\n", qch->queuetitle, qch->ani2, cvs, qch->cnam, qch->ani);
	} else {
		snprintf(subtitle, sizeof(subtitle), "%s\tII %02d (%s) %lu\n", qch->queuetitle, qch->ani2, qch->cnam, qch->ani);
	}

	bbs_ncurses_menu_set_subtitle(&menu, subtitle);
	if (!s_strlen_zero(url_reverse_lookup)) {
		bbs_ncurses_menu_addopt(&menu, 'v', "Re[v]erse Lookup", NULL);
	}

	opt = bbs_ncurses_menu_getopt_selection(qch->node, &menu);
	bbs_ncurses_menu_destroy(&menu);
	if (opt == 0) {
		return 0;
	}

	bbs_node_clear_screen(qch->node);
	bbs_node_flush_input(qch->node); /* Seems to be necessary to drain unwanted pending input, for multiple options */
	memset(&c, 0, sizeof(c));
	/* Do variable replacement via node variable,
	 * to avoid format string injection.
	 * In theory, this doesn't need to be (and probably shouldn't be)
	 * the agent's node; if we used a temporary node, we could clean it up
	 * immediately afterwards. */
	bbs_node_var_set_fmt(qch->node, "QUEUE_ANI", "%lu", qch->ani);

	switch (opt) {
	case 'v':
		return reverse_lookup(qch);
	default:
		bbs_warning("Unhandled menu return %d?\n", opt);
	}

	bbs_node_wait_key(qch->node, MIN_MS(2));
	return 0;
}

static int operator_dial_number(struct queue_call_handle *qch)
{
	char othernum[32];
	char agentchan[64];
	char dialnum[38];

	/* Node is already buffered here */
	bbs_node_writef(qch->node, "\nSTATION-TO-STATION NBR TO DIAL: ");
	if (bbs_node_read_line(qch->node, MIN_MS(5), othernum, sizeof(othernum)) <= 0) {
		return 0; /* If no number entered or other issue, just bail out */
	}

	/* At this point, the agent better be bridged to the caller. Otherwise, how'd we get a number? */
	if (bbs_ami_action_getvar_buf(NULL, "BRIDGEPEER", qch->channel, agentchan, sizeof(agentchan))) { /* Get agent's channel (since they're bridged now) */
		bbs_warning("Not connected to agent? Aborting.\n");
		return -1;
	}
	if (!*othernum || !atoi(othernum)) {
		bbs_debug(3, "Invalid number, aborting\n");
		return 0;
	}
	/* Station-to-station call.
	 * For some reason, xfer context wants 2 digits, so **, then call type (1/2/3), then number, then # to terminate in case <7 digits. */
	snprintf(dialnum, sizeof(dialnum), "w1%s%sw*2", othernum, strlen(othernum) < 7 ? "#" : "");
	if (bbs_ami_action_response_result(NULL, bbs_ami_action_axfer(NULL, agentchan, dialnum, context_operator_xfer))) {
		bbs_warning("Failed to set up attended transfer to %s\n", dialnum);
		return -1;
	}
	bbs_node_writef(qch->node, "DIALED %s + RLS\n", othernum);
	return 0;
}

/*! \brief 0+/0- operator calls */
static int handle_operator(struct queue_call_handle *qch)
{
	struct bbs_ncurses_menu menu;
	char subtitle[96];
	char subbuf[256];
	char opt;
	int res;
	struct bbs_curl c = {
		.forcefail = 1,
	};

	bbs_node_clear_screen(qch->node);
	bbs_ncurses_menu_init(&menu);
	bbs_ncurses_menu_set_title(&menu, "OPERATOR POSITION SYSTEM");

	/* Private network CVS (Caller Verification Status/Score) code */
	if (!s_strlen_zero(variable_cvs)) {
		int cvs;
		char *val;
		/* It would be more efficient to just get this once, when we request the other channel variables in mod_asterisk_queues,
		 * but this promotes better modularity since this is a queue-specific (or queue group specific) variable.
		 * XXX Maybe we can define variables we should request in mod_asterisk_queues? */
		val = bbs_ami_action_getvar(NULL, variable_cvs, qch->channel);
		cvs = atoi(S_IF(val));
		free_if(val);
		snprintf(subtitle, sizeof(subtitle), "OPERATOR 0 MINUS\tII %02d [CVS %02d] (%s) %lu -> %lu\n", qch->ani2, cvs, qch->cnam, qch->ani, qch->dnis);
	} else {
		snprintf(subtitle, sizeof(subtitle), "OPERATOR 0 MINUS\tII %02d (%s) %lu -> %lu\n", qch->ani2, qch->cnam, qch->ani, qch->dnis);
	}

	bbs_ncurses_menu_set_subtitle(&menu, subtitle);
	if (!s_strlen_zero(url_time_of_day)) {
		bbs_ncurses_menu_addopt(&menu, 'd', "Time of [D]ay", NULL);
	}
	if (!s_strlen_zero(url_local_exchanges)) {
		bbs_ncurses_menu_addopt(&menu, 'l', "[L]ocal Exchanges", NULL);
	}
	if (!s_strlen_zero(url_rate_quote)) {
		bbs_ncurses_menu_addopt(&menu, 'r', "[R]ate Quote", NULL);
	}
	if (!s_strlen_zero(context_operator_xfer)) {
		bbs_ncurses_menu_addopt(&menu, 's', "[S]tation-to-Station", NULL);
	}
	if (!s_strlen_zero(url_reverse_lookup)) {
		bbs_ncurses_menu_addopt(&menu, 'v', "Re[v]erse Lookup", NULL);
	}

	opt = bbs_ncurses_menu_getopt_selection(qch->node, &menu);
	bbs_ncurses_menu_destroy(&menu);
	if (opt == 0) {
		return 0;
	}

	bbs_node_clear_screen(qch->node);
	bbs_node_flush_input(qch->node); /* Seems to be necessary to drain unwanted pending input, for multiple options */
	memset(&c, 0, sizeof(c));
	/* Do variable replacement via node variable,
	 * to avoid format string injection.
	 * In theory, this doesn't need to be (and probably shouldn't be)
	 * the agent's node; if we used a temporary node, we could clean it up
	 * immediately afterwards. */
	bbs_node_var_set_fmt(qch->node, "QUEUE_ANI", "%lu", qch->ani);

	switch (opt) {
	case 'd': /* Time of Day */
		bbs_assert(!s_strlen_zero(url_time_of_day)); /* Wouldn't have added it as a valid option otherwise */
		bbs_node_substitute_vars(qch->node, url_time_of_day, subbuf, sizeof(subbuf));
		c.url = subbuf; /* This has to be after the substitution for some reason, or it'll still be empty when used */
		if (bbs_curl_get(&c)) {
			bbs_node_writef(qch->node, "Time of Day service unavailable\n");
		} else {
			char timebuf[48];
			if (strlen_zero(c.response)) {
				bbs_warning("Empty response from Time of Day service?\n");
			}
			for (;;) {
				nonlocaltime(c.response, timebuf, sizeof(timebuf));
				bbs_node_writef(qch->node, "\r%-2s %s\t\t%s", "TZ", c.response, timebuf);
				/* Repeat time until interrupted */
				if (bbs_node_poll(qch->node, SEC_MS(1))) {
					break;
				}
			}
			bbs_curl_free(&c);
			return 0; /* User already hit a key */
		}
		break;
	case 'l': /* Local Exchanges */
		bbs_node_substitute_vars(qch->node, url_local_exchanges, subbuf, sizeof(subbuf));
		c.url = subbuf;
		if (bbs_curl_get(&c)) {
			bbs_node_writef(qch->node, "Local Exchange lookup unavailable\n");
		} else {
			const char *key;
			json_t *value;
			json_error_t err;
			json_t *json = json_loads(c.response, 0, &err);
			bbs_curl_free(&c);
			if (json) {
				int same = 0;
				const char *skey = NULL;
				const char *pkey = NULL, *pcity = NULL, *pstate = NULL, *pcountry = NULL;
				char output[96];
				bbs_ncurses_menu_init(&menu);
				bbs_ncurses_menu_set_title(&menu, "LOCAL CALLING AREA");
				json_object_foreach(json, key, value) {
					const char *city, *state, *country;
					json_t *jcity = json_object_get(value, "city");
					json_t *jstate = json_object_get(value, "state");
					json_t *jcountry = json_object_get(value, "country");
					city = json_string_value(jcity);
					state = json_string_value(jstate);
					country = json_string_value(jcountry);
					same = 0;
					if (pkey) {
						const char *block1 = pkey + 3;
						const char *block2 = key + 3;
						/* Requiring conseuctive blocks for a row does mean
						 * if there are non-consecutive thousand blocks in the same NNX,
						 * they'll appear disjointly (in separate rows.
						 * Simply removing this is wrong since it'll fill in everything inbetween without further logic. */
						if (!strncmp(key, pkey, 3) && (*block2 == *block1 + 1) && !strcmp(city, pcity)
							&& ((!strlen_zero(state) && !strlen_zero(pstate) && !strcmp(state, pstate)) || (strlen_zero(state) && strlen_zero(pstate)))
							&& !strcmp(country, pcountry)) {
							/* Within an NNX, if all the info is the same for successive thousand blocks, print it out as such */
							same = 1;
						}
					}
#define IN_RANGE(digit) ('0' + digit >= *(skey + 3) && '0' + digit <= *(pkey + 3) ? #digit : " ")
					if (!same && skey) {
						/* This is the start of something new... */
						snprintf(output, sizeof(output), "%.3s   %s %s %s %s %s %s %s %s %s %s    %s %s %s", skey,
							IN_RANGE(0), IN_RANGE(1), IN_RANGE(2), IN_RANGE(3), IN_RANGE(4), IN_RANGE(5), IN_RANGE(6), IN_RANGE(7), IN_RANGE(8), IN_RANGE(9),
							pcountry, S_IF(pstate), pcity);
						bbs_debug(3, "Adding opt: %s\n", output);
						bbs_ncurses_menu_addopt(&menu, 0, output, NULL);
					}
					if (!same) {
						skey = key;
					}
					bbs_debug(7, "%s [%d]: %s/%s/%s\n", key, same, city, S_IF(state), country);
					pkey = key;
					pcity = city;
					pstate = state;
					pcountry = country;
				}
				/* Print out the last one */
				if (same && skey) {
					snprintf(output, sizeof(output), "%.3s   %s %s %s %s %s %s %s %s %s %s    %s %s %s", skey,
						IN_RANGE(0), IN_RANGE(1), IN_RANGE(2), IN_RANGE(3), IN_RANGE(4), IN_RANGE(5), IN_RANGE(6), IN_RANGE(7), IN_RANGE(8), IN_RANGE(9),
						pcountry, S_IF(pstate), pcity);
					bbs_ncurses_menu_addopt(&menu, 0, output, NULL);
#undef IN_RANGE
				}
				json_decref(json);
				/* Use menu to display the result, but we don't actually need to get any input,
				 * so just discard the result. */
				bbs_ncurses_menu_getopt(qch->node, &menu);
				bbs_ncurses_menu_destroy(&menu);
				return 0; /* Already exited menu by pressing a key */
			}
		}
		break;
	case 'r':
		bbs_node_writef(qch->node, "OTHER NBR: ");
		res = node_read_variable(qch->node, "QUEUE_OTHER_NUMBER");
		if (res <= 0) {
			return res;
		}
		bbs_node_substitute_vars(qch->node, url_rate_quote, subbuf, sizeof(subbuf));
		c.url = subbuf;
		if (bbs_curl_get(&c)) {
			bbs_node_writef(qch->node, "Rate Quote System unavailable\n");
		} else {
			json_error_t err;
			json_t *json = json_loads(c.response, 0, &err);
			bbs_curl_free(&c);
			if (json) {
				json_t *direct, *station, *person, *collect;
				const char *distance, *city, *state, *zip, *zip2;
				int ratestep, addmin;
				char output[512];
				const char *othernum;

				distance = json_string_value(json_object_get(json, "distance")); /* Safe to use if object_get returns NULL */
				city = json_string_value(json_object_get(json, "city"));
				state = json_string_value(json_object_get(json, "state"));
				zip = json_string_value(json_object_get(json, "zip"));
				zip2 = json_string_value(json_object_get(json, "zip2"));
				ratestep = (int) json_number_value(json_object_get(json, "ratestep"));
				addmin = (int) json_number_value(json_object_get(json, "addmin"));
				direct = json_object_get(json, "direct");
				station = json_object_get(json, "station");
				person = json_object_get(json, "person");
				collect = json_object_get(json, "collect");

#define CENTS_TO_DOLLARS(cents) (1.0 * cents / 100)
				bbs_node_lock(qch->node);
				othernum = bbs_node_var_get(qch->node, "QUEUE_OTHER_NUMBER");
				snprintf(output, sizeof(output),
					"%-10s %lu\n%-10s %s\n"
					"%-10s %s (mi)\n%-10s %s\n%-10s %s\n%-10s %s\n%-10s %s\n"
					"%-10s %d\n%-10s %d\n"
					"%-13s %5s %5s %5s\n"
					"%-13s %5d $%.2f %5d\n" "%-13s %5d $%.2f %5d\n" "%-13s %5d $%.2f %5d\n" "%-13s %5d $%.2f %5d\n",
					"CLG NO", qch->ani, "CLD NO", othernum,
					"DISTANCE", distance, "CITY", city, "STATE", state, "ZIP1", zip, "ZIP2", zip2,
					"RATE STEP", ratestep, "PER MIN", addmin,
					"CALL TYPE", "CODE", "BASE", "MIN",
					"DIRECT", json_object_int_value(direct, "ratecode"), CENTS_TO_DOLLARS(json_object_number_value(direct, "base")), json_object_int_value(direct, "basemin"),
					"STATION", json_object_int_value(station, "ratecode"), CENTS_TO_DOLLARS(json_object_number_value(station, "base")), json_object_int_value(station, "basemin"),
					"PERSON", json_object_int_value(person, "ratecode"), CENTS_TO_DOLLARS(json_object_number_value(person, "base")), json_object_int_value(person, "basemin"),
					"COLLECT", json_object_int_value(collect, "ratecode"), CENTS_TO_DOLLARS(json_object_number_value(collect, "base")), json_object_int_value(collect, "basemin")
					);
				bbs_node_unlock(qch->node);

				json_decref(json);
				bbs_node_writef(qch->node, "%s", output);
			}
		}
		break;
	case 's':
		bbs_node_buffer(qch->node);
		operator_dial_number(qch);
		bbs_node_unbuffer(qch->node);
		break;
	/*! \todo add options for person-to-person, collect calls */
	case 'v':
		return reverse_lookup(qch);
	default:
		bbs_warning("Unhandled menu return %d?\n", opt);
	}

	bbs_node_wait_key(qch->node, MIN_MS(2));
	return 0;
}

static int handle_intercept(struct queue_call_handle *qch)
{
	char othernum[32];
	char url[256];
	int res;
	struct bbs_curl c = {
		.forcefail = 1,
	};

	bbs_node_clear_screen(qch->node);
	bbs_node_writef(qch->node, "*** SPECIAL OPERATOR ***\nDNIS: %lu\nNBR DIALED: ", qch->dnis);
	res = node_read_variable(qch->node, "QUEUE_DIALED_NUMBER");
	if (res <= 0) {
		return res;
	}

	if (!s_strlen_zero(variable_intercepted_num)) {
		/* If we don't get here before the agent hangs up,
		 * trigger a recording to play on the channel,
		 * which will happen if this variable is not set. */
		bbs_ami_action_setvar(NULL, variable_intercepted_num, othernum, qch->channel);
	}

	bbs_node_substitute_vars(qch->node, url_intercept_lookup, url, sizeof(url));
	c.url = url;
	if (bbs_curl_get(&c)) {
		bbs_node_writef(qch->node, "Intercept lookup unavailable\n");
	} else {
		int exists = c.response[0] == '1';
		bbs_curl_free(&c);
		bbs_node_writef(qch->node, "%s\n", exists ? "WORKING NBR - DIAL AGAIN PLS" : "NO SUCH NBR - CHK AND REDIAL");
	}

	bbs_node_wait_key(qch->node, MIN_MS(2));
	return 0;
}

/* (NPA) NXX-XXXX */
#define NANPA_FORMATTED_NUMBER_BUF_SIZE 15

/* gcc thinks the strcpy at the end of this function could exceed the buffer,
 * but it can't, since we copy no more than 4 characters + NUL at that point */
#pragma GCC diagnostic ignored "-Warray-bounds"
#pragma GCC diagnostic ignored "-Wstringop-overflow"
/*! \note This function is NOT SAFE to call with a buffer size smaller than NANPA_FORMATTED_NUMBER_BUF_SIZE */
static void format_nanpa_number(const char *number, char *restrict buf, size_t len)
{
	size_t numlen;

	if (strlen_zero(number)) {
		*buf = '\0';
		return;
	}

	numlen = strlen(number);
	if (numlen > 11 || (numlen == 11 && *number != '1')) {
		/* Not valid NANPA number */
		safe_strncpy(buf, number, len);
		return;
	}

	bbs_assert(len >= NANPA_FORMATTED_NUMBER_BUF_SIZE);
	if (numlen == 11) {
		number++;
		numlen--;
	}
	bbs_assert(numlen <= 10);
	if (numlen > 7) {
		size_t digits = numlen - 7;
		if (numlen >= 10) {
			*buf++ = '(';
		}
		memcpy(buf, number, digits); /* Area code */
		buf += digits;
		number += digits;
		if (numlen >= 10) {
			*buf++ = ')';
		}
		*buf++ = ' ';
		numlen = 7;
	}
	if (numlen > 4) {
		size_t digits = numlen - 4;
		memcpy(buf, number, digits); /* Exchange */
		buf += digits;
		number += digits;
		*buf++ = '-';
	}
	strcpy(buf, number); /* Line number digits */
}

/*!
 * \brief Obtain the city ID for the requested location
 * \param qch
 * \retval -2 on failure, abort
 * \retval -1 if no matching results, try again
 * \retval 0 for nationwide search (XXX)
 * \return Positive city ID
 */
static int get_directory_location(struct queue_call_handle *qch)
{
	char *city = NULL, *state = NULL;
	char citystate[32];
	char fullcity[96];
	char fullstate[3];
	char title[54];
	char url[512];
	struct bbs_ncurses_menu menu;
	struct bbs_curl c = {
		.forcefail = 1,
	};
	int res, cityid = 0; /* MAX(id) can fit in an int */

	bbs_node_flush_input(qch->node);
	bbs_node_buffer(qch->node);
	bbs_node_writef(qch->node, "CTY.ST: ");
	res = bbs_node_read_line(qch->node, MIN_MS(5), citystate, sizeof(citystate));
	if (res <= 0) {
		return -2;
	}
	if (!strcasecmp(citystate, "XXX.")) {
		city = state = NULL; /* Wildcard location */
	} else {
		if (s_strlen_zero(citystate)) {
			/* Just hit ENTER, abort */
			return -2;
		}
		city = citystate;
		state = strchr(city, '.');
		if (state) {
			*state++ = '\0';
			bbs_str_toupper(state); /* Capitalize state fully */
		}
		*city = (char) toupper(*city); /* Capitalize city */
	}
	/* Got a location (or wildcard). */
	if (!strlen_zero(city)) {
		/* Specific city. Retrieve list of city/[state]. Try using state, fall back to country. */
		bbs_node_var_set(qch->node, "QUEUE_DIRECTORY_CITY", city);
		if (!strlen_zero(state)) {
			bbs_node_var_set(qch->node, "QUEUE_DIRECTORY_STATE", state);
		}
		bbs_node_substitute_vars(qch->node, url_directory_location, url, sizeof(url));
		bbs_debug(3, "URL: %s\n", url);
		c.url = url;
		if (bbs_curl_get(&c)) {
			bbs_warning("City lookup unavailable\n");
			return -2;
		} else {
			const char *key;
			char opt;
			json_t *value;
			json_error_t err;
			json_t *json = json_loads(c.response, 0, &err);
			bbs_curl_free(&c);
			if (!json) {
				/* No matches */
				return -1;
			}

			bbs_ncurses_menu_init(&menu);
			opt = 'A';
			json_object_foreach(json, key, value) {
				char optbuf[256];
				snprintf(optbuf, sizeof(optbuf), "[%c] %d %2s %2s %s",
					opt <= 'Z' ? opt : ' ',
					json_object_int_value(value, "id"),
					json_object_string_value(value, "country"),
					json_object_string_value(value, "state"),
					json_object_string_value(value, "city"));
				bbs_ncurses_menu_addopt(&menu, opt <= 'Z' ? opt : 0, optbuf, NULL);
				if (opt <= 'Z') {
					/* Don't increment after we run out,
					 * otherwise a char could wrap back around to 'A' eventually. */
					opt++;
				}
			}
			if (opt > 'A') {
				int index = 0;
				/* Menu contains items. */
				snprintf(title, sizeof(title), "KEYED:%s.%s", city, S_IF(state));
				bbs_ncurses_menu_set_title(&menu, title);
				res = bbs_ncurses_menu_getopt(qch->node, &menu);
				bbs_ncurses_menu_destroy(&menu);
				if (res < 0) {
					json_decref(json);
					return -2;
				}
				/* Find the option at this index again to extract the city and state */
				json_object_foreach(json, key, value) {
					if (index++ == res) {
						/* This is the option chosen. Extract city/state with full, actual names,
						 * not just the starts. */
						cityid = json_object_int_value(value, "id");
						safe_strncpy(fullcity, json_object_string_value(value, "city"), sizeof(fullcity));
						if (json_object_string_value(value, "state")) {
							safe_strncpy(fullstate, json_object_string_value(value, "state"), sizeof(fullstate));
						} else {
							safe_strncpy(fullstate, json_object_string_value(value, "country"), sizeof(fullstate));
						}
						city = fullcity;
						state = fullstate;
						break;
					}
				}
			}
			json_decref(json);
		}
		if (!cityid) {
			bbs_warning("Missing City ID\n");
			return -1;
		}
	} /* else, if "XXX." was entered, it's okay to not have a City ID here */

	return cityid;
}

enum directory_search_type {
	DIRECTORY_SEARCH_RES = (1 << 0),
	DIRECTORY_SEARCH_BUS = (1 << 1),
	DIRECTORY_SEARCH_REV = (1 << 2),
	DIRECTORY_SEARCH_PNET = (1 << 3),
};

static int handle_directory(struct queue_call_handle *qch)
{
	char agentchan[256];

	/* https://www.telephonetribute.com/todays_operator.html
	The first 3 letters of the city, then a period, then the 2 letter state abbrev. Some examples are below.
	LOU.KY. < - Louisville, Kentucky
	ANN.AL. < - Anniston, Alabama
	ATL.GA. < - Atlanta, Georgia
	XXX. < - Nationwide Search (prohibited for operators, only for supervisor use.)
	AMI. <Searches nation for any city starting with the letters A, M or I.)
	Once the operator keys in the city, she or he then presses the CTY/STT key. A List of all found cities matching this criteria is displayed. An example is shown below.
	KEYED: ANN.AL.
	A - Anniston
	B - Anniemanie
	C - Annitock
	D - Area 205
	E - Calhoun County
	For Anniston, the operator would press "A". 
	Then she keys in the listing. This is done in the same manner. First 3 letters of the first word, First 3 letters of the second word.
	Take Office Depot. You would key it in like this "OFF.DEP." A Listing in that city would appear:
	CUR.CITY: ANNISTON, ALABAMA (AREA 205, ANNISTON-CALHOUN COUNTY)
	LSTN: OFF.DEP.
	A-Office Depot 505 Bernard Ave. 205-238-5092
	B-Office Depot 912 Alexandra.Av. 256-999-2918
	A or B? <A/B> TOLL: $1.90
	In this screen the operator requests the street name of the listing. "Would you like the Office Depot on Bernard Avenue or Alexandria Ave?", then selecting the appropriate listing, by pressing A or B. Then AUTO/VBL. or HANDOFF on certain keyboards
	The customer is then charged $1.90. (whew!), they are then connected with the ARU. <Audio Response Unit>. This unit will read the following sentence twice, offer completion, then disconnect. */

	if (s_strlen_zero(url_directory_location)) {
		bbs_warning("Missing required variables for directory lookup\n");
		return -1;
	}

	if (bbs_ami_action_getvar_buf(NULL, "BRIDGEPEER", qch->channel, agentchan, sizeof(agentchan))) { /* Get agent's channel (since they're bridged now) */
		bbs_warning("Not connected to agent? Aborting.\n");
		return -1;
	}

	for (;;) {
		int res;
		char outputbuf[256];
		char listing[48];
		char url[512];
		char title[54];
		struct bbs_ncurses_menu menu;
		struct bbs_curl c = {
			.forcefail = 1,
		};
		enum directory_search_type stype;
		int cityid; /* MAX(id) can fit in an int */

		/* Reset variables from any previous queues */
		bbs_node_var_set(qch->node, "QUEUE_DIRECTORY_CITY", "");
		bbs_node_var_set(qch->node, "QUEUE_DIRECTORY_STATE", "");
		bbs_node_var_set(qch->node, "QUEUE_DIRECTORY_FIRST", "");
		bbs_node_var_set(qch->node, "QUEUE_DIRECTORY_LAST", "");
		bbs_node_var_set(qch->node, "QUEUE_DIRECTORY_LISTING", "");
		/* QUEUE_DIRECTORY_SEARCH_TYPE is always set explicitly so no need to reset here */

		bbs_node_flush_input(qch->node);
		bbs_node_clear_screen(qch->node); /* Clear screen so there's nothing to restore after running the location menu */
		cityid = get_directory_location(qch);
		if (cityid == -2) {
			break;
		} else if (cityid == -1) {
			continue;
		}

		/* Don't clear screen, that way CTY.ST will still be present after selecting type */

		/* What type of search?
		 * Directory assistance supports the following:
		 * - Residential (by name and location)
		 * - Business (by name and location)
		 * - Reverse Lookup (by phone number or address/city/state)
		 *
		 * Location nominally includes a city and state, but can also include a street address.
		 * Here, both PSTN directory searches and private network searches are options.
		 */
		bbs_ncurses_menu_init(&menu);
		bbs_ncurses_menu_set_title(&menu, "Search Type");
		/* Public network results */
		bbs_ncurses_menu_addopt(&menu, 'R', "[R] Residential", NULL);
		bbs_ncurses_menu_addopt(&menu, 'B', "[B] Business", NULL);
		bbs_ncurses_menu_addopt(&menu, 'N', "[N] Reverse Lookup", NULL);
		/* Private network results */
		bbs_ncurses_menu_addopt(&menu, 'P', "[P] PNET - Residential", NULL);
		bbs_ncurses_menu_addopt(&menu, 'O', "[O] PNET - Business", NULL);
		bbs_ncurses_menu_addopt(&menu, 'Q', "[Q] PNET - Reverse Lookup", NULL);
		res = bbs_ncurses_menu_getopt(qch->node, &menu);
		bbs_ncurses_menu_destroy(&menu);
		switch (res) {
			case 0:
				stype = DIRECTORY_SEARCH_RES;
				bbs_node_var_set(qch->node, "QUEUE_DIRECTORY_SEARCH_TYPE", "RESIDENTIAL");
				break;
			case 1:
				stype = DIRECTORY_SEARCH_BUS;
				bbs_node_var_set(qch->node, "QUEUE_DIRECTORY_SEARCH_TYPE", "BUSINESS");
				break;
			case 2:
				stype = DIRECTORY_SEARCH_REV;
				bbs_node_var_set(qch->node, "QUEUE_DIRECTORY_SEARCH_TYPE", "REVERSE_LOOKUP");
				break;
			case 3:
				stype = DIRECTORY_SEARCH_RES | DIRECTORY_SEARCH_PNET;
				bbs_node_var_set(qch->node, "QUEUE_DIRECTORY_SEARCH_TYPE", "PNET_RESIDENTIAL");
				break;
			case 4:
				stype = DIRECTORY_SEARCH_BUS | DIRECTORY_SEARCH_PNET;
				bbs_node_var_set(qch->node, "QUEUE_DIRECTORY_SEARCH_TYPE", "PNET_BUSINESS");
				break;
			case 5:
				stype = DIRECTORY_SEARCH_REV | DIRECTORY_SEARCH_PNET;
				bbs_node_var_set(qch->node, "QUEUE_DIRECTORY_SEARCH_TYPE", "PNET_REVERSE_LOOKUP");
				break;
			default:
				bbs_warning("Unexpected menu return %d\n", res);
				/* Fall through */
			case -1:
				return 0;
		}

		/* Now have a city and state (via city ID) (or not, for XXX). Next, get the listing. */
		bbs_node_flush_input(qch->node);
		bbs_node_buffer(qch->node);
		if (stype & DIRECTORY_SEARCH_REV) {
			bbs_node_writef(qch->node, stype & DIRECTORY_SEARCH_PNET ? "LSTN (NBR): " : "LSTN (NBR / ADDRESS): ");
			if (stype & DIRECTORY_SEARCH_PNET) {
				
			}
		} else {
			bbs_node_writef(qch->node, "LSTN: ");
		}
		res = bbs_node_read_line(qch->node, MIN_MS(2), listing, sizeof(listing));
		if (res <= 0) {
			return res;
		}
		if (s_strlen_zero(listing)) {
			/* This could return a huge number of results.
			 * Don't allow it. */
			bbs_node_writef(qch->node, "Empty listing search disallowed\n");
			continue;
		}

		if (stype & DIRECTORY_SEARCH_RES) {
			char *first, *last;
			last = listing;
			first = strsep(&last, ".");
			bbs_node_var_set(qch->node, "QUEUE_DIRECTORY_FIRST", first);
			if (!strlen_zero(last)) {
				bbs_node_var_set(qch->node, "QUEUE_DIRECTORY_LAST", last);
			}
			snprintf(title, sizeof(title), "LSTN:%s.%s", first, S_IF(last));
		} else {
			/* Business listing, or phone number to reverse lookup */
			bbs_node_var_set(qch->node, "QUEUE_DIRECTORY_LISTING", listing);
			snprintf(title, sizeof(title), "LSTN:%s", listing);
		}

		bbs_node_substitute_vars(qch->node, url_directory_lookup, url, sizeof(url));
		/* We should technically do a proper URL encode here,
		 * to avoid forming an illegal URL, but the syntax
		 * of first.last somewhat precludes that. */
		memset(&c, 0, sizeof(c));
		c.url = url;
		if (bbs_curl_get(&c)) {
			bbs_node_writef(qch->node, "Directory lookup unavailable\n");
			break;
		} else {
			size_t index;
			int main_number = 0;
			char number[32];
			char listingname[64];
			char opt;
			int optindex;
			const char *city = NULL, *state = NULL;
			json_t *value;
			json_error_t err;
			json_t *json = json_loads(c.response, 0, &err);
			bbs_curl_free(&c);

			if (!json) {
				/* No results. Ask again or abort. */
				bbs_node_writef(qch->node, "NO RECORDS FOUND\n");
				bbs_node_wait_key(qch->node, MIN_MS(2));
				bbs_node_writef(qch->node, "\n");
				continue;
			}

			bbs_ncurses_menu_init(&menu);
			opt = 'A';
			json_array_foreach(json, index, value) {
				/* We have 73 columns actually available for the menu, ideally 72, to leave a space on the RHS.
				 * A few columns are needed for column spacing, leaving us slightly less than that for data.
				 *
				 * For regular, omit the keybinding and the phone number.
				 * For PNET, omit the address.
				 *
				 * For PNET: 4 +  26      + 20 + 2 + 5 + 10 = 66 + 5 = 72
				 * Regular:       23 + 21 + 17 + 2 + 5      = 68 + 4 = 72
				 */
				if (stype & DIRECTORY_SEARCH_PNET) {
					snprintf(outputbuf, sizeof(outputbuf), "[%c] %-26.26s %20.20s %2.2s %5.5s %10.10s",
						opt <= 'Z' ? opt : ' ',
						json_object_string_value(value, "listing"), /* Print max of 28 characters, and no more */
						S_IF(json_object_string_value(value, "city")),
						S_IF(json_object_string_value(value, "state")),
						S_IF(json_object_string_value(value, "zip")),
						json_object_string_value(value, "number"));
				} else {
					/* Skip the keybinding to save 4 charaacters, since there's a lot to print.
					 * Also, omit the telephone number. */
					snprintf(outputbuf, sizeof(outputbuf), "%-23.23s %-21.21s %17.17s %2.2s %5.5s",
						json_object_string_value(value, "listing"), /* Print max of 28 characters, and no more */
						S_IF(json_object_string_value(value, "address")),
						S_IF(json_object_string_value(value, "city")),
						S_IF(json_object_string_value(value, "state")),
						S_IF(json_object_string_value(value, "zip")));
				}

				bbs_ncurses_menu_addopt(&menu, opt <= 'Z' && (stype & DIRECTORY_SEARCH_PNET) ? opt : 0, outputbuf, NULL);
				if (opt <= 'Z') {
					opt++;
				}
			}
			if (opt == 'A') {
				bbs_node_writef(qch->node, "NO RECORDS FOUND\n");
				bbs_node_wait_key(qch->node, MIN_MS(2));
				bbs_node_writef(qch->node, "\n");
				continue;
			}

			bbs_node_clear_screen(qch->node); /* Clear screen so there's nothing to restore after running the listing menu */

			/* At least 1 record found */
			bbs_ncurses_menu_set_title(&menu, title);
			res = bbs_ncurses_menu_getopt(qch->node, &menu);
			bbs_ncurses_menu_destroy(&menu);
			if (res < 0) {
				json_decref(json);
				return 0;
			}
			/* See which listing was selected. */
			optindex = 0;
			json_array_foreach(json, index, value) {
				if (optindex++ == res) {
					const char *listingval = json_object_string_value(value, "listing");
					safe_strncpy(listingname, listingval, sizeof(listingname));
					safe_strncpy(number, json_object_string_value(value, "number"), sizeof(number));
					main_number = !strlen_zero(listingval) && strstr(listingval, "Primary");
					city = json_object_string_value(value, "city");
					state = json_object_string_value(value, "state");
					break;
				}
			}

			/* Finally, we have a number, what we've been waiting for! */
			bbs_ncurses_menu_init(&menu);
			bbs_node_clear_screen(qch->node); /* Clear screen so there's nothing to restore after running the announcement menu */
			strcpy(title, "ANNOUNCEMENT - "); /* Safe */
			format_nanpa_number(number, title + STRLEN("ANNOUNCEMENT - "), sizeof(title) - STRLEN("ANNOUNCEMENT - "));
			bbs_ncurses_menu_set_title(&menu, title);
			bbs_ncurses_menu_addopt(&menu, 0, "AUTO/VBL HANDOFF", NULL);
			bbs_ncurses_menu_addopt(&menu, 0, "MANUAL", NULL);
			res = bbs_ncurses_menu_getopt(qch->node, &menu);
			bbs_ncurses_menu_destroy(&menu);

			switch (res) {
				case 0:
					snprintf(outputbuf, sizeof(outputbuf), "%c%s", main_number ? '0' : '1', number);
					bbs_ami_action_setvar(NULL, "directoryresult", outputbuf, qch->channel);
					/* Automatically release the call into the announcement system without requiring agent to release first */
					bbs_ami_action_response_result(NULL, bbs_ami_action(NULL, "Hangup", "Channel: %s\r\nCause: 16", agentchan)); /* Disconnect agent */
					bbs_node_writef(qch->node, "POSITION RLS\n");
					break;
				case 1:
					/* Display the formatted number */
					bbs_node_writef(qch->node, "%-7s %-30s\n%-7s %s, %s\n%-7s %s\n",
						"LSTN", listingname, "LOCN", S_IF(city), S_IF(state),  "NUMBER", title + STRLEN("ANNOUNCEMENT - "));
					break;
				default:
					bbs_warning("Unexpected menu return %d\n", res);
					/* Fall through */
				case -1:
					json_decref(json);
					continue;
			}
			json_decref(json);
			break;
		}
	}

	bbs_node_wait_key(qch->node, MIN_MS(2));
	return 0;
}

static int handle_coinzone(struct queue_call_handle *qch)
{
	char *coinzoneinfo, *tmp;
	int cents;
	char additional = 0;
	int remaining, last;
	int input;

	if (s_strlen_zero(variable_amount_required)) {
		return 0;
	}

	coinzoneinfo = bbs_ami_action_getvar(NULL, variable_amount_required, qch->channel);
	if (!coinzoneinfo) {
		bbs_warning("Variable '%s' not set on %s for Coin Zone call?\n", variable_amount_required, qch->channel);
		return -1;
	}

	tmp = strchr(coinzoneinfo, ',');
	if (tmp) {
		*tmp++ = '\0';
		additional = *tmp;
	}
	cents = atoi(coinzoneinfo);
	free(coinzoneinfo);

	bbs_node_clear_screen(qch->node);
	bbs_node_writef(qch->node, "%-30s\n%-15s $%.2f\n", "*** DEPOSIT REQUIRED ***", "AMOUNT: ", CENTS_TO_DOLLARS(cents));

	if (additional == 'A') {
		bbs_node_writef(qch->node, "ADDITIONAL\n");
	} else if (isalnum(additional)) { /* Really looking for a digit, but it's as a char, not actually numeric */
		/* This assumes the base period is a single digit (0-9 minutes). Reasonable... */
		bbs_node_writef(qch->node, "FIRST %c MIN\n", additional);
	}

	bbs_node_writef(qch->node,
		"*** REGISTERED COIN COUNTER ***\n"
		"(Q) QUIT\n"
		"(7) RESET (8) COLLECT (9) RETURN\n"
		"(4) RNGBK\n"
		"(1) 5¢    (2) 10¢     (3) 25¢\n"
		"(0) UNDO\n");

	bbs_node_unbuffer(qch->node);
	bbs_node_echo_off(qch->node);

	remaining = cents;
	last = 0;
	bbs_node_writef(qch->node, "\n$%.2f", CENTS_TO_DOLLARS(remaining));

	while (remaining > 0) {
		const char *lastaction = "";
		input = bbs_node_tread(qch->node, MIN_MS(5));
		if (input <= 0) {
			return input;
		}

		/* Keep track of the last thing that happened (size 1 stack), and also update balance remaining */
		switch (input) {
			case '1': /*  5 cents */
				remaining -= (last = 5);
				lastaction = "-5";
				break;
			case '2': /* 10 cents */
				remaining -= (last = 10);
				lastaction = "-10";
				break;
			case '3': /* 25 cents */
				remaining -= (last = 25);
				lastaction = "-25";
				break;
			case '7': /* reset */
				remaining = cents;
				lastaction = "RESET";
				last = 0;
				break;
			case '0': /* undo */
				if (last) {
					remaining += last;
					lastaction = "UNDO";
					last = 0;
				} else {
					bbs_node_ring_bell(qch->node); /* Undo not possible */
				}
				break;
			case 'q':
			case 'Q':
			case 'x':
			case 'X':
				return 0; /* Return directly rather than break because break won't exit the loop */
			default:
				break; /* Ignore */
		}

		if (remaining > 0) { /* Only print update if we're not done */
			/* Print all the same length so that the longer stuff (-25, UNDO, RESET)
			 * doesn't still remain on the screen after shorter stuff (-5) */
			bbs_node_writef(qch->node, "\r$%.2f %5s", CENTS_TO_DOLLARS(remaining), lastaction);
		}
	}

	bbs_node_writef(qch->node, "\nPOSITION RLS\n");
	bbs_node_wait_key(qch->node, MIN_MS(2));
	return 0;
}

/*!
 * \brief Validate and set ONI on a channel
 * \param qch
 * \param oni
 * \retval 0 on success, -1 on failure, 1 on invalid ONI
 */
static int set_oni(struct queue_call_handle *qch, const char *restrict oni)
{
	int res;
	char varname[256];
	char response[32];

	if (strlen_zero(oni)) {
		bbs_debug(4, "ONI sequence is empty\n");
		return -1;
	}

	/* Evaluate at the given extension to check validity.
	 * 1 = valid, anything else = invalid. */
	snprintf(varname, sizeof(varname), "EVAL_EXTEN(%s,%s,1)", context_oni_eval, oni); /* Don't enclose in ${} or it'll be treated as a variable! */
	res = bbs_ami_action_getvar_buf(NULL, varname, qch->channel, response, sizeof(response));
	if (res) {
		return -1;
	}
	res = response[0] != '1';
	if (!res) {
		/* If it's valid, actually set it on the channel.
		 * The dialplan can then manipulate this string into whatever it needs. */
		res = bbs_ami_action_setvar(NULL, variable_oni_set, oni, qch->channel);
	}
	return res;
}

/*! \brief Operator Number Identification */
static int handle_oni(struct queue_call_handle *qch)
{
	char inject_chan[32];
	char supervisor_chan[128];
	char agent_chan[256];
	char oni[32];
	char *pos;
	int errors = 0;
	int got_kp = 0;
	int res;

	if (s_strlen_zero(channel_queue_inject) || s_strlen_zero(context_oni_digits) || s_strlen_zero(variable_queue_channel)
		|| s_strlen_zero(variable_supervisor_channel)) {
		bbs_error("Missing required configuration for ONI handling\n");
		return 0;
	}

	bbs_node_var_set_fmt(qch->node, "QUEUE_CALL_ID", "%d", qch->id);
	bbs_node_substitute_vars(qch->node, channel_queue_inject, inject_chan, sizeof(inject_chan));

	if (bbs_ami_action_getvar_buf(NULL, "BRIDGEPEER", qch->channel, agent_chan, sizeof(agent_chan))) {
		bbs_warning("Not connected to agent? Aborting.\n");
		return -1;
	}

	res = bbs_ami_action_response_result(NULL, bbs_ami_action(NULL, "Originate",
		"Channel:%s\r\nContext:%s\r\nExten:%s\r\nPriority:%s\r\nVariable:%s=%s",
		inject_chan, context_oni_digits, "s", "1", variable_queue_channel, qch->channel));
	if (res) {
		bbs_error("Failed to originate audible ONI helper\n")
		return 0;
	}

	res = bbs_ami_action_getvar_buf(NULL, variable_supervisor_channel, qch->channel, supervisor_chan, sizeof(supervisor_chan));
	if (res) {
		bbs_error("Failed to get supervisor channel\n");
		return 0;
	}

	bbs_node_unbuffer(qch->node);
	bbs_node_clear_screen(qch->node);

	bbs_node_writef(qch->node, "%s\nDNIS: %lu\n\n", "*** OPERATOR NUMBER IDENTIFICATION ***", qch->dnis);
	bbs_node_writef(qch->node, "(Q) QUIT  (*) KP      (-) ST\n");

	pos = oni;
	for (;;) {
		char digitbuf[2];
		const char *exten = digitbuf;
		int c = bbs_node_tread(qch->node, MIN_MS(2));
		switch (c) {
			case 'q': /* Quit */
			case 'Q':
				return 0;
			case '*':
				got_kp = 1;
				break;
			default:
				break;
		}
		if (!got_kp) {
			continue; /* Don't accept any other digits until we've gotten a KP */
		}
		/* MF onto the channel */
		if (c == '-') {
			c = '#';
			exten = errors > 1 ? "#2" : errors ? "#1" : "#";
		} else if (!isdigit(c) && c != '*') {
			continue;
		}

		/* Not necessary for # but for * and digits */
		digitbuf[0] = (char) c;
		digitbuf[1] = '\0';

		res = bbs_ami_action_redirect(NULL, supervisor_chan, context_oni_digits, exten, "1");
		if (res) {
			bbs_warning("Failed to redirect %s -> %s,%s,1\n", supervisor_chan, context_oni_digits, exten);
			continue; /* Don't echo if we couldn't play it on the channel, for some reason */
		}
		if (c == '#') {
			bbs_node_writef(qch->node, " ST\n"); /* Number complete */
		} else if (c == '*') {
			oni[0] = '\0'; /* Start over */
			pos = oni;
			bbs_node_writef(qch->node, "\r KP");
		} else if (isdigit(c)) {
			*pos++ = (char) c;
			*pos = '\0';
			if (pos >= oni + sizeof(oni)) {
				goto error; /* Buffer exhaustion */
			}
			bbs_node_writef(qch->node, "%c", c);
		} else {
			__builtin_unreachable();
		}
		bbs_debug(5, "Partial ONI sequence: %s\n", oni);
		if (c != '#') {
			continue; /* Not done yet */
		}
		bbs_debug(3, "Complete ONI sequence: %s\n", oni);
		res = set_oni(qch, oni);
		if (!res) {
			break;
		}

error:
		bbs_debug(3, "ONI sequence '%s' is invalid\n", oni);
		errors++;
		/* Code 11 tone error indicator */
		res = bbs_ami_action_redirect(NULL, supervisor_chan, context_oni_digits, "11", "1");
		oni[0] = '\0';
		pos = oni;
	}

	/* If we're done, disconnect the agent, so the channel can proceed
	 * immediately, as soon as ST is received and we validate it. */
	bbs_ami_action_response_result(NULL, bbs_ami_action(NULL, "Hangup", "Channel:%s", agent_chan));

	bbs_node_writef(qch->node, "\nPOSITION RLS\n");
	bbs_node_wait_key(qch->node, MIN_MS(2));
	return 0;
}

enum tty_call_side {
	SIDE_CALLER,
	SIDE_CALLEE,
};

struct tty_rx {
	const char *channel;			/* Channel for TTY subscription */
	struct queue_call_handle *qch;	/* Call for this TTY */
	int *agent_turn;				/* Pointer so we know if agent is typing or not */
	enum tty_call_side side;		/* Is this on the caller or callee side? */
	int rxcount;					/* Number of times we've received data on this callback */
	RWLIST_ENTRY(tty_rx) entry;
	char data[];
};

static RWLIST_HEAD_STATIC(tty_calls, tty_rx);

#define TTY_EXTRA_DEBUG

/*! \brief Callback handling AMI events for this module */
static int ami_callback(struct ami_event *e, const char *eventname)
{
	struct tty_rx *t;
	const char *channel;
	const char *message;

	if (strcmp(eventname, "TddRxMsg")) {
		return -1; /* Don't care about anything else */
	}

	channel = ami_keyvalue(e, "Channel");
	if (strlen_zero(channel)) {
		bbs_warning("No channel for TddRxMsg?\n");
		return -1;
	}

	message = ami_keyvalue(e, "Message");
	if (strlen_zero(message)) {
		bbs_debug(9, "No TTY message from %s?\n", channel);
		return -1;
	} else if ((signed char) *message == -1) {
		/* Could happen prior to app_tdd commit dec1d4a5d332b3f11d022372695d8569c2e07a7f
		 * This is technically 0xff, but because we're using char instead of unsigned char,
		 * it's implicitly signed char, and so it'll manifest itself as -1 instead of 0xff,
		 * which gcc will complain can't fit into a char type. */
		return -1;
	} else if (!isprint(*message)) {
#ifdef TTY_EXTRA_DEBUG
		bbs_debug(9, "Skipping non-printable TTY activity on channel %s: %d\n", channel, *message);
#endif
		return -1;
	}

	RWLIST_RDLOCK(&tty_calls);
	RWLIST_TRAVERSE(&tty_calls, t, entry) {
		if (strcmp(channel, t->channel)) {
			continue;
		}
		/* Matches one of our channels.
		 * Blindly write to the agent's terminal and hope for the best...
		 * In reality, due to the protocol being essentially half duplex,
		 * (with only one person typing at a time), this is unlikely to be an issue,
		 * fat chance of anything getting clobbered since only one thread should be
		 * writing to the socket at a time anyways. */
		
		t->rxcount++; /* Increment counter of successful receptions */
		if (!strcmp(message, "\\n")) {
			/* Convert textual depiction of a newline to an actual newline.
			 * You might think we should also consider multi-character messages
			 * and do the same if a newline appears at the end of (or within)
			 * the message. However, since we use a small buffer (in particular,
			 * a buffer of size 1), we should be getting TTY decoded character by character,
			 * so just just comparing the entire message is sufficient. */
			message = "\n";
		} else if (!strcmp(message, "_")) {
			/* Convert _ back to space */
			message = " ";
		}

		if (*t->agent_turn) {
			/* If it's the agent's turn,
			 * then add a line break and indicate this is coming from the TDD. */
			bbs_node_any_write(t->qch->node, "\nTTY: %s", message);
			*t->agent_turn = 0;
		} else {
			bbs_node_any_write(t->qch->node, "%s", message);
		}

		/* Max of 1 subscription per channel, so if we already found it, abort */
		RWLIST_UNLOCK(&tty_calls);
		return 0;
	}
	RWLIST_UNLOCK(&tty_calls);

	/* It's TTY activity on a channel that isn't even in our list. */
#ifdef TTY_EXTRA_DEBUG
	bbs_debug(9, "Ignoring TTY activity on channel %s: %c\n", channel, isprint(*message) ? *message : '.');
#endif
	return -1;
}

static struct tty_rx *tty_subscribe(const char *channel, struct queue_call_handle *qch, int *agent_turn, enum tty_call_side side)
{
	struct tty_rx *t;

	RWLIST_WRLOCK(&tty_calls);
	RWLIST_TRAVERSE(&tty_calls, t, entry) {
		if (!strcmp(t->channel, channel)) {
			bbs_warning("TTY channel %s already registered?\n", channel);
			RWLIST_UNLOCK(&tty_calls);
			return NULL;
		}
	}
	t = calloc(1, sizeof(*t) + strlen(channel) + 1);
	if (ALLOC_FAILURE(t)) {
		return NULL;
	}
	strcpy(t->data, channel); /* Safe */
	t->channel = t->data;
	t->qch = qch;
	t->agent_turn = agent_turn;
	t->side = side;
	RWLIST_INSERT_HEAD(&tty_calls, t, entry);
	/* Listen for TDD on the channel */
	/* Options:
	 * b(1) - Use single character buffer to ensure immediacy of processing
	 * s - Send spaces as underscores
	 * m - Replace received audio frames with silence while TDD carrier is active
	 */
	if (bbs_ami_action_response_result(NULL, bbs_ami_action(NULL, "TddRx", "Channel:%s\r\nOptions:b(1)sm", channel))) {
		/* This will fail if TTY processing is already enabled on the channel,
		 * and that is expected.
		 * For that reason, it should not be enabled in the dialplan prior to trying to enable via AMI.
		 * Since we might switch which side is the TDD during the session, we know more than the dialplan
		 * does about the call and control with more granularity. */
		bbs_warning("Failed to enable TTY listener on %s channel %s\n", side == SIDE_CALLER ? "caller" : "callee", channel);
	} else {
		bbs_debug(3, "Now listening for TTY on %s channel %s\n", side == SIDE_CALLER ? "caller" : "callee", channel);
	}
	RWLIST_UNLOCK(&tty_calls);
	return t;
}

static void tty_unsubscribe(struct tty_rx *t)
{
	/* Unsubscribe to TDD */
	if (bbs_ami_action_response_result(NULL, bbs_ami_action(NULL, "TddStop", "Channel:%s", t->channel))) {
		/* Probably somehow already unsubscribed. */
		bbs_warning("Failed to disable TTY listener on %s\n", t->channel);
	} else {
		bbs_debug(3, "No longer listening for TTY on %s channel %s\n", t->side == SIDE_CALLER ? "caller" : "callee", t->channel);
	}
	RWLIST_WRLOCK_REMOVE_BY_FIELD(&tty_calls, channel, t->channel, entry);
	free(t);
}

static int cli_tty_subscriptions(struct bbs_cli_args *a)
{
	struct tty_rx *t;

	bbs_dprintf(a->fdout, "%5s %-6s %-6s %7s %s\n", "Call", "Side", "Turn", "RxCount", "Channel");
	RWLIST_RDLOCK(&tty_calls);
	RWLIST_TRAVERSE(&tty_calls, t, entry) {
		bbs_dprintf(a->fdout, "%5d %5s %6s %7d %s\n", t->qch->id, t->side == SIDE_CALLER ? "Caller" : "Callee", *t->agent_turn ? "Agent" : "Caller", t->rxcount, t->channel);
	}
	RWLIST_UNLOCK(&tty_calls);
	return 0;
}

static int tty_agent_dial_number(struct queue_call_handle *qch, int inverted)
{
	char othernum[32];
	char agentchan[64];
	char dialnum[36];
	int res;

	bbs_node_writef(qch->node, inverted ? "\nTTY NBR TO DIAL: " : "\nVOICE NBR TO DIAL: ");
	bbs_node_buffer(qch->node);
	res = bbs_node_read_line(qch->node, MIN_MS(5), othernum, sizeof(othernum));
	bbs_node_unbuffer(qch->node);
	if (res <= 0) {
		return 1; /* If no number entered or other issue, just bail out */
	}

	/* At this point, the agent better be bridged to the caller. Otherwise, how'd we get a number? */
	if (bbs_ami_action_getvar_buf(NULL, "BRIDGEPEER", qch->channel, agentchan, sizeof(agentchan))) { /* Get agent's channel (since they're bridged now) */
		bbs_warning("Not connected to agent? Aborting.\n");
		return -1;
	}
	if (!*othernum || !atoi(othernum)) {
		bbs_node_writef(qch->node, "\nInvalid number. Aborting.\n");
		bbs_node_wait_key(qch->node, MIN_MS(2));
		return 0;
	}
	/* Station-to-station call.
	 * For some reason, xfer context wants 2 digits, so **,
	 * then call type (1/2/3, 1 for station to station call),
	 * then number, then # to terminate in case < 7 digits to avoid timeout. */
	snprintf(dialnum, sizeof(dialnum), "%s1%s%s", inverted ? "AA" : "**", othernum, strlen(othernum) < 7 ? "#" : "");
	if (bbs_ami_action_response_result(NULL, bbs_ami_action_axfer(NULL, agentchan, dialnum, context_trs_transfer))) {
		bbs_node_writef(qch->node, "\nFailed to set up axfer.\n");
	} else {
		bbs_node_writef(qch->node, "Initiating call: %s\n", othernum);
		if (inverted) {
			/* We need to bridge all 3 channels, so that way the
			 * agent channel can receive the TDD output (squelched,
			 * so the original caller won't have to hear it),
			 * and the agent needs to be able to talk to the caller.
			 * The agent can do this manually by hitting *3,
			 * but we go ahead and do this automatically. */
			res = bbs_ami_action_response_result(NULL, bbs_ami_action(NULL, "PlayDTMF", "Channel:%s\r\nDigit:%c\r\nReceive: true", agentchan, '*'));
			if (!res) {
				res = bbs_ami_action_response_result(NULL, bbs_ami_action(NULL, "PlayDTMF", "Channel:%s\r\nDigit:%c\r\nReceive: true", agentchan, '3'));
			}
			if (res) {
				bbs_node_writef(qch->node, "Automatic conference setup failed: please dial *3\n");
			} else {
				bbs_debug(3, "Sent DTMF '*3' on %s\n", agentchan);
			}
		}
	}
	return 0;
}

static int agent_channel_alive(const char *agent_chan)
{
	char buf[32] = "";

	/* There's not an AMI action to check if a channel exists, per se,
	 * but we can check for a known variable that should exist. */
	if (bbs_ami_action_getvar_buf(NULL, "QUEUENAME", agent_chan, buf, sizeof(buf))) {
		bbs_debug(3, "Variable %s not set for channel %s, or channel does not exist\n", "QUEUENAME", agent_chan);
		return 0;
	}
	return 1;
}

static int swap_sides(struct queue_call_handle *qch, struct tty_rx **restrict t, const char **restrict ttychannel, int *our_turn, const char *newchan, enum tty_call_side side)
{
	if (!strcmp((*t)->channel, newchan)) {
		/* If we already have it the right way, no need to do anything. */
		bbs_debug(3, "No need to swap subscription, already %s\n", newchan);
		return 0;
	}
	bbs_verb(5, "Swapping TTY channel from %s to %s\n", (*t)->channel, newchan);
	tty_unsubscribe(*t); /* Unsubscribe current */
	*ttychannel = newchan; /* Just in case we changed it, reset */
	*t = tty_subscribe(*ttychannel, qch, our_turn, side); /* New subscription */
	return 0;
}

#define SET_TDD_SIDE_CALLER() \
	swap_sides(qch, &t, &ttychannel, &our_turn, qch->channel, SIDE_CALLEE); \
	bbs_node_writef(qch->node, "\nTTY CHANNEL IS NOW CALLER\n"); \
	tty_channel_is_caller = 1;

/* This case is slightly more complicated because, unlike the caller channel,
 * which always exists, the callee leg has to be established first.
 * (In the dialplan, this is really the caller side of the local channel
 * that dials the destination.)
 * Thus, we might need to retry a few times before it's ready to go.
 *
 * Additionally, in the case that we're doing an additional call after the first one,
 * variable_queuechannelout on the channel will already be set from the previous call.
 * However, the channel name it contains is stale and no longer valid; Getvar might succeed,
 * but trying to set up TddRx on it will fail since the channel no longer exists.
 * To ensure we read the right thing, we explicitly clear this variable
 * BEFORE setting up the call prior to calling the SET_TDD_SIDE_CALLEE macro. */
#define SET_TDD_SIDE_CALLEE() \
	c = 0; \
	queuechannelout[0] = '\0'; \
	while (bbs_ami_action_getvar_buf(NULL, variable_queuechannelout, qch->channel, queuechannelout, sizeof(queuechannelout))) { \
		if (bbs_node_safe_sleep(qch->node, 750)) { \
			goto exit; \
		} else if (c++ > 10) { \
			bbs_warning("Max attempts to retrieve '%s' exceeded\n", variable_queuechannelout); \
			goto exit; \
		} \
		bbs_debug(6, "Waiting a moment for '%s' channel to come into existence...\n", variable_queuechannelout); \
	} \
	queuechannelout[strlen(queuechannelout) - 1] = '1'; /* Replace ;2 for Local channel with ;1 since that's what we want */ \
	swap_sides(qch, &t, &ttychannel, &our_turn, queuechannelout, SIDE_CALLEE); \
	bbs_node_writef(qch->node, "\nTTY CHANNEL IS NOW CALLEE\n"); \
	tty_channel_is_caller = 0; \

/*! \brief Telecommunications Relay Service */
static int handle_trs(struct queue_call_handle *qch)
{
	int our_turn = 1;
	int modifier = 0;
	/* Assume caller is using a TTY by default (for voice calls, will change to other channel) */
	const char *ttychannel = qch->channel;
	int tty_channel_is_caller = 1;
	char queuechannelout[256];
	char agentchan[256];
	struct tty_rx *t;
	int calls = 0;
	int c;

	if (s_strlen_zero(variable_queuechannelout) || s_strlen_zero(relay_greeting)) {
		bbs_warning("Missing variables required for TRS\n");
		return 0;
	}

	/* It does take a brief second for the announcement of the call ID to the agent.
	 * If that's still ongoing, we won't be bridged yet.
	 * In that case, wait a second or two and then try again. */
	for (c = 0; c < 3; c++) {
		bbs_ami_action_getvar_buf(NULL, "BRIDGEPEER", qch->channel, agentchan, sizeof(agentchan));
		if (!s_strlen_zero(agentchan)) {
			break;
		}
		if (c >= 2) { /* Max attempts exceeded */
			bbs_warning("No agent channel connected to %s?\n", qch->channel);
			return -1;
		}
		if (bbs_node_safe_sleep(qch->node, SEC_MS(1))) {
			return -1;
		}
	}

	bbs_node_unbuffer(qch->node);
	bbs_node_clear_screen(qch->node);
	bbs_node_writef(qch->node, "=== TRS - %s OPR %04d [ESC+ for menu opts] ===", relay_greeting, qch->agentid);
	bbs_node_writef(qch->node,
		"[A] Swap TTY Relay Dir\n"
		"[F] F CA Relay Greeting\n"
		"[M] M CA Relay Greeting\n"
		"[T]TY -> Voice\n"
		"[V]oice -> TTY\n"
		"[Y] Cancel/End Call\n"
		"[Q]uit\n");

#define TTY_TX(fd, channel, fmt, ...) { \
	char tbuf[64]; \
	bbs_node_writef(qch->node, fmt, __VA_ARGS__); \
	snprintf(tbuf, sizeof(tbuf), fmt, __VA_ARGS__); \
	bbs_ami_action_response_result(NULL, bbs_ami_action(NULL, "TddTx", "Channel:%s\r\nMessage:%s", channel, tbuf)); \
}

	t = tty_subscribe(qch->channel, qch, &our_turn, SIDE_CALLER);
	if (!t) {
		return -1;
	}

	for (;;) {
		int input = bbs_node_tread(qch->node, MIN_MS(5));
		if (input <= 0) {
			tty_unsubscribe(t);
			return input;
		}
		if (!modifier && input == 27) { /* ESCAPE */
			/* Escape from conversation */
			modifier = 1;
			continue;
		}
		if (modifier) {
			int res;
			modifier = 0;
			switch (input) {
			case 'a': /* Swap Direction */
				if (tty_channel_is_caller) {
					SET_TDD_SIDE_CALLEE();
				} else {
					SET_TDD_SIDE_CALLER();
				}
				break;
			case 'f': /* Female */
			case 'm': /* Male */
				TTY_TX(fd, qch->channel, "_%s OPR %d%c NBR CALLING PLS? GA", relay_greeting, 110, toupper(input)); /*! \todo use real, unique operator ID */
				if (!our_turn) {
					bbs_node_writef(qch->node, "\rCA : ");
					our_turn = 1;
				}
				break;
			/* We never complete the attended transfer, so the parties are never bridged together! */
			case 't': /* TTY -> voice: place call (attended transfer) */
				if (!agent_channel_alive(agentchan)) {
					bbs_node_writef(qch->node, "\nAGENT CHANNEL INACTIVE\n");
					goto exit;
				}
				res = tty_agent_dial_number(qch, 0);
				if (res) {
					return res < 0 ? -1 : 0;
				}
				calls++;
				SET_TDD_SIDE_CALLER();
				break;
			case 'v': /* Voice -> TTY: place call (attended transfer, swap ttychannel) */
				if (!agent_channel_alive(agentchan)) {
					bbs_node_writef(qch->node, "\nAGENT CHANNEL INACTIVE\n");
					goto exit;
				}
				/* If this is not the first call, we need to reset this variable value
				 * to prevent reading an old value.
				 * See comments above SET_TDD_SIDE_CALLEE macro. */
				if (calls && bbs_ami_action_setvar(NULL, variable_queuechannelout, qch->channel, NULL)) {
					bbs_warning("Failed to reset variable prior to new call\n");
				}
				res = tty_agent_dial_number(qch, 1);
				if (res) {
					return res < 0 ? -1 : 0;
				}
				calls++;
				SET_TDD_SIDE_CALLEE();
				break;
			case 'y': /* Cancel/End outgoing leg (cancel axfer) */
				bbs_ami_action_getvar_buf(NULL, "BRIDGEPEER", qch->channel, agentchan, sizeof(agentchan));
				if (s_strlen_zero(agentchan)) {
					/* If not still bridged, something must've happened */
					bbs_node_writef(qch->node, "\nNO ACTIVE CALL\n");
				} else {
					if (bbs_ami_action_response_result(NULL, bbs_ami_action_cancel_axfer(NULL, agentchan))) {
						bbs_node_writef(qch->node, "\nERR CALL NOT TERMINATED\n");
					} else {
						bbs_node_writef(qch->node, "\nCALL TERMINATED\n");
					}
				}
				break;
			case 'q': /* Quit */
				return 0;
			default:
				bbs_debug(4, "Unrecognized command: %c\n", input);
			}
		} else {
			char tbuf[2];
			if (!our_turn) {
				bbs_node_writef(qch->node, "\nCA : ");
				our_turn = 1;
			}
			bbs_node_writef(qch->node, "%c", input); /* Echo char as we received it */
			if (isspace(input)) {
				input = '_'; /* AMI squashes pure whitespace, so send _ instead (same result) */
			}
			tbuf[0] = (char) input;
			tbuf[1] = '\0';
			if (bbs_ami_action_response_result(NULL, bbs_ami_action(NULL, "TddTx", "Channel:%s\r\nMessage:%s", qch->channel, tbuf))) {
				bbs_node_writef(qch->node, "\nERR DISCONNECTED RLS\n");
				bbs_node_wait_key(qch->node, MIN_MS(2));
				break;
			}
		}
	}

exit:
	if (t) {
		tty_unsubscribe(t);
	}
	return 0;
}

static int handle_emergency(struct queue_call_handle *qch)
{
	char url[256];
	char formatted_number[NANPA_FORMATTED_NUMBER_BUF_SIZE];
	char *n11translations;
	struct bbs_curl c = {
		.forcefail = 1,
	};

	if (s_strlen_zero(url_emergency_caller_info)) {
		bbs_warning("Missing required settings for emergency queue\n");
		return 0;
	}

	bbs_node_clear_screen(qch->node);
	bbs_node_writef(qch->node, "*** EMERGENCY LOOKUP: %lu\n", qch->ani); /* Careful! If the wrong format specifier is used, it will cause a segfault. gcc didn't catch this one. */

	bbs_node_var_set_fmt(qch->node, "QUEUE_ANI", "%lu", qch->ani);
	bbs_node_substitute_vars(qch->node, url_emergency_caller_info, url, sizeof(url));
	c.url = url;

	if (bbs_curl_get(&c)) {
		bbs_node_writef(qch->node, "AUTOMATIC LOCATION INFORMATION LOOKUP FAILED\n");
	} else {
		json_error_t err;
		json_t *json = json_loads(c.response, 0, &err);
		bbs_curl_free(&c);
		if (json) {
			const char *first, *last, *address, *city, *state, *country, *zip;
			unsigned long phone;
			first = json_object_string_value(json, "first");
			last = json_object_string_value(json, "last");
			address = json_object_string_value(json, "address");
			city = json_object_string_value(json, "city");
			state = json_object_string_value(json, "state");
			country = json_object_string_value(json, "country");
			zip = json_object_string_value(json, "zip");
			phone = (unsigned long) json_object_number_value(json, "phone"); /* XXX Casts double to integer - floating point error? */
			if (first) { /* If we got something, we probably got everything */
				bbs_node_writef(qch->node, "CALLER NAME:   %s, %s\n", last, first);
				bbs_node_writef(qch->node, "ADDRESS:       %s\n", address);
				bbs_node_writef(qch->node, "LOCATION:      %s, %s, %s %s\n", city, state, country, zip);
				if (phone) {
					char phonebuf[21];
					snprintf(phonebuf, sizeof(phonebuf), "%lu", phone);
					format_nanpa_number(phonebuf, formatted_number, sizeof(formatted_number));
					bbs_node_writef(qch->node, "PSTN TEL. NUM: %s\n", formatted_number);
				} else {
					bbs_node_writef(qch->node, "PSTN TEL. NUM: %s\n", "RECORD NOT FOUND"); /* Too large for formatted_number */
				}
			}
			json_decref(json);
		}
	}

	if (!s_strlen_zero(variable_n11translations)) {
		n11translations = bbs_ami_action_getvar(NULL, variable_n11translations, qch->channel);
		if (!n11translations) {
			bbs_warning("No '%s' variable for Emergency call on %s\n", variable_n11translations, qch->channel);
		} else {
			int i = 0;
			char *cur, *trans = n11translations;
			bbs_node_writef(qch->node, "\nAPPX. N11 TRANSLATIONS\n");
			while ((cur = strsep(&trans, ","))) {
				const char *title = NULL;
				switch (i) {
				case 0:
					title = "211 - UNITED WAY";
					break;
				case 1:
					title = "311 - NON-EMERGENCY";
					break;
				case 2:
					title = "511 - WEATHER";
					break;
				case 3:
					title = "711 - TRS";
					break;
				case 4:
					title = "811 - DIGGERS HOTLINE";
					break;
				case 5:
					title = "911 - POLICE DEPT.";
					break;
				default:
					bbs_warning("Unexpected value at index %d: %s\n", i, cur);
				}
				i++;
				if (title) {
					format_nanpa_number(cur, formatted_number, sizeof(formatted_number));
					bbs_node_writef(qch->node, "%-30s %-20s\n", title, S_OR(formatted_number, "RECORD NOT FOUND"));
				}
			}
			free(n11translations);
		}
	}
	bbs_node_wait_key(qch->node, MIN_MS(2));
	return 0;
}

static int load_config(void)
{
	int res = 0;
	struct bbs_config *cfg;

	cfg = bbs_config_load("mod_operator.conf", 1);
	if (!cfg) {
		/* This is a custom module for a specific system.
		 * Definitely decline to load if not relevant to the running system. */
		return -1;
	}

	res |= bbs_config_val_set_str(cfg, "operator", "url_time_of_day", url_time_of_day, sizeof(url_time_of_day));
	res |= bbs_config_val_set_str(cfg, "operator", "url_local_exchanges", url_local_exchanges, sizeof(url_local_exchanges));
	res |= bbs_config_val_set_str(cfg, "operator", "url_rate_quote", url_rate_quote, sizeof(url_rate_quote));
	res |= bbs_config_val_set_str(cfg, "operator", "url_reverse_lookup", url_reverse_lookup, sizeof(url_reverse_lookup));
	res |= bbs_config_val_set_str(cfg, "operator", "context_operator_xfer", context_operator_xfer, sizeof(context_operator_xfer));
	res |= bbs_config_val_set_str(cfg, "operator", "variable_cvs", variable_cvs, sizeof(variable_cvs));

	res |= bbs_config_val_set_str(cfg, "intercept", "variable_intercepted_num", variable_intercepted_num, sizeof(variable_intercepted_num));
	res |= bbs_config_val_set_str(cfg, "intercept", "url_intercept_lookup", url_intercept_lookup, sizeof(url_intercept_lookup));

	res |= bbs_config_val_set_str(cfg, "directory", "url_directory_location", url_directory_location, sizeof(url_directory_location));
	res |= bbs_config_val_set_str(cfg, "directory", "url_directory_lookup", url_directory_lookup, sizeof(url_directory_lookup));

	res |= bbs_config_val_set_str(cfg, "coinzone", "variable_amount_required", variable_amount_required, sizeof(variable_amount_required));

	res |= bbs_config_val_set_str(cfg, "oni", "channel_queue_inject", channel_queue_inject, sizeof(channel_queue_inject));
	res |= bbs_config_val_set_str(cfg, "oni", "context_oni_digits", context_oni_digits, sizeof(context_oni_digits));
	res |= bbs_config_val_set_str(cfg, "oni", "variable_queue_channel", variable_queue_channel, sizeof(variable_queue_channel));
	res |= bbs_config_val_set_str(cfg, "oni", "variable_supervisor_channel", variable_supervisor_channel, sizeof(variable_supervisor_channel));
	res |= bbs_config_val_set_str(cfg, "oni", "context_oni_eval", context_oni_eval, sizeof(context_oni_eval));
	res |= bbs_config_val_set_str(cfg, "oni", "variable_oni_set", variable_oni_set, sizeof(variable_oni_set));

	res |= bbs_config_val_set_str(cfg, "trs", "variable_queuechannelout", variable_queuechannelout, sizeof(variable_queuechannelout));
	res |= bbs_config_val_set_str(cfg, "trs", "relay_greeting", relay_greeting, sizeof(relay_greeting));
	res |= bbs_config_val_set_str(cfg, "trs", "context_trs_transfer", context_trs_transfer, sizeof(context_trs_transfer));

	res |= bbs_config_val_set_str(cfg, "emergency", "url_emergency_caller_info", url_emergency_caller_info, sizeof(url_emergency_caller_info));
	res |= bbs_config_val_set_str(cfg, "emergency", "variable_n11translations", variable_n11translations, sizeof(variable_n11translations));

	if (res) {
		bbs_debug(2, "One or more settings was missing\n");
	}
	bbs_config_unlock(cfg);
	return 0;
}

static struct bbs_cli_entry cli_commands_operator[] = {
	BBS_CLI_COMMAND(cli_tty_subscriptions, "operator tty subscriptions", 3, "List all TTY subscriptions", NULL),
};

static int unload_module(void)
{
	bbs_cli_unregister_multiple(cli_commands_operator);
	bbs_ami_callback_unregister(ami_callback);
	bbs_queue_call_handler_unregister("default");
	bbs_queue_call_handler_unregister("operator");
	bbs_queue_call_handler_unregister("intercept");
	bbs_queue_call_handler_unregister("directory");
	bbs_queue_call_handler_unregister("coinzone");
	bbs_queue_call_handler_unregister("oni");
	bbs_queue_call_handler_unregister("trs");
	bbs_queue_call_handler_unregister("emergency");
	return 0;
}

static int load_module(void)
{
	if (load_config()) {
		return -1;
	}
	bbs_queue_call_handler_register("default", handle_default); /* Note: There is nothing special about this being named "default" */
	bbs_queue_call_handler_register("operator", handle_operator);
	bbs_queue_call_handler_register("intercept", handle_intercept);
	bbs_queue_call_handler_register("directory", handle_directory);
	bbs_queue_call_handler_register("coinzone", handle_coinzone);
	bbs_queue_call_handler_register("oni", handle_oni);
	bbs_queue_call_handler_register("trs", handle_trs);
	bbs_queue_call_handler_register("emergency", handle_emergency);
	bbs_ami_callback_register(ami_callback);
	bbs_cli_register_multiple(cli_commands_operator);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("Operator Position System", "mod_asterisk_queues.so,mod_ncurses.so,mod_curl.so");
