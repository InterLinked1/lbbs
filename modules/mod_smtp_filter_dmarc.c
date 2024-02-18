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
 * \brief RFC7489 DMARC (Domain-based Message Authentication, Reporting, and Conformance)
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <opendmarc/dmarc.h>

#include "include/module.h"
#include "include/node.h"
#include "include/utils.h"
#include "include/config.h"
#include "include/mail.h"

#include "include/net_smtp.h"

static int enforce_rejects = 1;
static int enforce_quarantines = 1;
static int report_failures = 0;

/* == Reporting related == */
static char report_bcc[256] = "";
static char log_filename[256] = "";
static FILE *logfp = NULL;
static bbs_mutex_t loglock;

/* Taken from OpenDMARC opendmarc/opendmarc-ar.h, for ABI compatibility when using enums as ints */
#define	ARES_RESULT_PASS	0
#define	ARES_RESULT_SOFTFAIL	2
#define	ARES_RESULT_NEUTRAL	3
#define	ARES_RESULT_TEMPERROR	4
#define	ARES_RESULT_PERMERROR	5
#define	ARES_RESULT_NONE	6
#define ARES_RESULT_FAIL	7

/* From opendmarc/opendmarc.h */
#define	DMARC_RESULT_REJECT	0
#define	DMARC_RESULT_ACCEPT	2
#define	DMARC_RESULT_TEMPFAIL	3
#define	DMARC_RESULT_QUARANTINE	4

#define	DMARC_ARC_POLICY_RESULT_PASS	0
#define	DMARC_ARC_POLICY_RESULT_FAIL	2

static inline int dmarcf_spf_res(const char *result)
{
	if (!strcasecmp(result, "pass")) {
		return ARES_RESULT_PASS;
	} else if (!strcasecmp(result, "fail")) {
		return ARES_RESULT_FAIL;
	} else if (!strcasecmp(result, "softfail")) {
		return ARES_RESULT_SOFTFAIL;
	} else if (!strcasecmp(result, "neutral")) {
		return ARES_RESULT_NEUTRAL;
	} else if (!strcasecmp(result, "temperror")) {
		return ARES_RESULT_TEMPERROR;
	} else if (!strcasecmp(result, "none")) {
		return ARES_RESULT_NONE;
	} else {
		return ARES_RESULT_PERMERROR;
	}
}

static inline int spf_to_dmarc_res(int res)
{
	switch (res) {
		case DMARC_POLICY_SPF_OUTCOME_PASS: return ARES_RESULT_PASS;
		case DMARC_POLICY_SPF_OUTCOME_NONE: return ARES_RESULT_NONE;
		case DMARC_POLICY_SPF_OUTCOME_TMPFAIL: return ARES_RESULT_TEMPERROR;
		case DMARC_POLICY_SPF_OUTCOME_FAIL: return ARES_RESULT_FAIL;
		default: return ARES_RESULT_PERMERROR;
	}
	__builtin_unreachable();
}

static inline int arc_res(const char *result)
{
	if (!strcasecmp(result, "pass")) {
		return ARES_RESULT_PASS;
	} else if (!strcasecmp(result, "fail")) {
		return ARES_RESULT_FAIL;
	} else if (!strcasecmp(result, "none")) {
		return ARES_RESULT_NONE;
	} else {
		bbs_warning("Unexpected ARC result '%s'\n", result);
		return ARES_RESULT_NONE;
	}
}

static inline void check_log_file(void)
{
	/* Check if the log file has changed from underneath us.
	 * This would happen if opendmarc-importstats has been run since the last logging.
	 * More lightweight than using inotify to detect this. */
	if (!bbs_file_exists(log_filename)) {
		bbs_debug(1, "File '%s' has been rotated since last written to, reopening log file\n", log_filename);
		fclose(logfp);
		logfp = fopen(log_filename, "a");
		if (!logfp) {
			bbs_error("Failed to open %s for appending: %s\n", log_filename, strerror(errno));
		}
	}
}

static unsigned int jobid = 0;

/* == Main filter logic == */

static const char *policy_name(int p)
{
	switch (p) {
		case DMARC_RECORD_P_QUARANTINE:
			return "quarantine";
		case DMARC_RECORD_P_REJECT:
			return "reject";
		case DMARC_RECORD_P_UNSPECIFIED:
		case DMARC_RECORD_P_NONE:
		default:
			return "none";
	}
}

static OPENDMARC_LIB_T lib;

static int dmarc_filter_cb(struct smtp_filter_data *f)
{
	int dres;
	const char *domain;
	OPENDMARC_STATUS_T status, policy, apused;
	int spf_alignment, dkim_alignment;
	int is_ipv6;
	DMARC_POLICY_T *pctx;
	char dmarc_domain[256];
	int result, pct, enforce;
	char dmarc_result[sizeof(dmarc_domain) + 128];
	const char *adisposition, *aresult;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
	int spfres;
#pragma GCC diagnostic pop
	int p = 0, sp = 0;
	char mctx_jobid[48];
	time_t now;

	if (smtp_is_exempt_relay(f->smtp) || !smtp_should_verify_dmarc(f->smtp)) {
		return 0;
	}

	is_ipv6 = !bbs_hostname_is_ipv4(f->node->ip); /* If it's not IPv4, must be IPv6? */
	domain = smtp_mail_from_domain(f->smtp);
	if (!domain) {
		bbs_warning("Missing domain for received email?\n");
		return 0;
	}

#pragma GCC diagnostic ignored "-Wcast-qual"
	pctx = opendmarc_policy_connect_init((unsigned char*) f->node->ip, is_ipv6);
	if (!pctx) {
		bbs_error("Failed to allocate DMARC policy context\n");
		return 0;
	}

	opendmarc_policy_store_from_domain(pctx, (unsigned char*) domain);

	if (f->spf) {
		int dresult;
		if (!strcmp(f->spf, "pass")) {
			dresult = DMARC_POLICY_SPF_OUTCOME_PASS;
		} else if (!strcmp(f->spf, "fail")) {
			dresult = DMARC_POLICY_SPF_OUTCOME_FAIL;
		} else if (!strcmp(f->spf, "tempfail")) {
			dresult = DMARC_POLICY_SPF_OUTCOME_TMPFAIL;
		} else {
			dresult = DMARC_POLICY_SPF_OUTCOME_NONE;
		}
		/* We always use the MAIL FROM domain, not the HELO/EHLO domain */
		spfres = dres = opendmarc_policy_store_spf(pctx, (unsigned char*) domain, dresult, DMARC_POLICY_SPF_ORIGIN_MAILFROM, (unsigned char*) f->spf);
		if (dres != DMARC_PARSE_OKAY) {
			bbs_warning("Failed to parse SPF for DMARC: %d\n", dres);
		}
	}

	if (f->dkim) {
		char d_domain[256] = "";
		int dkim_result;
		const char *d = strstr(f->dkim, "header.d=");
		if (d) {
			d += STRLEN("header.d=");
			if (!strlen_zero(d)) {
				bbs_strncpy_until(d_domain, d, sizeof(d_domain), ' ');
			}
		}
		if (STARTS_WITH(f->dkim, "pass")) {
			dkim_result = DMARC_POLICY_DKIM_OUTCOME_PASS;
		} else if (STARTS_WITH(f->dkim, "fail")) {
			dkim_result = DMARC_POLICY_DKIM_OUTCOME_FAIL;
		} else if (STARTS_WITH(f->dkim, "tempfail")) {
			dkim_result = DMARC_POLICY_DKIM_OUTCOME_TMPFAIL;
		} else {
			dkim_result = DMARC_POLICY_DKIM_OUTCOME_NONE;
		}
#if (OPENDMARC_LIB_VERSION >= 0x01040000L) || (OPENDMARC_LIB_VERSION == 0x00000000L)
		/* Added in commit https://github.com/trusteddomainproject/OpenDMARC/commit/dbd87868f2ca9c2ef11529cd757d1cc5ab228833 */
		/* We could get this from the DKIM-Signature header, but otherwise it's not immediately readily available, so just pass NULL for now */
		dres = opendmarc_policy_store_dkim(pctx, (unsigned char*) d_domain, NULL, dkim_result, (unsigned char*) f->dkim);
#else
		dres = opendmarc_policy_store_dkim(pctx, (unsigned char*) d_domain, dkim_result, (unsigned char*) f->dkim);
#endif
		if (dres != DMARC_PARSE_OKAY) {
			bbs_warning("Failed to parse DKIM for DMARC: %d\n", dres);
		}
	}

	/* Enforcement percentage */
	opendmarc_policy_fetch_pct(pctx, &pct);

	status = opendmarc_policy_query_dmarc(pctx, (unsigned char*) domain);
#pragma GCC diagnostic pop
	switch (status) {
		case DMARC_PARSE_OKAY:
			break;
		case DMARC_DNS_ERROR_NO_RECORD:
			bbs_debug(5, "No DMARC record found for domain %s\n", domain);
			break;
		case DMARC_DNS_ERROR_TMPERR:
			bbs_warning("Temporary DNS failure\n");
			break;
		case DMARC_DNS_ERROR_NXDOMAIN:
			bbs_warning("No DNS records for %s\n", domain);
			break;
		/* These should never happen */
		case DMARC_PARSE_ERROR_EMPTY:
		case DMARC_PARSE_ERROR_NO_DOMAIN:
		case DMARC_PARSE_ERROR_NULL_CTX:
			bbs_warning("Unexpected status %d\n", status);
			break;
	}

	/* This is not the policy in the DNS record, but the actual result of the DMARC check */
	policy = opendmarc_get_policy_to_enforce(pctx);

	if (opendmarc_policy_fetch_p(pctx, &p) != DMARC_PARSE_OKAY) {
		bbs_warning("Failed to parse DMARC p\n");
	} else if (opendmarc_policy_fetch_sp(pctx, &sp) != DMARC_PARSE_OKAY) {
		bbs_warning("Failed to parse DMARC sp\n");
	}

	status = opendmarc_policy_fetch_alignment(pctx, &spf_alignment, &dkim_alignment);
	if (status == DMARC_PARSE_OKAY) {
		bbs_debug(5, "Alignments: SPF=%s, DKIM=%s\n",
			spf_alignment == DMARC_POLICY_SPF_ALIGNMENT_PASS ? "pass" : "fail",
			dkim_alignment == DMARC_POLICY_DKIM_ALIGNMENT_PASS ? "pass" : "fail");
	}

	if (opendmarc_policy_fetch_utilized_domain(pctx, (unsigned char*) dmarc_domain, sizeof(dmarc_domain)) != DMARC_PARSE_OKAY) {
		bbs_warning("Failed to get DMARC domain\n");
	}

	apused = opendmarc_get_policy_token_used(pctx);
	pct = pct ? pct : 100; /* If no %, default to 100% */
	enforce = random() % 100 < pct; /* Should we enforce the sending domain's policy, according to the enforcement percentage? */

	/* LBBS doesn't have a concept of "job IDs", like most other MTAs, do.
	 * Just use epoch time + monotonically increasing number. */
	now = time(NULL);
	bbs_mutex_lock(&loglock);
	snprintf(mctx_jobid, sizeof(mctx_jobid), "%ld-%u", now, ++jobid); /* Safe to increment, since surrounded by loglock */
	bbs_mutex_unlock(&loglock);

	/* If DMARC failed, send failure report */
	switch (policy) {
		case DMARC_POLICY_NONE: /* Alignment failed, but policy is 'none' - accept and report */
		case DMARC_POLICY_REJECT: /* Explicit reject */
		case DMARC_POLICY_QUARANTINE: /* Explicit quarantine */
			if (report_failures) {
				char tmpfilename[128] = "/tmp/dmarcrufXXXXXX";
				FILE *fp;
				unsigned char **ruv = opendmarc_policy_fetch_ruf(pctx, NULL, 0, 1);
				fp = bbs_mkftemp(tmpfilename, MAIL_FILE_MODE);
				if (fp) {
					char date[48];
					char mailfrom[256];
					struct tm tm;
					int c;
					int recipients = 0;

					/* We can't use bbs_make_email_file, since we have a different Content-Type */
					strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S %z", localtime_r(&now, &tm));
					fprintf(fp, "Date: %s\r\n", date);
					fprintf(fp, "From: DMARC Reporter <dmarc-noreply@%s>\r\n", smtp_hostname());
					for (c = 0; ruv && ruv[c]; c++) {
						char *recip;
						if (!STARTS_WITH((const char*) ruv[c], "mailto:")) {
							continue;
						}
						recip = (char*) ruv[c] + STRLEN("mailto:");
						if (strlen_zero(recip)) {
							continue; /* Empty mailto */
						}
						bbs_strterm(recip, '!');
						if (strlen_zero(recip)) {
							continue;
						}
						bbs_term_line(recip);
						if (strlen_zero(recip)) {
							continue;
						}
						/* We assume that all the recipients will fit on one line... which they SHOULD */
						bbs_debug(5, "Adding RUF report recipient: '%s'\n", recip);
						if (!recipients++) {
							fprintf(fp, "To: %s", recip);
						} else {
							fprintf(fp, ", %s", recip);
						}
					}
					/* Bcc */
					if (!s_strlen_zero(report_bcc)) {
						/* If only recipient, for some reason, then just use To,
						 * since nobody else is receiving the report, just in
						 * case the receiving email doesn't like emails without a To.
						 * Otherwise, add as Bcc. */
						bbs_debug(5, "Adding Bcc to report: %s\n", report_bcc);
						if (!recipients++) {
							fprintf(fp, "To: %s", report_bcc);
						} else {
							fprintf(fp, "\r\nBcc: %s", report_bcc);
						}
					}
					if (!recipients) {
						/* Report has no recipients, no point continuing */
						bbs_debug(2, "Aborting DMARC failure report addressed to no recipients\n");
						fclose(fp);
						unlink(tmpfilename);
					} else {
						fprintf(fp, "\r\n"); /* Finish To (or Bcc) header */
						fprintf(fp, "Subject: DMARC failure report for job %s\r\n", mctx_jobid);
						fprintf(fp, "Message-ID: <%s-%s>\r\n", "dmarcfail", mctx_jobid); /* job ID should already be unique, so use that as part of message ID here */
						fprintf(fp, "MIME-Version: 1.0\r\n");
						fprintf(fp, "Content-Type: multipart/report;\r\n"
									"\treport-type=feedback-report;\r\n"
									"\tboundary=\"%s:%s\"\r\n", smtp_hostname(), mctx_jobid);
						fprintf(fp, "\r\n"); /* EOH */
						fprintf(fp, "--%s:%s\r\n"
									"Content-Type: text/plain\r\n",
									smtp_hostname(), mctx_jobid);
						fprintf(fp, "\r\n"); /* EOH */
						fprintf(fp, "This is an authentication failure report for an email message received\r\n"
									"from IP %s on %s.\r\n\r\n", smtp_sender_ip(f->smtp), date);
						fprintf(fp, "--%s:%s\n"
									"Content-Type: message/feedback-report\r\n", smtp_hostname(), mctx_jobid);
						fprintf(fp, "\r\n"); /* EOH */
						fprintf(fp, "Feedback-Type: auth-failure\r\n");
						fprintf(fp, "Version: 1\r\n");
						fprintf(fp, "User-Agent: LBBS %s %s\r\n", BBS_VERSION, "DMARC Failure Reporter");
						fprintf(fp, "Auth-Failure: dmarc\r\n");
						fprintf(fp, "Authentication-Results: %s; dmarc=fail header.from=%s\r\n", bbs_hostname(), dmarc_domain);
						fprintf(fp, "Original-Envelope-Id: %s\r\n", mctx_jobid);
						fprintf(fp, "Original-Mail-From: %s\r\n", smtp_from(f->smtp));
						fprintf(fp, "Source-IP: %s\r\n", smtp_sender_ip(f->smtp));
						fprintf(fp, "Reported-Domain: %s\r\n", smtp_from_domain(f->smtp));
						/* If the headers were available, we could also add them all here
						 * fprintf(fp, "--%s:%s\r\nContent-Type: text/rfc822-headers\r\n", smtp_hostname(), mctx_jobid);
						 * foreach header => fprintf(fp, "%s: %s\r\n", hdr, val);
						 * fprintf(fp, "\r\n--%s:%s--\r\n", smtp_hostname(), mctx_jobid);
						 *
						 * However, this obviously has some privacy implications.
						 * Many major mail providers no longer send failure reports at all for that reason.
						 * Therefore, it could be argued that NOT including headers here is a feature, not a bug!
						 */
						fclose(fp);
						snprintf(mailfrom, sizeof(mailfrom), "dmarc-noreply@%s", smtp_hostname());
						bbs_mail_message(tmpfilename, mailfrom, NULL); /* Thin wrapper around smtp_inject, effectively, which extracts recipients from message for us */
					}
				}
			} else {
				bbs_debug(4, "DMARC failed for %s, but not sending failure report due to local policy\n", dmarc_domain);
			}
			break;
		default:
			break;
	}

	/* DMARC result (whether message successfully verified or not) */
	switch (policy) {
		case DMARC_POLICY_ABSENT: /* No DMARC record found */
		case DMARC_FROM_DOMAIN_ABSENT: /* No From: domain */
			aresult = "none";
			result = DMARC_RESULT_ACCEPT;
			break;
		case DMARC_POLICY_NONE: /* Alignment failed, but policy is 'none' */
			aresult = "fail"; /* Accept and report */
			result = DMARC_RESULT_ACCEPT;
			break;
		case DMARC_POLICY_PASS: /* Explicit accept */
			aresult = "pass";
			result = DMARC_RESULT_ACCEPT;
			break;
		case DMARC_POLICY_REJECT: /* Explicit reject */
			aresult = "fail";
			result = DMARC_RESULT_ACCEPT;
			if (!enforce_rejects) {
				bbs_notice("Message failed DMARC policy for %s, but not rejected due to local policy\n", dmarc_domain);
			} else if (enforce) {
				result = DMARC_RESULT_REJECT;
				bbs_notice("Message rejected by DMARC policy for %s\n", dmarc_domain);
			} else {
				bbs_notice("Message failed DMARC policy for %s, but not rejected due to sampling percentage\n", dmarc_domain);
			}
			break;
		case DMARC_POLICY_QUARANTINE: /* Explicit quarantine */
			aresult = "fail";
			result = DMARC_RESULT_ACCEPT;
			if (!enforce_quarantines) {
				bbs_notice("Message failed DMARC policy for %s, but not quarantined due to local policy\n", dmarc_domain);
			} else if (enforce) {
				result = DMARC_RESULT_QUARANTINE;
				bbs_notice("Message quarantined by DMARC policy for %s\n", dmarc_domain);
			} else {
				bbs_notice("Message failed DMARC policy for %s, but not quarantined due to sampling percentage\n", dmarc_domain);
			}
			break;
		default:
			aresult = "temperror";
			result = DMARC_RESULT_TEMPFAIL;
			break;
	}

	/* If DMARC failed but ARC passed, override */
	if (result == DMARC_RESULT_REJECT) {
		if (f->arc && !strcmp(f->arc, "pass")) { /* f->arc could be none, fail, pass */
			bbs_debug(2, "Message failed DMARC, but passed ARC, so accepting\n");
			result = DMARC_RESULT_ACCEPT;
			/* Leave aresult as is */
		} else if (f->arc) {
			bbs_debug(2, "Message failed DMARC (%s) and ARC (%s)\n", aresult, f->arc);
		} else {
			bbs_debug(2, "Message failed DMARC and no ARC results available\n");
		}
	}

	/* Disposition: actual effective result (whether message will be accepted or not) */
	switch (result) {
		case DMARC_RESULT_REJECT: /* We intend to reject this message */
			adisposition = "reject";
			break;
		case DMARC_RESULT_QUARANTINE: /* We intend to quarantine this message */
			adisposition = "quarantine";
			break;
		case DMARC_RESULT_ACCEPT:
		default: /* We're not going to do anything to this message (just let it proceed normally) */
			adisposition = "none";
			break;
	}

	bbs_debug(4, "Used %s policy (%s), %d%% enforcement\n", DMARC_USED_POLICY_IS_SP ? "subdomain" : "domain", policy_name(apused == DMARC_USED_POLICY_IS_SP ? sp : p), pct);
	snprintf(dmarc_result, sizeof(dmarc_result), "%s (p=%s sp=%s dis=%s) header.from=%s",
		aresult, /* actual result - whether things verified successfully or not */
		policy_name(apused == DMARC_USED_POLICY_IS_SP ? sp : p), /* p= (domain policy) */
		policy_name(sp), /* sp= (subdomain policy) */
		adisposition, /* dis= (disposition) - what we're doing with the message */
		dmarc_domain);
	REPLACE(f->dmarc, dmarc_result);

	if (logfp) {
		unsigned char **ruv;
		int adkim, aspf;

		/* If we have a OpenDMARC-style history file for logging, log it.
		 * We log exactly the same way that OpenDMARC's opendmarc/opendmarc.c does.
		 * However, it's a lot easier for us since each filter isn't running in a separate process,
		 * and we can just write to the file all at once, rather than building up a string. */
		bbs_mutex_lock(&loglock);
		check_log_file();

		/* For cross-referencing with the OpenDMARC source code,
		 * actual function names from their code are used,
		 * but transparently redirected to fprintf, so if needed,
		 * it should be easy to find where this logic came from to debug.
		 * Not all the variable names provided for printf arguments are named the same,
		 * but the format string and everything prior to that should be identical. */
#define dmarcf_dstring_printf(hb, fmt, ...) fprintf(logfp, fmt, ## __VA_ARGS__)

		/* General */
		dmarcf_dstring_printf(dfc->mctx_histbuf, "job %s\n", mctx_jobid);

		/* Hostname is smfi_getsymval with sendmail macro "j".
		 * https://web.mit.edu/freebsd/head/contrib/sendmail/libmilter/docs/smfi_getsymval.html
		 * $j is the full hostname: https://docstore.mik.ua/orelly/networking_2ndEd/tcp/appe_03.htm
		 * This is OUR hostname, not the remote hostname. */

		dmarcf_dstring_printf(dfc->mctx_histbuf, "reporter %s\n", smtp_hostname());
		dmarcf_dstring_printf(dfc->mctx_histbuf, "received %ld\n", now);
		dmarcf_dstring_printf(dfc->mctx_histbuf, "ipaddr %s\n", smtp_sender_ip(f->smtp));
		dmarcf_dstring_printf(dfc->mctx_histbuf, "from %s\n", smtp_from_domain(f->smtp)); /* From domain */
		dmarcf_dstring_printf(dfc->mctx_histbuf, "mfrom %s\n", smtp_mail_from_domain(f->smtp)); /* MAIL FROM domain */
		/* Skip ARC SPF/DKIM logging, since we don't check ARC in this module */
		/* SPF */
		if (f->spf) {
			dmarcf_dstring_printf(dfc->mctx_histbuf, "spf %d\n", dmarcf_spf_res(f->spf));
			/* Can't be used uninitialized since we only use spfres when f->spf, and always set on that path */
			dmarcf_dstring_printf(dfc->mctx_histbuf, "spf %d\n", spf_to_dmarc_res(spfres));
		}
		/* DMARC */
		dmarcf_dstring_printf(dfc->mctx_histbuf, "pdomain %s\n", dmarc_domain);
		dmarcf_dstring_printf(dfc->mctx_histbuf, "policy %d\n", policy);
		ruv = opendmarc_policy_fetch_rua(pctx, NULL, 0, 1);
		if (ruv) {
			int c;
			for (c = 0; ruv[c]; c++) {
				dmarcf_dstring_printf(dfc->mctx_histbuf, "rua %s\n", ruv[c]);
			}
		} else {
			dmarcf_dstring_printf(dfc->mctx_histbuf, "rua -\n");
		}

		dmarcf_dstring_printf(dfc->mctx_histbuf, "pct %d\n", pct);

		opendmarc_policy_fetch_adkim(pctx, &adkim);
		dmarcf_dstring_printf(dfc->mctx_histbuf, "adkim %d\n", adkim);

		opendmarc_policy_fetch_aspf(pctx, &aspf);
		dmarcf_dstring_printf(dfc->mctx_histbuf, "aspf %d\n", aspf);

		dmarcf_dstring_printf(dfc->mctx_histbuf, "p %d\n", p);
		dmarcf_dstring_printf(dfc->mctx_histbuf, "sp %d\n", sp);
		dmarcf_dstring_printf(dfc->mctx_histbuf, "align_dkim %d\n", spf_alignment);
		dmarcf_dstring_printf(dfc->mctx_histbuf, "align_spf %d\n", dkim_alignment);

		/* ARC Override */
		if (f->arc) {
			int arcpolicypass = strcmp(f->arc, "fail") ? DMARC_ARC_POLICY_RESULT_PASS : DMARC_ARC_POLICY_RESULT_FAIL;
			dmarcf_dstring_printf(dfc->mctx_histbuf, "arc %d\n", arc_res(f->arc));
			/* We can't really do the arc_policy one here (iterating through ARC-Seal headers),
			 * since that would require access to the internals of the ARC parser
			 * in mod_smtp_filter_arc, and we can't stick our gubbins in there from here.
			 * However, this field is mandatory in the DB schema so just use an empty one for now. */
			dmarcf_dstring_printf(dfc->mctx_histbuf, "arc_policy %d json:[]\n", arcpolicypass);
		}
		dmarcf_dstring_printf(dfc->mctx_histbuf, "action %d\n", result);

		fflush(logfp);
		bbs_mutex_unlock(&loglock);
	}

	/* If disposition is REJECT or QUARANTINE, mark that for processing once filter execution has completed.
	 * We still return 0 for QUARANTINE, since return 1 would abort filter execution, and we do want the Authentication-Results
	 * header to get added if we're saving the message. */
	if (result == DMARC_RESULT_REJECT) {
		f->reject = 1;
		opendmarc_policy_connect_shutdown(pctx);
		return 1;
	} else if (result == DMARC_RESULT_QUARANTINE) {
		f->quarantine = 1;
	}

	opendmarc_policy_connect_shutdown(pctx);
	return 0;
}

struct smtp_filter_provider dmarc_filter = {
	.on_body = dmarc_filter_cb,
};

static int load_config(void)
{
	struct bbs_config *cfg = bbs_config_load("mod_smtp_filter_dmarc.conf", 1);

	if (!cfg) {
		return 0;
	}

	bbs_config_val_set_true(cfg, "enforcement", "reject", &enforce_rejects);
	bbs_config_val_set_true(cfg, "enforcement", "quarantine", &enforce_quarantines);

	bbs_config_val_set_true(cfg, "reporting", "reportfailures", &report_failures);
	bbs_config_val_set_str(cfg, "reporting", "reportbcc", report_bcc, sizeof(report_bcc));
	if (!bbs_config_val_set_str(cfg, "reporting", "historyfile", log_filename, sizeof(log_filename))) {
		logfp = fopen(log_filename, "a");
		if (!logfp) {
			bbs_error("Failed to open %s for appending: %s\n", log_filename, strerror(errno));
		}
	}

	bbs_config_free(cfg);
	return 0;
}

static int load_module(void)
{
	if (opendmarc_policy_library_init(&lib) != DMARC_PARSE_OKAY) {
		bbs_error("Failed to initialize libopendmarc\n");
		return -1;
	}

	load_config();
	bbs_mutex_init(&loglock, NULL);

	/* Wait until SPF and DKIM/ARC have completed (priorities 1 and 2 respectively) before making any DMARC assessment.
	 * However, we need to run before auth_filter in mod_smtp_filter. */
	smtp_filter_register(&dmarc_filter, SMTP_FILTER_PREPEND, SMTP_SCOPE_COMBINED, SMTP_DIRECTION_IN, 5);
	return 0;
}

static int unload_module(void)
{
	smtp_filter_unregister(&dmarc_filter);
	if (logfp) {
		fclose(logfp);
	}
	bbs_mutex_destroy(&loglock);
	opendmarc_policy_library_shutdown(&lib);
	return 0;
}

BBS_MODULE_INFO_DEPENDENT("RFC7489 DMARC Validation", "net_smtp.so");
