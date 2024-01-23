/*
 * LBBS -- The Lightweight Bulletin Board System
 *
 * Copyright (C) 2024, Naveen Albert
 *
 * Naveen Albert <bbs@phreaknet.org>
 *
 */

/*! \file
 *
 * \brief Rate Limiting
 *
 */

struct bbs_rate_limit {
	struct timespec a;	/* Time at beginning of interval */
	struct timespec b;	/* Time of last hit */
	int interval;		/* Duration of interval in ms */
	int max;			/* Max number of hits per interval */
	int reqcount;		/* Number of hits so far this interval */
};

/*!
 * \brief Initialize rate limit
 * \param[out] r
 * \param interval The size of the sliding window, in milliseconds
 * \param max The maximum number of requests per sliding window
 * \retval 0 on success, -1 on failure
 * \note Rate limiting is not 100% precise, but these parameters are useful for tuning the rate limiter.
 */
int bbs_rate_limit_init(struct bbs_rate_limit *r, int interval, int max);

/*!
 * \brief Check if this request exceeds a rate limit
 * \param r
 * \retval 0 if doesn't exceed or an error occured (since we fail safe)
 * \retval 1 if exceeds rate limit
 * \note There are no false positives but there may be false negatives (requests allowed that are not desired)
 * \note Calling bbs_rate_limit_exceeded if bbs_rate_limit_init returns nonzero is undefined behavior.
 *       The rate limiting code is written to be fast and will only work correctly when used properly.
 * \note This is not multithread safe and should be surrounded with locking if needed.
 */
int bbs_rate_limit_exceeded(struct bbs_rate_limit *r);
