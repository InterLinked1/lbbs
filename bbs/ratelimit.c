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
 * \brief Rate Limiting
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <sys/time.h>

#include "include/time.h" /* use timespecsub */
#include "include/ratelimit.h"

static inline void reset_rate_limit(struct bbs_rate_limit *r)
{
	/* We call reset_rate_limit when
	 * we get a hit and we want to reset,
	 * but since we got a hit, we set to 1, not 0. */
	r->reqcount = 1;
}

/*!
 * \brief Initialize rate limit
 * \param[out] r
 * \param interval The size of the sliding window, in milliseconds
 * \param max The maximum number of requests per sliding window
 * \retval 0 on success, -1 on failure
 */
int bbs_rate_limit_init(struct bbs_rate_limit *r, int interval, int max)
{
	memset(r, 0, sizeof(struct bbs_rate_limit));

	if (max < 1) {
		bbs_error("Invalid rate limit cap: %d\n", max);
		return -1;
	}

	r->interval = interval;
	r->max = max;
	r->reqcount = 0;

	/* To avoid having to check if r->a is 0 or an actual time
	 * every single time, initialize this to the current time, to start. */
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &r->a)) {
		bbs_error("clock_gettime failed: %s\n", strerror(errno));
		return -1;
	}

	memcpy(&r->b, &r->a, sizeof(struct timespec));
	return 0;
}

static inline long ms_since(struct timespec *start, struct timespec *now)
{
	struct timespec diff;
	timespecsub(now, start, &diff);
	return (1000 * diff.tv_sec) + (diff.tv_nsec / 1000000); /* 1,000,000 ns in a ms - wow! */
}

int bbs_rate_limit_exceeded(struct bbs_rate_limit *r)
{
	struct timespec now;
	long ms;

	/* Rate limiting is a (perhaps surprisingly) complicated thing.
	 * They need to be accurate, handle edge cases well, and be performant.
	 * There are a few basic algorithms that exist for it;
	 * we use a variation of the "sliding window" approach,
	 * closer to the sliding window counter than the sliding window log,
	 * since that allows us to avoid allocations. */

	/* We don't need wall clock time,
	 * just relative time. */
	if (clock_gettime(CLOCK_MONOTONIC_RAW, &now)) {
		bbs_error("clock_gettime failed: %s\n", strerror(errno));
		/* Fail safe */
		return 0;
	}

	/*
	 * First, check if the time since the last call exceeds
	 * the rate limit. If so, reset reqcount to the beginning. */
	if (ms_since(&r->b, &now) > r->interval) {
		reset_rate_limit(r);
		/* What's new is now old */
		memcpy(&r->a, &now, sizeof(struct timespec)); /* Update interval start */
		memcpy(&r->b, &now, sizeof(struct timespec)); /* Update last hit */
		/* This is the fast path. If it's been a while (more than the interval),
		 * and we just got a hit, we can't possibly have exceeded the rate limit. */
		return 0;
	}

	/*
	 * The first request, we store the timestamp, A and ++reqcount
	 * For requests 2, 3, 4... max, we update timestamp B and ++reqcount. */
	if (++r->reqcount <= r->max) {
		/* Haven't exceeded rate limit just yet. */
		memcpy(&r->b, &now, sizeof(struct timespec)); /* Update last hit */
		return 0; /* This is another fast path */
	}

	/*
	 * When we get the max + 1'th request, we check (and reset our state afterwards in both cases):
	 *
	 *                  Is NOW - A longer than interval?
	 */

	bbs_debug(3, "Rate limit threshold has been triggered (%d max per %d ms)\n", r->max, r->interval);
	ms = ms_since(&r->a, &now);
	if (ms <= r->interval) {
		/* We have DEFINITELY exceeded the rate limit */
		bbs_notice("Rate limit exceeded (%d requests in the past %ld ms)\n", r->reqcount, ms);
		reset_rate_limit(r);
		/* Do NOT reset the interval start time,
		 * or that would incorrectly end the rate limiting. */
		memcpy(&r->b, &now, sizeof(struct timespec)); /* Update last hit */
		return 1;
	}

	/* We have probably not exceeded the rate limit, but there could be some false negatives.
	 * Consider if we get all our requests right at the end of an interval.
	 * Request max + 1 is found NOT to exceed the rate limit, so we reset our state.
	 * However, if we get a couple more requests very quickly, then we may exceed the rate limit
	 * over SOME sliding window, just not either of the two windows we picked, individually.
	 *
	 * To mitigate this, suitably small windows should be used.
	 * Resetting at the beginning if it's been more than interval already also mitigates this.
	 *
	 * Example: Suppose interval = 10 and max = 4
	 * R = Allowed, reset
	 * X = Allowed, increment
	 * ! = Rate Limited (rejected)
	 *
	 *  1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9
	 *  R X X X !
	 *  R       X X X !
	 *  R             X X R X X X
	 *                R X X X !
	 *  R         X         X
	 *
	 * The 3rd case is an example where traffic is allowed that should technically be rate limited in a perfect world.
	 * This is because at interval 10, we reset our counts and timestamps, since an interval has passed since A.
	 * However, if we were to have reset at interval 8, this would get flagged.
	 *
	 * That's not to say this algorithm is bad. In the real world, getting a hit and then a series of hits within the interval
	 * that on their own would exceed the rate limit is not super likely. It's more likely we'd get a series of hits out of the blue,
	 * which is the 4th scenario, and the rate limiter can detect that just fine.
 	 */

	/*! \note The one thing that could be easily tweaked is in example #5 above:
	 * Should the 3rd request reset (R) or be another hit? (X)
	 * Right now, it's just another hit.
	 * If we wanted to check if the interval has ended and reset, that could be done.
	 * However, I don't think this would help... ? */

	/* This is the case where we're not 100% sure either way,
	 * since we only use constant space data to keep track.
	 * Fail open and allow the request, and reset. */
	reset_rate_limit(r);
	memcpy(&r->a, &now, sizeof(struct timespec)); /* Update interval start */
	memcpy(&r->b, &now, sizeof(struct timespec)); /* Update last hit */
	return 0;
}
