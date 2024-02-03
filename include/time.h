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
 * \brief Time and locale
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/* This is a BSD macro, so probably not available by default on most systems */
#ifndef timespecsub
#define timespecsub(tsp, usp, vsp)                          \
    do {                                                    \
        (vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;      \
        (vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;   \
        if ((vsp)->tv_nsec < 0) {                           \
            (vsp)->tv_sec--;                                \
            (vsp)->tv_nsec += 1000000000L;                  \
        }                                                   \
    } while (0)
#endif
