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
 * \brief Alertpipe
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/*!
 * \brief Signal alertpipe
 * \retval Same as write()
 */
ssize_t bbs_alertpipe_write(int alert_pipe[2]);

/*!
 * \brief Read from an alertpipe.
 * \note Must be done whenever an alertpipe has been written to
 * \retval Same as read()
 */
int bbs_alertpipe_read(int alert_pipe[2]);

/*! \brief Initialize an alertpipe */
int bbs_alertpipe_create(int alert_pipe[2]);

/*! \brief Close an alertpipe */
int bbs_alertpipe_close(int alert_pipe[2]);

/*! \brief Mark alertpipe's file descriptors as closed */
#define bbs_alertpipe_clear(p) p[0] = -1; p[1] = -1;

/*!
 * \brief Wait indefinitely for traffic on an alertpipe
 * \retval Same as poll()
 */
int bbs_alertpipe_poll(int alert_pipe[2]);
