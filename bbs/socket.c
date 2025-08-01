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
 * \brief Socket functions
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

#include "include/bbs.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h> /* struct timeval for musl */
#include <netinet/in.h> /* use sockaddr_in */
#include <net/if.h> /* use ifreq */
#include <sys/un.h>	/* use struct sockaddr_un */
#include <arpa/inet.h> /* use inet_ntop */
#include <netdb.h> /* use getnameinfo */
#include <ifaddrs.h>
#include <poll.h>

#ifdef __linux__
/* <linux/tcp.h> includes some of the same stuff as <netinet/tcp.h>, so don't include both, just one or the other */
#include <linux/tcp.h>
#else
#include <netinet/tcp.h> /* use TCP_NODELAY */
#endif

#ifdef __linux__
#include <sys/sendfile.h>
#elif defined(__FreeBSD__)
#include <sys/types.h>
#include <sys/uio.h>
#else
#error "sendfile API unavailable"
#endif

/* #define DEBUG_TEXT_IO */

#ifdef DEBUG_TEXT_IO
#include <ctype.h>
#endif

/* Generic socket functions are in utils.h */
#include "include/utils.h"
/* Most node specific functions are in node.h */
#include "include/node.h"

#include "include/term.h" /* use bbs_unbuffer */
#include "include/alertpipe.h"
#include "include/net.h"
#include "include/linkedlists.h"
#include "include/startup.h"

#define LISTEN_BACKLOG 64

/* These are extern in bbs.c */
extern int option_connect_timeout;
extern int option_rebind;

int __bbs_make_unix_socket(int *sock, const char *sockfile, const char *perm, uid_t uid, gid_t gid, const char *file, int line, const char *func)
{
	struct sockaddr_un sunaddr; /* UNIX socket */
	int res;
	int uds_socket;

	/* Remove any existing socket file */
	*sock = -1;
	unlink(sockfile);

	/* Set up the UNIX domain socket. */
#if defined(DEBUG_FD_LEAKS) && DEBUG_FD_LEAKS == 1
	uds_socket = __bbs_socket(PF_LOCAL, SOCK_STREAM, 0, file, line, func);
#else
	UNUSED(file);
	UNUSED(line);
	UNUSED(func);
	uds_socket = socket(PF_LOCAL, SOCK_STREAM, 0);
#endif
	if (uds_socket < 0) {
		bbs_error("Unable to create UNIX domain socket: %s\n", strerror(errno));
		return -1;
	}

	memset(&sunaddr, 0, sizeof(sunaddr));
	sunaddr.sun_family = AF_LOCAL;
	safe_strncpy(sunaddr.sun_path, sockfile, sizeof(sunaddr.sun_path));

	res = bind(uds_socket, (struct sockaddr *) &sunaddr, sizeof(sunaddr));
	if (res) {
		bbs_error("Unable to bind UNIX domain socket to %s: %s\n", sockfile, strerror(errno));
		close(uds_socket);
		return -1;
	}
	res = listen(uds_socket, LISTEN_BACKLOG);
	if (res < 0) {
		bbs_error("Unable to listen on UNIX domain socket %s: %s\n", sockfile, strerror(errno));
		close(uds_socket);
		return -1;
	}

	if (chown(sockfile, uid, gid) < 0) {
		bbs_error("Unable to change ownership of %s: %s\n", sockfile, strerror(errno));
	}

	if (!strlen_zero(perm)) {
		unsigned int p1;
		mode_t p;
		sscanf(perm, "%30o", &p1);
		p = (mode_t) p1;
		if ((chmod(sockfile, p)) < 0) {
			bbs_error("Unable to change file permissions of %s: %s\n", sockfile, strerror(errno));
		}
	}

	*sock = uds_socket;
	return 0;
}

/*!
 * \brief Create and bind a TCP or UDP socket to a specific port
 * \param[out] sock Socket file descriptor
 * \param rebind Whether to try to force reuse of a particular port if already in use
 * \param type SOCK_DGRAM for UDP or SOCK_STREAM for TCP
 * \param ip Specific IP/CIDR to which to bind, or NULL for all
 * \param interface Specific interface to which to bind, or NULL for all
 * \param file
 * \param line
 * \param func
 * \retval 0 on success, -1 on failure
 */
static int __bbs_socket_bind(int *sock, int rebind, int type, int port, const char *ip, const char *interface, const char *file, int line, const char *func)
{
	int res;
	struct sockaddr_in sinaddr; /* Internet socket */

#if defined(DEBUG_FD_LEAKS) && DEBUG_FD_LEAKS == 1
	*sock = __bbs_socket(AF_INET, type, 0, file, line, func);
#else
	UNUSED(file);
	UNUSED(line);
	UNUSED(func);
	*sock = socket(AF_INET, type, 0);
#endif
	if (*sock < 0) {
		bbs_error("Unable to create %s socket: %s\n", type == SOCK_STREAM ? "TCP" : "UDP", strerror(errno));
		return -1;
	}

	memset(&sinaddr, 0, sizeof(sinaddr));
	sinaddr.sin_family = AF_INET;
	sinaddr.sin_port = htons((uint16_t) port); /* Public port on which to listen */

	if (!strlen_zero(ip)) {
		sinaddr.sin_addr.s_addr = inet_addr(ip);
	} else {
		sinaddr.sin_addr.s_addr = INADDR_ANY;
	}

	if (!strlen_zero(interface)) {
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		safe_strncpy(ifr.ifr_name, interface, sizeof(ifr.ifr_name));
#ifdef __linux__
		if (setsockopt(*sock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
			bbs_error("Failed to set SO_BINDTODEVICE(%s): %s\n", interface, strerror(errno));
#elif defined(__FreeBSD__) && defined(IP_SENDIF)
		if (setsockopt(*sock, SOL_SOCKET, IP_SENDIF, &ifr, sizeof(ifr)) < 0) {
			bbs_error("Failed to set IP_SENDIF(%s): %s\n", interface, strerror(errno));
#else
		if (1) {
			bbs_error("Restricting binding to a specific interface is not supported on this platform\n");
#endif
			close(*sock);
			return -1;
		}
	}

	if (rebind && type == SOCK_STREAM) {
		const int enable = 1;
		/* This is necessary since trying a bind without reuse and then trying with reuse
		 * can actually still fail (for some reason...).
		 * If you reuse the first time, though, it should always work.
		 * This does defeat the safety checking here, to warn if the port was already in use,
		 * but for cases where we already know that it's not, or that multiple BBS processes
		 * aren't running, then this may be worth it (e.g. the test framework)
		 */
		if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
			bbs_error("Failed to set SO_REUSEADDR: %s\n", strerror(errno));
			close(*sock);
			return -1;
		}
		if (setsockopt(*sock, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0) {
			bbs_error("Failed to set SO_REUSEPORT: %s\n", strerror(errno));
			close(*sock);
			return -1;
		}
	}

	res = bind(*sock, (struct sockaddr*) &sinaddr, sizeof(sinaddr));
	if (res) {
		res = errno;
		close(*sock);
		errno = res; /* Close but preserve the errno from bind failing */
	}
	return res;
}

static int __bbs_make_ip_socket(int *sock, int port, int type, const char *ip, const char *interface, const char *file, int line, const char *func)
{
	int res;

	res = __bbs_socket_bind(sock, option_rebind, type, port, ip, interface, file, line, func);
	while (res && errno == EADDRINUSE) {
		/* Don't do this by default.
		 * If somehow multiple instances of the BBS are running,
		 * then weird things can happen as a result of multiple BBS processes
		 * running on the same port. Sometimes things will work, usually they won't.
		 *
		 * (We do try really hard in bbs.c to prevent multiple instances of the BBS
		 *  from being run at the same time, mostly accidentally, and this usually
		 *  works, but it's not foolproof.)
		 *
		 * Therefore, try to bind without reusing first, and only if that fails,
		 * reuse the port, but make some noise about this just in case. */
		if (option_rebind) {
			bbs_error("Port %d was already in use, retrying with reuse\n", port);
		} else {
			bbs_warning("Port %d was already in use, retrying with reuse\n", port);
		}

		if (bbs_safe_sleep(500)) {
			bbs_verb(4, "Aborting socket bind due to exceptional BBS activity\n");
			break;
		}

		/* The reason we pass option_rebind again instead of just 1 to always force rebind
		 * at this point is if we don't request reuse initially, it doesn't work if we
		 * ask for it now. And, per the comment above, it's not always ideal to
		 * ask for it initially either.
		 * Thus the only elegant way to ensure we always rebind successfully is if the
		 * BBS is started with the -b option. */
		res = __bbs_socket_bind(sock, option_rebind, type, port, ip, interface, file, line, func);
		if (!option_rebind) {
			/* If we don't require reuse, try once and then give up */
			break;
		}
	}
	if (res) {
		bbs_error("Unable to bind %s socket to port %d: %s\n", type == SOCK_STREAM ? "TCP" : "UDP", port, strerror(errno));
		*sock = -1;
		return -1;
	}

	if (type == SOCK_STREAM) {
		if (listen(*sock, LISTEN_BACKLOG) < 0) {
			bbs_error("Unable to listen on %s socket on port %d: %s\n", type == SOCK_STREAM ? "TCP" : "UDP", port, strerror(errno));
			close(*sock);
			*sock = -1;
			return -1;
		}
	}
	bbs_debug(1, "Started %s listener on port %d\n", type == SOCK_STREAM ? "TCP" : "UDP", port);
	return 0;
}

int __bbs_make_tcp_socket(int *sock, int port, const char *file, int line, const char *func)
{
	return __bbs_make_ip_socket(sock, port, SOCK_STREAM, NULL, NULL, file, line, func);
}

int __bbs_make_udp_socket(int *sock, int port, const char *ip, const char *interface, const char *file, int line, const char *func)
{
	return __bbs_make_ip_socket(sock, port, SOCK_DGRAM, ip, interface, file, line, func);
}

int bbs_fd_valid(int fd)
{
	return fcntl(fd, F_GETFD) != -1;
}

int bbs_unblock_fd(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		bbs_error("fcntl(%d) failed: %s\n", fd, strerror(errno));
		bbs_log_backtrace();
		return -1;
	}
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags)) {
		bbs_error("fcntl(%d) failed: %s\n", fd, strerror(errno));
		return -1;
	}
	return 0;
}

int bbs_block_fd(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		bbs_error("fcntl(%d) failed: %s\n", fd, strerror(errno));
		return -1;
	}
	flags &= ~O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags)) {
		bbs_error("fcntl(%d) failed: %s\n", fd, strerror(errno));
		return -1;
	}
	return 0;
}

int bbs_node_cork(struct bbs_node *node, int enabled)
{
	int i = enabled;
	/* This is TCP-specific, so it has to operate on the actual socket file descriptor,
	 * not any of the other node file descriptors. */
#ifdef __FreeBSD__
	if (setsockopt(node->sfd, IPPROTO_TCP, TCP_NOPUSH, &i, sizeof(i))) { /* FreeBSD */
#else
	if (setsockopt(node->sfd, IPPROTO_TCP, TCP_CORK, &i, sizeof(i))) { /* Linux */
#endif
		bbs_error("setsockopt(%d) failed: %s\n", node->sfd, strerror(errno));
		return -1;
	} else {
		/* net_imap fiddles corking around a lot, so high debug level to reduce noisiness */
		bbs_debug(10, "%s corking on node %d\n", enabled ? "Enabled" : "Disabled", node->id);
	}
	return 0;
}

int bbs_set_fd_tcp_nodelay(int fd, int enabled)
{
	int i = enabled;
	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &i, sizeof(i))) {
		bbs_error("setsockopt(%d) failed: %s\n", fd, strerror(errno));
		bbs_log_backtrace();
		return -1;
	} else {
		bbs_debug(5, "%s Nagle's algorithm on socket %d\n", enabled ? "Disabled" : "Enabled", fd);
	}
	return 0;
}

int bbs_set_fd_tcp_pacing_rate(int fd, int rate)
{
	int i = rate;
	if (setsockopt(fd, SOL_SOCKET, SO_MAX_PACING_RATE, &i, sizeof(i))) {
		bbs_error("setsockopt(%d) failed: %s\n", fd, strerror(errno));
		return -1;
	} else {
		if (rate) {
			bbs_debug(3, "Set TCP pacing rate to %d bytes/sec\n", rate);
		} else {
			bbs_debug(3, "Disabled TCP pacing rate\n");
		}
	}
	return 0;
}

int bbs_node_wait_until_output_sent(struct bbs_node *node)
{
#ifdef __linux__
	struct tcp_info info;
	socklen_t len = sizeof(info);
#endif

	/* If emulated speed, and data is in the slow_write queue,
	 * we're still writing.
	 * This check is needed since we don't write the data
	 * until the artificial delay has passed, so the
	 * number of packets unacked is usually always 0. */
	if (node->speed) {
		do {
			while (node->slow_bytes_left > 0) {
				unsigned int sleepms = 10; /* 10 ms by default */
				if (node->speed) {
					unsigned int sleepus;
					/* If we have a certain number of bytes left
					 * and we know we're writing at node->speed us per byte,
					 * then we can sleep until that's about up. */
					sleepus = node->speed * (unsigned int) node->slow_bytes_left;
					sleepms = sleepus / 1000;
				}
				if (bbs_node_safe_sleep(node, (int) sleepms)) {
					return -1;
				}
			}
			/* Wait to make sure we're not going to start writing more data. */
			bbs_node_safe_sleep(node, 2);
		} while (node->slow_bytes_left > 0);
	}

#ifdef __linux__
	/* If it's the network link that's actually slow,
	 * then the acks will take some time to come back. */
	for (;;) {
		if (getsockopt(node->sfd, IPPROTO_TCP, TCP_INFO, &info, &len)) {
			bbs_error("getsockopt(%d) failed: %s\n", node->sfd, strerror(errno));
			return -1;
		}
		bbs_debug(9, "File descriptor %d has %d packet%s unacked\n", node->sfd, info.tcpi_unacked, ESS(info.tcpi_unacked));
		if (info.tcpi_unacked <= 1) {
			break;
		}
		if (bbs_node_safe_sleep(node, 100)) {
			return -1;
		}
	}
#endif
	return 0;
}

int bbs_hostname_has_ip(const char *hostname, const char *ip)
{
	char buf[256];
	socklen_t len = sizeof(buf);
	int e;
	struct addrinfo hints, *res, *ai;
	struct sockaddr_in *saddr_in; /* IPv4 */
	struct sockaddr_in6 *saddr_in6; /* IPv6 */

	/* Resolve the hostname */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; /* IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* TCP */

	e = getaddrinfo(hostname, NULL, &hints, &res);
	if (e) {
		bbs_error("getaddrinfo(%s): %s\n", hostname, gai_strerror(e));
		return 0;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			saddr_in = (struct sockaddr_in *) ai->ai_addr;
			inet_ntop(ai->ai_family, &saddr_in->sin_addr, buf, len); /* Print IPv4*/
			if (!strcmp(buf, ip)) {
				freeaddrinfo(res);
				return 1;
			}
		} else if (ai->ai_family == AF_INET6) {
			saddr_in6 = (struct sockaddr_in6 *) ai->ai_addr;
			inet_ntop(ai->ai_family, &saddr_in6->sin6_addr, buf, len); /* Print IPv6 */
			if (!strcmp(buf, ip)) {
				freeaddrinfo(res);
				return 1;
			}
		}
	}

	freeaddrinfo(res);
	return 0;
}

int bbs_resolve_hostname(const char *hostname, char *buf, size_t len)
{
	int e;
	struct addrinfo hints, *res, *ai;
	struct sockaddr_in *saddr_in; /* IPv4 */
	struct sockaddr_in6 *saddr_in6; /* IPv6 */

	/* Resolve the hostname */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; /* IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* TCP */

	e = getaddrinfo(hostname, NULL, &hints, &res);
	if (e) {
		bbs_error("getaddrinfo(%s): %s\n", hostname, gai_strerror(e));
		return -1;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			saddr_in = (struct sockaddr_in *) ai->ai_addr;
			inet_ntop(ai->ai_family, &saddr_in->sin_addr, buf, (socklen_t) len); /* Print IPv4*/
			break; /* Use the 1st one that works */
		} else if (ai->ai_family == AF_INET6) {
			saddr_in6 = (struct sockaddr_in6 *) ai->ai_addr;
			inet_ntop(ai->ai_family, &saddr_in6->sin6_addr, buf, (socklen_t) len); /* Print IPv6 */
			break; /* Use the 1st one that works */
		}
	}

	freeaddrinfo(res);

	if (strcmp(hostname, buf)) {
		bbs_debug(5, "Resolved hostname %s to %s\n", hostname, buf);
	}
	return 0;
}

int __bbs_tcp_connect(const char *hostname, int port, const char *file, int line, const char *func)
{
	char ip[256];
	int e;
	struct addrinfo hints, *res, *ai;
	struct sockaddr_in sin;
	socklen_t slen = sizeof(sin);
	struct sockaddr_in *saddr_in; /* IPv4 */
	struct sockaddr_in6 *saddr_in6; /* IPv6 */
	int sfd = -1;
	struct timeval timeout;
	int lport = 0;

	/* Resolve the hostname */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC; /* IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* TCP */

	e = getaddrinfo(hostname, NULL, &hints, &res);
	if (e) {
		bbs_error("getaddrinfo (%s): %s\n", hostname, gai_strerror(e));
		return -1;
	}

	for (ai = res; ai; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			saddr_in = (struct sockaddr_in *) ai->ai_addr;
			saddr_in->sin_port = htons((uint16_t) port);
			inet_ntop(ai->ai_family, &saddr_in->sin_addr, ip, sizeof(ip)); /* Print IPv4*/
		} else if (ai->ai_family == AF_INET6) {
			saddr_in6 = (struct sockaddr_in6 *) ai->ai_addr;
			saddr_in6->sin6_port = htons((uint16_t) port);
			inet_ntop(ai->ai_family, &saddr_in6->sin6_addr, ip, sizeof(ip)); /* Print IPv6 */
		} else {
			continue;
		}

#if defined(DEBUG_FD_LEAKS) && DEBUG_FD_LEAKS == 1
		sfd = __bbs_socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol, file, line, func);
#else
		UNUSED(file);
		UNUSED(line);
		UNUSED(func);
		sfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
#endif

		if (sfd == -1) {
			bbs_error("socket: %s\n", strerror(errno));
			continue;
		}
		bbs_debug(3, "Attempting connection to %s:%d\n", ip, port);
		/* Put the socket in nonblocking mode to prevent connect from blocking for a long time.
		 * Using SO_SNDTIMEO works on Linux and is easier than doing bbs_unblock_fd before and bbs_block_fd after. */
		timeout.tv_sec = option_connect_timeout;
		timeout.tv_usec = 0;
		if (setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) {
			bbs_error("setsockopt failed: %s\n", strerror(errno));
			close(sfd);
			sfd = -1;
			continue;
		}
		if (connect(sfd, ai->ai_addr, ai->ai_addrlen)) {
			if (errno == EINPROGRESS) {
				bbs_warning("Aborting connection to %s:%d (timed out after %d second%s)\n", ip, port, option_connect_timeout, ESS(option_connect_timeout));
			} else {
				bbs_error("connect: %s\n", strerror(errno));
			}
			close(sfd);
			sfd = -1;
			continue;
		}
		break; /* Use the 1st one that works */
	}

	freeaddrinfo(res);
	if (sfd == -1) {
		return -1;
	} else {
		timeout.tv_sec = 0; /* Change back to fully blocking */
		if (setsockopt(sfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) {
			bbs_warning("Failed to make file descriptor %d blocking again: %s\n", sfd, strerror(errno));
		}
	}

	/* Figure out what port we're using locally for this connection */
	if (getsockname(sfd, (struct sockaddr *) &sin, &slen)) {
		bbs_warning("getsockname failed: %s\n", strerror(errno));
	} else {
		lport = ntohs(sin.sin_port);
	}

	bbs_debug(1, "Connected to %s:%d using port %d\n", hostname, port, lport);
	return sfd;
}

int bbs_timed_accept(int socket, int ms, const char *ip)
{
	struct sockaddr_in sinaddr;
	socklen_t len;
	int sfd;
	struct pollfd pfd;
	char new_ip[56];

	pfd.fd = socket;
	pfd.events = POLLIN;

	for (;;) {
		int res = poll(&pfd, 1, ms);
		pthread_testcancel();
		if (res < 0) {
			if (errno == EINTR) {
				continue;
			}
			bbs_warning("poll returned error: %s\n", strerror(errno));
			return -1;
		}
		if (pfd.revents) {
			len = sizeof(sinaddr);
			sfd = accept(socket, (struct sockaddr *) &sinaddr, &len);
			bbs_get_remote_ip(&sinaddr, new_ip, sizeof(new_ip));
			bbs_debug(1, "Accepting new TCP connection from %s\n", new_ip);
			if (!strlen_zero(ip) && strcmp(ip, new_ip)) {
				bbs_warning("Rejecting connection from %s (not from %s)\n", new_ip, ip);
				close(sfd);
				return -1;
			}
		} else {
			bbs_debug(5, "poll expired without accept()\n");
			return -1; /* Nobody connected to us before poll expired. Return -1 since 0 is technically a valid file descriptor. */
		}
		if (sfd < 0) {
			if (errno == EINTR) {
				continue;
			}
			bbs_debug(1, "accept returned %d: %s\n", sfd, strerror(errno));
			return -1;
		}
		bbs_debug(7, "accepted fd = %d\n", sfd);
		return sfd;
	}
	return -1;
}

int bbs_socket_shutdown(int fd)
{
	return shutdown(fd, SHUT_RDWR);
}

void __bbs_socket_close(int *socket, const char *file, int line, const char *func)
{
	/* Calling shutdown on the socket first
	 * avoids needing to call bbs_pthread_cancel_kill,
	 * which is a lot cleaner and helps avoid deadlocks. */
	bbs_socket_shutdown(*socket);
#if defined(DEBUG_FD_LEAKS) && DEBUG_FD_LEAKS == 1
	__bbs_close(*socket, file, line, func);
#else
	UNUSED(file);
	UNUSED(line);
	UNUSED(func);
	close(*socket);
#endif
	*socket = -1;
}

void bbs_socket_thread_shutdown(int *socket, pthread_t thread)
{
	bbs_socket_close(socket);
	bbs_pthread_join(thread, NULL);
}

int bbs_socket_pending_shutdown(int fd)
{
	char c;
	ssize_t res;

	if (bbs_poll(fd, 0) == 0) {
		/* No activity pending on the socket, so it's still open. */
		return 0;
	}

	/* Something is pending on the socket. Try to peek a byte,
	 * and if that fails, assume the remote end probably closed the connection. */
	res = recv(fd, &c, 1, MSG_PEEK);
	return res <= 0;
}

struct tcp_listener {
	void *(*handler)(void *varg);
	void *module;
	int port;
	int socket;
	const char *name;
	RWLIST_ENTRY(tcp_listener) entry;
};

static RWLIST_HEAD_STATIC(listeners, tcp_listener);

static pthread_t multilistener_thread = 0;
static int multilistener_alertpipe[2] = { -1, -1 };
static int num_listeners = 0;

static struct tcp_listener *list_add_listener(int port, int sfd, const char *name, void *(*handler)(void *varg), void *module)
{
	struct tcp_listener *l;

	l = calloc(1, sizeof(*l));
	if (!l) {
		return NULL;
	}
	l->port = port;
	l->socket = sfd;
	l->name = name;
	l->handler = handler;
	l->module = module;

	return l;
}

/*! \brief Single thread to poll all registered TCP listeners, to avoid creating lots of listener threads (similar to ssl_io_thread in tls.c) */
static void *tcp_multilistener(void *unused)
{
	static RWLIST_HEAD_STATIC(listeners_local, tcp_listener);
	int num_sockets = 0;
	struct pollfd *pfds = NULL;
	int exiting = 0;
	int rebuild = 1; /* This thread isn't started unless there's a listener, so we need to build a list from the get go. */

	UNUSED(unused);

	for (;;) {
		int i, res;
		struct tcp_listener *l, *l2;
		if (bbs_is_shutting_down() && !exiting) {
			/* Stop accepting connections on this socket. We do this to prevent an influx of connections
			 * from blocking shutdown. */
			exiting = 1;
			rebuild = 1;
		}
		if (rebuild) {
			/* Clear our copy and rebuild. Keep in mind this is not a common operation,
			 * so we do it this way to optimize performance for when a listener accepts a connection (don't need to hold any locks),
			 * not for rebuilding the list itself. */
			rebuild = 0;
			num_sockets = 0;
			RWLIST_WRLOCK_REMOVE_ALL(&listeners_local, entry, free);
			RWLIST_WRLOCK(&listeners);
			RWLIST_TRAVERSE(&listeners, l, entry) {
				l2 = list_add_listener(l->port, l->socket, l->name, l->handler, l->module);
				if (ALLOC_SUCCESS(l2)) {
					RWLIST_INSERT_TAIL(&listeners_local, l2, entry);
					num_sockets++;
				}
			}
			RWLIST_UNLOCK(&listeners);
			bbs_debug(6, "TCP multilistener is now watching %d socket%s\n", num_sockets, ESS(num_sockets));
			if (!num_sockets && bbs_is_shutting_down()) {
				/* If we're shutting down and we're the last listener, then we can safely exit. */
				break;
			}
			free_if(pfds);
			pfds = calloc((size_t) num_sockets + 1, sizeof(*pfds));
			if (ALLOC_FAILURE(pfds)) {
				break; /* Uh oh... */
			}
			i = 0;
			pfds[i].fd = multilistener_alertpipe[0];
			pfds[i].events = POLLIN;
			RWLIST_TRAVERSE(&listeners_local, l, entry) {
				i++;
				bbs_assert(i <= num_sockets + 1);
				pfds[i].fd = l->socket;
				pfds[i].events = exiting ? POLLHUP : POLLIN; /* Ignore new connections during shutdown */
			}
		}
		for (i = 0; i < num_sockets + 1; i++) {
			pfds[i].revents = 0;
		}
		res = poll(pfds, (nfds_t) num_sockets + 1, -1);
		if (res < 0) {
			if (errno != EINTR) {
				bbs_warning("poll returned error: %s\n", strerror(errno));
				break;
			}
			continue;
		}
		if (pfds[0].revents) {
			bbs_alertpipe_read(multilistener_alertpipe);
			rebuild = 1;
			continue; /* Rebuild list immediately */
		}
		i = 0; /* The first listener is at index 1, so start at 0 so the ++ will start us at 1 */
		RWLIST_TRAVERSE(&listeners_local, l, entry) {
			struct sockaddr_in sinaddr;
			socklen_t len;
			int sfd;
			struct bbs_node *node;
			char new_ip[56];

			i++;
			if (!res || i >= num_sockets + 1) {
				break;
			} else if (!pfds[i].revents) {
				continue;
			}
			res--; /* Processed one event. Break the loop as soon as there are no more, to avoid traversing all like with select(). */

			len = sizeof(sinaddr);
			sfd = accept(pfds[i].fd, (struct sockaddr *) &sinaddr, &len);
			bbs_get_remote_ip(&sinaddr, new_ip, sizeof(new_ip));

			if (sfd < 0) {
				if (errno != EINTR) {
					bbs_warning("accept returned %d (fd %d, %s, %s): %s\n", sfd, pfds[i].fd, l->name, new_ip, strerror(errno));
				}
				continue;
			}

			bbs_soft_assert(l->name != NULL);

			/* Throttle connections from this IP address if needed */
			if (bbs_node_ip_count(&sinaddr) >= bbs_maxnodes_per_ip()) {
				bbs_notice("Rejecting new %s connection from %s (exceeds maximum connections from this IP address)\n", l->name, new_ip);
				close(sfd);
				continue;
			}

			bbs_debug(1, "Accepting new %s connection from %s\n", l->name, new_ip);

			/* Note that l->name is const memory allocated as part of l.
			 * That means the listener must not go away while any nodes are using it
			 * (which shouldn't happen anyways) */
			node = __bbs_node_request(sfd, l->name, &sinaddr, -1, l->module);
			if (!node) {
				close(sfd);
			} else {
				node->port = (short unsigned int) l->port;
				node->skipjoin = 1;
				if (bbs_pthread_create_detached(&node->thread, NULL, l->handler, node)) { /* Run the BBS on this node */
					bbs_node_unlink(node);
				}
			}
		}
	}

	free_if(pfds);
	bbs_alertpipe_close(multilistener_alertpipe);
	RWLIST_WRLOCK_REMOVE_ALL(&listeners_local, entry, free);
	return NULL;
}

static bbs_mutex_t tcp_start_lock = BBS_MUTEX_INITIALIZER;
static int tcp_multilistener_started = 0;

static int start_tcp_multilistener(void)
{
	int res = 0;
	/* Thread doesn't exist yet. Start it up. */
	if (bbs_alertpipe_create(multilistener_alertpipe)) { /* Create an alertpipe for future signaling. */
		res = -1; /* Not much we can do if this fails... */
	} else if (bbs_pthread_create(&multilistener_thread, NULL, tcp_multilistener, NULL)) {
		res = -1;
	}
	return res;
}

void tcp_listener_cleanup(void)
{
	/* Synchronously wait for TCP multilistener thread to exit, to avoid warning about this thread still being registered at shutdown */
	if (multilistener_thread) {
		bbs_pthread_join(multilistener_thread, NULL);
	}
}

int __bbs_start_tcp_listener(int port, const char *name, void *(*handler)(void *varg), void *module)
{
	struct tcp_listener *l;
	int sfd;
	int res;

	if (bbs_is_shutting_down()) {
		return -1;
	}

	if (bbs_make_tcp_socket(&sfd, port)) {
		return -1;
	}

	res = bbs_register_network_protocol(name, (unsigned int) port);
	if (res) {
		bbs_warning("Failed to register network protocol on port %d\n", port);
		return -1;
	}

	l = list_add_listener(port, sfd, name, handler, module);
	if (ALLOC_FAILURE(l)) {
		close(sfd);
		bbs_unregister_network_protocol((unsigned int) port);
		return -1;
	}

	RWLIST_WRLOCK(&listeners);
	RWLIST_INSERT_TAIL(&listeners, l, entry);
	num_listeners++;
	RWLIST_UNLOCK(&listeners);

	bbs_debug(1, "Registered TCP listener for %s on port %d\n", name, port);

	/* Signal the listener thread there's a new socket on which to listen.
	 * But if the BBS is still starting, delay that until the BBS is fully started,
	 * and just signal it once then.
	 * There are two reasons for doing this.
	 * One is better performance.
	 * The other is that we probably don't want to accept TCP connections before we're fully started, anyways. */
	bbs_mutex_lock(&tcp_start_lock);
	if (!tcp_multilistener_started) {
		/* The first time that a module requests a TCP listener,
		 * we'll need to either queue the multilistener thread to be started
		 * once startup completes, or go ahead and start it immediately. */
		bbs_run_when_started(start_tcp_multilistener, STARTUP_PRIORITY_URGENT);
		tcp_multilistener_started = 1;
	} else if (bbs_is_fully_started()) {
		/* If we already started the listener,
		 * we only need to signal it if the BBS is already started.
		 * If it's still starting, the listener thread won't start
		 * listening until startup finishes anyways. */
		bbs_alertpipe_write(multilistener_alertpipe);
	}
	bbs_mutex_unlock(&tcp_start_lock);
	return 0;
}

int __bbs_start_tcp_listener3(int port, int port2, int port3, const char *name, const char *name2, const char *name3, void *(*handler)(void *varg), void *module)
{
	int res = -1;

	if (port) {
		res = __bbs_start_tcp_listener(port, name, handler, module);
		if (res) {
			return res;
		}
	}
	if (port2) {
		res = __bbs_start_tcp_listener(port2, name2, handler, module);
		if (res) {
			if (port) {
				bbs_stop_tcp_listener(port);
			}
			return res;
		}
	}
	if (port3) {
		res = __bbs_start_tcp_listener(port3, name3, handler, module);
		if (res) {
			if (port) {
				bbs_stop_tcp_listener(port);
			}
			if (port2) {
				bbs_stop_tcp_listener(port2);
			}
			return res;
		}
	}
	return res;
}

int bbs_stop_tcp_listener(int port)
{
	struct tcp_listener *l;
	int sfd;

	RWLIST_WRLOCK(&listeners);
	RWLIST_TRAVERSE_SAFE_BEGIN(&listeners, l, entry) {
		if (l->port == port) {
			RWLIST_REMOVE_CURRENT(entry);
			sfd = l->socket;
			free(l);
			break;
		}
	}
	RWLIST_TRAVERSE_SAFE_END;
	if (l) {
		num_listeners--;
	} else {
		bbs_error("Port %d is not registered\n", port);
	}
	RWLIST_UNLOCK(&listeners);

	if (!l) {
		return -1;
	}

	bbs_unregister_network_protocol((unsigned int) port);
	close(sfd);
	if (bbs_is_fully_started()) {
		bbs_alertpipe_write(multilistener_alertpipe); /* This will wake up the listener thread and cause it to remove the listener */
	} /* else, it didn't even start yet anyways */
	return 0;
}

void bbs_tcp_listener3(int socket, int socket2, int socket3, const char *name, const char *name2, const char *name3, void *(*handler)(void *varg), void *module)
{
	struct sockaddr_in sinaddr;
	socklen_t len;
	struct pollfd pfds[3];
	nfds_t nfds = 0;
	struct bbs_node *node;
	char new_ip[56];

	if (socket != -1) {
		pfds[nfds].fd = socket;
		pfds[nfds].events = POLLIN;
		nfds++;
	}
	if (socket2 != -1) {
		pfds[nfds].fd = socket2;
		pfds[nfds].events = POLLIN;
		nfds++;
	}
	if (socket3 != -1) {
		pfds[nfds].fd = socket3;
		pfds[nfds].events = POLLIN;
		nfds++;
	}

	if (!nfds) { /* No sockets on which to listen? Then time to check out. */
		bbs_warning("This thread is useless\n");
		return; /* Peace out, folks */
	}

	bbs_debug(1, "Started %s/%s/%s listener thread\n", S_IF(name), S_IF(name2), S_IF(name3));

	for (;;) {
		int sfd, sockidx;
		int res = poll(pfds, nfds, -1); /* Wait forever for an incoming connection. */
		pthread_testcancel();
		if (res < 0) {
			if (errno != EINTR) {
				bbs_warning("poll returned error: %s\n", strerror(errno));
				break;
			}
			continue;
		}
		if (pfds[0].revents) {
			len = sizeof(sinaddr);
			sfd = accept(pfds[0].fd, (struct sockaddr *) &sinaddr, &len);
			sockidx = pfds[0].fd == socket ? 0 : pfds[0].fd == socket2 ? 1 : 2; /* Could be socket, socket2, or socket3 */
		} else if (pfds[1].revents) {
			len = sizeof(sinaddr);
			sfd = accept(pfds[1].fd, (struct sockaddr *) &sinaddr, &len);
			sockidx = pfds[1].fd == socket ? 0 : pfds[1].fd == socket2 ? 1 : 2; /* Could only be socket2 or socket3, technically */
		} else if (pfds[2].revents) {
			len = sizeof(sinaddr);
			sfd = accept(pfds[2].fd, (struct sockaddr *) &sinaddr, &len);
			sockidx = pfds[2].fd == socket ? 0 : pfds[2].fd == socket2 ? 1 : 2; /* Could only be socket 3, technically */
		} else {
			bbs_error("No revents?\n");
			continue; /* Shouldn't happen? */
		}
		if (sfd < 0) {
			if (errno != EINTR) {
				bbs_debug(1, "accept returned %d: %s\n", sfd, strerror(errno));
			}
			bbs_debug(3, "accept: %s\n", strerror(errno));
			break;
		}

		bbs_get_remote_ip(&sinaddr, new_ip, sizeof(new_ip));
		bbs_debug(1, "Accepting new %s connection from %s\n", pfds[sockidx].fd == socket ? name : pfds[sockidx].fd == socket2 ? name2 : name3, new_ip);

		node = __bbs_node_request(sfd, sockidx == 0 ? name : sockidx == 1 ? name2 : name3, &sinaddr, -1, module);
		if (!node) {
			close(sfd);
		} else {
			node->skipjoin = 1;
			if (bbs_pthread_create_detached(&node->thread, NULL, handler, node)) { /* Run the BBS on this node */
				bbs_node_unlink(node);
			}
		}
	}
}

void bbs_tcp_listener2(int socket, int socket2, const char *name, const char *name2, void *(*handler)(void *varg), void *module)
{
	return bbs_tcp_listener3(socket, socket2, -1, name, name2, NULL, handler, module);
}

struct handshake_args {
	struct bbs_node *node;
	int (*handshake)(struct bbs_node *node);
};

static void *node_handler_with_handshake(void *varg)
{
	struct handshake_args *a = varg;
	struct bbs_node *node = a->node;
	int (*handshake)(struct bbs_node *node) = a->handshake;
	free(a);
	if (handshake(node)) {
		bbs_node_unlink(node);
		return NULL;
	}
	return bbs_node_handler(node);
}

static void __bbs_tcp_listener(int socket, const char *name, int (*handshake)(struct bbs_node *node), void *(*handler)(void *varg), void *module)
{
	struct sockaddr_in sinaddr;
	socklen_t len;
	int sfd;
	struct pollfd pfd;
	struct bbs_node *node;
	char new_ip[56];

	pfd.fd = socket;
	pfd.events = POLLIN;

	bbs_debug(1, "Started %s listener thread\n", name);

	for (;;) {
		int res = poll(&pfd, 1, -1); /* Wait forever for an incoming connection. */
		pthread_testcancel();
		if (res < 0) {
			if (errno != EINTR) {
				bbs_warning("poll returned error: %s\n", strerror(errno));
				break;
			}
			continue;
		}
		if (!pfd.revents) {
			bbs_error("No revents?\n");
			continue; /* Shouldn't happen? */
		}
		len = sizeof(sinaddr);
		sfd = accept(socket, (struct sockaddr *) &sinaddr, &len);
		if (sfd < 0) {
			if (errno != EINTR) {
				/* If shutdown is called on the listener socket, then we'll hit this,
				 * and that's great, not bad at all. It allows us to exit cleanly,
				 * on our own terms. */
				bbs_debug(1, "accept returned %d: %s\n", sfd, strerror(errno));
				break;
			}
			continue;
		}

		bbs_get_remote_ip(&sinaddr, new_ip, sizeof(new_ip));
		bbs_debug(1, "Accepting new %s connection from %s\n", name, new_ip);
		bbs_debug(7, "accepted fd = %d\n", sfd);

		node = __bbs_node_request(sfd, name, &sinaddr, -1, module);
		if (!node) {
			close(sfd);
		} else {
			node->skipjoin = 1;
			if (handshake) {
				struct handshake_args *h;
				/* Don't execute the handshake callback in this thread, or it will
				 * block the accept from accepting further connections until complete. */
				h = calloc(1, sizeof(*h));
				if (ALLOC_FAILURE(h)) {
					bbs_node_unlink(node);
					continue;
				}
				h->handshake = handshake;
				h->node = node;
				if (bbs_pthread_create_detached(&node->thread, NULL, node_handler_with_handshake, h)) {
					free(h);
					bbs_node_unlink(node);
				}
			} else if (bbs_pthread_create_detached(&node->thread, NULL, handler, node)) { /* Run the BBS on this node */
				bbs_node_unlink(node);
			}
		}
	}
}

void bbs_tcp_comm_listener(int socket, const char *name, int (*handshake)(struct bbs_node *node), void *module)
{
	return __bbs_tcp_listener(socket, name, handshake, bbs_node_handler, module);
}

void bbs_tcp_listener(int socket, const char *name, void *(*handler)(void *varg), void *module)
{
	return __bbs_tcp_listener(socket, name, NULL, handler, module);
}

int bbs_get_local_ip(struct bbs_node *node, char *buf, size_t len)
{
	int res = -1;
	struct sockaddr_in *sinaddr;
	struct ifaddrs *iflist, *iface;
	int loops = 0;
	if (getifaddrs(&iflist)) {
		bbs_error("getifaddrs failed: %s\n", strerror(errno));
		return -1;
	}

loop:
	for (iface = iflist; iface; iface = iface->ifa_next) {
		int af;
		char netmaskbuf[32];
		struct sockaddr_in *netmask;
		if (!iface->ifa_addr) {
			/* This can be NULL for interfaces without an IP address assigned. */
			continue;
		}
		af = iface->ifa_addr->sa_family;
		switch (af) {
			case AF_INET:
				sinaddr = (struct sockaddr_in *) iface->ifa_addr;
				netmask = (struct sockaddr_in *) iface->ifa_netmask;
				bbs_get_remote_ip(sinaddr, buf, len);
				if (bbs_is_loopback_ipv4(buf)) {
					break; /* Skip the loopback interface, we want the (a) real one */
				}
				/* Yeah, not very efficient, but since we store the node's IP as
				 * a string, rather than binary, we have to convert the netmask, too,
				 * for comparison (but we're also printing it, so, whatever). */
				inet_ntop(af, &netmask->sin_addr, netmaskbuf, sizeof(netmaskbuf));
				bbs_debug(5, "%s: %s/%s\n", iface->ifa_name, buf, netmaskbuf);
				res = 0;
				if (node && !loops) {
					struct in_addr addr;
					uint32_t netmask_mask;
					int netmasklen = 0;
					char cidr_range[96];

					/* Convert subnet mask to prefix length */
					inet_pton(af, netmaskbuf, &addr);
					netmask_mask = ntohl(addr.s_addr);
					while (netmask_mask & 0x80000000) {
						netmask_mask <<= 1;
						netmasklen++;
					}

					snprintf(cidr_range, sizeof(cidr_range), "%s/%d", buf, netmasklen);
					/* If we have a node, that means we have an IP address against which to compare,
					 * and we want the interface on which this connection arrived.
					 * For example, if this interface has a public IP but the node has a private one,
					 * we should look for an interface with a private address.
					 *
					 * Of course, it's impossible to reliably determine the IP address
					 * that a client behind certain kinds of NAT used to get to us,
					 * e.g. a NAT'ed VPN tunnel. */
					if (bbs_cidr_match_ipv4(node->ip, cidr_range)) {
						/* IP matches netmask */
						bbs_debug(5, "%s matches CIDR range %s\n", node->ip, cidr_range);
						goto done;
					} /* else, check next interface and see if it matches */
				} else {
					goto done; /* Break out of for loop */
				}
			case AF_INET6:
			default:
				break;
		}
	}

	bbs_debug(4, "Unable to determine matching interface, using default\n");
	loops++;
	goto loop;

done:
	if (res) {
		bbs_error("Failed to determine local IP address\n");
	}

	freeifaddrs(iflist);
	return res;
}

int bbs_get_hostname(const char *ip, char *buf, size_t len)
{
	struct sockaddr_in address;

	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = inet_addr(ip);

	return getnameinfo((struct sockaddr*) &address, sizeof(address), buf, (socklen_t) len, NULL, 0, 0);
}

int bbs_get_remote_ip(struct sockaddr_in *sinaddr, char *buf, size_t len)
{
	struct in_addr ip_addr = sinaddr->sin_addr;
	if (!inet_ntop(AF_INET, &ip_addr, buf, (socklen_t) len)) { /* XXX Assumes IPv4 */
		bbs_error("Failed to get IP address: %s\n", strerror(errno));
		return -1;
	}
	return 0;
}

int bbs_get_fd_ip(int fd, char *buf, size_t len)
{
	struct sockaddr_in sinaddr;
	socklen_t slen = sizeof(sinaddr);
	if (getpeername(fd, (struct sockaddr*) &sinaddr, &slen)) {
		bbs_error("getpeername(%d) failed: %s\n", fd, strerror(errno));
		return -1;
	}
	return bbs_get_remote_ip(&sinaddr, buf, len);
}

int bbs_save_remote_ip(struct sockaddr_in *sinaddr, struct bbs_node *node)
{
	char addrstr[64];

	if (bbs_get_remote_ip(sinaddr, addrstr, sizeof(addrstr))) {
		return -1;
	}
	node->ip = strdup(addrstr);
	node->rport = ntohs(sinaddr->sin_port);
	if (ALLOC_FAILURE(node->ip)) {
		bbs_error("Failed to duplicate IP address '%s'\n", addrstr);
		return -1;
	}
	return 0;
}

int bbs_hostname_is_ipv4(const char *hostname)
{
	struct sockaddr_in sa;

	if (!inet_pton(AF_INET, hostname, &(sa.sin_addr))) {
		return 0;
	}

	return 1;
}

static int ipv4_is_private_ipv4(uint32_t a)
{
	/* RFC 1918 private address ranges: */

	/* Class A: 10.0.0.0/8 */
	if (a >> 24 == 0xA) {
		return 'A';
	}

	/* Class B: 172.16.0.0/12 */
	if (a >> 20 == 0xAC1) {
		return 'B';
	}

	/* Class C: 192.168.0.0/16 */
	if (a >> 16 == 0xC0A8) {
		return 'C';
	}
	return 0;
}

int bbs_is_loopback_ipv4(const char *ip)
{
	struct in_addr addr;
	uint32_t a;

	if (!inet_aton(ip, &addr)) {
		bbs_error("IP address invalid: %s\n", ip);
		return 0;
	}

	a = htonl(addr.s_addr & 0xFFFFFFFF);
	/* Loopback range is 127.0.0.1/8 */
	return a >> 24 == 0x7F;
}

int bbs_ip_is_nonpublic_ipv4(const char *ip)
{
	struct in_addr addr;
	uint32_t a;

	if (!inet_aton(ip, &addr)) {
		bbs_error("IP address invalid: %s\n", ip);
		return 0;
	}

	a = htonl(addr.s_addr & 0xFFFFFFFF);
	return (a >> 24 == 0x7F) || ipv4_is_private_ipv4(a);
}

int bbs_ip_is_private_ipv4(const char *ip)
{
	struct in_addr addr;
	uint32_t a;

	if (!inet_aton(ip, &addr)) {
		bbs_error("IP address invalid: %s\n", ip);
		return 0;
	}

	a = htonl(addr.s_addr & 0xFFFFFFFF);
	return ipv4_is_private_ipv4(a);
}

int bbs_address_nonpublic(const char *hostname)
{
	char resolved_ip[256];
	/* Resolve the hostname (if it is one) to an IP, then do a direct comparison. */
	if (bbs_resolve_hostname(hostname, resolved_ip, sizeof(resolved_ip))) {
		return 0;
	}
	return bbs_ip_is_nonpublic_ipv4(resolved_ip);
}

int bbs_cidr_match_ipv4(const char *ip, const char *cidr)
{
	char cidr_dup[64];
	char *tmp;
	int netbits;
	struct in_addr addr, netmask;
	uint32_t a, b;
	int match;

	safe_strncpy(cidr_dup, cidr, sizeof(cidr_dup));
	tmp = strchr(cidr_dup, '/');
	if (tmp) {
		*tmp++ = '\0';
		if (!*tmp) {
			bbs_error("Malformed CIDR range: %s\n", cidr);
			return 0;
		}
		netbits = atoi(tmp);
	} else {
		/* Assume it's a /32 (single IP) */
		netbits = 32;
	}
	if (!inet_aton(ip, &addr)) {
		bbs_error("IP address invalid: %s\n", ip);
		return 0;
	}
	if (!inet_aton(cidr_dup, &netmask)) {
		bbs_error("CIDR range invalid: %s\n", cidr);
		return 0;
	}
	if (netbits < 0 || netbits > 32) {
		bbs_error("Invalid CIDR range: %s\n", cidr);
		return 0;
	}

	if (netbits == 0) {
		return 1; /* Short-circuit, since we can't shift a 32-bit value by 32 bits. /0 allows everything. */
	}

	/* Discard anything except the last 32 bits, if there are more. */
	/* Oh, also make sure we use big endian so all the bits are in order. */
	a = htonl(addr.s_addr & 0xFFFFFFFF);
	b = htonl(netmask.s_addr & 0xFFFFFFFF);

	a = a >> (32 - netbits);
	b = b >> (32 - netbits);

	match = a == b;
	bbs_debug(7, "IP comparison (%d): %08x/%08x => match: %s\n", netbits, a, b, match ? "yes" : "no");
	return match;
}

int bbs_ip_match_ipv4(const char *ip, const char *s)
{
	char resolved_ip[256];
	/* It's an IP address or hostname. */
	if (strchr(s, '/')) {
		/* It's a CIDR range. Do a direct comparison. */
		if (bbs_cidr_match_ipv4(ip, s)) {
			bbs_debug(5, "%s matches CIDR range %s\n", ip, s);
			return 1;
		}
		return 0;
	}
	/* Resolve the hostname (if it is one) to an IP, then do a direct comparison. */
	if (bbs_resolve_hostname(s, resolved_ip, sizeof(resolved_ip))) {
		return 0;
	}
	if (!strcmp(ip, resolved_ip)) {
		bbs_debug(5, "IP match: %s -> %s\n", s, ip);
		return 1;
	}
	return 0;
}

const char *poll_revent_name(int revents)
{
	if (revents & POLLIN) {
		return "POLLIN";
	} else if (revents & POLLPRI) {
		return "POLLPRI";
	} else if (revents & POLLOUT) {
		return "POLLOUT";
	} else if (revents & POLLRDHUP) {
		return "POLLRDHUP";
	} else if (revents & POLLERR) {
		return "POLLERR";
	} else if (revents & POLLHUP) {
		return "POLLHUP";
	} else if (revents & POLLNVAL) {
		return "POLLNVAL";
	} else {
		return "(None)";
	}
}



/* XXX This duplicates code, we should combine core logic of bbs_poll and bbs_node_poll */
static int __bbs_poll_interrupt(int fd, int ms, int abort_on_eintr)
{
	struct pollfd pfd;
	int res;

	pfd.fd = fd;
	pfd.events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	for (;;) {
		res = poll(&pfd, 1, ms);
		if (res < 0) {
			if (errno != EINTR) {
				bbs_warning("poll returned error: %s\n", strerror(errno));
				break;
			}
			bbs_debug(7, "poll interrupted\n");
			if (abort_on_eintr) {
				break;
			}
			continue;
		}
		if (res > 0) {
			if (!pfd.revents) {
				bbs_error("poll returned %d but no revents?\n", res);
			} else if (!(pfd.revents & POLLIN)) {
				if (pfd.revents & BBS_POLL_QUIT) {
					bbs_debug(1, "poll returned %d but got %s?\n", res, poll_revent_name(pfd.revents));
					res = -1; /* override to -1 since fd is closed */
					break;
				}
				bbs_error("poll returned %d but got %s?\n", res, poll_revent_name(pfd.revents));
			}
			break;
		}
		break;
	}
#ifdef DEBUG_POLL
	bbs_debug(10, "poll returned %d on fd %d\n", res, fd);
#else
	if (res <= 0) { /* Only log consequential events */
		bbs_debug(10, "poll returned %d on fd %d\n", res, fd);
	}
#endif
	return res;
}

int bbs_poll(int fd, int ms)
{
	return __bbs_poll_interrupt(fd, ms, 0);
}

int bbs_poll_interrupt(int fd, int ms)
{
	return __bbs_poll_interrupt(fd, ms, 1);
}

/* XXX For INTERNAL_POLL_THRESHOLD stuff, if ms == -1, instead of asserting, just set ms to INT_MAX or loop forever, internally */

/* XXX Lots of code duplicated between bbs_node_poll and __bbs_multi_poll */
static int __bbs_multi_poll(struct bbs_node *node, struct pollfd pfds[], int numfds, int ms)
{
	int i, res;

	/* Finish initializing pfds (hopefully the caller set the fds!) */
	for (i = 0; i < numfds; i++) {
		pfds[i].events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;
		pfds[i].revents = 0;
	}

	for (;;) {
		/* XXX If the pty master thread closes the slavefd,
		 * we won't see that until the poll expires, for some reason,
		 * at which point it will return 1, with POLLNVAL.
		 * To speed this up, if ms is larger than some threshold (say 15 seconds),
		 * do a loop with 1 poll call every 15 seconds up to the ms timer.
		 * Of course, more optimal would be to figure out how to get poll to return
		 * immediately when the slavefd has been closed.
		 * For now, this is a good compromise.
		 */

/* A smaller threshold means less time for stale connections to persist.
 * However, this comes at the cost of efficiency.
 * So we pick something that's small enough for a good user experience,
 * (allows dead nodes to be reaped relatively quickly)
 * but large enough to be adequately efficient.
 */
#define INTERNAL_POLL_THRESHOLD SEC_MS(15)
		if (ms > INTERNAL_POLL_THRESHOLD) {
			int msleft = ms;
			for (;;) {
				res = poll(pfds, (unsigned int) numfds, MIN(msleft, INTERNAL_POLL_THRESHOLD));
				if (res == 0 && msleft > INTERNAL_POLL_THRESHOLD) {
					msleft -= INTERNAL_POLL_THRESHOLD;
#ifdef EXTRA_DEBUG
					bbs_debug(10, "Internal poll elapsed with no activity, %d ms left (will poll(%d))\n", msleft, MIN(msleft, INTERNAL_POLL_THRESHOLD));
#endif
					continue; /* Call poll again */
				} /* else, something happened, fall through */
				break;
			}
		} else {
			res = poll(pfds, (unsigned int) numfds, ms);
		}
		if (res < 0) {
			if (errno != EINTR) {
				bbs_warning("poll returned error: %s\n", strerror(errno));
				break;
			}
			bbs_debug(7, "poll interrupted\n");
			if (node && node->interrupt) {
				bbs_node_interrupt_ack(node);
				return -1;
			}
			continue;
		}
		if (res > 0) {
			/* Check all the polled fds to see what happened */
			for (i = 0; i < numfds; i++) {
				if (pfds[i].revents) {
					res = i + 1; /* Return 1-indexed pfd with activity */
#ifdef EXTRA_DEBUG
					bbs_debug(10, "Got revent %s on pfds[%d]\n", poll_revent_name(pfds[i].revents), i);
#endif
					if (!(pfds[i].revents & POLLIN)) {
						if (pfds[i].revents & BBS_POLL_QUIT) {
							bbs_debug(1, "poll returned %d but got %s\n", res, poll_revent_name(pfds[i].revents));
							res = -1; /* override to -1 since fd is closed */
							break;
						}
						bbs_error("poll returned %d but got %s?\n", res, poll_revent_name(pfds[i].revents));
					}
					break;
				}
			}
			break;
		}
		break;
	}
#ifdef EXTRA_DEBUG
	bbs_debug(10, "multipoll returned %d on pfd %d\n", res, i);
#endif
	return res;
}

/* XXX bbs_node_poll should really use bbs_multi_poll internally to avoid duplicating code. Might be a tiny performance hit? */
int bbs_multi_poll(struct pollfd pfds[], int numfds, int ms)
{
	return __bbs_multi_poll(NULL, pfds, numfds, ms);
}

/* This is not an assertion, or even a warning, since it can legitimately happen right after a node disconnects and that would be overkill. */
#define REQUIRE_SLAVE_FD(node) \
	if (node->slavefd == -1) { \
		bbs_debug(1, "Node %d has no active slave fd\n", node->id); \
		return -1; \
	}

/*! \note fd is the last arg in case in the future, we want to expand this to accept variadic args of fds */
int bbs_node_poll2(struct bbs_node *node, int ms, int fd)
{
	struct pollfd pfds[2];

	REQUIRE_SLAVE_FD(node);

	if (bbs_node_interrupted(node)) {
		/* This could happen if the interrupt flag is set while the node thread isn't executing poll(2).
		 * In that case, we'll be blissfully unaware of the interrupt until bbs_node_poll is called. */
		bbs_debug(1, "Node %u still has an interrupt pending, declining to poll the slave\n", node->id);
		bbs_node_interrupt_ack(node);
		return -1;
	}

	/* Watch for data written from the master end of the PTY to the slave end. */
	/* The lock/unlock to get node->slavefd here is a little silly. It just makes helgrind happy. */
	bbs_node_lock(node);
	pfds[0].fd = node->slavefd;
	bbs_node_unlock(node);
	pfds[1].fd = fd;

	return __bbs_multi_poll(node, pfds, 2, ms);
}

int bbs_node_poll(struct bbs_node *node, int ms)
{
	struct pollfd pfd;
	int res;

	REQUIRE_SLAVE_FD(node);

	/* We should never be polling indefinitely for a BBS node. */
	bbs_assert(ms >= 0);

	if (bbs_node_interrupted(node)) {
		/* This could happen if the interrupt flag is set while the node thread isn't executing poll(2).
		 * In that case, we'll be blissfully unaware of the interrupt until bbs_node_poll is called. */
		bbs_debug(1, "Node %u still has an interrupt pending, declining to poll the slave\n", node->id);
		bbs_node_interrupt_ack(node);
		return -1;
	}

	/* Watch for data written from the master end of the PTY to the slave end. */
	/* The lock/unlock to get node->slavefd here is a little silly. It just makes helgrind happy. */
	bbs_node_lock(node);
	pfd.fd = node->slavefd;
	bbs_node_unlock(node);
	pfd.events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	for (;;) {
		/* XXX If the pty master thread closes the slavefd,
		 * we won't see that until the poll expires, for some reason,
		 * at which point it will return 1, with POLLNVAL.
		 * To speed this up, if ms is larger than some threshold (say 15 seconds),
		 * do a loop with 1 poll call every 15 seconds up to the ms timer.
		 * Of course, more optimal would be to figure out how to get poll to return
		 * immediately when the slavefd has been closed.
		 * For now, this is a good compromise.
		 */

/* A smaller threshold means less time for stale connections to persist.
 * However, this comes at the cost of efficiency.
 * So we pick something that's small enough for a good user experience,
 * (allows dead nodes to be reaped relatively quickly)
 * but large enough to be adequately efficient.
 */
#define INTERNAL_POLL_THRESHOLD SEC_MS(15)
		if (ms > INTERNAL_POLL_THRESHOLD) {
			int msleft = ms;
			for (;;) {
				res = poll(&pfd, 1, MIN(msleft, INTERNAL_POLL_THRESHOLD));
				if (res == 0 && msleft > INTERNAL_POLL_THRESHOLD) {
					msleft -= INTERNAL_POLL_THRESHOLD;
#if 0
					bbs_debug(10, "Internal poll elapsed with no activity, %d ms left (will poll(%d))\n", msleft, MIN(msleft, INTERNAL_POLL_THRESHOLD));
#endif
					continue; /* Call poll again */
				} /* else, something happened, fall through */
				break;
			}
		} else {
			res = poll(&pfd, 1, ms);
		}
		if (!node->active) {
			/* If poll was interrupted because we're dead now, then exit */
			bbs_debug(6, "Node %u no longer active, aborting poll\n", node->id);
			res = -1;
			break;
		}
		if (res < 0) {
			if (errno != EINTR) {
				bbs_warning("poll returned error: %s\n", strerror(errno));
				break;
			}
			bbs_debug(7, "poll interrupted\n");
			if (node->interrupt) {
				bbs_node_interrupt_ack(node);
				return -1;
			}
			continue;
		}
		if (res > 0) {
			if (!pfd.revents) {
				bbs_error("Node %d: poll returned %d but no revents?\n", node->id, res);
			} else if (!(pfd.revents & POLLIN)) {
				if (pfd.revents & BBS_POLL_QUIT) {
					bbs_debug(1, "Node %d: poll returned %d but got %s\n", node->id, res, poll_revent_name(pfd.revents));
					res = -1; /* override to -1 since fd is closed */
					break;
				}
				bbs_error("Node %d: poll returned %d but got %s?\n", node->id, res, poll_revent_name(pfd.revents));
			}
			break;
		}
		break;
	}
	bbs_debug(10, "Node %d: poll returned %d\n", node->id, res);
	return res;
}

int bbs_node_tpoll(struct bbs_node *node, int ms)
{
	int everwarned = 0, res = 0;
	int wasbuffered = node->buffered; /* We could be buffered or unbuffered, with echo or without */
	int hadecho = node->echo;
	int pollms = ms;
	int attempts = 0;

	/* If the poll is long enough, we do a preliminary poll first.
	 * If this poll expires, give the user a warning that s/he's about to be disconnected.
	 * Then, if the next poll expires, actually disconnect.
	 */

/*! \brief If doing a warning, how long before disconnect we should warn. */
#define MIN_WARNING_MS SEC_MS(30)

/*! \brief Minimum amount of poll time (ms) for which we should even bother doing a warning.
 * Polls shorter than this will expire with no warning.
 * Should be at least twice the warning time, or the warning would be triggered before even half the poll is done, which makes no sense.
 */
#define MIN_POLL_MS_FOR_WARNING 2 * MIN_WARNING_MS

	for (;;) {
		int warned;
		if (++attempts > 1) {
			bbs_debug(6, "tpoll iteration %d (%d ms)\n", attempts, pollms);
		}
		ms = pollms;
		warned = 0;
		if (ms >= MIN_POLL_MS_FOR_WARNING) {
			/* Wait until there's MIN_WARNING_MS ms left. */
			res = bbs_node_poll(node, ms - MIN_WARNING_MS);
			if (!res) {
				bbs_debug(8, "Node %d has been inactive for %d ms, warning\n", node->id, ms - MIN_WARNING_MS);
				bbs_verb(5, "Node %d is at imminent risk of timing out\n", node->id);
				if (everwarned) {
					/* If already warned, don't keep adding more new lines. */
					bbs_node_clear_line(node);
					NEG_RETURN(bbs_node_writef(node, "\r"));
				} else {
					/* Don't begin with \r because we may not necessarily want to erase current line. */
					/* On the contrary, start with a LF for safety, since bbs_node_wait_key for example doesn't end in LF.
					 * Finally, don't end with a LF. */
					NEG_RETURN(bbs_node_writef(node, "\n"));
				}
				if (!NODE_IS_TDD(node)) {
					NEG_RETURN(bbs_node_writef(node, "%sAre you still there? []%s", COLOR(TERM_COLOR_RED), COLOR_RESET));
					/* Ring the bell to get the user's attention. */
					NEG_RETURN(bbs_node_ring_bell(node));
				} else {
					NEG_RETURN(bbs_node_writef(node, "Still there?"));
				}

				ms = MIN_WARNING_MS;
				everwarned = warned = 1;
				/* If wasbuffered, then we don't actually know if the next bbs_node_poll returned 1
				 * because the user started typing and stopped before hitting ENTER (and the timer went off),
				 * or because the user responded to the "Are you still there?".
				 * As a result, we need to check if the buffer has data when we put
				 * the terminal into noncanonical mode, before polling, so we know which of the 2 cases is true.
				 *
				 * We don't actually need to call poll with 0 to check, we can just flush the buffer here,
				 * as well as below. This guarantees that the next bbs_node_poll won't return immediately
				 * because of data that was present in the buffer prior to the warning, simply
				 * because we changed to noncanonical mode.
				 */
				bbs_node_unbuffer(node); /* Non-canonical mode for warning response, no echo */
				NEG_RETURN(bbs_node_flush_input(node));
			}
		}

		/* This is the first poll if <= MIN_POLL_MS_FOR_WARNING, and possibly if >. */
		if (!res) {
			res = bbs_node_poll(node, ms);
			if (res > 0 && warned) {
				/* This was a response to the "Are you still there?" prompt, not whatever the BBS was doing.
				 * Flush the response to ignore everything pending in the input buffer.
				 * (If we were in canonical mode, there could be more than 1 byte to flush.)
				 */
				NEG_RETURN(bbs_node_flush_input(node));
				/* Ate response, now start over */
				if (wasbuffered) {
					bbs_node_clear_line(node); /* Erase prompt */
					NEG_RETURN(bbs_node_writef(node, "\r"));
					bbs_node_buffer_input(node, hadecho); /* Canonical mode, same echo */
				} else {
					/* Prevent "Are you still there?" from lingering on menus after confirmation */
					bbs_node_clear_line(node); /* Erase prompt */
					NEG_RETURN(bbs_node_writef(node, "\r"));
				}
				continue; /* Start the poll over again, now that the user confirmed s/he's still there */
			} else if (!res && warned && wasbuffered) {
				bbs_node_buffer_input(node, hadecho); /* Restore before continuing */
			}
		}
		break;
	}

	if (ms && res == 0) {
		/* Write directly to the socket fd instead of using the PTY fd,
		 * because otherwise the node might shut everything down before
		 * the PTY master thread has time to relay it to the socket fd.
		 *
		 * Note that because we're writing directly to the socket fd,
		 * we must do CR LF, not just LF.
		 */
		NODE_SWRITE(node, node->wfd, COLOR_RESET "\r\nYou've been inactive too long.\r\n");
		bbs_verb(4, "Node %d timed out due to inactivity\n", node->id);
	}
	return res;
}

ssize_t bbs_node_read(struct bbs_node *node, char *buf, size_t len)
{
	ssize_t res;

	REQUIRE_SLAVE_FD(node);

	bbs_node_lock(node);
	res = read(node->slavefd, buf, len);
	bbs_node_unlock(node);
	if (res <= 0) {
		bbs_debug(5, "Node %d: read returned %ld\n", node->id, res);
	}

	if (res == 1) {
		bbs_debug(10, "Node %d: read %ld byte (%d)\n", node->id, res, *buf);
	} else {
		bbs_debug(10, "Node %d: read %ld bytes\n", node->id, res);
	}
	return res;
}

ssize_t bbs_node_poll_read(struct bbs_node *node, int ms, char *buf, size_t len)
{
	ssize_t res = bbs_node_poll(node, ms);
	if (res <= 0) {
		return res;
	}
	res = bbs_node_read(node, buf, len);
	if (res <= 0) {
		/* If read returns 0, return -1, since the connection is dead anyways,
		 * to reserve a return value of 0 for poll timeout. */
		return -1;
	}
	return res;
}

ssize_t bbs_poll_read(int fd, int ms, char *buf, size_t len)
{
	ssize_t res = bbs_poll(fd, ms);
	if (res <= 0) {
		return res;
	}
	res = read(fd, buf, len);
	if (res <= 0) {
		/* If read returns 0, return -1, since the connection is dead anyways,
		 * to reserve a return value of 0 for poll timeout. */
		return -1;
	}
	return res;
}

int bbs_expect(int fd, int ms, char *buf, size_t len, const char *str)
{
	ssize_t res;

	*buf = '\0'; /* Clear the buffer, in case we don't read anything at all. */
	res = bbs_poll_read(fd, ms, buf, len - 1);
	if (res <= 0) {
		return -1;
	}

	buf[res] = '\0'; /* Safe */
	bbs_debug(6, "Read: %s%s", buf, res > 1 && buf[res - 1] == '\n' ? "" : "\n"); /* Don't add an additional LF if there's already one. */

	if (!strstr(buf, str)) {
		bbs_debug(1, "Expected '%s', got: %s\n", str, buf);
		return 1;
	}
	return 0;
}

int bbs_expect_line(int fd, int ms, struct readline_data *rldata, const char *str)
{
	ssize_t res;

	rldata->buf[0] = '\0'; /* Clear the buffer, in case we don't read anything at all. */
	res = bbs_readline(fd, rldata, "\r\n", ms);
	if (res <= 0) {
		return -1;
	}

	if (!strstr(rldata->buf, str)) {
		bbs_debug(1, "Expected '%s', got: %s\n", str, rldata->buf);
		return 1;
	}
	return 0;
}

static int bbs_tread(int fd, int ms)
{
	int res;

	if (fd < 0) {
		bbs_error("Invalid file descriptor: %d\n", fd);
		bbs_soft_assert(fd >= 0); /* Trigger a backtrace dump */
		return -1;
	}

	bbs_assert(ms > 0); /* There would be no reason to use bbs_node_tpoll over bbs_node_poll unless ms > 0. */
	res = (int) bbs_poll(fd, ms);

	if (res > 0) {
		char buf[1];
		res = (int) read(fd, buf, sizeof(buf));
		if (res <= 0) {
			return res;
		}
		return buf[0]; /* Return the char that was read */
	}
	return res;
}

int bbs_node_tread(struct bbs_node *node, int ms)
{
	int res;

	bbs_assert(ms > 0); /* There would be no reason to use bbs_node_tpoll over bbs_node_poll unless ms > 0. */
	res = bbs_node_tpoll(node, ms);

	if (res > 0) {
		char buf[1];
		res = (int) bbs_node_read(node, buf, sizeof(buf));
		if (res <= 0) {
			return res;
		}
		return buf[0]; /* Return the char that was read */
	}
	return res;
}

/*!
 * \retval -1 node disconnected
 * \retval 0 ESC (just the ESC key, no escape sequence)
 * \retval positive escape sequence code
 */
static int __bbs_node_read_escseq(struct bbs_node *node, int fd)
{
	/* We can't just declare a variable pointing to the right function to use, since their arguments are of different types (node vs int). Use a macro instead. */
#define bbs_proper_tread(node, fd, ms) node ? bbs_node_tread(node, ms) : bbs_tread(fd, ms)

	int c1, c2, c3;
	/* We already read ESC (27). Try to read further characters. */
	c1 = bbs_proper_tread(node, fd, 10); /* 10ms ought to be more than enough. We should really get everything at once. */
	if (c1 <= 0) {
		return c1 < 0 ? c1 : KEY_ESC;
	}
	switch (c1) {
		case 91:
			c2 = bbs_proper_tread(node, fd, 10);
			if (c2 <= 0) {
				return c2;
			}
			switch (c2) {
				case 49:
					c3 = bbs_proper_tread(node, fd, 10);
					if (c3 <= 0) {
						return c3 < 0 ? c3 : KEY_HOME;
					}
					switch (c3) {
						/* F function keys */
						case 49 ... 53:
							return KEY_F(1 + c3 - 49); /* F1 to F5 */
						/* 54 is skipped */
						case 55 ... 57:
							return KEY_F(6 + c3 - 55); /* F6 to F8 */
						default:
							bbs_debug(3, "Unhandled escape sequence: %d %d\n", c1, c2);
							break;
					}
					break;
				case 50:
					c3 = bbs_proper_tread(node, fd, 2);
					if (c3 <= 0) {
						return c3 < 0 ? c3 : KEY_IC; /* INSERT */
					}
					switch (c3) {
						case 48 ... 49:
							return KEY_F(9 + c3 - 48); /* F9 to F10 */
						/* Skip 50 */
						case 51 ... 52:
							return KEY_F(11 + c3 - 51); /* F11 to F12 */
						default:
							bbs_debug(3, "Unhandled escape sequence: %d %d\n", c1, c2);
							break;
					}
					break;
				case 51:
					return KEY_DC; /* DELETE */
				case 52:
					return KEY_END;
				case 53:
					return KEY_PPAGE; /* PG UP */
				case 54:
					return KEY_NPAGE; /* PG DOWN */
				case 65:
					return KEY_UP;
				case 66:
					return KEY_DOWN;
				case 67:
					return KEY_RIGHT;
				case 68:
					return KEY_LEFT;
				default:
					bbs_debug(3, "Unhandled escape sequence: %d %d\n", c1, c2);
					break;
			}
			break;
		default:
			bbs_debug(3, "Unhandled escape sequence: %d\n", c1);
			break;
	}
	return 0;
#undef bbs_proper_tread
}

int bbs_read_escseq(int fd)
{
	int res = __bbs_node_read_escseq(NULL, fd);
	if (res > 0) {
		bbs_debug(5, "Escape sequence converted to %d\n", res);
	}
	return res;
}

int bbs_node_read_escseq(struct bbs_node *node)
{
	int res = __bbs_node_read_escseq(node, -1);
	return res;
}

int bbs_node_read_line(struct bbs_node *node, int ms, char *buf, size_t len)
{
#ifdef DEBUG_TEXT_IO
	int i;
#endif
	int res;
	size_t left = len;
	int bytes_read = 0;
	char *startbuf = buf;
	char *term = NULL;
	char *nterm;
	int keep_trying = 0;

	REQUIRE_SLAVE_FD(node);

	/* Do not call bbs_node_buffer(node) here,
	 * calling functions should do that if needed.
	 * This allows to read with echo on or off (e.g. passwords),
	 * we don't know what's appropriate here. */

	if (!node->buffered) {
		bbs_warning("Node %d is not buffered when calling %s\n", node->id, __func__);
	}

	for (;;) {
		ssize_t bytes;
		if (keep_trying) {
			res = bbs_node_poll(node, 5);
			if (res == 0) {
				/* It's okay, we were just checking to see if there was more input,
				 * (remember we set ms to be very small)
				 * if there's not, proceed with what we got. */
				break;
			}
		} else {
			res = bbs_node_tpoll(node, ms);
		}
		if (res <= 0) {
			bbs_debug(10, "Node %d: poll returned %d\n", node->id, res);
			return res;
		}
		bytes = bbs_node_read(node, buf, len);
		if (bytes <= 0) {
			bbs_debug(10, "Node %d: read returned %ld\n", node->id, bytes);
			return (int) bytes;
		}
		nterm = memchr(buf, '\0', (size_t) bytes);
		/* Telnet may send CR NUL or CR LF, so check CR first, then LF.
		 * To make things even more confusing, Windows Telnet and SyncTERM seem to send LF LF.
		 * (Though it could be the PTY line discipline converting things that results in this)
		 * We want to be able to handle CR (NUL), CR LF, LF LF, and LF successfully.
		 * If we see either CR or LF, terminate the buffer there.
		 */

		/*! \todo BUGBUG Still lots of inconsistencies.
		 * On Windows Telnet and in SyncTERM, we get extra lines inbetween carriage returns.
		 * In PuTTY with Telnet, there are ^@'s at the beginning of lines after this function returns.
		 */
		if (!term) { /* In the case where we poll again for a few ms (below), this will be true, don't do this again. */
			term = memchr(buf, '\r', (size_t) bytes); /* There is no strnchr function. Use memchr. */
			if (!term) {
				term = memchr(buf, '\n', (size_t) bytes);
			}
		}
		buf += bytes;
		left -= (size_t) bytes;
		bytes_read += (int) bytes;
#ifdef DEBUG_TEXT_IO
		for (i = 0; i < bytes_read; i++) {
			bbs_debug(10, "read[%d] %d / '%c'\n", i, startbuf[i], isprint(startbuf[i]) ? startbuf[i] : ' ');
		}
#endif
		if (nterm || term || left <= 0) {
			/* Remove any line ending from input. */
			if (term) {
				*term = '\0';
			}
			if (!nterm && term) {
				/* Got a CR and/or LF from client, but no NUL.
				 * The NUL could be trailing and we might read it next time.
				 * Or maybe there won't be a NUL, certain client+protocols seem to send one, some don't.
				 * If we do get one, we should get the NUL before returning. If we're not going to get one,
				 * then it's probably no biggie.
				 * Poll again for a brief period of time (<5 ms) in case more input is going to be available shortly.
				 */
				keep_trying = 1;
				continue;
			}
			break;
		}
	}

	if (*startbuf == '\0') {
		/* This isn't an issue per se in and of itself,
		 * but probably an irregularity in reading input above. */
		bbs_debug(1, "First character received was NUL?\n"); /* XXX seems to happen if user just presses ENTER immediately */
	}

	bbs_debug(10, "Node %d: read(%d) %.*s\n", node->id, bytes_read, bytes_read, startbuf);
	if (!node->buffered) {
		bbs_warning("Node %d is not buffered when ending %s?\n", node->id, __func__); /* Not as bad if not buffered when starting, but strange... */
	}
	return bytes_read;
}

int bbs_get_response(struct bbs_node *node, int qlen, const char *q, int pollms, char *buf, int len, int *tries, int minlen, const char *reqchars)
{
	int res;
	int attempt = 1;
	const char *c;

	for (; *tries > 0; *tries -= 1, attempt++) { /* Retries here count less than retries of the main loop */
		if (attempt > 1) {
			bbs_debug(4, "Attempt #%d to get response for question\n", attempt);
		}
		if (qlen) {
			NONPOS_RETURN(bbs_node_writef(node, "%-*s", qlen, q));
		} else {
			NONPOS_RETURN(bbs_node_writef(node, "%s", q));
		}
		res = bbs_node_read_line(node, pollms, buf, (size_t) len);
		/* bbs_node_read_line returns the number of bytes read.
		 * However, in most cases, we'll want to subtract 1, because we null terminated the new line read as input.
		 * Therefore, we can approximate the strlen with res - 1 (so long as res > 0)
		 */
		if (res < 0) {
			return res;
		} else if (res == 0) {
			/* bbs_node_read_line uses bbs_node_tpoll, so if the tpoll times out (returns 0), then we must return,
			 * as we already printed out "You've been inactive too long" at this point. */
			return -1; /* -1, not 0, we're already due for disconnect. */
		} else if (strlen_zero(buf)) {
			NONPOS_RETURN(bbs_node_writef(node, "%sPlease try again.%s\n", COLOR(TERM_COLOR_RED), COLOR(TERM_COLOR_WHITE)));
			continue; /* Empty responses not allowed. Try again, eventually we'll hit max attempts */
		} if (res - 1 < minlen) {
			if (NODE_IS_TDD(node)) {
				NONPOS_RETURN(bbs_node_writef(node, "Inadequate, try again.\n"));
			} else {
				NONPOS_RETURN(bbs_node_writef(node, "%sInadequate response, please try again.%s\n", COLOR(TERM_COLOR_RED), COLOR(TERM_COLOR_WHITE)));
			}
			continue; /* Too short */
		} else if (res - 1 >= len) {
			if (NODE_IS_TDD(node)) {
				NONPOS_RETURN(bbs_node_writef(node, "Too long, try again.\n"));
			} else {
				NONPOS_RETURN(bbs_node_writef(node, "%sResponse is too long, please try again.%s\n", COLOR(TERM_COLOR_RED), COLOR(TERM_COLOR_WHITE)));
			}
			continue;
		} else if (!bbs_str_isprint(buf)) {
			/* Contains nonprintable characters. Reject. */
			if (NODE_IS_TDD(node)) {
				NONPOS_RETURN(bbs_node_writef(node, "Invalid, try again.\n"));
			} else {
				NONPOS_RETURN(bbs_node_writef(node, "%sResponse contains invalid characters, please try again.%s\n", COLOR(TERM_COLOR_RED), COLOR(TERM_COLOR_WHITE)));
			}
			continue;
		}
		if (reqchars) {
			for (c = reqchars; *c; c++) {
				if (!strchr(buf, *c)) {
					if (NODE_IS_TDD(node)) {
						NONPOS_RETURN(bbs_node_writef(node, "Inadequate, try again.\n"));
					} else {
						NONPOS_RETURN(bbs_node_writef(node, "%sInadequate response, please try again.%s\n", COLOR(TERM_COLOR_RED), COLOR(TERM_COLOR_WHITE)));
					}
					/* We're in a double loop, we want to continue the outer loop */
					goto continueloop; /* Missing required chars */
				}
			}
		}
		break;
continueloop:
		continue;
	}
	if (*tries <= 0) {
		bbs_debug(5, "Max attempts reached, disconnecting\n");
		return 1;
	}
	return 0;
}

#ifdef DEBUG_TEXT_IO
static void print_printable(char *s, int len)
{
	int i;

	for (i = 0; i < len; i++, s++) {
		char c = *s;
		if (c < 0) {
			c += 256;
		}
		if (isprint(c)) {
			bbs_debug(10, "STR[%d] => %d (%c)\n", i, c, c);
		} else {
			bbs_debug(10, "STR[%d] => %d\n", i, c);
		}
	}
}
#endif

int bbs_flush_input(int fd)
{
	char buf[64];
	int res;

	for (;;) {
		/* Poll and read again and again until poll says there's no input waiting. */
		res = bbs_poll(fd, 0);
		if (res <= 0) {
			break;
		}
		res = (int) read(fd, buf, sizeof(buf));
		if (res <= 0) {
			break;
		}
		bbs_debug(5, "Flushed %d bytes\n", res);
#ifdef DEBUG_TEXT_IO
		print_printable(buf, res);
#endif
	}
	return res;
}

int bbs_node_flush_input(struct bbs_node *node)
{
	char buf[64];
	int res;

	for (;;) {
		/* Poll and read again and again until poll says there's no input waiting. */
		res = bbs_node_poll(node, 0);
		if (res <= 0) {
			break;
		}
		res = (int) bbs_node_read(node, buf, sizeof(buf));
		if (res <= 0) {
			break;
		}
		bbs_debug(5, "Flushed %d byte%s\n", res, ESS(res));
#ifdef DEBUG_TEXT_IO
		print_printable(buf, res);
#endif
	}
	return res;
}

ssize_t bbs_timed_read(int fd, char *restrict buf, size_t len, int ms)
{
	ssize_t bytes = 0;

	for (;;) {
		ssize_t res = read(fd, buf, len);
		if (res <= 0) {
			return res;
		}
		bytes += res;
		buf += res;
		len -= (long unsigned) res;
		if (len <= 0) {
			bbs_debug(7, "Buffer (size %lu) is now full\n", len);
			return res;
		}
		if (bbs_poll(fd, ms) <= 0) {
			return res;
		}
	}
	__builtin_unreachable();
}

static ssize_t timed_write(struct pollfd *pfd, int fd, const char *restrict buf, size_t len, int ms)
{
	size_t left = len;
	ssize_t written = 0;

	if (bbs_assertion_failed(fd >= 0)) {
		/* Can possibly happen if a node's file descriptors are set to -1 while the node is still running.
		 * Any further write attempts would then be invalid.
		 * However, node writes should be guarded with REQUIRE_SLAVE_FD so we shouldn't be getting here... */
		return -1;
	}

	do {
		ssize_t res;

		/* Wait until the file descriptor becomes writable (again) */
		pfd->revents = 0;
		res = poll(pfd, 1, ms); /* Avoid tight loop */
		if (!res) {
			bbs_debug(2, "File descriptor %d did not become writable after %d ms\n", fd, ms);
			break;
		} else if (!(pfd->revents & POLLOUT)) {
			/* Got activity but fd is not writable.
			 * Probably a disconnect. */
			bbs_debug(2, "Exceptional activity (%s) while writing on fd %d\n", poll_revent_name(pfd->revents), fd);
			break;
		}
		res = write(fd, buf, left);
		if (res <= 0) {
			if (res == 0) {
				/* POSIX write never returns 0, unless the buffer length is 0, so this is suspect...
				 * If the buffer length was 0, shame on the application for trying to write 0 bytes.
				 * If it wasn't, then something has gone terribly wrong. */
				bbs_warning("write returned 0 (buffer length: %lu)\n", len);
				bbs_log_backtrace();
			}
			return res;
		}
		buf += res;
		written += res;
		left -= (size_t) res;
	} while (left > 0);
	return written;
}

static ssize_t full_write(struct pollfd *pfd, int fd, const char *restrict buf, size_t len)
{
	/* We could use a poll time of -1, in theory,
	 * to block "forever". However, we don't actually
	 * ever want to block "forever", just long enough
	 * as is reasonable, perhaps, for TCP buffers to drain, etc.
	 * If that doesn't happen in a reasonably timely manner,
	 * we're not making any progress at all,
	 * the remote side isn't responsive and
	 * we should just disconnect. */
	ssize_t bytes = timed_write(pfd, fd, buf, len, SEC_MS(60));
	if (bytes <= 0) {
		/* Applications should be checking this return value regularly
		 * to terminate node execution if needed.
		 * In this particular case, a return value of 0 is logically
		 * interpreted as a total failure and should result in disconnect. */
		if (errno) { /* Not all nonpos returns are errors. Don't log spurious error for non-error branches (e.g. Exceptional activity, not writable) */
			bbs_error("Failed to fully write %lu bytes to fd %d: %s\n", len, fd, strerror(errno));
		}
		return -1;
	}
	return bytes;
}

static int bbs_node_ansi_write(struct bbs_node *node, const char *restrict buf, size_t len)
{
	struct pollfd pfd;
	size_t left = len;
	size_t written = 0;
	char *sp;

	pfd.fd = node->slavefd;
	pfd.events = POLLOUT | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	REQUIRE_SLAVE_FD(node);
	/* So helgrind doesn't complain about data race if node is shut down
	 * and slavefd closed during write */
	bbs_node_io_lock(node);
	while (left > 0) {
		ssize_t res;
		size_t bytes;

#define MIN_SKIP_SPACES "    "
		/* The printf formatting arguments are often used for alignment by space padding.
		 * However, sending a large number of spaces over the wire is not efficient.
		 * We can use the "Cursor Forward" ANSI escape sequence for supporting terminals
		 * to speed this up.
		 * The escape sequence itself is going to be at least 4 characters,
		 * so if it's less than 4 characters, we may as well send individual spaces. */
		sp = memmem(buf, left, MIN_SKIP_SPACES, STRLEN(MIN_SKIP_SPACES));
		if (sp != buf) { /* Edge case: if we're starting with spaces, skip writing anything for now */
			/* Must be non-NULL (> 0x0) and not starting at the current position */
			bytes = sp > buf ? ((size_t) (sp - buf)) : left; /* If sp, then it must be within left, so no need for bounds check */
			bbs_assert(bytes <= node->cols); /* We wouldn't have called this function if this weren't true, so part of the buffer can't be larger */
			res = full_write(&pfd, node->slavefd, buf, bytes);
			if (res < 0) {
				bbs_debug(5, "Node %d: write (%lu bytes) returned %ld\n", node->id, bytes, res);
				bbs_node_io_unlock(node);
				return (int) res;
			}
			buf += res;
			written += (size_t) res;
			left -= (size_t) res;
		}

		if (sp) { /* Skip spaces */
			char esc_seq[15];
			size_t esc_len;
			int skipped = 4;
			/* We already know 4 spaces follow, no need to count those */
			buf += 4;
			written += 4;
			left -= 4;
			while (*buf == ' ' && left--) {
				buf++;
				written++;
				skipped++;
			}
			/* At least 4, so always send an escape sequence (must be at least 1 for that) */
			esc_len = (size_t) snprintf(esc_seq, sizeof(esc_seq), "\e[%dC", skipped);
			res = full_write(&pfd, node->slavefd, esc_seq, esc_len);
			if (res < 0) {
				bbs_debug(5, "Node %d: write returned %ld\n", node->id, res);
				bbs_node_io_unlock(node);
				return (int) res;
			}
			/* Already incremented to account for these spaces, don't add anything further */
		}
	}
	bbs_node_io_unlock(node);
	return (int) written;
}

#define DETECT_IMPROPER_NODE_WRITES

ssize_t bbs_node_write(struct bbs_node *node, const char *buf, size_t len)
{
	struct pollfd pfd;
	ssize_t res;

#ifdef DETECT_IMPROPER_NODE_WRITES
	if (node->thread != pthread_self()) {
		/* These kinds of writes are dangerous, because if any thread besides the node thread
		 * blocks writing to a node, then it's game over for the BBS due to our threading and I/O model.
		 * These writes should be using bbs_node_any_fd_write instead. */
		bbs_warning("Attempt to write to node %d by thread %lu\n", node->id, (unsigned long) pthread_self());
	}
#endif

	if (node->ansi && node->cols && len <= node->cols) {
		return bbs_node_ansi_write(node, buf, len);
	}

	pfd.fd = node->slavefd;
	pfd.events = POLLOUT | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	REQUIRE_SLAVE_FD(node);
	/* So helgrind doesn't complain about data race if node is shut down
	 * and slavefd closed during write */
	bbs_node_io_lock(node);
	res = full_write(&pfd, node->slavefd, buf, len);
	if (res <= 0 || res != (ssize_t) len) {
		bbs_debug(5, "Node %d: write returned %ld/%lu\n", node->id, res, len);
	}
	bbs_node_io_unlock(node);
	return res;
}

ssize_t bbs_write(int fd, const char *buf, size_t len)
{
	struct pollfd pfd;
	ssize_t res;

	pfd.fd = fd;
	pfd.events = POLLOUT | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	res = full_write(&pfd, fd, buf, len);
	if (res <= 0) {
		bbs_debug(5, "fd %d: write returned %ld: %s\n", fd, res, res ? strerror(errno) : "");
	}
	return res;
}

ssize_t bbs_timed_write(int fd, const char *buf, size_t len, int ms)
{
	struct pollfd pfd;
	ssize_t res;
	if (bbs_unblock_fd(fd)) {
		return -1;
	}

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLOUT | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	res = timed_write(&pfd, fd, buf, len, ms);
	if (res <= 0) {
		if (res == -1) {
			bbs_error("write(%d) failed (%ld): %s\n", fd, res, strerror(errno));
		}
	} else if (res != (ssize_t) len) {
		bbs_debug(1, "Wanted to write %lu bytes to fd %d, only wrote %ld\n", len, fd, res);
	}

	bbs_block_fd(fd); /* Restore */
	return res;
}

/* \note Assumes fd is a file descriptor corresponding to a file */
static off_t fd_get_filesize(int fd)
{
	off_t max_offset, cur_offset;

	cur_offset = lseek(fd, 0, SEEK_CUR);
	if (cur_offset == -1) {
		bbs_error("Failed to get current file position: %s\n", strerror(errno));
		return -1;
	}
	max_offset = lseek(fd, 0, SEEK_END);
	if (max_offset == -1) {
		bbs_error("Failed to seek to end of file: %s\n", strerror(errno));
		return -1;
	}
	lseek(fd, cur_offset, SEEK_SET); /* Restore original offset */
	return max_offset;
}

ssize_t bbs_sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
	/* sendfile (like write) can return before writing all the requested bytes.
	 * This wrapper function will retry as appropriate to fully write the message as best we can. */
	ssize_t written = 0;
	off_t localoffset = 0;
	struct pollfd pfd;

	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = out_fd;
	pfd.events = POLLOUT | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

	for (;;) {
#ifdef __linux__
		ssize_t res = sendfile(out_fd, in_fd, offset ? offset : &localoffset, count);
#elif defined(__FreeBSD__)
		ssize_t res = sendfile(out_fd, in_fd, offset ? *offset : localoffset, count, NULL, NULL, 0);
#else
#error "Missing sendfile"
#endif
		if (res < 0) {
			bbs_error("Failed to write %lu bytes, sendfile %d -> %d failed: %s\n", count, in_fd, out_fd, strerror(errno));
			return res;
		}
		written += res;
		if (res == (ssize_t) count) {
			break;
		}
		/* It's typical for sendfile to only send 8,192 bytes at a time,
		 * so for sending much more than that, this can be a very spammy message. */
		bbs_debug(10, "Wanted to write %lu bytes at offset %ld, but was only able to write %ld this round\n", count, offset ? *offset : localoffset, res); /* Keep trying */
		count -= (size_t) res;
		/* if offset is not NULL, then on Linux, sendfile automatically increments it
		 * by the number of sent bytes. */
#ifdef __FreeBSD__
		/* Also adjust the offset for sendfile */
		if (offset) {
			*offset += res;
		} else {
			localoffset += res;
		}
#endif
		if (!res) {
			int pres;
			/* Wasn't able to write any bytes this round.
			 * This means that either the file descriptor isn't writable right now,
			 * or the specified offset/byte count is not valid. */
			off_t eff_offset = offset ? *offset : localoffset;
			off_t size = fd_get_filesize(in_fd);
			if (size > 0 && eff_offset >= size) {
				/* Offset is at the end of the file or past it.
				 * This will never work. */
				bbs_error("Specified file offset (%ld) exceeds file size (%ld)\n", eff_offset, size);
				return -1;
			}
			bbs_debug(8, "Waiting for file descriptor %d to become writable\n", out_fd);
			pfd.revents = 0;
			pres = poll(&pfd, 1, SEC_MS(30));
			if (pres < 0) {
				if (errno != EINTR) {
					bbs_error("poll failed: %s\n", strerror(errno));
					return -1;
				}
			} else if (!pres) {
				/* Can't wait forever... */
				bbs_warning("File descriptor %d did not become writable after 30 seconds\n", out_fd);
				return -1;
			} else if (!(pfd.revents & POLLOUT)) {
				bbs_warning("Exceptional activity on file descriptor %d while waiting for it to become writable\n", out_fd);
				return -1;
			}
		}
	}

	return written;
}

ssize_t bbs_node_fd_write(struct bbs_node *node, int fd, const char *buf, size_t len)
{
	ssize_t res;

#ifdef DETECT_IMPROPER_NODE_WRITES
	if (node->thread != pthread_self()) {
		/* See comment in bbs_node_write */
		bbs_warning("Attempt to write to node %d by thread %lu\n", node->id, (unsigned long) pthread_self());
	}
#endif

	bbs_node_io_lock(node);
	res = bbs_write(fd, buf, len);
	bbs_node_io_unlock(node);

	return res;
}

ssize_t __attribute__ ((format (gnu_printf, 3, 4))) bbs_node_fd_writef(struct bbs_node *node, int fd, const char *fmt, ...)
{
	char *buf;
	int len;
	ssize_t res;
	va_list ap;

	if (!strchr(fmt, '%')) {
		return bbs_node_fd_write(node, fd, fmt, strlen(fmt));
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}

	res = bbs_node_fd_write(node, fd, buf, (size_t) len);
	free(buf);
	return res;
}

ssize_t __attribute__ ((format (gnu_printf, 3, 4))) bbs_auto_fd_writef(struct bbs_node *node, int fd, const char *fmt, ...)
{
	char *buf;
	int len;
	ssize_t res;
	va_list ap;

	if (!node && fd < 0) {
		/* e.g. mod_chanserv writes */
		bbs_debug(3, "Discarding write output (no node and no fd)\n");
		return 0;
	}

	if (!strchr(fmt, '%')) {
		return node ? bbs_node_fd_write(node, fd, fmt, strlen(fmt)) : bbs_write(fd, fmt, strlen(fmt));
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}

	res = node ? bbs_node_fd_write(node, fd, buf, (size_t) len) : bbs_write(fd, buf, (size_t) len);
	free(buf);
	return res;
}

ssize_t __attribute__ ((format (gnu_printf, 3, 4))) bbs_auto_any_fd_writef(struct bbs_node *node, int fd, const char *fmt, ...)
{
	char *buf;
	int len;
	ssize_t res;
	va_list ap;

	if (!node && fd < 0) {
		/* e.g. mod_chanserv writes */
		bbs_debug(3, "Discarding write output (no node and no fd)\n");
		return 0;
	}

	if (!strchr(fmt, '%')) {
		return node ? bbs_node_any_fd_write(node, fd, fmt, strlen(fmt)) : bbs_write(fd, fmt, strlen(fmt));
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}

	res = bbs_node_any_fd_write(node, fd, buf, (size_t) len);
	free(buf);
	return res;
}

ssize_t bbs_node_any_fd_write(struct bbs_node *node, int fd, const char *buf, size_t len)
{
	ssize_t res;

	/* In case the node thread is blocked on I/O,
	 * we do NOT try to lock the node in this function normally.
	 * Instead, we use trylock to avoid possible deadlocks. */

	if (bbs_node_dead(node)) {
		bbs_warning("Node %d is dead, skipping write\n", node->id);
		return -1;
	}

	if (node->thread == pthread_self()) {
		/* The caller could have used bbs_node_fd_write directly, but maybe it was iterating over a list of clients,
		 * in which case it would be convenient to just use this function for all of them, since it's more general. */
		bbs_node_io_lock(node);
	} else {
		int tries = 10;
		int lockres;
		/* Wait up to 100 ms to grab the lock */
		for (;;) {
			lockres = bbs_node_io_trylock(node);
			if (!lockres) { /* Success */
				break;
			}
			if (!--tries) {
				bbs_warning("Failed to lock node %d, write failed\n", node->id);
				return 0; /* I/O did not fail, we just did not get a chance to do any, so this is an accurate return value */
			}
			if (bbs_node_safe_sleep(node, 10)) { /* Avoid tight loop. Wait 10 ms, then try again */
				return -1;
			}
		}
	}

	/* Try to write the full data, but abort if we can't make progress */
	res = bbs_timed_write(fd, buf, len, SEC_MS(1));
	bbs_node_io_unlock(node);

	return res;
}

ssize_t __attribute__ ((format (gnu_printf, 3, 4))) bbs_node_any_fd_writef(struct bbs_node *node, int fd, const char *fmt, ...)
{
	char *buf;
	int len;
	ssize_t res;
	va_list ap;

	if (!strchr(fmt, '%')) {
		return bbs_node_any_fd_write(node, fd, fmt, strlen(fmt));
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}

	res = bbs_node_any_fd_write(node, fd, buf, (size_t) len);
	free(buf);
	return res;
}

/* Note: In case this gets forgotten about and somebody thinks that some of the bbs_node functions
 * can be easily refactored: it's not that simple, because bbs_node_write is NOT the same
 * as calling bbs_write with node->slavefd. In particular, the bbs_node I/O functions may
 * acquire node locks. The regular I/O functions do not do this.
 * For that reason, you can't simply have bbs_node_writef call bbs_writef under the hood, etc. */
ssize_t __attribute__ ((format (gnu_printf, 2, 3))) bbs_node_writef(struct bbs_node *node, const char *fmt, ...)
{
	char *buf;
	int len;
	ssize_t res;
	va_list ap;

	if (!strchr(fmt, '%')) {
		/* If the format string doesn't contain any %'s, there are no variadic arguments.
		 * Just write it directly, to avoid allocating memory unnecessarily. */
		return bbs_node_write(node, fmt, strlen(fmt));
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}

	res = bbs_node_write(node, buf, (size_t) len);
	free(buf);
	return res;
}

ssize_t __attribute__ ((format (gnu_printf, 2, 3))) bbs_writef(int fd, const char *fmt, ...)
{
	char *buf;
	int len;
	ssize_t res;
	va_list ap;

	if (!strchr(fmt, '%')) {
		/* If the format string doesn't contain any %'s, there are no variadic arguments.
		 * Just write it directly, to avoid allocating memory unnecessarily. */
		return bbs_write(fd, fmt, strlen(fmt));
	}

	va_start(ap, fmt);
	len = vasprintf(&buf, fmt, ap);
	va_end(ap);

	if (len < 0) {
		return -1;
	}

	res = bbs_write(fd, buf, (size_t) len);
	free(buf);
	return res;
}

int bbs_node_clear_screen(struct bbs_node *node)
{
	if (!node->ansi || !(node->ans & ANSI_CLEAR_SCREEN)) {
		return 0;
	}
	return bbs_node_write(node, TERM_CLEAR, STRLEN(TERM_CLEAR)) == STRLEN(TERM_CLEAR) ? 0 : -1;
}

int bbs_node_clear_line(struct bbs_node *node)
{
	if (!node->ansi || !(node->ans & ANSI_CLEAR_LINE)) {
		return 0;
	}
	return bbs_node_write(node, TERM_RESET_LINE, STRLEN(TERM_RESET_LINE)) == STRLEN(TERM_RESET_LINE) ? 0 : -1;
}

int bbs_node_set_pos(struct bbs_node *node, int row, int col)
{
	if (!node->ansi || !(node->ans & ANSI_CURSOR_SET)) {
		return 0;
	}
	return bbs_node_writef(node, TERM_CURSOR_POS_SET_FMT, row, col) < 0 ? -1 : 0;
}

int bbs_node_up_one_line(struct bbs_node *node)
{
	if (!node->ansi) {
		return 0;
	}
	if (node->ans & ANSI_UP_ONE_LINE) {
		return bbs_node_write(node, TERM_UP_ONE_LINE, STRLEN(TERM_UP_ONE_LINE)) == STRLEN(TERM_UP_ONE_LINE) ? 0 : -1;
	}
	/* Some terminals, like NetRunner, don't support this.
	 * However, we can still emulate this by setting the cursor explicitly. */
	if ((node->ans & ANSI_CURSOR_SET) && (node->ans & ANSI_CURSOR_QUERY)) {
		int row, col;
		node_get_cursor_pos(node, &row, &col);
		if (row > 1) {
			row--;
		}
		return bbs_node_set_pos(node, row, col);
	}
	bbs_warning("Unable to move terminal up one line (terminal does not support relevant ANSI escape sequences)\n");
	return 0; /* Don't return -1, or that could be interpreted as a node disconnect */
}

int bbs_node_set_term_title(struct bbs_node *node, const char *s)
{
	if (!node->ansi || !(node->ans & ANSI_TERM_TITLE)) {
		return 0;
	}
	return bbs_node_writef(node, TERM_TITLE_FMT, s) <= 0 ? -1 : 0; /* for xterm, screen, etc. */
}

int bbs_node_restore_term_title(struct bbs_node *node)
{
	if (!node->ansi || !(node->ans & ANSI_TERM_TITLE)) {
		return 0;
	}
	return bbs_node_write(node, TERM_TITLE_RESTORE_FMT, STRLEN(TERM_TITLE_RESTORE_FMT)) == STRLEN(TERM_RESET_LINE) ? 0 : -1; /* for xterm, screen, etc. */
}

int bbs_node_set_term_icon(struct bbs_node *node, const char *s)
{
	if (!node->ansi || !(node->ans & ANSI_TERM_TITLE)) {
		return 0;
	}
	return bbs_node_writef(node, TERM_ICON_FMT, s) <= 0 ? -1 : 0;
}

int bbs_node_reset_color(struct bbs_node *node)
{
	if (!node->ansi || !(node->ans & ANSI_COLORS)) {
		return 0;
	}
	return bbs_node_write(node, COLOR_RESET, STRLEN(COLOR_RESET)) == STRLEN(COLOR_RESET) ? 0 : -1;
}

int bbs_node_draw_line(struct bbs_node *node, char c)
{
	unsigned int i, cols = node->cols ? node->cols : 80; /* Assume 80x24 if not available */
	char buf[384]; /* Avoid cols + 2 for gcc -Wstack-protector */

	if (cols + 2 >= (int) (sizeof(buf) - 1)) {
		bbs_warning("Truncation occured of line for node with %d cols\n", node->cols);
		/* Not fatal */
	}

	for (i = 0; i < cols; i++) {
		buf[i] = c;
	}
	buf[i++] = '\n'; /* New line */
	buf[i] = '\0';
	/* Write all at once */
	return bbs_node_write(node, buf, cols + 1) == cols + 1 ? 0 : -1; /* No need to actually write the NUL, just through the LF */
}

int bbs_node_ring_bell(struct bbs_node *node)
{
	if (!node->ansi) {
		return 0;
	}
	/* This function should be sparingly used. Users are annoyed if the bell goes off all the time.
	 * So log every time it's used. */
	bbs_debug(7, "Ringing bell for node %d\n", node->id);
	return bbs_node_write(node, TERM_BELL, STRLEN(TERM_BELL)) == STRLEN(TERM_BELL) ? 0 : -1;
}

#define HIT_KEY_PROMPT_LONG "Hit a key, any key..."
#define HIT_KEY_PROMPT_SHORT "Hit key:"

int bbs_node_wait_key(struct bbs_node *node, int ms)
{
	bbs_debug(6, "Waiting %d ms for any input\n", ms);
	NEG_RETURN(bbs_node_unbuffer(node));
	NEG_RETURN(bbs_node_flush_input(node)); /* Discard anything that may be pending so bbs_node_tpoll doesn't return immediately. */
	if (!NODE_IS_TDD(node)) {
		NEG_RETURN(bbs_node_writef(node, "\r\n%s%s%s", COLOR(TERM_COLOR_RED), "[" HIT_KEY_PROMPT_LONG "]", COLOR_RESET));
	} else {
		NEG_RETURN(bbs_node_writef(node, "\r\n%s", "[" HIT_KEY_PROMPT_SHORT "]"));
	}

	/* Wait up to ms for any key, doesn't matter what key so discard input if/when received. */
	if (bbs_node_tpoll(node, ms) <= 0 || bbs_node_flush_input(node) < 0) {
		return -1;
	}
	return 0;
}
