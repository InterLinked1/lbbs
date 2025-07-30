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
 * \brief File descriptor leak wrapper
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 *
 * \note Do not include this header file directly anywhere, it is already included in bbs.h
 */

void bbs_fd_shutdown(void);
int bbs_fd_init(void);

#if defined(DEBUG_FD_LEAKS) && DEBUG_FD_LEAKS == 1
#define	open(a,...)	__bbs_open(__FILE__,__LINE__,__func__, a, __VA_ARGS__)
#define pipe(a)		__bbs_pipe(a, __FILE__,__LINE__,__func__)
#define socketpair(a,b,c,d)	__bbs_socketpair(a, b, c, d, __FILE__,__LINE__,__func__)
#define socket(a,b,c)	__bbs_socket(a, b, c, __FILE__,__LINE__,__func__)
#define accept(a,b,c)	__bbs_accept(a, b, c, __FILE__,__LINE__,__func__)
#define close(a)	__bbs_close(a, __FILE__,__LINE__,__func__)
#define	fopen(a,b)	__bbs_fopen(a, b, __FILE__,__LINE__,__func__)
#define	fclose(a)	__bbs_fclose(a, __FILE__,__LINE__,__func__)
#define	dup2(a,b)	__bbs_dup2(a, b, __FILE__,__LINE__,__func__)
#define dup(a)		__bbs_dup(a, __FILE__,__LINE__,__func__)
#define eventfd(a,b)	__bbs_eventfd(a, b, __FILE__,__LINE__,__func__)

int bbs_std_close(int fd);
FILE *bbs_std_fopen(const char *path, const char *mode);
int bbs_std_fclose(FILE *ptr);

/*! \brief Manually indicate that a file descriptor is open. */
#define bbs_mark_opened(f) __bbs_mark_opened(f, __FILE__,__LINE__,__func__)

/*!
 * \brief Mark a file descriptor as closed. This is useful if
 * a file descriptor was opened by the BBS and closed by another library,
 * so we can keep the internal state table of file descriptors synchronized.
 * This function takes you at your word, so be sure it really is closed!
 * \param fd File descriptor
 * \retval 0 on success, 1 if fd was open at the time of this function call
 */
#define bbs_mark_closed(f) __bbs_mark_closed(f, __FILE__,__LINE__,__func__)

int __bbs_open(const char *file, int line, const char *func, const char *path, int flags, ...);
int __bbs_pipe(int *fds, const char *file, int line, const char *func);
int __bbs_socketpair(int domain, int type, int protocol, int sv[2], const char *file, int line, const char *func);
int __bbs_socket(int domain, int type, int protocol, const char *file, int line, const char *func);
int __bbs_accept(int socket, struct sockaddr *address, socklen_t *address_len, const char *file, int line, const char *func);
int __bbs_eventfd(unsigned int initval, int flags, const char *file, int line, const char *func);
int __bbs_close(int fd, const char *file, int line, const char *func);
int __bbs_mark_opened(int fd, const char *file, int line, const char *func);
int __bbs_mark_closed(int fd, const char *file, int line, const char *func);
FILE *__bbs_fopen(const char *path, const char *mode, const char *file, int line, const char *func);
int __bbs_fclose(FILE *ptr, const char *file, int line, const char *func);
int __bbs_dup2(int oldfd, int newfd, const char *file, int line, const char *func);
int __bbs_dup(int oldfd, const char *file, int line, const char *func);
#else
#define bbs_std_close(fd) close(fd)
#define bbs_std_fopen(path, mode) fopen(path, mode)
#define bbs_std_fclose(fp) fclose(fp)
#define bbs_mark_opened(f)
#define bbs_mark_closed(f)
#endif /* DEBUG_FD_LEAKS */
