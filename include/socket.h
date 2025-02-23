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
 * \brief Socket functions
 *
 * \author Naveen Albert <bbs@phreaknet.org>
 */

/*!
 * \brief Create a UNIX domain socket
 * \param sock Pointer to socket
 * \param sockfile Socket file path
 * \param perm Permissions for socket
 * \param uid User ID. -1 to not change.
 * \param gid Group ID. -1 to not change.
 * \retval 0 on success, -1 on failure
 */
#define bbs_make_unix_socket(sock, sockfile, perm, uid, gid) __bbs_make_unix_socket(sock, sockfile, perm, uid, gid, __FILE__, __LINE__, __func__)

int __bbs_make_unix_socket(int *sock, const char *sockfile, const char *perm, uid_t uid, gid_t gid, const char *file, int line, const char *func);

/*!
 * \brief Create and bind a TCP socket to a particular port
 * \param[out] sock Pointer to socket
 * \param port Port number on which to create the socket
 * \retval 0 on success, -1 on failure
 */
#define bbs_make_tcp_socket(sock, port) __bbs_make_tcp_socket(sock, port, __FILE__, __LINE__, __func__)

int __bbs_make_tcp_socket(int *sock, int port, const char *file, int line, const char *func);

/*!
 * \brief Create and bind a UDP socket to a particular port
 * \param[out] sock Pointer to socket
 * \param port Port number on which to create the socket
 * \param ip Specific IP/CIDR to which to bind, or NULL for all
 * \param interface Specific interface to which to bind, or NULL for all
 * \retval 0 on success, -1 on failure
 */
#define bbs_make_udp_socket(sock, port, ip, interface) __bbs_make_udp_socket(sock, port, ip, interface, __FILE__, __LINE__, __func__)

int __bbs_make_udp_socket(int *sock, int port, const char *ip, const char *interface, const char *file, int line, const char *func);

/*! \brief Put a socket in nonblocking mode */
int bbs_unblock_fd(int fd);

/*! \brief Put a socket in blocking mode */
int bbs_block_fd(int fd);

/*!
 * \brief Cork or uncork a node's TCP session
 * \param node
 * \param enabled 1 to buffer data in the kernel until full packets are available to send, 0 to disable
 * \note If enabled, this MUST be disabled at some point to ensure pending data is fully written!
 * \note You should not use this function unless no better alternative is available, use with caution!
 * \retval 0 on success, -1 on failure
 */
int bbs_node_cork(struct bbs_node *node, int enabled);

/*!
 * \brief Enable or disable Nagle's algorithm
 * \param fd
 * \param enabled 1 to disable Nagle's algorithm, 0 to enable
 * \retval 0 on success, -1 on failure
 */
int bbs_set_fd_tcp_nodelay(int fd, int enabled);

/*!
 * \brief Set the TCP pacing rate
 * \param fd
 * \param rate Rate, in bytes per second
 * \retval 0 on success, -1 on failure
 */
int bbs_set_fd_tcp_pacing_rate(int fd, int rate);

/*!
 * \brief Suspend I/O until pending output data for a node has been sent
 * \param node Node
 * \retval 0 on success
 * \retval -1 on failure
 */
int bbs_node_wait_until_output_sent(struct bbs_node *node);

/*!
 * \brief Check whether a given hostname has an A record for a particular IP address
 * \param hostname Hostname to check
 * \param ip IP address for which to check
 * \retval 1 if there is a match, 0 if there are no matches
 */
int bbs_hostname_has_ip(const char *hostname, const char *ip);

/*!
 * \brief Resolve a hostname to an IP address
 * \param hostname Hostname or IP address
 * \param[out] buf IP address
 * \param[out] len Size of buf.
 * \retval -1 on failure, 0 on success
 */
int bbs_resolve_hostname(const char *hostname, char *buf, size_t len);

/*!
 * \brief Open a TCP socket to another server
 * \param hostname DNS hostname of server
 * \param port Destination port number
 * \retval -1 on failure, socket file descriptor otherwise
 * \note This does not perform TLS negotiation, use ssl_client_new immediately or later in the session for encryption.
 */
#define bbs_tcp_connect(hostname, port) __bbs_tcp_connect(hostname, port, __FILE__, __LINE__, __func__)

int __bbs_tcp_connect(const char *hostname, int port, const char *file, int line, const char *func);

/*!
 * \brief Wrapper around accept(), with poll timeout
 * \param socket Socket fd
 * \param ms poll time in ms
 * \param ip Optional IP restriction. NULL to allow any IP address.
 * \retval -1 on failure, socket file descriptor otherwise
 */
int bbs_timed_accept(int socket, int ms, const char *ip);

/*!
 * \brief Cleanly shutdown and close a socket
 * \param socket Pointer to socket fd
 */
void bbs_socket_close(int *socket);

/*!
 * \brief Cleanly shutdown and close a socket and an associated listening thread
 * \param socket Pointer to socket fd
 * \param thread
 */
void bbs_socket_thread_shutdown(int *socket, pthread_t thread);

/*!
 * \brief Check whether a socket has been closed by the remote peer, without reading from it
 * \param fd
 * \retval 1 if closed, 0 if no activity
 */
int bbs_socket_pending_shutdown(int fd);

/*!
 * \brief Listen on a TCP socket
 * \param port TCP port number
 * \param name Name of network service
 * \param handler Handler to execute to handle nodes spawned by this listener
 * \retval 0 on success, -1 on failure
 */
#define bbs_start_tcp_listener(port, name, handler) __bbs_start_tcp_listener(port, name, handler, BBS_MODULE_SELF)

int __bbs_start_tcp_listener(int port, const char *name, void *(*handler)(void *varg), void *module);

/*! \brief Same as bbs_start_tcp_listener but, like bbs_tcp_listener3, for multiple TCP listeners at once */
#define bbs_start_tcp_listener3(port, port2, port3, name, name2, name3, handler) __bbs_start_tcp_listener3(port, port2, port3, name, name2, name3, handler, BBS_MODULE_SELF)

int __bbs_start_tcp_listener3(int port, int port2, int port3, const char *name, const char *name2, const char *name3, void *(*handler)(void *varg), void *module);

/*!
 * \brief Stop a TCP listener registered previously using bbs_start_tcp_listener
 * \param port TCP port number
 * \retval 0 on success, -1 on failure
 * \note This does not close the socket
 */
int bbs_stop_tcp_listener(int port);

/*!
 * \brief Run a terminal services TCP network login service listener thread
 * \param socket Socket fd
 * \param name Name of network login service, e.g. Telnet, RLogin, etc.
 * \param handshake Handshake callback function. It should return 0 to proceed and -1 to abort.
 * \param module Module reference
 */
void bbs_tcp_comm_listener(int socket, const char *name, int (*handshake)(struct bbs_node *node), void *module);

/*!
 * \brief Run a generic TCP network login service listener thread
 * \param socket Socket fd
 * \param name Name of network login service, e.g. Telnet, RLogin, etc.
 * \param handler Service handler function
 * \param module Module reference
 */
void bbs_tcp_listener(int socket, const char *name, void *(*handler)(void *varg), void *module);

/*!
 * \brief Run a generic TCP network login service listener thread for up to 2 sockets
 * \param socket Socket fd (typically the insecure socket). -1 if not needed.
 * \param socket2 Optional 2nd fd (typically the secure socket). -1 if not needed.
 * \param name Name of network login service corresponding to socket
 * \param name2 Name of network login service corresponding to socket2
 * \param handler Common service handler function (for both sockets)
 * \param module Module reference
 */
void bbs_tcp_listener2(int socket, int socket2, const char *name, const char *name2, void *(*handler)(void *varg), void *module);

/*!
 * \brief Run a generic TCP network login service listener thread for up to 3 sockets
 * \param socket Socket fd (typically the insecure socket). -1 if not needed.
 * \param socket2 Optional 2nd fd (typically the secure socket). -1 if not needed.
 * \param socket3 Optional 3rd fd. -1 if not needed.
 * \param name Name of network login service corresponding to socket
 * \param name2 Name of network login service corresponding to socket2
 * \param name3 Name of network login service corresponding to socket3
 * \param handler Common service handler function (for all sockets)
 * \param module Module reference
 */
void bbs_tcp_listener3(int socket, int socket2, int socket3, const char *name, const char *name2, const char *name3, void *(*handler)(void *varg), void *module);

/*!
 * \brief Get local IP address of the BBS itself, i.e. the IP address to which a connection was established
 * \param node Node to fetch the IP address associated with the interface being used by this node, NULL to get the default one.
 * \param[out] buf
 * \param len
 * \retval 0 on success, -1 on failure
 */
int bbs_get_local_ip(struct bbs_node *node, char *buf, size_t len);

/*!
 * \brief Get the hostname of an IP address
 * \param ip IP address
 * \param[out] buf
 * \param len Size of buf
 * \retval 0 on success, -1 on failure
 * \note If no hostname is determinable, the IP address may be returned and this will count as success.
 */
int bbs_get_hostname(const char *ip, char *buf, size_t len);

/*!
 * \brief Get remote IP address
 * \param sinaddr
 * \param buf
 * \param len
 * \retval 0 on success, -1 on failure
 */
int bbs_get_remote_ip(struct sockaddr_in *sinaddr, char *buf, size_t len);

/*!
 * \brief Get remote IP address, from a file descriptor
 * \param fd
 * \param[out] buf
 * \param len
 * \retval 0 on success, -1 on failure
*/
int bbs_get_fd_ip(int fd, char *buf, size_t len);

/*!
 * \brief Save remote IP address
 * \param sinaddr
 * \param node
 * \retval 0 on success, -1 on failure
 */
int bbs_save_remote_ip(struct sockaddr_in *sinaddr, struct bbs_node *node);

/*! \brief Check whether a hostname is an IPv4 address */
int bbs_hostname_is_ipv4(const char *hostname);

/*!
 * \brief Whether an IP address is a loopback address
 * \param ip String representation of IPv4 address
 * \retval 0 on error or if not a loopback IP address
 * \retval nonzero if loopback address
 */
int bbs_is_loopback_ipv4(const char *ip);

/*!
 * \brief Whether an IP address is a private IPv4 address (in an RFC 1918 range) or a loopback address
 * \param ip String representation of IPv4 address
 * \retval 0 on error or if not a nonpublic IP address
 * \retval nonzero if private IPv4 address or loopback address
 * \note This is similar to bbs_ip_is_private_ipv4, except it is broader because it includes the loopback address
 */
int bbs_ip_is_nonpublic_ipv4(const char *ip);

/*!
 * \brief Whether an IP address is a public IPv4 address (not a private or loopback IPv4 address)
 */
#define bbs_ip_is_public_ipv4(ip) (!bbs_ip_is_nonpublic_ipv4(ip))

/*!
 * \brief Whether an IP address is a private IPv4 address (in an RFC 1918 range)
 * \param ip String representation of IPv4 address
 * \retval 0 on error or if not a private IP address
 * \return 'A' if a Class A private address
 * \return 'B' if a Class B private address
 * \return 'C' if a Class C private address
 */
int bbs_ip_is_private_ipv4(const char *ip);

/*!
 * \brief Whether an IP address or hostname is a private or loopback IP address (in an RFC 1918 range)
 * \param hostname IP address or hostname to check
 * \retval 0 on error or if not in private range or loopback address
 * \return 1 if private or loopback address
 * \note This function is similar to bbs_ip_is_nonpublic_ipv4, except it allows for hostnames or IP addresses as input, instead of just IPs
 * \note This function does not currently support IPv6, but could be extended to later
 */
int bbs_address_nonpublic(const char *hostname);

/*!
 * \brief Check if an IP address is within a specified CIDR range
 * \param ip IP address to check, e.g. 192.168.1.1
 * \param cidr CIDR range, e.g. 192.168.1.1/24
 * \retval 1 if in range, 0 if error or not in range
 */
int bbs_cidr_match_ipv4(const char *ip, const char *cidr);

/*!
 * \brief Check if an IP address matches an IP address, CIDR range, or hostname
 * \param ip IP address to check, e.g. 192.168.1.1
 * \param s IPv4 address, IPv4 CIDR range, or hostname (not recommended, since it will only match one of the returned IPs, if multiple)
 * \retval 1 if IP address matches, 0 if not
 */
int bbs_ip_match_ipv4(const char *ip, const char *s);

/*! \brief Get the name of a poll revent */
const char *poll_revent_name(int revents);
