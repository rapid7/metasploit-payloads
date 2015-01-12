/*!
 * @file unix_socket_server.c
 * @brief Definitions for functions which provide an unix domain socket server.
 * @details An implementation of an unix domain socket for local communications.
 *          Useful to communicate data between processes. It is used while in
 *          meterpreter migration to share the socket between the old and new
 *          host process.
 */
#include "unix_socket_server.h"

/*!
 * @brief Creates an unix local domain socket and listens on it.
 * @param s Pointer to the \c server_un to start.
 * @param sock_path File path for the local domain socket.
 * @returns Indication of success or failure.
 * @retval 0 Indicates success.
 */
LONG
start_server(server_un *s, LPSTR sock_path) {
	LONG flags;

	if ((sock_path == NULL) || (s == NULL))
		return ERROR_INVALID_PARAMETER;

	s->timeout.tv_sec = DEFAULT_TIMEOUT; // Default timeout
	s->timeout.tv_usec = 0;

	dprintf("[UNIX SOCKET SERVER] Setting up the server");
	if ((s->socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		dprintf("[UNIX SOCKET SERVER] socket failed");
		return errno;
	}

	// Set up non blocking mode
	// http://stackoverflow.com/questions/3444729/using-accept-and-select-at-the-same-time
	FD_ZERO(&(s->set));
	FD_SET(s->socket, &(s->set));
	flags = fcntl(s->socket, F_GETFL, 0);
	fcntl(s->socket, F_SETFL, flags | O_NONBLOCK);

	s->local.sun_family = AF_UNIX;

	memset(s->local.sun_path, 0, UNIX_PATH_MAX);
	strncpy(s->local.sun_path, sock_path, UNIX_PATH_MAX - 1);
	unlink(s->local.sun_path);

	if (bind(s->socket, (struct sockaddr *)&(s->local), sizeof(struct sockaddr_un)) == -1) {
		dprintf("[UNIX SOCKET SERVER] bind failed");
		return errno;
	}

	if (listen(s->socket, 1) == -1) {
		dprintf("[UNIX SOCKET SERVER] listen failed");
		return errno;
	}

	return 0;
}

/*!
 * @brief Accepts a new connection.
 * @param s Pointer to the \c server_un listening.
 * @param timeout Time, in seconds, to wait for a new connection (default = 5).
 * @returns Indication of success or failure.
 * @retval 0 Indicates success.
 */
LONG
accept_connection(server_un *s, DWORD timeout) {
	connection_un *c;
	LONG rv;
	int len;

	if (s == NULL) {
		dprintf("[UNIX SOCKET SERVER] NULL server");
		return ERROR_INVALID_PARAMETER;
	}

	c = &(s->client);

	if (c == NULL) {
		dprintf("[UNIX SOCKET SERVER] NULL server");
		return ERROR_INVALID_PARAMETER;
	}

	if (timeout != -1) {
		s->timeout.tv_sec = timeout;
	}

	dprintf("[UNIX SOCKET SERVER] Waiting for a new connection");
	rv = select(s->socket + 1, &(s->set), NULL, NULL, &(s->timeout));

	if(rv == -1) {
		dprintf("[UNIX SOCKET SERVER] select failed");
		return errno;
	} else if (rv == 0) {
		dprintf("[UNIX SOCKET SERVER] timeout");
		return ETIME;
	}

	len = sizeof(struct sockaddr_un);
	if ((c->socket = accept(s->socket, (struct sockaddr *)&(c->remote), &len)) == -1) {
		dprintf("[UNIX SOCKET SERVER] accept failed");
		return errno;
	}

	return 0;
}

/*!
 * @brief Close an existent connection.
 * @param c Pointer to the \c connection_un to close.
 * @returns Indication of success or failure.
 * @retval 0 Indicates success.
 */
LONG
close_connection(connection_un *c) {
	if (c == NULL) {
		dprintf("[UNIX SOCKET SERVER] NULL connection");
		return ERROR_INVALID_PARAMETER;
	}

	if (close(c->socket) == -1){
		dprintf("[UNIX SOCKET SERVER] Close connection failed");
		return errno;
	}

	return 0;
}

/*!
 * @brief Stops a listening server.
 * @param c Pointer to the \c server_un to stop.
 * @returns Indication of success or failure.
 * @retval 0 Indicates success.
 */
LONG
stop_server(server_un *s) {
	if (s == NULL) {
		dprintf("[UNIX SOCKET SERVER] NULL server");
		return ERROR_INVALID_PARAMETER;
	}

	close_connection(&(s->client));
	close(s->socket);
	unlink(s->local.sun_path);

	return 0;
}

/*!
 * @brief Sends a files descriptor over an existing connection.
 * @param c Pointer to the \c connection_un to send the socket.
 * @param fd file descriptor to send.
 * @returns Indication of success or failure.
 * @retval 0 Indicates success.
 */
LONG
send_socket(connection_un *c, HANDLE fd) {
	struct iovec vector;
	struct msghdr msg;
	struct cmsghdr * cmsg;

	dprintf("[UNIX SOCKET SERVER] Building message for socket sharing...");
	vector.iov_base = "METERPRETER";
	vector.iov_len = strlen("METERPRETER") + 1;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vector;
	msg.msg_iovlen = 1;

	cmsg = alloca(sizeof(struct cmsghdr) + sizeof(fd));
	cmsg->cmsg_len = sizeof(struct cmsghdr) + sizeof(fd);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;

	memcpy(CMSG_DATA(cmsg), &fd, sizeof(fd));

	msg.msg_control = cmsg;
	msg.msg_controllen = cmsg->cmsg_len;

	if (sendmsg(c->socket, &msg, 0) != vector.iov_len) {
		dprintf("[UNIX SOCKET SERVER] sendmsg failed");
		return errno;
	}

	return 0;
}
