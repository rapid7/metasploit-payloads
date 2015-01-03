/*!
 * @file passfd_server.c
 * @brief Definitions for functions which allow to share a file descriptor.
 */
#include "passfd_server.h"
#include "unix_socket_server.h"

/*!
 * @brief Shares a \c SOCKET through an unix local domain socket.
 * @details Shares a \c SOCKET between processes in the same machine. A local 
 *          domain socket is used to share the file descriptor. This function 
 *          setups a local domain socket socket, listens for a new connection, 
 *          sends the \c SOCKET after getting it and finally stops.
 * @param orig_fd \c SOCKET to share.
 * @param sock_path File path for the local domain socket.
 * @returns Indication of success or failure.
 * @retval 0 Indicates success.
 */
LONG
passfd(SOCKET orig_fd, LPSTR sock_path) {
	server_un s;
	LONG result = 0;

	result = start_server(&s, sock_path);
	if (result != 0) {
		dprintf("[PASSFD] Starting server failed");
		return result;
	}	

	result = accept_connection(&s, 5);
	if (result != 0) {
		goto stop;
	}

	result = send_socket(&(s.client), orig_fd);
	if (result != 0) {
		goto stop;
	}

stop:
	stop_server(&s);	
	return result;
}

