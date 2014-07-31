/*!
 * @file unix_socket_server.h
 * @brief Declarations for functions which provide a unix domain socket server.
 */
#include "common.h"

/*! Default timeout (seconds) to apply when waiting for a new connection. */
#define DEFAULT_TIMEOUT 5

/*! @brief Container struct for a connection handled by the server. */
typedef struct {
	SOCKET socket;             ///< Connection socket.
	struct sockaddr_un remote; ///< Address of the connection. 
} connection_un; 

/*! @brief Container struct for a unix domain socket server */
typedef struct {
	struct sockaddr_un local; ///< Address of the server.
	connection_un client;     ///< Connection handled by the server.
	fd_set set;               ///< Set of file descriptors to monitor when accepting new connections.
	struct timeval timeout;   ///< Timeout to apply when waitinf for a new connection.
	SOCKET socket;	          ///< Server socket.
} server_un;

LONG start_server(server_un *s, LPSTR sock_path);
LONG accept_connection(server_un *s, DWORD timeout);
LONG close_connection(connection_un *c);
LONG stop_server(server_un *s);
LONG send_socket(connection_un *c, HANDLE fd);
