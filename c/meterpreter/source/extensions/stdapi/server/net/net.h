#ifndef _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_NET_NET_H
#define _METERPRETER_SOURCE_EXTENSION_STDAPI_STDAPI_SERVER_NET_NET_H

/*
 * Generic socket context
 */
typedef struct _SocketContext
{
	Remote   *remote;
	Channel  *channel;
	WSAEVENT notify;
	SOCKET   fd;
	BOOL     ipv6;
} SocketContext;

/*
 * UDP socket context (localhost/localport and peerhost/peerport are optional)
 */
typedef struct _UdpSocketContext
{
	SocketContext sock;
	short localport;
	IN_ADDR localhost;
	short peerport;
	IN_ADDR peerhost;
} UdpSocketContext;

typedef SocketContext		TcpClientContext;
typedef SocketContext		TcpServerContext;
typedef UdpSocketContext	UdpClientContext;

#define free_tcp_client_context(x) free_socket_context((SocketContext *)x)
#define free_udp_client_context(x) free_socket_context((SocketContext *)x)

/*
 * Request handlers
 */
DWORD request_net_tcp_client_channel_open(Remote *remote, Packet *packet);
DWORD request_net_tcp_server_channel_open(Remote *remote, Packet *packet);
DWORD request_net_udp_channel_open(Remote *remote, Packet *packet);

// Resolve
DWORD request_resolve_host(Remote *remote, Packet *packet);
DWORD request_resolve_hosts(Remote *remote, Packet *packet);

// Config
DWORD request_net_config_get_routes(Remote *remote, Packet *packet);
DWORD request_net_config_add_route(Remote *remote, Packet *packet);
DWORD request_net_config_remove_route(Remote *remote, Packet *packet);

DWORD request_net_config_get_interfaces(Remote *remote, Packet *packet);

DWORD request_net_config_get_arp_table(Remote *remote, Packet *packet);

DWORD request_net_config_get_netstat(Remote *remote, Packet *packet);

DWORD request_net_config_get_proxy_config(Remote *remote, Packet *packet);

// Socket
DWORD request_net_socket_tcp_shutdown(Remote *remote, Packet *packet);

/*
 * Channel creation
 */
DWORD create_tcp_client_channel(Remote *remote, LPCSTR host,USHORT port, Channel **outChannel);

VOID free_socket_context(SocketContext *ctx);

#endif
