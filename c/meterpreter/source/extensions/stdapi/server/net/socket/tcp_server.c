/*!
 * @file tcp_server.c
 * @brief
 */
#include "precomp.h"
#include "common_metapi.h"
#include "tcp.h"

#include <ws2tcpip.h>

// These fields aren't defined unless the SDK version is set to something old enough.
// So we define them here instead of dancing with SDK versions, allowing us to move on
// and still support older versions of Windows.
#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6 41
#endif

#if !defined(in6addr_any) && !defined(__MINGW32__)
extern IN6_ADDR in6addr_any;
#endif

/*!
 * @brief Get the address family.
 * @param address The address.
 * @returns Returns the address family.
 * @retval AF_INET, AF_INET6, AF_UNSPEC
 */
static int get_ai_family(const char* address) {
	struct addrinfo* resolved_host = NULL;
	static struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_flags = AI_NUMERICHOST
	};

	int ai_family = AF_UNSPEC;
	if (getaddrinfo(address, NULL, &hints, &resolved_host) == 0) {
		ai_family = resolved_host->ai_family;
		freeaddrinfo(resolved_host);
	}
	return ai_family;
}

// @brief see https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-inet_pton
static int inet_pton(int af, const char* src, void* dst) {
	errno_t error = 0;
	struct addrinfo* resolved_host = NULL;
	struct addrinfo hints = {
		.ai_family = af,
		.ai_flags = AI_NUMERICHOST
	};

	if ((src == NULL) || (dst == NULL)) {
		WSASetLastError(WSAEFAULT);
		return -1;
	}

	if ((af != AF_INET) && (af != AF_INET6)) {
		WSASetLastError(WSAEAFNOSUPPORT);
		return -1;
	}
	
	int ai_family = AF_UNSPEC;
	if (getaddrinfo(src, NULL, &hints, &resolved_host)) {
		return 0;
	}
	if (resolved_host->ai_family != af) {  // verify the returned address is of the expected family
		freeaddrinfo(resolved_host);
		return 0;
	}
	if (af == AF_INET) {
		error = memcpy_s(dst, sizeof(struct in_addr), &((struct sockaddr_in*)resolved_host->ai_addr)->sin_addr, sizeof(struct in_addr));
	} else if (af == AF_INET6) {
		error = memcpy_s(dst, sizeof(struct in_addr6), &((struct sockaddr_in6*)resolved_host->ai_addr)->sin6_addr, sizeof(struct in_addr6));
	}
	freeaddrinfo(resolved_host);

	if (error) {
		return 0;
	}
	
	return 1;
}

/*!
 * @brief Deallocates and cleans up the attributes of a tcp server socket context.
 * @param ctx Pointer to the context to free.
 */
VOID free_tcp_server_context(TcpServerContext * ctx)
{
	do
	{
		if (!ctx)
		{
			break;
		}

		dprintf("[TCP-SERVER] free_tcp_server_context. ctx=0x%08X", ctx);

		if (ctx->fd)
		{
			closesocket(ctx->fd);
			ctx->fd = 0;
		}

		if (ctx->channel)
		{
			met_api->channel.close(ctx->channel, ctx->remote, NULL, 0, NULL);
			ctx->channel = NULL;
		}

		if (ctx->notify)
		{
			met_api->scheduler.signal_waitable(ctx->notify, SchedulerStop);
			ctx->notify = NULL;
		}

		free(ctx);

	} while (0);
}

/*!
 * @brief Closes the server socket and brings down the client connections.
 * @param channel Pointer to the TCP channel to close.
 * @param request The request packet.
 * @param context The channel context.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS This value is always returned.
 */
DWORD tcp_channel_server_close(Channel * channel, Packet * request, LPVOID context)
{
	TcpServerContext * ctx = (TcpServerContext *)context;

	do
	{
		dprintf("[TCP-SERVER] tcp_channel_server_close. channel=0x%08X, ctx=0x%08X", channel, ctx);

		if (!ctx)
		{
			break;
		}

		// Set the context channel to NULL so we don't try to close the
		// channel (since it's already being closed)
		ctx->channel = NULL;

		// Free the context
		free_tcp_server_context(ctx);

		// Set the native channel operations context to NULL
		met_api->channel.set_native_io_context(channel, NULL);

	} while (0);

	return ERROR_SUCCESS;
}

/*!
 * @brief Create a TCP client channel from a socket.
 * @param serverCtx Pointer to the TCP server context.
 * @param sock The socket handle.
 * @returns Pointer to the newly created client context.
 */
TcpClientContext * tcp_channel_server_create_client(TcpServerContext * serverCtx, SOCKET sock)
{
	DWORD dwResult = ERROR_SUCCESS;
	TcpClientContext * clientctx = NULL;
	StreamChannelOps chops = { 0 };

	do
	{
		if (!serverCtx)
		{
			BREAK_WITH_ERROR("[TCP-SERVER] tcp_channel_server_create_client. serverCtx == NULL", ERROR_INVALID_HANDLE);
		}

		clientctx = (TcpClientContext *)malloc(sizeof(TcpClientContext));
		if (!clientctx)
		{
			BREAK_WITH_ERROR("[TCP-SERVER] tcp_channel_server_create_client. clientctx == NULL", ERROR_NOT_ENOUGH_MEMORY);
		}

		memset(clientctx, 0, sizeof(TcpClientContext));

		clientctx->remote = serverCtx->remote;
		clientctx->fd = sock;

		clientctx->notify = WSACreateEvent();
		if (clientctx->notify == WSA_INVALID_EVENT)
		{
			BREAK_ON_WSAERROR("[TCP-SERVER] tcp_channel_server_create_client. WSACreateEvent failed");
		}

		if (WSAEventSelect(clientctx->fd, clientctx->notify, FD_READ | FD_CLOSE) == SOCKET_ERROR)
		{
			BREAK_ON_WSAERROR("[TCP-SERVER] tcp_channel_server_create_client. WSAEventSelect failed");
		}

		memset(&chops, 0, sizeof(StreamChannelOps));

		chops.native.context = clientctx;
		chops.native.write = tcp_channel_client_write;
		chops.native.close = tcp_channel_client_close;

		clientctx->channel = met_api->channel.create_stream(0, 0, &chops);
		if (!clientctx->channel)
		{
			BREAK_WITH_ERROR("[TCP-SERVER] tcp_channel_server_create_client. clientctx->channel == NULL", ERROR_INVALID_HANDLE);
		}

		dwResult = met_api->scheduler.insert_waitable(clientctx->notify, clientctx, NULL, (WaitableNotifyRoutine)tcp_channel_client_local_notify, NULL);

	} while (0);

	if (dwResult != ERROR_SUCCESS)
	{
		if (clientctx)
		{
			free(clientctx);
			clientctx = NULL;
		}
	}

	return clientctx;
}

/*!
 * @brief Notify routine for a tcp server channel to pick up its new client connections..
 * @param remote Pointer to the remote instance.
 * @param serverCtx Pointer to the TCP server context.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS Notification completed successfully.
 */
DWORD tcp_channel_server_notify(Remote * remote, TcpServerContext * serverCtx)
{
	DWORD dwResult = ERROR_SUCCESS;
	TcpClientContext* clientctx = NULL;
	Packet* request = NULL;
	SOCKADDR_IN6 clientaddr = { 0 };
	SOCKADDR_IN6 serveraddr = { 0 };
	SOCKET sock = 0;
	DWORD size = 0;
	char* localhost = NULL;
	char* peerhost = NULL;
	int localport = 0;
	int peerport = 0;

	do
	{
		if (!serverCtx)
		{
			BREAK_WITH_ERROR("[TCP-SERVER] tcp_channel_server_notify. serverCtx == NULL", ERROR_INVALID_HANDLE);
		}

		ResetEvent(serverCtx->notify);

		size = sizeof(SOCKADDR_IN6);

		sock = accept(serverCtx->fd, (SOCKADDR*)&clientaddr, &size);
		if (sock == INVALID_SOCKET)
		{
			if (WSAGetLastError() == WSAEWOULDBLOCK)
			{
				Sleep(100);
				break;
			}

			BREAK_ON_WSAERROR("[TCP-SERVER] tcp_channel_server_notify. accept failed");
		}

		dprintf("[TCP-SERVER] tcp_channel_server_notify. Got new client connection on channel %d. sock=%d", met_api->channel.get_id(serverCtx->channel), sock);

		clientctx = tcp_channel_server_create_client(serverCtx, sock);
		if (!clientctx)
		{
			BREAK_WITH_ERROR("[TCP-SERVER] tcp_channel_server_notify. clientctx == NULL", ERROR_INVALID_HANDLE);
		}

		size = sizeof(SOCKADDR_IN6);

		if (getsockname(serverCtx->fd, (SOCKADDR *)&serveraddr, &size) == SOCKET_ERROR)
		{
			BREAK_ON_WSAERROR("[TCP-SERVER] request_net_tcp_server_channel_open. getsockname failed");
		}

		if (!serverCtx->ipv6)
		{
			localhost = inet_ntoa(((SOCKADDR_IN*)&serveraddr)->sin_addr);
		}

		if (!localhost)
		{
			localhost = "";
		}

		localport = ntohs(serverCtx->ipv6 ? serveraddr.sin6_port : ((SOCKADDR_IN*)&serveraddr)->sin_port);

		if (!serverCtx->ipv6)
		{
			peerhost = inet_ntoa(((SOCKADDR_IN*)&clientaddr)->sin_addr);
		}

		if (!peerhost)
		{
			peerhost = "";
		}

		peerport = ntohs(serverCtx->ipv6 ? clientaddr.sin6_port : ((SOCKADDR_IN*)&clientaddr)->sin_port);

		dprintf("[TCP-SERVER] tcp_channel_server_notify. New connection %s:%d <- %s:%d", localhost, localport, peerhost, peerport);

		request = met_api->packet.create(PACKET_TLV_TYPE_REQUEST, COMMAND_ID_STDAPI_NET_TCP_CHANNEL_OPEN);
		if (!request)
		{
			BREAK_WITH_ERROR("[TCP-SERVER] request_net_tcp_server_channel_open. met_api->packet.create failed", ERROR_INVALID_HANDLE);
		}

		met_api->packet.add_tlv_uint(request, TLV_TYPE_CHANNEL_ID, met_api->channel.get_id(clientctx->channel));
		met_api->packet.add_tlv_uint(request, TLV_TYPE_CHANNEL_PARENTID, met_api->channel.get_id(serverCtx->channel));
		met_api->packet.add_tlv_string(request, TLV_TYPE_LOCAL_HOST, localhost);
		met_api->packet.add_tlv_uint(request, TLV_TYPE_LOCAL_PORT, localport);
		met_api->packet.add_tlv_string(request, TLV_TYPE_PEER_HOST, peerhost);
		met_api->packet.add_tlv_uint(request, TLV_TYPE_PEER_PORT, peerport);

		dwResult = met_api->packet.transmit(serverCtx->remote, request, NULL);

	} while (0);

	return dwResult;
}

/*!
 * @brief Allocates a streaming TCP server channel.
 * @param remote Pointer to the remote instance.
 * @param packet Pointer to the request packet.
 * @returns Indication of success or failure.
 * @retval ERROR_SUCCESS Opening the server channel completed successfully.
 */
DWORD request_net_tcp_server_channel_open(Remote * remote, Packet * packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	int iResult = 0;
	TcpServerContext * ctx = NULL;
	Packet * response = NULL;
	char * localHost = NULL;
	StreamChannelOps chops = { 0 };
	USHORT localPort = 0;
	int ai_family = AF_UNSPEC;

	do
	{
		response = met_api->packet.create_response(packet);
		if (!response)
		{
			BREAK_WITH_ERROR("[TCP-SERVER] request_net_tcp_server_channel_open. response == NULL", ERROR_NOT_ENOUGH_MEMORY);
		}

		ctx = (TcpServerContext *)malloc(sizeof(TcpServerContext));
		if (!ctx)
		{
			BREAK_WITH_ERROR("[TCP-SERVER] request_net_tcp_server_channel_open. ctx == NULL", ERROR_NOT_ENOUGH_MEMORY);
		}

		memset(ctx, 0, sizeof(TcpServerContext));

		ctx->remote = remote;

		localPort = (USHORT)(met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_LOCAL_PORT) & 0xFFFF);
		localHost = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_LOCAL_HOST);

		if ((localHost) && (strlen(localHost) == 0)) {
			// normalize empty host strings
			localHost = NULL;
		}
		if (localHost) {
			ai_family = get_ai_family(localHost);
			if ((ai_family != AF_INET) && (ai_family != AF_INET6)) {
				BREAK_WITH_ERROR("[TCP-SERVER] request_net_tcp_server_channel_open. bind failed, invalid address (unsupported family)", ERROR_INVALID_PARAMETER);
			}
		}
		else {
			ai_family = AF_INET6;
		}

		ctx->fd = WSASocket(ai_family, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
		if (ctx->fd == INVALID_SOCKET)
		{
			if ((ai_family == AF_INET6) && (!localHost)) {
				// if the socket that failed to be created was IPv6 but it was only selected because no
				// address was specified, fail back to IPv4
				ai_family = AF_INET;
				ctx->fd = WSASocket(ai_family, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
			}	
		}
		else if (ai_family == AF_INET6)
		{
			int no = 0;
			if (setsockopt(ctx->fd, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&no, sizeof(no)) == SOCKET_ERROR)
			{
				// fallback to ipv4 - we're probably running on Windows XP or earlier here, which means that to
				// support IPv4 and IPv6 we'd need to create two separate sockets. IPv6 on XP isn't that common
				// so instead, we'll just revert back to v4 and listen on that one address instead.
				closesocket(ctx->fd);
				ai_family = AF_INET;
				ctx->fd = WSASocket(ai_family, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
			}
		}
		if (ctx->fd == INVALID_SOCKET) {
			BREAK_ON_WSAERROR("[TCP-SERVER] request_net_tcp_server_channel_open. WSASocket failed");
		}

		struct sockaddr_in6 sockAddr = { 0 };
		DWORD sockAddrSize = 0;

		iResult = 1; // inet_pton success
		if (ai_family == AF_INET)
		{
			struct sockaddr_in* v4Addr = (struct sockaddr_in*)&sockAddr;
			if (localHost) {
				iResult = inet_pton(AF_INET, localHost, &v4Addr->sin_addr);
			}
			else {
				v4Addr->sin_addr.s_addr = htons(INADDR_ANY);
			}
			v4Addr->sin_family = AF_INET;
			v4Addr->sin_port = htons(localPort);
			sockAddrSize = sizeof(struct sockaddr_in);
			ctx->ipv6 = FALSE;
		}
		else if (ai_family == AF_INET6)
		{
			if (localHost) {
				iResult = inet_pton(AF_INET6, localHost, &sockAddr.sin6_addr);
			}
			else {
				sockAddr.sin6_addr = in6addr_any;
			}
			sockAddr.sin6_family = AF_INET6;
			sockAddr.sin6_port = htons(localPort);
			sockAddrSize = sizeof(struct sockaddr_in6);
			ctx->ipv6 = TRUE;
		}
		else {
			BREAK_WITH_ERROR("[TCP-SERVER] request_net_tcp_server_channel_open. bind failed, invalid address (unsupported family)", ERROR_INVALID_PARAMETER);
		}

		// inet_pton returns 1 on success, 0 and -1 on failure depending on if an error is placed in WSAGetLastError
		if (iResult == -1) {
			BREAK_ON_WSAERROR("[TCP-SERVER] request_net_tcp_server_channel_open. bind failed, invalid address (inet_pton failure, WSAError)");
		} else if (iResult != 1) {
			BREAK_WITH_ERROR("[TCP-SERVER] request_net_tcp_server_channel_open. bind failed, invalid address (inet_pton failure)", ERROR_INVALID_PARAMETER);
		}


		if (bind(ctx->fd, (SOCKADDR *)&sockAddr, sockAddrSize) == SOCKET_ERROR)
		{
			BREAK_ON_WSAERROR("[TCP-SERVER] request_net_tcp_server_channel_open. bind failed");
		}

		if (listen(ctx->fd, SOMAXCONN) == SOCKET_ERROR)
		{
			BREAK_ON_WSAERROR("[TCP-SERVER] request_net_tcp_server_channel_open. listen failed");
		}

		ctx->notify = WSACreateEvent();
		if (ctx->notify == WSA_INVALID_EVENT)
		{
			BREAK_ON_WSAERROR("[TCP-SERVER] request_net_tcp_server_channel_open. WSACreateEvent failed");
		}

		if (WSAEventSelect(ctx->fd, ctx->notify, FD_ACCEPT) == SOCKET_ERROR)
		{
			BREAK_ON_WSAERROR("[TCP-SERVER] request_net_tcp_server_channel_open. WSAEventSelect failed");
		}

		memset(&chops, 0, sizeof(StreamChannelOps));
		chops.native.context = ctx;
		chops.native.close = tcp_channel_server_close;

		ctx->channel = met_api->channel.create_stream(0, CHANNEL_FLAG_SYNCHRONOUS, &chops);
		if (!ctx->channel)
		{
			BREAK_WITH_ERROR("[TCP-SERVER] request_net_tcp_server_channel_open. channel_create_stream failed", ERROR_INVALID_HANDLE);
		}

		met_api->scheduler.insert_waitable(ctx->notify, ctx, NULL, (WaitableNotifyRoutine)tcp_channel_server_notify, NULL);

		met_api->packet.add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, met_api->channel.get_id(ctx->channel));
		net_tlv_pack_local_addrinfo(ctx, response);

		dprintf("[TCP-SERVER] request_net_tcp_server_channel_open. tcp server %s:%d on channel %d", localHost, localPort, met_api->channel.get_id(ctx->channel));

	} while (0);

	met_api->packet.transmit_response(dwResult, remote, response);

	do
	{
		if (dwResult == ERROR_SUCCESS)
		{
			break;
		}

		dprintf("[TCP-SERVER] Error encountered %u 0x%x", dwResult, dwResult);

		if (!ctx)
		{
			break;
		}

		if (ctx->fd)
		{
			dprintf("[TCP-SERVER] Destroying socket");
			closesocket(ctx->fd);
		}

		if (ctx->channel)
		{
			dprintf("[TCP-SERVER] Destroying channel");
			met_api->channel.destroy(ctx->channel, packet);
		}

		free(ctx);

	} while (0);

	return dwResult;
}
