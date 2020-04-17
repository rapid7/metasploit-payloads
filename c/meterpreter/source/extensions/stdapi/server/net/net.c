#include "precomp.h"
#include "common_metapi.h"

#include <winsock2.h>
#include <ws2tcpip.h>

static char * parse_sockaddr(struct sockaddr_storage *addr, uint16_t *port)
{
	char *host = NULL;

	host = malloc(INET6_ADDRSTRLEN);
	if (host) {
		if (addr->ss_family == AF_INET) {
			struct sockaddr_in *s = (struct sockaddr_in *)addr;
			*port = ntohs(s->sin_port);
			inet_ntop(AF_INET, &s->sin_addr, host, INET6_ADDRSTRLEN);
		}
		else if (addr->ss_family == AF_INET6) {
			struct sockaddr_in6 *s = (struct sockaddr_in6 *)addr;
			*port = ntohs(s->sin6_port);
			inet_ntop(AF_INET6, &s->sin6_addr, host, INET6_ADDRSTRLEN);
		}
	}
	return host;
}

const char * inet_ntop(int af, const void *src, char *dst, socklen_t size) {
	struct sockaddr_storage addr;

	ZeroMemory(&addr, sizeof(addr));
	addr.ss_family = af;

	if (af == AF_INET) {
		((struct sockaddr_in *)&addr)->sin_addr = *(struct in_addr *)src;
	}
	else if (af == AF_INET6) {
		((struct sockaddr_in6 *)&addr)->sin6_addr = *(struct in6_addr *)src;
	}

	if (!WSAAddressToStringA((struct sockaddr *)&addr, sizeof(addr), NULL, dst, &size)) {
		dst = NULL;
	}
	return dst;
}

/*!
* @brief Add the local socket address information to the specified packet.
* @param sock_ctx Pointer to the socket context to retrieve the address for.
* @param packet Packet to add the LOCAL_HOST and LOCAL_PORT TLVs to.
* @retval ERROR_SUCCESS Adding the TLVs was successful.
*/
DWORD net_tlv_pack_local_addrinfo(SocketContext *sock_ctx, Packet *packet)
{
	struct sockaddr_storage addr;
	int len = sizeof(addr);
	char *localhost = NULL;
	uint16_t localport = 0;

	if (getsockname(sock_ctx->fd, (struct sockaddr *)&addr, &len) == -1) {
		return ERROR_UNIDENTIFIED_ERROR;
	}

	localhost = parse_sockaddr(&addr, &localport);
	if (localhost == NULL) {
		return ERROR_OUTOFMEMORY;
	}

	met_api->packet.add_tlv_string(packet, TLV_TYPE_LOCAL_HOST, localhost);
	met_api->packet.add_tlv_uint(packet, TLV_TYPE_LOCAL_PORT, localport);
	free(localhost);
	localhost = NULL;
	return ERROR_SUCCESS;
}
