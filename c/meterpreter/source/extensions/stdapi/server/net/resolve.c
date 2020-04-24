#include "precomp.h"
#include "common_metapi.h"
#include <stdio.h>

#include <winsock2.h>
#include <ws2tcpip.h>

DWORD resolve_host(LPCSTR hostname, u_short ai_family, struct in_addr *result, struct in6_addr *result6)
{
	struct addrinfo hints, *list;
	struct in_addr addr;
	struct in6_addr addr6;
	struct sockaddr_in *sockaddr_ipv4;
	struct sockaddr_in6 *sockaddr_ipv6;
	int iResult;

	WSADATA wsaData;
	iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
	if (iResult != NO_ERROR)
	{
		dprintf("Could not initialise Winsock: %x.", iResult);
		return iResult;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_family = ai_family;

	dprintf("Attempting to resolve '%s'", hostname);

	iResult = getaddrinfo(hostname, NULL, &hints, &list);

	if (iResult != NO_ERROR)
	{
		dprintf("Unable to resolve host Error: %x.", iResult);
		dprintf("Error msg: %s", gai_strerror(iResult));
	}
	else
	{
		switch (list->ai_family) {
		case AF_INET:
			sockaddr_ipv4 = (struct sockaddr_in *) list->ai_addr;
			addr = sockaddr_ipv4->sin_addr;
			memcpy((void*)result, &addr, sizeof(result));
		case AF_INET6:
			sockaddr_ipv6 = (struct sockaddr_in6 *) list->ai_addr;
			addr6 = sockaddr_ipv6->sin6_addr;
			memcpy((void*)result6, &addr6, sizeof(struct in6_addr));
		default:
			break;
		}
	}

	freeaddrinfo(list);
	WSACleanup();

	return iResult;
}

DWORD request_resolve_host(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	LPCSTR hostname = NULL;
	struct in_addr addr;
	struct in6_addr addr6;
	u_short ai_family = AF_INET;
	int iResult;

	hostname = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_HOST_NAME);

	if (!hostname)
	{
		iResult = ERROR_INVALID_PARAMETER;
		dprintf("Hostname not set");
	}
	else
	{
		ai_family = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ADDR_TYPE);
		iResult = resolve_host(hostname, ai_family, &addr, &addr6);
		if (iResult == NO_ERROR)
		{
			if (ai_family == AF_INET)
			{
				met_api->packet.add_tlv_raw(response, TLV_TYPE_IP, &addr, sizeof(struct in_addr));
			} else {
				met_api->packet.add_tlv_raw(response, TLV_TYPE_IP, &addr6, sizeof(struct in_addr6));
			}
			met_api->packet.add_tlv_uint(response, TLV_TYPE_ADDR_TYPE, ai_family);
		}
		else
		{
			dprintf("Unable to resolve_host %s error: %x", hostname, iResult);
		}
	}

	met_api->packet.transmit_response(iResult, remote, response);
	return ERROR_SUCCESS;
}

DWORD request_resolve_hosts(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	Tlv hostname = {0};
	int index = 0;
	int iResult;
	u_short ai_family = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ADDR_TYPE);

	while( met_api->packet.enum_tlv( packet, index++, TLV_TYPE_HOST_NAME, &hostname ) == ERROR_SUCCESS )
	{
		struct in_addr addr = {0};
		struct in6_addr addr6 = {0};

		iResult = resolve_host((LPCSTR)hostname.buffer, ai_family, &addr, &addr6);

		if (iResult == NO_ERROR)
		{
			if (ai_family == AF_INET)
			{
				met_api->packet.add_tlv_raw(response, TLV_TYPE_IP, &addr, sizeof(struct in_addr));
			} else {
				met_api->packet.add_tlv_raw(response, TLV_TYPE_IP, &addr6, sizeof(struct in_addr6));
			}
		}
		else
		{
			dprintf("Unable to resolve_host %s error: %x", hostname.buffer, iResult);
			met_api->packet.add_tlv_raw(response, TLV_TYPE_IP, NULL, 0);
		}
		met_api->packet.add_tlv_uint(response, TLV_TYPE_ADDR_TYPE, ai_family);
	}

	met_api->packet.transmit_response(NO_ERROR, remote, response);
	return ERROR_SUCCESS;
}
