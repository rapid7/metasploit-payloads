#include "precomp.h"
#include <stdio.h>

#ifdef _WIN32
  #include <ws2tcpip.h>
  #include <winsock2.h>
#else
  #include <netdb.h>
  #include <arpa/inet.h>
#endif

DWORD resolve_host(LPCTSTR hostname, char* addr, u_short* addr_type, u_short* addr_length)
{
	struct hostent *he;
	int i = 0;

#ifdef _WIN32
	WSADATA data;
	if (WSAStartup (MAKEWORD(1, 1), &data) != 0)
	{
		dprintf("Could not initialise Winsock.\n", stderr);
		return 1;
	}
#endif

	he = gethostbyname (hostname);
	if (he == NULL)
	{
		return h_errno;
	}

	for(i = 0; i < he->h_length; i++)
	{
		memcpy(addr+i, &(he->h_addr_list[0][i]), 1);
	}
	*addr_type = he->h_addrtype;
	*addr_length = he->h_length;

#ifdef _WIN32
	WSACleanup ();
#endif

	return h_errno;
}

DWORD request_resolve_host(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	LPCTSTR hostname = NULL;
	char addr[16];
	u_short addr_type;
	u_short addr_length;
	DWORD result = NULL;

	hostname = packet_get_tlv_value_string(packet, TLV_TYPE_HOST_NAME);

	if (!hostname)
		result = ERROR_INVALID_PARAMETER;
	else
	{
		result = resolve_host(hostname, addr, &addr_type, &addr_length);
		packet_add_tlv_raw(response, TLV_TYPE_IP, addr, addr_length);
		packet_add_tlv_uint(response, TLV_TYPE_ADDR_TYPE, addr_type);
	}

	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

DWORD request_resolve_hosts(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	Tlv hostname = {0};
	DWORD result = NULL;
	int index = 0;

	while( packet_enum_tlv( packet, index++, TLV_TYPE_HOST_NAME, &hostname ) == ERROR_SUCCESS )
	{
		char addr[16] = {0};
		u_short addr_type = 0;
		u_short addr_length = 0;

		resolve_host((LPCTSTR)hostname.buffer, addr, &addr_type, &addr_length);

		packet_add_tlv_raw(response, TLV_TYPE_IP, addr, addr_length);
		packet_add_tlv_uint(response, TLV_TYPE_ADDR_TYPE, addr_type);
	}

	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}
