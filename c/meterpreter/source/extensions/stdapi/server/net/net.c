#include "precomp.h"
#include <stdio.h>

#ifdef _WIN32
#include <ws2tcpip.h>
#include <winsock2.h>
#else
#include <netdb.h>
#include <arpa/inet.h>
#endif

DWORD resolve_host(LPCTSTR hostname, char* addr, short* addr_type, short* addr_length)
{
    struct hostent *he;
	int i = 0;

	#ifdef _WIN32
		WSADATA data;
		if (WSAStartup (MAKEWORD(1, 1), &data) != 0)
		{
			printf("Could not initialise Winsock.\n", stderr);
			exit (1);
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

//DWORD resolve_host_ipv4(LPCTSTR hostname, LPCTSTR ipv4)
//{
//    struct hostent *he;
//
//	#ifdef _WIN32
//		WSADATA data;
//		if (WSAStartup (MAKEWORD(1, 1), &data) != 0)
//		{
//			dprintf("Could not initialise Winsock.\n", stderr);
//			return h_errno;
//		}
//	#endif
//
//    he = gethostbyname(hostname);
//    if (he == NULL)
//    {
//		return h_errno;
//    }
//
//	strcpy(ipv4,(inet_ntoa (*((struct in_addr *) he->h_addr_list[0]))));
//
//	#ifdef _WIN32
//		WSACleanup ();
//	#endif
//
//	return h_errno;
//}

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
		packet_add_tlv_uint(response, TLV_TYPE_ADDR_LENGTH, addr_length);
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
		Tlv resolve[3] = {0};
		char addr[16] = {0};
		short addr_type = 0;
		short addr_length = 0;

		resolve_host((PCHAR)hostname.buffer, addr, &addr_type, &addr_length);

		packet_add_tlv_raw(response, TLV_TYPE_IP, addr, addr_length);
			
		//resolve[0].header.length = strlen(addr) + 1;
		//resolve[0].header.type   = TLV_TYPE_IP;
		//resolve[0].buffer        = (PUCHAR)addr;
		//resolve[1].header.length = sizeof(addr_type);
		//resolve[1].header.type   = TLV_TYPE_ADDR_TYPE;
		//resolve[1].buffer        = (PUCHAR)addr_type;
		//resolve[2].header.length = sizeof(addr_length);
		//resolve[2].header.type   = TLV_TYPE_ADDR_LENGTH;
		//resolve[2].buffer        = (PUCHAR)addr_length;

		//packet_add_tlv_group(packet, TLV_TYPE_RESOLVE, resolve, 3);
	}

	packet_transmit_response(result, remote, response);
	return ERROR_SUCCESS;
}

//DWORD request_resolve_hostname_ipv4(Remote *remote, Packet *packet)
//{
//	Packet *response = packet_create_response(packet);
//	LPCTSTR hostname = NULL;
//	LPCTSTR ipv4[16];
//	DWORD result = NULL;
//
//	hostname = packet_get_tlv_value_string(packet, TLV_TYPE_HOST_NAME);
//
//	if (!hostname)
//		result = ERROR_INVALID_PARAMETER;
//	else
//	{
//		result = resolve_host_ipv4(hostname, ipv4);
//		packet_add_tlv_string(response, TLV_TYPE_IP, (LPCSTR)ipv4);
//	}
//
//	packet_transmit_response(result, remote, response);
//	return ERROR_SUCCESS;
//}
//
//DWORD request_resolve_hosts_ipv4(Remote *remote, Packet *packet)
//{
//	Packet *response = packet_create_response(packet);
//	LPCTSTR hostname = NULL;
//	LPCTSTR ipv4[16];
//	DWORD result = NULL;
//
//	hostname = packet_get_tlv_value_string(packet, TLV_TYPE_HOST_NAME);
//
//	if (!hostname)
//		result = ERROR_INVALID_PARAMETER;
//	else
//	{
//		result = resolve_host_ipv4(hostname, ipv4);
//		packet_add_tlv_string(response, TLV_TYPE_VALUE_DATA, (LPCSTR)ipv4);
//	}
//
//	packet_transmit_response(result, remote, response);
//	return ERROR_SUCCESS;
//}
//
