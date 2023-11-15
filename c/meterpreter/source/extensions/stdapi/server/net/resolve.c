#include "precomp.h"
#include "common_metapi.h"
#include <stdio.h>

#include <winsock2.h>
#include <ws2tcpip.h>

/// <summary>
/// Resolve a hostname. Don't forget to call `freeaddrinfo` on the `address_info` parameter once done with it.
/// </summary>
/// <param name="hostname">Long pointer to a string</param>
/// <param name="ai_family">The family to get the IP address for (IPv6 / IPv4)</param>
/// <param name="address_info">The resulting addrinfo structure</param>
/// <returns>0 on success, a Windows error code on error</returns>
DWORD resolve_host(const LPCSTR hostname, UINT ai_family, struct addrinfo **address_info)
{
	if (hostname == NULL)
	{
		dprintf("Hostname not set");
		return ERROR_INVALID_PARAMETER;
	}

	if (address_info == NULL)
	{
		dprintf("Null pointer provided as output to resolve_host");
		return ERROR_INVALID_PARAMETER;
	}

	WSADATA wsaData;
	DWORD iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != ERROR_SUCCESS)
	{
		dprintf("Could not initialise Winsock: %x.", iResult);
		return iResult;
	}

	struct addrinfo hints = { 0 };
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_family = ai_family;

	dprintf("Attempting to resolve '%s'", hostname);

	iResult = getaddrinfo(hostname, NULL, &hints, address_info);
	if (iResult != ERROR_SUCCESS)
	{
		dprintf("Unable to resolve host '%s' Error: %x.", hostname, iResult);
		dprintf("Error msg: %s", gai_strerror(iResult));
		return iResult;
	}
	dprintf("Resolved host '%s' successfully", hostname);

	dprintf("Performing Win Socket cleanup");
	iResult = WSACleanup();
	if (iResult != ERROR_SUCCESS)
	{
		dprintf("WSACleanup failed with return code %x", iResult);
		return iResult;
	}
	dprintf("WSACleanup completed successfully");

	return ERROR_SUCCESS;
}

/// <summary>
/// Add in all resolved IP addresses for a specific hostname to a TLV group.
/// </summary>
/// <param name="group">The group to insert resolved host IP addresses into.</param>
/// <param name="host">The hostname or a list of hostnames to add to the group.</param>
/// <returns>0 on success.</returns>
DWORD add_all_host_ips_to_group(Packet* group, struct addrinfo* host)
{
	if (group == NULL)
	{
		dprintf("Null pointer provided as group");
		return ERROR_INVALID_PARAMETER;
	}

	for (struct addrinfo* current = host; current != NULL; current = current->ai_next)
	{
		switch (current->ai_family)
		{
		case AF_INET:
			dprintf("Adding IP v4 Family to Group TLV");
			met_api->packet.add_tlv_uint(group, TLV_TYPE_ADDR_TYPE, (UINT)current->ai_family);
			dprintf("Adding IP v4 Address to Group TLV");
			struct in_addr ipv4_addr = ((struct sockaddr_in*)(current->ai_addr))->sin_addr;
			met_api->packet.add_tlv_raw(group, TLV_TYPE_IP, &ipv4_addr, sizeof(struct in_addr));
			break;
		case AF_INET6:
			dprintf("Adding IP v6 Family to Group TLV");
			met_api->packet.add_tlv_uint(group, TLV_TYPE_ADDR_TYPE, (UINT)current->ai_family);
			dprintf("Adding IP v6 Address to Group TLV");
			struct in6_addr ipv6_addr = ((struct sockaddr_in6*)(current->ai_addr))->sin6_addr;
			met_api->packet.add_tlv_raw(group, TLV_TYPE_IP, &ipv6_addr, sizeof(struct in6_addr));
			break;
		default:
			dprintf("Unknown family, skipping entry.");
			continue;
		}
	}
	return ERROR_SUCCESS;
}

DWORD request_resolve_host(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	LPCSTR hostname = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_HOST_NAME);
	UINT ai_family = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ADDR_TYPE);
	DWORD iResult = ERROR_SUCCESS;

	struct addrinfo* result;
	iResult = resolve_host(hostname, ai_family, &result);
	if (iResult != ERROR_SUCCESS || result == NULL)
	{
		dprintf("Could not resolve_host for '%s': %x", hostname, iResult);
		goto done;
	}

	dprintf("Creating group for resolve host entry");
	Packet* resolved_hosts = met_api->packet.create_group();
	if (resolved_hosts == NULL)
	{
		dprintf("Could not create TLV Group");
		goto done;
	}

	if (add_all_host_ips_to_group(resolved_hosts, result) != ERROR_SUCCESS)
	{
		dprintf("Error adding resolved host IP addresses to group");
	}

	dprintf("Adding IP TLVs to Group TLV in response packet");
	met_api->packet.add_group(response, TLV_TYPE_RESOLVE_HOST_ENTRY, resolved_hosts);
	dprintf("Freeing addrinfo");
	freeaddrinfo(result);

done:
	dprintf("Sending return packet for resolve_host");
	met_api->packet.transmit_response(iResult, remote, response);
	return ERROR_SUCCESS;
}

DWORD request_resolve_hosts(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	Tlv hostname = {0};
	int index = 0;
	int iResult = 0;
	UINT ai_family = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_ADDR_TYPE);

	while( met_api->packet.enum_tlv( packet, index++, TLV_TYPE_HOST_NAME, &hostname ) == ERROR_SUCCESS )
	{
		struct addrinfo* addr = NULL;

		iResult = resolve_host((LPCSTR)hostname.buffer, ai_family, &addr);

		Packet* resolved_host_group = met_api->packet.create_group();

		if (iResult != ERROR_SUCCESS || addr == NULL)
		{
			dprintf("Unable to resolve_host %s error: %x", hostname.buffer, iResult);
			goto done;
		}

		if (add_all_host_ips_to_group(resolved_host_group, addr) != ERROR_SUCCESS)
		{
			dprintf("Error adding resolved host IP addresses to group");
			goto done;
		}

		met_api->packet.add_group(response, TLV_TYPE_RESOLVE_HOST_ENTRY, resolved_host_group);
		if (addr != NULL) { dprintf("Freeing Address Info for hostname: %s", hostname.buffer); freeaddrinfo(addr); }
	}

done:
	met_api->packet.transmit_response(iResult, remote, response);
	return ERROR_SUCCESS;
}
