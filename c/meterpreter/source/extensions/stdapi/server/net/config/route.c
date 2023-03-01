#include "precomp.h"
#include "common.h"
#include "common_metapi.h"
#include <netioapi.h>

typedef NETIO_STATUS(NETIOAPI_API_* GETBESTINTERFACE)(IPAddr dwDestAddr, PDWORD pdwBestIfIndex);
typedef NETIO_STATUS(NETIOAPI_API_* GETIPFORWARDTABLE2)(ADDRESS_FAMILY Family, PMIB_IPFORWARD_TABLE2* Table);
typedef NETIO_STATUS(NETIOAPI_API_* GETIPINTERFACEENTRY)(PMIB_IPINTERFACE_ROW Row);

typedef struct v6netmask
{
	unsigned int mask[4];
} v6netmask;

DWORD add_remove_route(Packet *request, BOOLEAN add);

static unsigned int bit32mask(unsigned bits){
    unsigned int netmask;
    if (bits == 32)
        netmask = 0xffffffff;
    else{
        netmask = ((0xffffffff << (32 - (bits % 32))) & 0xffffffff);
    }
    return netmask;
}

static void bit128mask(unsigned int bits, v6netmask* netmask){
    unsigned int part = bit32mask(bits);
    if (bits >= 96) {
        netmask->mask[0] = 0xffffffff;
        netmask->mask[1] = 0xffffffff;
        netmask->mask[2] = 0xffffffff;
        netmask->mask[3] = htonl(part);
    }
    else if (bits >= 64) {
        netmask->mask[0] = 0xffffffff;
        netmask->mask[1] = 0xffffffff;
        netmask->mask[2] = htonl(part);
        netmask->mask[3] = 0x0;
    }
    else if (bits >= 32) {
        netmask->mask[0] = 0xffffffff;
        netmask->mask[1] = htonl(part);
        netmask->mask[2] = 0x0;
        netmask->mask[3] = 0x0;
    }
    else {
        netmask->mask[0] = htonl(part);
        netmask->mask[1] = 0x0;
        netmask->mask[2] = 0x0;
        netmask->mask[3] = 0x0;
    }
    return;
}
/*
 * Returns zero or more routes to the requestor from the active routing table
 */
DWORD request_net_config_get_routes(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	DWORD dwResult = ERROR_SUCCESS;
	DWORD index;
	DWORD metric_bigendian;

	PMIB_IPFORWARDTABLE table_ipv4 = NULL;
	PMIB_IPFORWARD_TABLE2 table_ipv6 = NULL;
	DWORD tableSize = sizeof(MIB_IPFORWARDROW) * 96;
	char int_name[20];

	do
	{
		// Allocate storage for the routing table
		if (!(table_ipv4 = (PMIB_IPFORWARDTABLE)malloc(tableSize)))
		{
			dwResult = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Get the routing table
		if (GetIpForwardTable(table_ipv4, &tableSize, TRUE) != NO_ERROR)
		{
			BREAK_ON_ERROR("[NET] request_net_config_get_routes: GetIpForwardTable failed");
		}

		// Enumerate it
		for (index = 0;
			index < table_ipv4->dwNumEntries;
			index++)
		{
			Tlv route[5];
			memset(int_name, 0, sizeof(int_name));

			route[0].header.type = TLV_TYPE_SUBNET;
			route[0].header.length = sizeof(DWORD);
			route[0].buffer = (PUCHAR)&table_ipv4->table[index].dwForwardDest;
			route[1].header.type = TLV_TYPE_NETMASK;
			route[1].header.length = sizeof(DWORD);
			route[1].buffer = (PUCHAR)&table_ipv4->table[index].dwForwardMask;
			route[2].header.type = TLV_TYPE_GATEWAY;
			route[2].header.length = sizeof(DWORD);
			route[2].buffer = (PUCHAR)&table_ipv4->table[index].dwForwardNextHop;

			// we just get the interface index, not the name, because names can be __long__
			_itoa(table_ipv4->table[index].dwForwardIfIndex, int_name, 10);
			route[3].header.type = TLV_TYPE_STRING;
			route[3].header.length = (DWORD)strlen(int_name) + 1;
			route[3].buffer = (PUCHAR)int_name;

			metric_bigendian = htonl(table_ipv4->table[index].dwForwardMetric1);
			route[4].header.type = TLV_TYPE_ROUTE_METRIC;
			route[4].header.length = sizeof(DWORD);
			route[4].buffer = (PUCHAR)&metric_bigendian;

			met_api->packet.add_tlv_group(response, TLV_TYPE_NETWORK_ROUTE,
				route, 5);
		}

		v6netmask v6_mask;
		MIB_IPINTERFACE_ROW iface = { .Family = AF_INET6 };
		GETIPFORWARDTABLE2 pGetIpForwardTable2 = (GETIPFORWARDTABLE2)GetProcAddress(GetModuleHandle(TEXT("Iphlpapi.dll")), "GetIpForwardTable2");

		// GetIpForwardTable2 is only available on Windows Vista and later.
		if (!pGetIpForwardTable2) {
			break;
		}
		if (pGetIpForwardTable2(AF_INET6, &table_ipv6) != NO_ERROR) {
			BREAK_ON_ERROR("[NET] request_net_config_get_routes: GetIpForwardTable2 failed");
		}

		// Enumerate it
		for (index = 0;
			index < table_ipv6->NumEntries;
			index++)
		{
			Tlv route[5];
			memset(int_name, 0, sizeof(int_name));
			iface.InterfaceIndex = table_ipv6->Table[index].InterfaceIndex;
			if (GetIpInterfaceEntry(&iface) != NO_ERROR)
			{
				CONTINUE_ON_ERROR("[NET] request_net_config_get_routes: GetIpInterfaceEntry failed");
			}

			route[0].header.type   = TLV_TYPE_SUBNET;
			route[0].header.length = sizeof(DWORD)*4;
			route[0].buffer        = (PUCHAR)&table_ipv6->Table[index].DestinationPrefix.Prefix.Ipv6.sin6_addr;

			bit128mask(table_ipv6->Table[index].DestinationPrefix.PrefixLength, &v6_mask);
			route[1].header.type   = TLV_TYPE_NETMASK;
			route[1].header.length = sizeof(DWORD)*4;
			route[1].buffer        = (PUCHAR)v6_mask.mask;

			route[2].header.type   = TLV_TYPE_GATEWAY;
			route[2].header.length = sizeof(DWORD)*4;
			route[2].buffer        = (PUCHAR)&table_ipv6->Table[index].NextHop.Ipv6.sin6_addr;

			// we just get the interface index, not the name, because names can be __long__
			_itoa(table_ipv6->Table[index].InterfaceIndex, int_name, 10);
			route[3].header.type   = TLV_TYPE_STRING;
			route[3].header.length = (DWORD)strlen(int_name)+1;
			route[3].buffer        = (PUCHAR)int_name;

			metric_bigendian = htonl(table_ipv6->Table[index].Metric + iface.Metric);
			route[4].header.type   = TLV_TYPE_ROUTE_METRIC;
			route[4].header.length = sizeof(DWORD);
			route[4].buffer        = (PUCHAR)&metric_bigendian;

			met_api->packet.add_tlv_group(response, TLV_TYPE_NETWORK_ROUTE,
					route, 5);
		}
	} while (0);

	if(table_ipv4)
		free(table_ipv4);
	if(table_ipv6)
		free(table_ipv6);

	met_api->packet.transmit_response(dwResult, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Adds a route to the routing table
 */
DWORD request_net_config_add_route(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;

	result = add_remove_route(packet, TRUE);

	// Transmit the response packet
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Removes a route from the routing table
 */
DWORD request_net_config_remove_route(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	DWORD result;

	result = add_remove_route(packet, FALSE);

	// Transmit the response packet
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Adds or removes a route from the supplied request
 */
DWORD add_remove_route(Packet *packet, BOOLEAN add)
{
	MIB_IPFORWARDROW route;
	GETBESTINTERFACE pGetBestInterface = NULL;
	GETIPINTERFACEENTRY pGetIpInterfaceEntry = NULL;
	LPCSTR subnet;
	LPCSTR netmask;
	LPCSTR gateway;
	DWORD dwResult;

	subnet  = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_SUBNET_STRING);
	netmask = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_NETMASK_STRING);
	gateway = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_GATEWAY_STRING);

	memset(&route, 0, sizeof(route));

	route.dwForwardDest    = inet_addr(subnet);
	route.dwForwardMask    = inet_addr(netmask);
	route.dwForwardNextHop = inet_addr(gateway);
	route.dwForwardType    = MIB_IPROUTE_TYPE_INDIRECT; // Assume next hop.
	route.dwForwardProto   = MIB_IPPROTO_NETMGMT;
	route.dwForwardAge     = -1;
	route.dwForwardMetric1 = 0;

	pGetBestInterface = (GETBESTINTERFACE)GetProcAddress(GetModuleHandle(TEXT("iphlpapi")), "GetBestInterface");
	if (!pGetBestInterface) {
		dprintf("[NET] add_remove_route: GetBestInterface is not available.");
		return ERROR_NOT_SUPPORTED;
	}

	dwResult = pGetBestInterface(route.dwForwardNextHop, &route.dwForwardIfIndex);
	if (dwResult != ERROR_SUCCESS) {
		dprintf("[NET] add_remove_route: GetBestInterface failed. error=%d (0x%x)", dwResult, (ULONG_PTR)dwResult);
		return dwResult;
	}
	dprintf("[NET] add_remove_route: GetBestInterface returned ifIndex=%d.", route.dwForwardIfIndex);

	pGetIpInterfaceEntry = (GETIPINTERFACEENTRY)GetProcAddress(GetModuleHandle(TEXT("iphlpapi")), "GetIpInterfaceEntry");
	// If GetIpInterfaceEntry is available, use it to set the default metric because newer systems require that
	if (pGetIpInterfaceEntry) {
		MIB_IPINTERFACE_ROW iface = { .Family = AF_INET, .InterfaceIndex = route.dwForwardIfIndex };
		dwResult = pGetIpInterfaceEntry(&iface);
		if (dwResult == NO_ERROR) {
			route.dwForwardMetric1 = iface.Metric;
		}
		else {
			dprintf("[NET] add_remove_route: GetIpInterfaceEntry failed. error=%d (0x%x)", dwResult, (ULONG_PTR)dwResult);
		}
	}
	else {
		dprintf("[NET] add_remove_route: GetIpInterfaceEntry is not available.");
	}

	if (add) {
		dwResult = CreateIpForwardEntry(&route);
	}
	else {
		dwResult = DeleteIpForwardEntry(&route);
	}

	if (dwResult != ERROR_SUCCESS) {
		dprintf("[NET] add_remove_route: %sIpForwardEntry failed. error=%d (0x%x)", (add ? "Create" : "Delete"), dwResult, (ULONG_PTR)dwResult);
	}
	return dwResult;
}
