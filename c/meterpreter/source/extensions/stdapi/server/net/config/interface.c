#include "precomp.h"

#ifdef _WIN32
#include <iptypes.h>
#include <ws2ipdef.h>
#endif

#ifdef _WIN32
DWORD get_interfaces_windows_mib(Remote *remote, Packet *response)
{
	DWORD tableSize = sizeof(MIB_IPADDRROW);
	DWORD index;
	MIB_IFROW iface;

	PMIB_IPADDRTABLE table = (PMIB_IPADDRTABLE)malloc(sizeof(PMIB_IPADDRTABLE));
	if (table == NULL)
	{
		return ERROR_OUTOFMEMORY;
	}

	// attempt with an insufficient buffer size
	DWORD result = GetIpAddrTable(table, &tableSize, TRUE);
	if (result == ERROR_INSUFFICIENT_BUFFER)
	{
		table = (PMIB_IPADDRTABLE)realloc(table, tableSize);

		if (table == NULL)
		{
			return ERROR_OUTOFMEMORY;
		}

		if (GetIpAddrTable(table, &tableSize, TRUE) != NO_ERROR)
		{
			free(table);
			return GetLastError();
		}
	}
	// it might have worked with a single row!
	else if (result != NO_ERROR)
	{
		free(table);
		return GetLastError();
	}

	// Enumerate the entries
	for (index = 0; index < table->dwNumEntries; index++)
	{
		Packet* group = packet_create_group();

		packet_add_tlv_uint(group, TLV_TYPE_INTERFACE_INDEX, table->table[index].dwIndex);
		packet_add_tlv_raw(group, TLV_TYPE_IP, (PUCHAR)&table->table[index].dwAddr, sizeof(DWORD));
		packet_add_tlv_raw(group, TLV_TYPE_NETMASK, (PUCHAR)&table->table[index].dwMask, sizeof(DWORD));

		iface.dwIndex = table->table[index].dwIndex;

		// If interface information can get gotten, use it.
		if (GetIfEntry(&iface) == NO_ERROR)
		{
			packet_add_tlv_raw(group, TLV_TYPE_MAC_ADDR, (PUCHAR)iface.bPhysAddr, iface.dwPhysAddrLen);
			packet_add_tlv_uint(group, TLV_TYPE_INTERFACE_MTU, iface.dwMtu);

			if (iface.bDescr)
			{
				packet_add_tlv_string(group, TLV_TYPE_MAC_NAME, iface.bDescr);
			}
		}

		// Add the interface group
		packet_add_group(response, TLV_TYPE_NETWORK_INTERFACE, group);
	}

	free(table);
	return ERROR_SUCCESS;
}

DWORD get_interfaces_windows(Remote *remote, Packet *response)
{
	DWORD result = ERROR_SUCCESS;

	ULONG flags = GAA_FLAG_INCLUDE_PREFIX
		| GAA_FLAG_SKIP_DNS_SERVER
		| GAA_FLAG_SKIP_MULTICAST
		| GAA_FLAG_SKIP_ANYCAST;

	LPSOCKADDR sockaddr;

	ULONG family = AF_UNSPEC;
	IP_ADAPTER_ADDRESSES *pAdapters = NULL;
	IP_ADAPTER_ADDRESSES *pCurr = NULL;
	ULONG outBufLen = 0;
	DWORD(WINAPI *gaa)(DWORD, DWORD, void *, void *, void *);

	// Use the newer version so we're guaranteed to have a large enough struct.
	// Unfortunately, using these probably means it won't compile on older
	// versions of Visual Studio.  =(
	IP_ADAPTER_UNICAST_ADDRESS_LH *pAddr = NULL;
	IP_ADAPTER_UNICAST_ADDRESS_LH *pPref = NULL;
	// IP_ADAPTER_PREFIX is only defined if NTDDI_VERSION > NTDDI_WINXP
	// Since we request older versions of things, we have to be explicit
	// when using newer structs.
	IP_ADAPTER_PREFIX_XP *pPrefix = NULL;

	// We can't rely on the `Length` parameter of the IP_ADAPTER_PREFIX_XP struct
	// to tell us if we're on Vista or not because it always comes out at 48 bytes
	// so we have to check the version manually.
	OSVERSIONINFOEX v;

	gaa = (DWORD(WINAPI *)(DWORD, DWORD, void*, void*, void*))GetProcAddress(
		GetModuleHandle("iphlpapi"), "GetAdaptersAddresses");
	if (!gaa)
	{
		dprintf("[INTERFACE] No 'GetAdaptersAddresses'. Falling back on get_interfaces_windows_mib");
		return get_interfaces_windows_mib(remote, response);
	}

	gaa(family, flags, NULL, pAdapters, &outBufLen);
	if (!(pAdapters = malloc(outBufLen)))
	{
		return ERROR_NOT_ENOUGH_MEMORY;
	}

	if (gaa(family, flags, NULL, pAdapters, &outBufLen))
	{
		result = GetLastError();
		goto out;
	}

	dprintf("[INTERFACE] pAdapters->Length = %d", pAdapters->Length);
	// According to http://msdn.microsoft.com/en-us/library/windows/desktop/aa366058(v=vs.85).aspx
	// the PIP_ADAPTER_PREFIX doesn't exist prior to XP SP1. We check for this via the `Length`
	// value, which is 72 in XP without an SP, but 144 in later versions.
	if (pAdapters->Length <= 72)
	{
		dprintf("[INTERFACE] PIP_ADAPTER_PREFIX is missing");
		result = get_interfaces_windows_mib(remote, response);
		goto out;
	}

	// we'll need to know the version later on
	memset(&v, 0, sizeof(v));
	v.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	GetVersionEx((LPOSVERSIONINFO)&v);

	// Enumerate the entries
	for (pCurr = pAdapters; pCurr; pCurr = pCurr->Next)
	{
		// Save the first prefix for later in case we don't have an OnLinkPrefixLength
		pPrefix = pCurr->FirstPrefix;

		Packet* group = packet_create_group();

		dprintf("[INTERFACE] Adding index: %u", pCurr->IfIndex);
		packet_add_tlv_uint(group, TLV_TYPE_INTERFACE_INDEX, pCurr->IfIndex);

		dprintf("[INTERFACE] Adding MAC");
		packet_add_tlv_raw(group, TLV_TYPE_MAC_ADDR, (PUCHAR)pCurr->PhysicalAddress, pCurr->PhysicalAddressLength);

		dprintf("[INTERFACE] Adding Description");
		packet_add_tlv_wstring(group, TLV_TYPE_MAC_NAME, pCurr->Description);

		dprintf("[INTERFACE] Adding MTU: %u", pCurr->Mtu);
		packet_add_tlv_uint(group, TLV_TYPE_INTERFACE_MTU, pCurr->Mtu);

		for (pAddr = (IP_ADAPTER_UNICAST_ADDRESS_LH*)pCurr->FirstUnicastAddress;
			pAddr; pAddr = pAddr->Next)
		{
			sockaddr = pAddr->Address.lpSockaddr;
			if (AF_INET != sockaddr->sa_family && AF_INET6 != sockaddr->sa_family)
			{
				// Skip interfaces that aren't IP
				continue;
			}

			DWORD prefix = 0;
			if (v.dwMajorVersion >= 6) {
				// Then this is Vista+ and the OnLinkPrefixLength member
				// will be populated
				dprintf("[INTERFACES] >= Vista, using prefix: %x", pAddr->OnLinkPrefixLength);
				prefix = htonl(pAddr->OnLinkPrefixLength);
			}
			else if (pPrefix)
			{
				dprintf("[INTERFACES] < Vista, using prefix: %x", pPrefix->PrefixLength);
				prefix = htonl(pPrefix->PrefixLength);
			}
			else
			{
				dprintf("[INTERFACES] < Vista, no prefix");
				prefix = 0;
			}

			if (prefix)
			{
				dprintf("[INTERFACE] Adding Prefix: %x", prefix);
				// the UINT value is already byte-swapped, so we add it as a raw instead of
				// swizzling the bytes twice.
				packet_add_tlv_raw(group, TLV_TYPE_IP_PREFIX, (PUCHAR)&prefix, sizeof(prefix));
			}

			if (sockaddr->sa_family == AF_INET)
			{
				dprintf("[INTERFACE] Adding IPv4 Address: %x", ((struct sockaddr_in *)sockaddr)->sin_addr);
				packet_add_tlv_raw(group, TLV_TYPE_IP, (PUCHAR)&(((struct sockaddr_in *)sockaddr)->sin_addr), 4);
			}
			else
			{
				dprintf("[INTERFACE] Adding IPv6 Address");
				packet_add_tlv_raw(group, TLV_TYPE_IP, (PUCHAR)&(((struct sockaddr_in6 *)sockaddr)->sin6_addr), 16);
				packet_add_tlv_raw(group, TLV_TYPE_IP6_SCOPE, (PUCHAR)&(((struct sockaddr_in6 *)sockaddr)->sin6_scope_id), sizeof(DWORD));
			}

		}
		// Add the interface group
		packet_add_group(response, TLV_TYPE_NETWORK_INTERFACE, group);
	}

out:
	free(pAdapters);

	return result;
}

#else /* _WIN32 */
int get_interfaces_linux(Remote *remote, Packet *response)
{
	struct ifaces_list *ifaces = NULL;
	int i;
	int result;
	uint32_t interface_index_bigendian, mtu_bigendian;
	DWORD allocd_entries = 10;

	dprintf("Grabbing interfaces");
	result = netlink_get_interfaces(&ifaces);
	dprintf("Got 'em");

	if (!result) {
		for (i = 0; i < ifaces->entries; i++) {
			Packet* group = packet_create_group();
			int tlv_cnt = 0;
			int j = 0;
			dprintf("Building TLV for iface %d", i);

			packet_add_tlv_string(group, TLV_TYPE_MAC_NAME, ifaces->ifaces[i].name);
			packet_add_tlv_raw(group, TLV_TYPE_MAC_ADDR, ifaces->ifaces[i].hwaddr, 6);
			packet_add_tlv_uint(group, TLV_TYPE_INTERFACE_MTU, ifaces->ifaces[i].mtu);
			packet_add_tlv_string(group, TLV_TYPE_INTERFACE_FLAGS, ifaces->ifaces[i].flags);
			packet_add_tlv_uint(group, TLV_TYPE_INTERFACE_INDEX, ifaces->ifaces[i].index);

			for (j = 0; j < ifaces->ifaces[i].addr_count; j++) {
				if (ifaces->ifaces[i].addr_list[j].family == AF_INET) {
					dprintf("ip addr for %s", ifaces->ifaces[i].name);
					packet_add_tlv_raw(group, TLV_TYPE_IP, (PUCHAR)&ifaces->ifaces[i].addr_list[j].ip.addr, sizeof(__u32));
					packet_add_tlv_raw(group, TLV_TYPE_NETMASK, (PUCHAR)&ifaces->ifaces[i].addr_list[j].nm.netmask, sizeof(__u32));
				} else {
					dprintf("-- ip six addr for %s", ifaces->ifaces[i].name);
					packet_add_tlv_raw(group, TLV_TYPE_IP, (PUCHAR)&ifaces->ifaces[i].addr_list[j].ip.addr6, sizeof(__u128));
					packet_add_tlv_raw(group, TLV_TYPE_NETMASK, (PUCHAR)&ifaces->ifaces[i].addr_list[j].nm.netmask6, sizeof(__u128));
				}
			}

			dprintf("Adding TLV to group");
			packet_add_group(response, TLV_TYPE_NETWORK_INTERFACE, group);
			dprintf("done Adding TLV to group");
		}
	}

	free(ifaces);

	return result;
}
#endif


/*
 * Returns zero or more local interfaces to the requestor
 */
DWORD request_net_config_get_interfaces(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;

#ifdef _WIN32
	result = get_interfaces_windows(remote, response);
#else
	result = get_interfaces_linux(remote, response);
#endif

	// Transmit the response if valid
	packet_transmit_response(result, remote, response);

	return result;
}




