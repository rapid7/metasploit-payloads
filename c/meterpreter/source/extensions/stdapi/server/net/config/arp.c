#include "precomp.h"

DWORD get_arp_table(Remote *remote, Packet *response)
{
	PMIB_IPNETTABLE pIpNetTable = NULL;
	DWORD result = ERROR_SUCCESS;
	DWORD dwSize = 0;
	DWORD dwRetVal;
	DWORD i;
	char interface_index[10];

	do {
		dwRetVal = GetIpNetTable(NULL, &dwSize, 0);

		/* Get the size required by GetIpNetTable() */
		if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
			pIpNetTable = (MIB_IPNETTABLE *) malloc (dwSize);
		}

		else if ((dwRetVal != NO_ERROR) && (dwRetVal != ERROR_NO_DATA)) {
			result = ERROR_NOT_SUPPORTED;
			break;
		}

		if (pIpNetTable == NULL) {
			result = GetLastError();
			break;
		}

		if ((dwRetVal = GetIpNetTable(pIpNetTable, &dwSize, 0)) == NO_ERROR) {
			dprintf("[ARP] found %d arp entries", pIpNetTable->dwNumEntries);
			for (i = 0 ; i < pIpNetTable->dwNumEntries ; i++) {
				// send only dynamic or static entry
				if ((pIpNetTable->table[i].dwType == MIB_IPNET_TYPE_DYNAMIC) ||
					(pIpNetTable->table[i].dwType == MIB_IPNET_TYPE_STATIC)) {
					Tlv arp[3];
					// can't send interface name as it can be _big_, so send index instead
					sprintf_s(interface_index, sizeof(interface_index), "%d", pIpNetTable->table[i].dwIndex);

					arp[0].header.type   = TLV_TYPE_IP;
					arp[0].header.length = sizeof(DWORD);
					arp[0].buffer        = (PUCHAR)&pIpNetTable->table[i].dwAddr;

					arp[1].header.type   = TLV_TYPE_MAC_ADDR;
					arp[1].header.length = 6;
					arp[1].buffer        = (PUCHAR)pIpNetTable->table[i].bPhysAddr;

					arp[2].header.type   = TLV_TYPE_MAC_NAME;
					arp[2].header.length = (DWORD)strlen(interface_index) + 1;
					arp[2].buffer        = (PUCHAR)interface_index;

					packet_add_tlv_group(response, TLV_TYPE_ARP_ENTRY, arp, 3);
				}
			}
			free(pIpNetTable);
		}
		else { // GetIpNetTable failed
			result = GetLastError();
			break;
		}
	} while (0);

	return result;
}

/*
 * Returns zero or more arp entries to the requestor from the arp cache
 */
DWORD request_net_config_get_arp_table(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result;

	result = get_arp_table(remote, response);

	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

