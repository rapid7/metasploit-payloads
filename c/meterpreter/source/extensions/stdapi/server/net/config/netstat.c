#include "precomp.h"

#include "common_metapi.h"

// Note: both connection_entry and connection_table were moved from
// common.h into here because:
// 1) connection_table contains a zero-length array which causes all C++
//    compiles to throw warnings.
// 2) These two structures are only used by this file anyway.

struct connection_entry {
	char type; // AF_INET / AF_INET6
	union {
		__u32  addr;
		__u128 addr6;
	} local_addr;
	union {
		__u32  addr;
		__u128 addr6;
	} remote_addr;
	__u32 local_port;
	__u32 remote_port;
	unsigned char protocol[5]; // tcp/tcp6/udp/udp6
	unsigned char state[15]; // established, syn_sent..
	__u32 uid;
	__u32 inode;
	unsigned char program_name[30]; // pid/program_name or "-"
};

struct connection_table {
	int entries;
	int max_entries;
	struct connection_entry table[0];
};

/*
 * check if there is enough place for another connection entry and allocate some more
 * memory if necessary
 */
DWORD check_and_allocate(struct connection_table **table_connection)
{
	DWORD newsize;
	struct connection_table * tmp_table;

	if ((*table_connection)->entries >= (*table_connection)->max_entries) {
			newsize = sizeof(struct connection_table);
			newsize += ((*table_connection)->entries + 10) * sizeof(struct connection_entry);
			tmp_table = (struct connection_table *)realloc(*table_connection, newsize);
			if (tmp_table == NULL) {
				free(*table_connection);
				return ERROR_NOT_ENOUGH_MEMORY;
			}

			*table_connection = tmp_table;
			memset(&(*table_connection)->table[(*table_connection)->entries], 0, 10 * sizeof(struct connection_entry));
			(*table_connection)->max_entries += 10;
	}
	return ERROR_SUCCESS;
}

/*
 * write pid/process_name in buffer
 */

DWORD set_process_name(DWORD pid, char * buffer, DWORD buffer_size)
{
	HANDLE hSnapshot;

	hSnapshot = met_api->win_api.kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32W pe32;
		pe32.dwSize = sizeof(PROCESSENTRY32W);
		if (met_api->win_api.kernel32.Process32FirstW(hSnapshot, &pe32)) {
			do {
				if (pe32.th32ProcessID == pid) {
					_snprintf_s(buffer, buffer_size-1, _TRUNCATE, "%d/%S", pid, pe32.szExeFile);
					break;
				}
			} while (met_api->win_api.kernel32.Process32NextW(hSnapshot, &pe32));
		}
		met_api->win_api.kernel32.CloseHandle(hSnapshot);
	}
	return ERROR_SUCCESS;
}

char *tcp_connection_states[] = {
   "", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT",
   "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB", "UNKNOWN" };

#ifndef __MINGW32__
typedef struct _MIB_TCP6ROW_OWNER_MODULE {
  UCHAR         ucLocalAddr[16];
  DWORD         dwLocalScopeId;
  DWORD         dwLocalPort;
  UCHAR         ucRemoteAddr[16];
  DWORD         dwRemoteScopeId;
  DWORD         dwRemotePort;
  DWORD         dwState;
  DWORD         dwOwningPid;
  LARGE_INTEGER liCreateTimestamp;
  ULONGLONG     OwningModuleInfo[TCPIP_OWNING_MODULE_SIZE];
} MIB_TCP6ROW_OWNER_MODULE, *PMIB_TCP6ROW_OWNER_MODULE;

typedef struct _MIB_UDP6ROW_OWNER_MODULE {
  UCHAR         ucLocalAddr[16];
  DWORD         dwLocalScopeId;
  DWORD         dwLocalPort;
  DWORD         dwOwningPid;
  LARGE_INTEGER liCreateTimestamp;
  union {
    struct {
      int SpecificPortBind  :1;
    };
    int    dwFlags;
  };
  ULONGLONG     OwningModuleInfo[TCPIP_OWNING_MODULE_SIZE];
} MIB_UDP6ROW_OWNER_MODULE, *PMIB_UDP6ROW_OWNER_MODULE;

typedef struct _MIB_TCP6TABLE_OWNER_MODULE {
  DWORD                    dwNumEntries;
  MIB_TCP6ROW_OWNER_MODULE table[ANY_SIZE];
} MIB_TCP6TABLE_OWNER_MODULE, *PMIB_TCP6TABLE_OWNER_MODULE;

typedef struct {
  DWORD                    dwNumEntries;
  MIB_UDP6ROW_OWNER_MODULE table[ANY_SIZE];
} MIB_UDP6TABLE_OWNER_MODULE, *PMIB_UDP6TABLE_OWNER_MODULE;

#endif

/*
 * retrieve tcp table for win 2000 and NT4 ?
 */
DWORD get_tcp_table_win2000_down(struct connection_table **table_connection)
{
	PMIB_TCPTABLE pTcpTable = NULL;
	struct connection_entry * current_connection;
	DWORD dwSize = 0;
	DWORD dwRetVal = 0;
	DWORD result = ERROR_SUCCESS;
	DWORD i, state;

	do {
		dwRetVal = met_api->win_api.iphlpapi.GetTcpTable(pTcpTable, &dwSize, TRUE);
		dprintf("[NETSTAT TCP] need %d bytes",dwSize);
		/* Get the size required by GetTcpTable() */
		if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
			pTcpTable = (MIB_TCPTABLE *) malloc (dwSize);
		}
		else if (dwRetVal != NO_ERROR) {
				result = ERROR_NOT_SUPPORTED;
				break;
		}

		if ((dwRetVal = met_api->win_api.iphlpapi.GetTcpTable(pTcpTable, &dwSize, TRUE)) == NO_ERROR) {
			dprintf("[NETSTAT] found %d tcp connections", pTcpTable->dwNumEntries);
			for (i = 0 ; i < pTcpTable->dwNumEntries ; i++) {
				// check available memory and allocate if necessary
				if (check_and_allocate(table_connection) == ERROR_NOT_ENOUGH_MEMORY) {
					free(pTcpTable);
					return ERROR_NOT_ENOUGH_MEMORY;
				}
				current_connection = &(*table_connection)->table[(*table_connection)->entries];
				current_connection->type             = AF_INET;
				current_connection->local_addr.addr  = pTcpTable->table[i].dwLocalAddr;
				current_connection->remote_addr.addr = pTcpTable->table[i].dwRemoteAddr;
				current_connection->local_port       = met_api->win_api.ws2_32.ntohs((u_short)(pTcpTable->table[i].dwLocalPort & 0x0000ffff));
				// if socket is in LISTEN, remote_port is garbage, force value to 0
				if (pTcpTable->table[i].dwState == MIB_TCP_STATE_LISTEN)
					current_connection->remote_port  = 0;
				else
					current_connection->remote_port  = met_api->win_api.ws2_32.ntohs((u_short)(pTcpTable->table[i].dwRemotePort & 0x0000ffff));

				state = pTcpTable->table[i].dwState;
				if ((state <= 0) || (state > 12))
					state = 13; // points to UNKNOWN in the state array
				strncpy_s((char*)current_connection->state, sizeof(current_connection->state), tcp_connection_states[state], sizeof(current_connection->state));
				strncpy_s((char*)current_connection->protocol, sizeof(current_connection->protocol), "tcp", sizeof(current_connection->protocol));

				// force program_name to "-"
				strncpy_s((char*)current_connection->program_name, sizeof(current_connection->program_name), "-", sizeof(current_connection->program_name));

				(*table_connection)->entries++;
			}
			free(pTcpTable);
		}
		else { // GetTcpTable failed
			result = met_api->win_api.kernel32.GetLastError();
			break;
		}
	} while (0) ;

	return result;
}

/*
 * retrieve tcp table for win xp and up
 */
DWORD get_tcp_table(struct connection_table **table_connection)
{
	DWORD result = ERROR_SUCCESS;
	struct connection_entry * current_connection = NULL;
	MIB_TCPTABLE_OWNER_MODULE  * tablev4 = NULL;
	MIB_TCP6TABLE_OWNER_MODULE * tablev6 = NULL;
	MIB_TCPROW_OWNER_MODULE  * currentv4 = NULL;
	MIB_TCP6ROW_OWNER_MODULE * currentv6 = NULL;
	DWORD i, state, dwSize, tableResult;

	do {
		// IPv4 part
		dwSize = 0;
		tableResult = met_api->win_api.iphlpapi.GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0);
		// Systems that don't support GetExtendedTcpTable use the legacy table.
		if (tableResult == ERROR_PROC_NOT_FOUND) {
			return get_tcp_table_win2000_down(table_connection);
		}
		if (tableResult == ERROR_INSUFFICIENT_BUFFER) {
			tablev4 = (MIB_TCPTABLE_OWNER_MODULE *)malloc(dwSize);
			tableResult = met_api->win_api.iphlpapi.GetExtendedTcpTable(tablev4, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_MODULE_ALL, 0);
			if (tableResult == NO_ERROR) {
				for(i=0; i<tablev4->dwNumEntries; i++) {
					// check available memory and allocate if necessary
					if (check_and_allocate(table_connection) == ERROR_NOT_ENOUGH_MEMORY) {
						free(tablev4);
						return ERROR_NOT_ENOUGH_MEMORY;
					}
					currentv4 = &tablev4->table[i];
					current_connection = &(*table_connection)->table[(*table_connection)->entries];
					current_connection->type             = AF_INET;
					current_connection->local_addr.addr  = currentv4->dwLocalAddr;
					current_connection->remote_addr.addr = currentv4->dwRemoteAddr;
					current_connection->local_port       = met_api->win_api.ws2_32.ntohs((u_short)(currentv4->dwLocalPort & 0x0000ffff));
					// if socket is in LISTEN, remote_port is garbage, force value to 0
					if (currentv4->dwState == MIB_TCP_STATE_LISTEN)
						current_connection->remote_port  = 0;
					else
						current_connection->remote_port  = met_api->win_api.ws2_32.ntohs((u_short)(currentv4->dwRemotePort & 0x0000ffff));

					state = currentv4->dwState;
					if ((state <= 0) || (state > 12))
						state = 13; // points to UNKNOWN in the state array
					strncpy((char*)current_connection->state, tcp_connection_states[state], sizeof(current_connection->state) - 1);
					strncpy((char*)current_connection->protocol, "tcp", sizeof(current_connection->protocol) - 1);

					// force program_name to "-" and try to get real name through GetOwnerModuleFromXXXEntry
					strncpy((char*)current_connection->program_name, "-", sizeof(current_connection->program_name) - 1);

					set_process_name(currentv4->dwOwningPid, (char*)current_connection->program_name, sizeof(current_connection->program_name) - 1);

					(*table_connection)->entries++;
				}
			}
			else { // GetExtendedTcpTable failed
				result = tableResult;
				if (tablev4)
					free(tablev4);
				break;
			}
			if (tablev4)
				free(tablev4);
		}
		// IPv6 part
		dwSize = 0;
		tableResult = met_api->win_api.iphlpapi.GetExtendedTcpTable(NULL, &dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0);
		if (tableResult == ERROR_INSUFFICIENT_BUFFER) {
			tablev6 = (MIB_TCP6TABLE_OWNER_MODULE *)malloc(dwSize);
			tableResult = met_api->win_api.iphlpapi.GetExtendedTcpTable(tablev6, &dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_MODULE_ALL, 0);
			if (tableResult == NO_ERROR) {
				for(i=0; i<tablev6->dwNumEntries; i++) {
					// check available memory and allocate if necessary
					if (check_and_allocate(table_connection) == ERROR_NOT_ENOUGH_MEMORY) {
						free(tablev6);
						return ERROR_NOT_ENOUGH_MEMORY;
					}
					currentv6 = &tablev6->table[i];
					current_connection = &(*table_connection)->table[(*table_connection)->entries];
					current_connection->type             = AF_INET6;
					memcpy(&current_connection->local_addr.addr6, currentv6->ucLocalAddr, sizeof(current_connection->local_addr.addr6));
					memcpy(&current_connection->remote_addr.addr6, currentv6->ucRemoteAddr, sizeof(current_connection->remote_addr.addr6));
					current_connection->local_port       = met_api->win_api.ws2_32.ntohs((u_short)(currentv6->dwLocalPort & 0x0000ffff));
					// if socket is in LISTEN, remote_port is garbage, force value to 0
					if (currentv6->dwState == MIB_TCP_STATE_LISTEN)
						current_connection->remote_port  = 0;
					else
						current_connection->remote_port  = met_api->win_api.ws2_32.ntohs((u_short)(currentv6->dwRemotePort & 0x0000ffff));

					state = currentv6->dwState;
					if ((state <= 0) || (state > 12))
						state = 13; // points to UNKNOWN in the state array
					strncpy((char*)current_connection->state, tcp_connection_states[state], sizeof(current_connection->state) - 1);
					strncpy((char*)current_connection->protocol, "tcp6", sizeof(current_connection->protocol) - 1);

					// force program_name to "-" and try to get real name through GetOwnerModuleFromXXXEntry
					strncpy((char*)current_connection->program_name, "-", sizeof(current_connection->program_name) - 1);

					set_process_name(currentv6->dwOwningPid, (char*)current_connection->program_name, sizeof(current_connection->program_name));

					(*table_connection)->entries++;
				}
			}
			else { // GetExtendedTcpTable failed
				result = tableResult;
				if (tablev6)
					free(tablev6);
				break;
			}
			if (tablev6)
				free(tablev6);
		}

	} while (0);
	return result;
}

/*
 * retrieve udp table for win 2000 and NT4 ?
 */
DWORD get_udp_table_win2000_down(struct connection_table **table_connection)
{
	PMIB_UDPTABLE pUdpTable = NULL;
	struct connection_entry * current_connection;
	DWORD dwSize = 0;
	DWORD dwRetVal = 0;
	DWORD result = ERROR_SUCCESS;
	DWORD i;

	do {
		dwRetVal = met_api->win_api.iphlpapi.GetUdpTable(pUdpTable, &dwSize, TRUE);
		dprintf("[NETSTAT UDP] need %d bytes",dwSize);
		/* Get the size required by GetUdpTable() */
		if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
			pUdpTable = (MIB_UDPTABLE *) malloc (dwSize);
		}
		else if (dwRetVal != NO_ERROR) {
				result = ERROR_NOT_SUPPORTED;
				break;
		}

		if ((dwRetVal = met_api->win_api.iphlpapi.GetUdpTable(pUdpTable, &dwSize, TRUE)) == NO_ERROR) {
			dprintf("[NETSTAT] found %d udp connections", pUdpTable->dwNumEntries);
			for (i = 0 ; i < pUdpTable->dwNumEntries ; i++) {
				// check available memory and allocate if necessary
				if (check_and_allocate(table_connection) == ERROR_NOT_ENOUGH_MEMORY) {
					free(pUdpTable);
					return ERROR_NOT_ENOUGH_MEMORY;
				}
				// GetUdpTable reports only listening UDP sockets, not "active" ones
				current_connection = &(*table_connection)->table[(*table_connection)->entries];
				current_connection->type             = AF_INET;
				current_connection->local_addr.addr  = pUdpTable->table[i].dwLocalAddr;
				current_connection->remote_addr.addr = 0;
				current_connection->local_port       = met_api->win_api.ws2_32.ntohs((u_short)(pUdpTable->table[i].dwLocalPort & 0x0000ffff));
				current_connection->remote_port      = 0;

				// force state to ""
				strncpy((char*)current_connection->state, "", sizeof(current_connection->state) - 1);
				strncpy((char*)current_connection->protocol, "udp", sizeof(current_connection->protocol) - 1);

				// force program_name to "-"
				strncpy((char*)current_connection->program_name, "-", sizeof(current_connection->program_name) - 1);

				(*table_connection)->entries++;
			}
			free(pUdpTable);
		}
		else { // GetUdpTable failed
			result = met_api->win_api.kernel32.GetLastError();
			break;
		}
	} while (0) ;

	return result;
}


/*
 * retrieve udp table for win xp and up
 */
DWORD get_udp_table(struct connection_table **table_connection)
{
	DWORD result = ERROR_SUCCESS;
	struct connection_entry * current_connection = NULL;
	MIB_UDPTABLE_OWNER_MODULE  * tablev4 = NULL;
	MIB_UDP6TABLE_OWNER_MODULE * tablev6 = NULL;
	MIB_UDPROW_OWNER_MODULE  * currentv4 = NULL;
	MIB_UDP6ROW_OWNER_MODULE * currentv6 = NULL;
	DWORD i, dwSize, tableResult;

	do {
		// IPv4 part
		dwSize = 0;
		tableResult = met_api->win_api.iphlpapi.GetExtendedUdpTable(NULL, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_MODULE, 0);
		// Systems that don't support GetExtendedUdpTable use the legacy table.
		if (tableResult == ERROR_PROC_NOT_FOUND) {
			return get_udp_table_win2000_down(table_connection);
		}
		if (tableResult == ERROR_INSUFFICIENT_BUFFER) {
			tablev4 = (MIB_UDPTABLE_OWNER_MODULE *)malloc(dwSize);
			tableResult = met_api->win_api.iphlpapi.GetExtendedUdpTable(tablev4, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_MODULE, 0);
			if (tableResult == NO_ERROR) {
				for(i=0; i<tablev4->dwNumEntries; i++) {
					// check available memory and allocate if necessary
					if (check_and_allocate(table_connection) == ERROR_NOT_ENOUGH_MEMORY) {
						free(tablev4);
						return ERROR_NOT_ENOUGH_MEMORY;
					}
					// GetExtendedUdpTable reports only listening UDP sockets, not "active" ones
					currentv4 = &tablev4->table[i];
					current_connection = &(*table_connection)->table[(*table_connection)->entries];
					current_connection->type             = AF_INET;
					current_connection->local_addr.addr  = currentv4->dwLocalAddr;
					current_connection->remote_addr.addr = 0;
					current_connection->local_port       = met_api->win_api.ws2_32.ntohs((u_short)(currentv4->dwLocalPort & 0x0000ffff));
					current_connection->remote_port  = 0;

					strncpy((char*)current_connection->state, "", sizeof(current_connection->state) - 1);
					strncpy((char*)current_connection->protocol, "udp", sizeof(current_connection->protocol) - 1);

					// force program_name to "-" and try to get real name through GetOwnerModuleFromXXXEntry
					strncpy((char*)current_connection->program_name, "-", sizeof(current_connection->program_name) - 1);

					set_process_name(currentv4->dwOwningPid, (char*)current_connection->program_name, sizeof(current_connection->program_name));

					(*table_connection)->entries++;
				}
			}
			else { // GetExtendedUdpTable failed
				result = tableResult;
				if (tablev4)
					free(tablev4);
				break;
			}
			if (tablev4)
				free(tablev4);
		}
		// IPv6 part
		dwSize = 0;
		tableResult = met_api->win_api.iphlpapi.GetExtendedUdpTable(NULL, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0);
		if (tableResult == ERROR_INSUFFICIENT_BUFFER) {
			tablev6 = (MIB_UDP6TABLE_OWNER_MODULE *)malloc(dwSize);
			tableResult = met_api->win_api.iphlpapi.GetExtendedUdpTable(tablev6, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_MODULE, 0);
			if (tableResult == NO_ERROR) {
				for(i=0; i<tablev6->dwNumEntries; i++) {
					// check available memory and allocate if necessary
					if (check_and_allocate(table_connection) == ERROR_NOT_ENOUGH_MEMORY) {
						free(tablev6);
						return ERROR_NOT_ENOUGH_MEMORY;
					}
					currentv6 = &tablev6->table[i];
					current_connection = &(*table_connection)->table[(*table_connection)->entries];
					current_connection->type          = AF_INET6;
					memcpy(&current_connection->local_addr.addr6, currentv6->ucLocalAddr, sizeof(current_connection->local_addr.addr6));
					memset(&current_connection->remote_addr.addr6, 0, sizeof(current_connection->remote_addr.addr6));
					current_connection->local_port   = met_api->win_api.ws2_32.ntohs((u_short)(currentv6->dwLocalPort & 0x0000ffff));
					current_connection->remote_port  = 0;

					strncpy((char*)current_connection->state, "", sizeof(current_connection->state) - 1);
					strncpy((char*)current_connection->protocol, "udp6", sizeof(current_connection->protocol) - 1);

					// force program_name to "-" and try to get real name through GetOwnerModuleFromXXXEntry
					strncpy((char*)current_connection->program_name, "-", sizeof(current_connection->program_name) - 1);

					set_process_name(currentv6->dwOwningPid, (char*)current_connection->program_name, sizeof(current_connection->program_name));

					(*table_connection)->entries++;
				}
			}
			else { // GetExtendedUdpTable failed
				result = tableResult;
				if (tablev6)
					free(tablev6);
				break;
			}
			if (tablev6)
				free(tablev6);
		}

	} while (0);
	return result;

}



DWORD get_connection_table(Remote *remote, Packet *response)
{
	struct connection_table *table_connection = NULL;
	struct connection_entry * current_connection;
	DWORD dwRetVal;
	int index;
	DWORD local_port_be, remote_port_be;

	table_connection = (struct connection_table *)calloc(sizeof(struct connection_table) + 10 * sizeof(struct connection_entry), 1);
	table_connection->max_entries = 10;

	dwRetVal = get_tcp_table(&table_connection);
	if (dwRetVal == ERROR_NOT_ENOUGH_MEMORY)
		return ERROR_NOT_ENOUGH_MEMORY;

	dwRetVal = get_udp_table(&table_connection);
	if (dwRetVal == ERROR_NOT_ENOUGH_MEMORY)
		return ERROR_NOT_ENOUGH_MEMORY;


	for(index = 0; index < table_connection->entries; index++) {
		Tlv connection[7];
		current_connection = &table_connection->table[index];
		if (current_connection->type == AF_INET) {
			connection[0].header.type      = TLV_TYPE_LOCAL_HOST_RAW;
			connection[0].header.length    = sizeof(__u32);
			connection[0].buffer           = (PUCHAR)&current_connection->local_addr.addr;

			connection[1].header.type      = TLV_TYPE_PEER_HOST_RAW;
			connection[1].header.length    = sizeof(__u32);
			connection[1].buffer           = (PUCHAR)&current_connection->remote_addr.addr;
		}
		else {
			connection[0].header.type      = TLV_TYPE_LOCAL_HOST_RAW;
			connection[0].header.length    = sizeof(__u128);
			connection[0].buffer           = (PUCHAR)&current_connection->local_addr.addr6;

			connection[1].header.type      = TLV_TYPE_PEER_HOST_RAW;
			connection[1].header.length    = sizeof(__u128);
			connection[1].buffer           = (PUCHAR)&current_connection->remote_addr.addr6;
		}

		local_port_be = met_api->win_api.ws2_32.htonl(current_connection->local_port);
		connection[2].header.type      = TLV_TYPE_LOCAL_PORT;
		connection[2].header.length    = sizeof(__u32);
		connection[2].buffer           = (PUCHAR)&local_port_be;

		remote_port_be = met_api->win_api.ws2_32.htonl(current_connection->remote_port);
		connection[3].header.type      = TLV_TYPE_PEER_PORT;
		connection[3].header.length    = sizeof(__u32);
		connection[3].buffer           = (PUCHAR)&remote_port_be;

		connection[4].header.type      = TLV_TYPE_MAC_NAME;
		connection[4].header.length    = (DWORD)strlen((char*)current_connection->protocol) + 1;
		connection[4].buffer           = (PUCHAR)(current_connection->protocol);

		connection[5].header.type      = TLV_TYPE_SUBNET_STRING;
		connection[5].header.length    = (DWORD)strlen((char*)current_connection->state) + 1;
		connection[5].buffer           = (PUCHAR)(current_connection->state);

		connection[6].header.type      = TLV_TYPE_PROCESS_NAME;
		connection[6].header.length    = (DWORD)strlen((char*)current_connection->program_name) + 1;
		connection[6].buffer           = (PUCHAR)(current_connection->program_name);

		met_api->packet.add_tlv_group(response, TLV_TYPE_NETSTAT_ENTRY, connection, 7);
	}
	dprintf("sent %d connections", table_connection->entries);

	if (table_connection)
	{
		free(table_connection);
	}

	return ERROR_SUCCESS;
}

/*
 * Returns zero or more connection entries to the requestor from the connection list
 */
DWORD request_net_config_get_netstat(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	DWORD result;

	result = get_connection_table(remote, response);

	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

