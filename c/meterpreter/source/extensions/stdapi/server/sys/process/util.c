#include "precomp.h"
#include "common_metapi.h"

DWORD copy_memory_to_process(HANDLE process, BOOLEAN allocate,
	LPVOID *buffer, DWORD length, DWORD prot);

/*
 * Executes a portion of code in the address space of the supplied process
 * and returns the exit code of the thread that is created
 *
 * FIXME: can-block
 */
DWORD execute_code_stub_in_process(HANDLE process, PVOID buffer, ULONG length,
	LPVOID parameter, DWORD parameterLength, LPDWORD rv)
{
	HANDLE thread = NULL;
	LPVOID paramInProcess = (LPVOID)parameter;
	LPVOID codeInProcess  = (LPVOID)buffer;
	DWORD  threadId;
	DWORD  result = ERROR_SUCCESS;
	DWORD  wait;

	do
	{ 
		// Copy the code and parameter storage
		if ((result = copy_memory_to_process(process, TRUE, &codeInProcess,
			length, PAGE_EXECUTE_READ)) != ERROR_SUCCESS)
		{
			break;
		}
		
		if ((result = copy_memory_to_process(process, TRUE, &paramInProcess,
			parameterLength, PAGE_EXECUTE_READWRITE)) != ERROR_SUCCESS)
		{
			break;
		}

		// Create the thread in the target process
		if (!(thread = met_api->thread.create_remote(process, 0, codeInProcess, paramInProcess, 0, &threadId)))
		{
			result = met_api->win_api.kernel32.GetLastError();
			break;
		}

		// Wait for the thread to terminate
		while ((wait = met_api->win_api.kernel32.WaitForSingleObjectEx(thread, 1000, TRUE)) != WAIT_OBJECT_0)
		{
			if (wait == WAIT_FAILED)
			{
				result = met_api->win_api.kernel32.GetLastError();
				break;
			}
		}
		
		if (rv)
		{
			met_api->win_api.kernel32.GetExitCodeThread(thread, rv);
		}

		// Free the memory in the process
		if ((!met_api->win_api.kernel32.VirtualFreeEx(process, codeInProcess, 0, MEM_RELEASE)) ||
		    (!met_api->win_api.kernel32.VirtualFreeEx(process, paramInProcess, 0, MEM_RELEASE)))
		{
			result = met_api->win_api.kernel32.GetLastError();
			break;
		}
	} while (0);

	// Close the thread handle if one was obtained
	if (thread)
	{
		met_api->win_api.kernel32.CloseHandle(thread);
	}

	return result;
}

/*
 * Copies memory to the target process, optionally allocating it
 */
DWORD copy_memory_to_process(HANDLE process, BOOLEAN allocate,
		LPVOID *buffer, DWORD length, DWORD prot)
{
	LPVOID remoteBuffer = *buffer;
	SIZE_T  written;
	DWORD  result = ERROR_SUCCESS;

	do
	{
		if (allocate)
		{
			// Allocate storage for the buffer
			if (!(remoteBuffer = met_api->win_api.kernel32.VirtualAllocEx(process, NULL, length, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
			{
				result = met_api->win_api.kernel32.GetLastError();
				break;
			}
		}

		// Copy the memory from local to remote
		if (!met_api->win_api.kernel32.WriteProcessMemory(process, remoteBuffer, *buffer, length, &written))
		{
			result = met_api->win_api.kernel32.GetLastError();
			break;
		}

		// Re-protect the region to have the protection mask specified
		if (prot != PAGE_EXECUTE_READWRITE)
		{
			DWORD old;

			if (!met_api->win_api.kernel32.VirtualProtectEx(process, remoteBuffer, length, prot, &old))
			{
				result = met_api->win_api.kernel32.GetLastError();
				break;
			}
		}
	} while (0);

	// Update the buffer pointer
	*buffer = remoteBuffer;

	return result;
}
