#include "common.h"
#include "remote_thread.h"
#include "metapi.h"

/*! @brief Container structure for a client identifer used when creating remote threads with RtlCreateUserThread. */
typedef struct _MIMI_CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENTID;

/*!
 * @brief Helper function for creating a remote thread in a privileged process.
 * @param hProcess Handle to the target process.
 * @param sStackSize Size of the stack to use (if unsure, specify 0).
 * @param pvStartAddress Pointer to the function entry point that has been loaded into the target.
 * @param pvStartParam Pointer to the parameter to pass to the thread function.
 * @param dwCreateFlags Creation flags to use when creating the new thread.
 * @param pdwThreadId Pointer to the buffer that will receive the thread ID (optional).
 * @return Handle to the new thread.
 * @retval NULL Indicates an error, which can be retrieved with \c GetLastError().
 * @remark This function has been put in place to wrap up the handling of creating remote threads
 *         in privileged processes across all operating systems. In Windows XP and earlier, the
 *         \c CreateRemoteThread() function was sufficient to handle this case, however this changed
 *         in Vista and has been that way since. For Vista onwards, the use of the hidden API function
 *         \c RtlCreateUserThread() is required. This function attempts to use \c CreateRemoteThread()
 *         first and if that fails it will fall back to \c RtlCreateUserThread(). This means that the
 *         existing behaviour is kept for when running on XP and earlier, or when the user is already
 *         running within a privileged process.
 */
HANDLE create_remote_thread(HANDLE hProcess, SIZE_T sStackSize, LPVOID pvStartAddress, LPVOID pvStartParam, DWORD dwCreateFlags, LPDWORD pdwThreadId)
{
	NTSTATUS ntResult;
	BOOL bCreateSuspended;
	DWORD dwThreadId;
	HANDLE hThread;
	CLIENTID ClientId;

	if (pdwThreadId == NULL)
	{
		pdwThreadId = &dwThreadId;
	}

	hThread = met_api->win_api.kernel32.CreateRemoteThread(hProcess, NULL, sStackSize, (LPTHREAD_START_ROUTINE)pvStartAddress, pvStartParam, dwCreateFlags, pdwThreadId);

	// ERROR_NOT_ENOUGH_MEMORY is returned when the function fails due to insufficient privs
	// on Vista and later.
	if (GetLastError() == ERROR_NOT_ENOUGH_MEMORY)
	{
		dprintf("[REMOTETHREAD] CreateRemoteThread seems to lack permissions, trying alternative options");
		hThread = NULL;

		dprintf("[REMOTETHREAD] Attempting thread creation with RtlCreateUserThread");
		bCreateSuspended = (dwCreateFlags & CREATE_SUSPENDED) == CREATE_SUSPENDED;
		ntResult = met_api->win_api.ntdll.RtlCreateUserThread(hProcess, NULL, bCreateSuspended, 0, 0, 0, (PVOID)pvStartAddress, pvStartParam, &hThread, &ClientId);
		SetLastError(ntResult);

		if (ntResult == 0 && pdwThreadId)
		{
			*pdwThreadId = PtrToUint(ClientId.UniqueThread);
		}
	}

	return hThread;
}

