/*!
 * @file window.c
 * @brief Definitions for window management functionality
 */
#include "extapi.h"
#include "window.h"

VOID add_enumerated_window(Packet *pResponse, QWORD qwHandle, const char* cpWindowTitle, DWORD dwProcessId);
DWORD enumerate_windows(Packet *response, BOOL bIncludeUnknown, QWORD parentWindow);

#ifdef _WIN32

/*! @brief The maximum number of characters extracted from a window title. */
#define MAX_WINDOW_TITLE 256

/*! @brief EnumChildWindows function pointer type. */
typedef BOOL(WINAPI * PENUMCHILDWINDOWS)(HWND hWndParent, WNDENUMPROC enumProc, LPARAM lparam);
/*! @brief GetWindowTextA function pointer type. */
typedef int (WINAPI * PGETWINDOWTEXA)(HWND hWnd, LPSTR lpString, int nMaxCount);
/*! @brief GetWindowThreadProcessId function pointer type. */
typedef DWORD(WINAPI * PGETWINDOWTHREADPROCESSID)(HWND hWnd, LPDWORD lpdwProcessId);

/*! @brief Container type used to maintain state across EnumChildWindows callback calls. */
typedef struct _EnumWindowsState
{
	Packet* pResponse;                                     ///< Pointer to the \c Packet to add results to.
	BOOL bIncludeUnknown;                                  ///< Flag indicating if unknown windows should be included.
	PGETWINDOWTEXA pGetWindowTextA;                        ///< Pointer to the GetWindowTextA function.
	PGETWINDOWTHREADPROCESSID pGetWindowThreadProcessId;   ///< Pointer to the GetWindowThreadProcessId function.
} EnumWindowsState;

/*!
 * @brief Callback used during enumeration of desktop Windows.
 * @hWnd Handle to the Window that was enumerated.
 * @hWnd lParam State value passed in during enumeration.
 * @returns Indication of whether to continue enumeration.
 *          This function always returns \c TRUE.
 */
BOOL CALLBACK enumerate_windows_callback(HWND hWnd, LPARAM lParam)
{
	char windowTitle[MAX_WINDOW_TITLE];
	DWORD dwThreadId = 0;
	DWORD dwProcessId = 0;
	EnumWindowsState* pState = (EnumWindowsState*)lParam;

	dprintf("[EXTAPI WINDOW] Enumerated window %x", hWnd);

	do
	{
		dprintf("[EXTAPI WINDOW] Getting window title %p", pState->pGetWindowTextA);
		if (pState->pGetWindowTextA(hWnd, windowTitle, MAX_WINDOW_TITLE) == 0)
		{
			dprintf("[EXTAPI WINDOW] Unable to get window title. Setting to <unknown>.");
			if (pState->bIncludeUnknown)
			{
				strncpy_s(windowTitle, MAX_WINDOW_TITLE, "<unknown>", MAX_WINDOW_TITLE - 1);
			}
			else
			{
				break;
			}
		}

		dprintf("[EXTAPI WINDOW] Getting process ID %p", pState->pGetWindowThreadProcessId);
		dwThreadId = pState->pGetWindowThreadProcessId(hWnd, &dwProcessId);

		dprintf("[EXTAPI WINDOW] Adding enumerated response");
		add_enumerated_window(pState->pResponse, (QWORD)hWnd, windowTitle, dwProcessId);
	} while (0);

	return TRUE;
}
#endif

/*!
 * @brief Perform enumeration of windows.
 * @param response Pointer to the \c Packet which will contain the response.
 * @param bIncludeUnknown Set to \c TRUE if unknown windows are to be included.
 * @param parentWindow Handle to the parent window to use for enumeration.
 *        Set this value to \c NULL to enumerate top-level windows.
 * @returns Indication success or failure.
 * @remark This function is currently only supported in Windows (not POSIX).
 */
DWORD enumerate_windows(Packet *response, BOOL bIncludeUnknown, QWORD parentWindow)
{
#ifdef _WIN32
	// currently we only support Windoze

	DWORD dwResult;
	HMODULE hUser32 = NULL;
	PENUMCHILDWINDOWS pEnumChildWindows;
	EnumWindowsState state;

	do
	{
		dprintf("[EXTAPI WINDOW] Loading user32.dll");
		if ((hUser32 = LoadLibraryA("user32.dll")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI WINDOW] Unable to load user32.dll");
		}

		dprintf("[EXTAPI WINDOW] Searching for GetWindowTextA");
		if ((state.pGetWindowTextA = (PGETWINDOWTEXA)GetProcAddress(hUser32, "GetWindowTextA")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI WINDOW] Unable to locate GetWindowTextA in user32.dll");
		}
		dprintf("[EXTAPI WINDOW] Found GetWindowTextA %p", state.pGetWindowTextA);

		dprintf("[EXTAPI WINDOW] Searching for GetWindowThreadProcessId");
		if ((state.pGetWindowThreadProcessId = (PGETWINDOWTHREADPROCESSID)GetProcAddress(hUser32, "GetWindowThreadProcessId")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI WINDOW] Unable to locate GetWindowThreadProcessId in user32.dll");
		}

		dprintf("[EXTAPI WINDOW] Found GetWindowThreadProcessId %p", state.pGetWindowThreadProcessId);

		state.pResponse = response;
		state.bIncludeUnknown = bIncludeUnknown;

		dprintf("[EXTAPI WINDOW] Searching for EnumChildWindows");
		if ((pEnumChildWindows = (PENUMCHILDWINDOWS)GetProcAddress(hUser32, "EnumChildWindows")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI WINDOW] Unable to locate EnumChildWindows in user32.dll");
		}

		dprintf("[EXTAPI WINDOW] Beginning enumeration of child windows with parent %u", parentWindow);
		if (!pEnumChildWindows(parentWindow != 0 ? (HWND)parentWindow : NULL, (WNDENUMPROC)enumerate_windows_callback, (LPARAM)&state))
		{
			BREAK_ON_ERROR("[EXTAPI WINDOW] Failed to enumerate child windows");
		}

		dwResult = ERROR_SUCCESS;
	} while (0);

	if (hUser32)
	{
		FreeLibrary(hUser32);
	}

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

/*!
 * @brief Handle the request for window enumeration.
 * @param remote Pointer to the \c Remote making the request.
 * @param packet Pointer to the request \c Packet.
 * @returns Indication of success or failure.
 */
DWORD request_window_enum(Remote *remote, Packet *packet)
{
	QWORD parentWindow = 0;
	DWORD dwResult = ERROR_SUCCESS;
	BOOL bIncludeUnknown = FALSE;
	Packet * response = packet_create_response(packet);

	do
	{
		if (!response)
		{
			dprintf("[EXTAPI WINDOW] Unable to create response packet");
			dwResult = ERROR_OUTOFMEMORY;
			break;
		}

		// Extract the specified parent window. If this is NULL, that's ok, as we'll
		// just enumerate top-level windows.
		parentWindow = packet_get_tlv_value_qword(packet, TLV_TYPE_EXT_WINDOW_ENUM_HANDLE);

		// Extract the flag that indicates of unknown windows should be included in the output
		bIncludeUnknown = packet_get_tlv_value_bool(packet, TLV_TYPE_EXT_WINDOW_ENUM_INCLUDEUNKNOWN);

		dprintf("[EXTAPI WINDOW] Beginning window enumeration");
		dwResult = enumerate_windows(response, bIncludeUnknown, parentWindow);

	} while (0);

	dprintf("[EXTAPI WINDOW] Transmitting response back to caller.");
	if (response)
	{
		packet_transmit_response(dwResult, remote, response);
	}

	return dwResult;
}

/*!
 * @brief Add an enumerated window to the response.
 * @param pResponse Pointer to the \c Response to add the window detail to.
 * @param qwHandle Handle to the window that was found/enumerated/
 * @param cpWindowTitle Title of the window.
 * @param dwProcessId ID of the process that the Window belongs to.
 */
VOID add_enumerated_window(Packet *pResponse, QWORD qwHandle, const char* cpWindowTitle, DWORD dwProcessId)
{
	Packet* pGroup = packet_create_group();

	packet_add_tlv_uint(pGroup, TLV_TYPE_EXT_WINDOW_ENUM_PID, dwProcessId);
	packet_add_tlv_qword(pGroup, TLV_TYPE_EXT_WINDOW_ENUM_HANDLE, qwHandle);
	packet_add_tlv_string(pGroup, TLV_TYPE_EXT_WINDOW_ENUM_TITLE, cpWindowTitle);

	packet_add_group(pResponse, TLV_TYPE_EXT_WINDOW_ENUM_GROUP, pGroup);
}
