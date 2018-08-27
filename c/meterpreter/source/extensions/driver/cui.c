/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016
*
*  TITLE:       CUI.C
*
*  VERSION:     1.00
*
*  DATE:        18 Jan 2016
*
*  Console output.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* cuiPrintText
*
* Purpose:
*
* Output text to the console or file.
*
*/

/*
VOID cuiPrintText(
	_In_ HANDLE hOutConsole,
	_In_ LPWSTR lpText,
	_In_ BOOL ConsoleOutputEnabled,
	_In_ BOOL UseReturn
	)
{
	SIZE_T consoleIO;
	DWORD bytesIO;
	LPWSTR Buffer;

	if (lpText == NULL)
		return;

	consoleIO = _strlen(lpText);
	if ((consoleIO == 0) || (consoleIO > MAX_PATH * 4))
		return;

	consoleIO = consoleIO * sizeof(WCHAR) + 4 + sizeof(UNICODE_NULL);
	Buffer = (LPWSTR)RtlAllocateHeap(RtlGetCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, consoleIO);
	if (Buffer) {

		_strcpy(Buffer, lpText);
		if (UseReturn) _strcat(Buffer, TEXT("\r\n"));

		consoleIO = _strlen(Buffer);

		if (ConsoleOutputEnabled == TRUE) {
			WriteConsole(hOutConsole, Buffer, (DWORD)consoleIO, &bytesIO, NULL);
		}
		else {
			WriteFile(hOutConsole, Buffer, (DWORD)(consoleIO * sizeof(WCHAR)), &bytesIO, NULL);
		}
		RtlFreeHeap(RtlGetCurrentPeb()->ProcessHeap, 0, Buffer);
	}
}
*/