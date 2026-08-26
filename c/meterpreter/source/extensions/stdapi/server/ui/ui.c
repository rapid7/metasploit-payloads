#include "precomp.h"
#include "common_metapi.h"

HMODULE hookLibrary = NULL;

/*
 * Extract and load the hook library
 */
DWORD extract_hook_library()
{
	HGLOBAL global = NULL;
	HRSRC fileHandle = NULL;
	LPVOID raw = NULL;
	DWORD rawSize = 0;
	DWORD result = ERROR_SUCCESS;
	CHAR tempFile[1024];
	FILE *fd = NULL;

	memset(tempFile, 0, sizeof(tempFile));

	do
	{
		met_api->win_api.kernel32.ExpandEnvironmentStringsA("%TEMP%\\hook.dll", tempFile,
				sizeof(tempFile) - 1);

		fileHandle = met_api->win_api.kernel32.FindResourceA(hAppInstance,
				MAKEINTRESOURCE(IDR_HOOK_DLL), "IMG");

		if (!fileHandle)
		{
			result = met_api->win_api.kernel32.GetLastError();
			break;
		}

		global  = met_api->win_api.kernel32.LoadResource(hAppInstance, fileHandle);
		raw     = met_api->win_api.kernel32.LockResource(global);
		rawSize = met_api->win_api.kernel32.SizeofResource(hAppInstance, fileHandle);

		met_api->win_api.kernel32.DeleteFileA(tempFile);

		// Write the file to disk
		if (met_api->win_api.kernel32.GetFileAttributesA(tempFile) == INVALID_FILE_ATTRIBUTES)
		{
			if ((fd = fopen(tempFile, "wb")))
			{
				fwrite(raw, 1, rawSize, fd);

				fclose(fd);
			}
			else
				result = met_api->win_api.kernel32.GetLastError();
		}

		// Try to load the library
		if (!(hookLibrary = met_api->win_api.kernel32.LoadLibraryA(tempFile)))
		{
			result = met_api->win_api.kernel32.GetLastError();
			break;
		}

	} while (0);

	return result;
}
