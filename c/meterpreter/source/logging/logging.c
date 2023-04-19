#ifdef DEBUGTRACE
#include "../common/common.h"

HANDLE lock = NULL;
HANDLE hFile = NULL;

HANDLE init_logging(wchar_t* filePath) {
	hFile = CreateFileW(filePath,                // name of the write
		GENERIC_WRITE,          // open for writing
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,    // do share (7)
		NULL,                   // default security
		OPEN_ALWAYS,             // create new file or open existing file
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template
	lock = CreateMutex(NULL, FALSE, NULL);

	if (hFile == NULL) {
		dprintf("[LOGGING] Logging to file failed to initialize");
	}
	return hFile;
}

void log_to_file(char* buffer) {
	if (hFile) {
		WaitForSingleObject(lock, INFINITE);

		DWORD bytesWritten = 0;
		WriteFile(hFile, buffer, (DWORD)strlen(buffer), &bytesWritten, NULL);
		ReleaseMutex(lock);
	}
}

HANDLE get_logging_context() {
	return hFile;
}

HANDLE get_lock() {
	return lock;
}

void set_logging_context(HANDLE ctx, HANDLE lock1) {
	hFile = ctx;
	lock = lock1;
}
#endif