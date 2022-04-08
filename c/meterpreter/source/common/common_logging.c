#include "common.h"
HANDLE lock = NULL;
HANDLE hFile = NULL;

HANDLE initLogging(wchar_t* filePath) {
	hFile = CreateFileW(filePath,                // name of the write
		GENERIC_WRITE,          // open for writing
		FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,    // do share (7)
		NULL,                   // default security
		CREATE_ALWAYS,             // create new file always
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template
	lock = CreateMutex(NULL, FALSE, NULL);

	if (hFile == NULL) {
        dprintf("[LOGGING] Logging to file failed to initialize");
	}
	return hFile;
}

void logToFile(char* buffer) {
    if (hFile) {
        WaitForSingleObject(lock, INFINITE);

        LPDWORD bytesWritten = 0;
        WriteFile(hFile, buffer, (DWORD)strlen(buffer), bytesWritten, NULL);
        ReleaseMutex(lock);
    }
}

HANDLE getLoggingContext() {
	return hFile;
}

HANDLE getLock() {
	return lock;
}

void setLoggingContext(HANDLE ctx, HANDLE lock1) {
	hFile = ctx;
	lock = lock1;
}