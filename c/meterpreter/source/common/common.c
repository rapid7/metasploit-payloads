/*!
 * @file common.c
 * @brief Definitions for various common components used across the Meterpreter suite.
 */
#include "common.h"

#ifdef _WIN32

#define SLEEP_MAX_SEC (MAXDWORD / 1000)

/*!
 * @brief Returns a unix timestamp in UTC.
 * @return Integer value representing the UTC Unix timestamp of the current time.
 */
int current_unix_timestamp(void) {
	SYSTEMTIME system_time;
	FILETIME file_time;
	ULARGE_INTEGER ularge;

	GetSystemTime(&system_time);
	SystemTimeToFileTime(&system_time, &file_time);

	ularge.LowPart = file_time.dwLowDateTime;
	ularge.HighPart = file_time.dwHighDateTime;
	return (long)((ularge.QuadPart - 116444736000000000) / 10000000L);
}

/*!
 * @brief Sleep for the given number of seconds.
 * @param seconds DWORD value representing the number of seconds to sleep.
 * @remark This was implemented so that extended sleep times can be used (beyond the
 *         49 day limit imposed by Sleep()).
 */
VOID sleep(DWORD seconds)
{
	while (seconds > SLEEP_MAX_SEC)
	{
		Sleep(SLEEP_MAX_SEC * 1000);
		seconds -= SLEEP_MAX_SEC;
	}
	Sleep(seconds * 1000);
}

#else

#include <sys/time.h>

/*!
 * @brief Returns a unix timestamp in UTC.
 * @return Integer value representing the UTC Unix timestamp of the current time.
 */
int current_unix_timestamp(void) {
	struct timeval tv;
	struct timezone tz;

	memset(&tv, 0, sizeof(tv));
	memset(&tz, 0, sizeof(tz));

	gettimeofday(&tv, &tz);
	return (long) tv.tv_usec;
}
#endif

#ifndef _WIN32

int debugging_enabled;

/*!
 * @brief Writes debug to a temporary file based on the current PID.
 */
void real_dprintf(char *filename, int line, const char *function, char *format, ...)
{
	va_list args;
	char buffer[2048];
	int size;
	static int fd;
	int retried = 0;

	filename = basename(filename);
	size = snprintf(buffer, sizeof(buffer), "[%s:%d (%s)] ", filename, line, function);

	va_start(args, format);
	vsnprintf(buffer + size, sizeof(buffer) - size, format, args);
	strcat(buffer, "\n");
	va_end(args);

retry_log:
	if(fd <= 0) {
		char filename[128];
		sprintf(filename, "/tmp/meterpreter.log.%d%s", getpid(), retried ? ".retry" : "" );

		fd = open(filename, O_RDWR|O_TRUNC|O_CREAT|O_SYNC, 0644);

		if(fd <= 0) return;
	}

	if(write(fd, buffer, strlen(buffer)) == -1 && (errno == EBADF)) {
		fd = -1;
		retried++;
		goto retry_log;
	}
}

void enable_debugging()
{
	debugging_enabled = 1;
}

#endif

VOID xor_bytes(DWORD xorKey, LPBYTE buffer, DWORD bufferSize)
{
	static BOOL initialised = FALSE;
	if (!initialised)
	{
		srand((unsigned int)time(NULL));
		initialised = TRUE;
	}

	LPBYTE xor = (LPBYTE)&xorKey;

	for (DWORD i = 0; i < bufferSize; ++i)
	{
		buffer[i] ^= xor[i % sizeof(DWORD)];
	}
}
