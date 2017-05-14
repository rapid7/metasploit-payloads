/*!
 * @file common.c
 * @brief Definitions for various common components used across the Meterpreter suite.
 */
#include "common.h"

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
