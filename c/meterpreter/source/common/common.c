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

VOID xor_bytes(BYTE xorKey[4], LPBYTE buffer, DWORD bufferSize)
{
	dprintf("[XOR] XORing %u bytes with key %02x%02x%02x%02x", bufferSize, xorKey[0], xorKey[1], xorKey[2], xorKey[3]);
	for (DWORD i = 0; i < bufferSize; ++i)
	{
		buffer[i] ^= xorKey[i % 4];
	}
}

VOID rand_xor_key(BYTE buffer[4])
{
	static BOOL initialised = FALSE;
	if (!initialised)
	{
		srand((unsigned int)time(NULL));
		initialised = TRUE;
	}

	buffer[0] = (rand() % 254) + 1;
	buffer[1] = (rand() % 254) + 1;
	buffer[2] = (rand() % 254) + 1;
	buffer[3] = (rand() % 254) + 1;
}

BOOL is_null_guid(BYTE guid[sizeof(GUID)])
{
	return memcmp(guid, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", sizeof(guid)) == 0 ? TRUE : FALSE;
}