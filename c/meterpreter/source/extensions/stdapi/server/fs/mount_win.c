#include "precomp.h"

#pragma comment(lib, "mpr.lib")

// each drive is in the form "A:\\\0" (4 chars), plus a NULL terminator at the end
#define DRIVE_STRINGS_LEN (4 * 26 + 1)

DWORD request_fs_mount_show(Remote *remote, Packet *packet)
{
	DWORD dwResult = ERROR_SUCCESS;
	Packet *response = packet_create_response(packet);

	CHAR driveStrings[DRIVE_STRINGS_LEN] = { 0 };

	do
	{
		if (GetLogicalDriveStringsA(DRIVE_STRINGS_LEN, driveStrings) == 0)
		{
			BREAK_ON_ERROR("[MOUNT] Failed to get drive strings");
		}

		dprintf("[MOUNT] enumerating %p ... ", driveStrings);

		for (CHAR* d = driveStrings; *d != '\0'; d += strlen(d) + 1)
		{
			dprintf("[MOUNT] Drive found: %s", d);

			Packet* driveData = packet_create_group();
			UINT driveType = GetDriveTypeA(d);
			dprintf("[MOUNT] %s drive type %u (0x%x)", d, driveType, driveType);

			packet_add_tlv_string(driveData, TLV_TYPE_MOUNT_NAME, d);
			packet_add_tlv_uint(driveData, TLV_TYPE_MOUNT_TYPE, driveType);

			// get network UNC path if it's a network drive
			if (driveType == DRIVE_REMOTE)
			{
				dprintf("[MOUNT] %s is a remote drive", d);
				DWORD bufSize = 0;
				CHAR temp;
				if (WNetGetUniversalNameA(d, UNIVERSAL_NAME_INFO_LEVEL, &temp, &bufSize) == ERROR_MORE_DATA)
				{
					dprintf("[MOUNT] %s remote name requires bytes: %u", d, bufSize);
					LPVOID buffer = malloc(bufSize + 1);
					dprintf("[MOUNT] %s allocated %p", d, buffer);
					if (WNetGetUniversalNameA(d, UNIVERSAL_NAME_INFO_LEVEL, buffer, &bufSize) == NO_ERROR)
					{
						dprintf("[MOUNT] %s got universal name", d);
						UNIVERSAL_NAME_INFOA* nameInfo = (UNIVERSAL_NAME_INFOA*)buffer;
						if (nameInfo->lpUniversalName)
						{
							packet_add_tlv_string(driveData, TLV_TYPE_MOUNT_UNCPATH, nameInfo->lpUniversalName);
						}
					}
					else
					{
						dprintf("[MOUNT] %s failed to get remote name: %u (0x%x)", d, GetLastError(), GetLastError());
					}
					SAFE_FREE(buffer);
				}
				else
				{
					dprintf("[MOUNT] %s failed to get remote name size: %u (0x%x)", d, GetLastError(), GetLastError());
				}
			}

			ULARGE_INTEGER userFreeBytes, totalBytes, totalFreeBytes;
			dprintf("[MOUNT] %s getting free space ...", d);
			if (GetDiskFreeSpaceExA(d, &userFreeBytes, &totalBytes, &totalFreeBytes) != 0)
			{
				packet_add_tlv_qword(driveData, TLV_TYPE_MOUNT_SPACE_USER, userFreeBytes.QuadPart);
				packet_add_tlv_qword(driveData, TLV_TYPE_MOUNT_SPACE_TOTAL, totalBytes.QuadPart);
				packet_add_tlv_qword(driveData, TLV_TYPE_MOUNT_SPACE_FREE, totalFreeBytes.QuadPart);
			}

			packet_add_group(response, TLV_TYPE_MOUNT, driveData);
		}
	} while (0);

	packet_transmit_response(dwResult, remote, response);

	return ERROR_SUCCESS;
}