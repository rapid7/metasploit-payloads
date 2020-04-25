#include "precomp.h"
#include "common_metapi.h"
#include <windows.h>
#include <stdio.h>
#include "defs.h"

#define EpochTimeToSystemTime(epoch, sys) \
	{ \
		struct tm et; \
		localtime_s(&et, &epoch); \
		memset(sys, 0, sizeof(SYSTEMTIME)); \
		(sys)->wYear    = et.tm_year + 1900; \
		(sys)->wMonth   = et.tm_mon + 1; \
		(sys)->wDay     = et.tm_mday; \
		(sys)->wHour    = et.tm_hour; \
		(sys)->wMinute  = et.tm_min; \
		(sys)->wSecond  = et.tm_sec; \
	}

#define SystemTimeToEpochTime(sys, epoch) \
	{ \
		struct tm et; \
		memset(&et, 0, sizeof(et)); \
		et.tm_year = (sys)->wYear - 1900; \
		et.tm_mon  = (sys)->wMonth -1; \
		et.tm_mday = (sys)->wDay; \
		et.tm_hour = (sys)->wHour; \
		et.tm_min  = (sys)->wMinute; \
		et.tm_sec  = (sys)->wSecond; \
		*(epoch) = mktime(&et); \
	}

int SetFileBasicInfo(HANDLE file, FILE_BASIC_INFORMATION *file_info)
{
	HMODULE ntdll_handle = GetModuleHandle("ntdll.dll");
	if (ntdll_handle == NULL) {
		return -1;
	}

	NTSETINFORMATIONFILE NtSetInformationFile =
		(NTSETINFORMATIONFILE)GetProcAddress(ntdll_handle, "NtSetInformationFile");
	if (NtSetInformationFile == NULL) {
		return -1;
	}

	IO_STATUS_BLOCK status_block = {0};
	return NtSetInformationFile(file, &status_block, file_info,
			sizeof *file_info, FileBasicInformation);
}

int GetFileBasicInfo(HANDLE file, FILE_BASIC_INFORMATION *file_info)
{
	HMODULE ntdll_handle = GetModuleHandle("ntdll.dll");
	if (ntdll_handle == NULL) {
		return -1;
	}

	NTQUERYINFORMATIONFILE NtQueryInformationFile =
		(NTQUERYINFORMATIONFILE)GetProcAddress(ntdll_handle, "NtQueryInformationFile");
	if (NtQueryInformationFile == NULL) {
		return -1;
	}

	IO_STATUS_BLOCK status_block = {0};
	return NtQueryInformationFile(file, &status_block, file_info,
			sizeof *file_info, FileBasicInformation);
}

HANDLE FileOpen(char *filename)
{
	if (filename == NULL) {
		return NULL;
	}

	wchar_t *name = met_api->string.utf8_to_wchar(filename);
	if (name == NULL) {
		return NULL;
	}

	HANDLE file = CreateFileW(name,
		FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
		0, NULL, OPEN_EXISTING, 0, NULL);

	free(name);
	return file;
}

void FileClose(HANDLE file)
{
	if (file) {
		CloseHandle(file);
	}
}

int SystemTimeToLargeInteger(SYSTEMTIME in, LARGE_INTEGER *out) {

	FILETIME filetime;
	FILETIME utcfiletime;

    if (SystemTimeToFileTime(&in, &filetime) == 0 ||
			LocalFileTimeToFileTime(&filetime, &utcfiletime) == 0) {
		return -1;
	}

	out->LowPart = utcfiletime.dwLowDateTime;
	out->HighPart = utcfiletime.dwHighDateTime;

	return 0;
}

int LargeIntegerToSystemTime(SYSTEMTIME *localsystemtime, LARGE_INTEGER largeinteger) {

	FILETIME localfiletime;
	FILETIME filetime = {
		.dwLowDateTime = largeinteger.LowPart,
		.dwHighDateTime = largeinteger.HighPart
	};

	if (FileTimeToLocalFileTime(&filetime, &localfiletime) == 0 ||
    		FileTimeToSystemTime(&localfiletime, localsystemtime) == 0) {
		return -1;
	}

	return 0;
}

int SetFileTimes(HANDLE file, SYSTEMTIME time)
{
	FILE_BASIC_INFORMATION fbi;
	if (GetFileBasicInfo(file, &fbi)) {
		return -1;
	}

	LARGE_INTEGER time_int;
	if (SystemTimeToLargeInteger(time, &time_int)) {
		return -1;
	}

	fbi.ChangeTime = time_int;
	fbi.CreationTime = time_int;
	fbi.LastAccessTime = time_int;
	fbi.LastWriteTime = time_int;

	if (SetFileBasicInfo(file, &fbi)) {
		return -1;
	}

	return 0;
}

#define FS_MAX_PATH  32768

int SetDirectoryTimes(wchar_t * directory, SYSTEMTIME time)
{
	wchar_t firstFile[FS_MAX_PATH];
	swprintf_s(firstFile, FS_MAX_PATH, L"%s\\*", directory);

	WIN32_FIND_DATAW data;
	HANDLE file = FindFirstFileW(firstFile, &data);
	if (file != INVALID_HANDLE_VALUE) {
		do {
			if (wcscmp(data.cFileName, L".") && wcscmp(data.cFileName, L"..")) {
				/*
				 * Set the times for all entries in this directory
				 */
				HANDLE file = CreateFileW(data.cFileName,
					FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
					0, NULL, OPEN_EXISTING, 0, NULL);
				if (file) {
					SetFileTimes(file, time);
					CloseHandle(file);
				}
			}
		} while (FindNextFileW(file, &data) != 0);

		FindClose(file);
	} else {
		if (GetLastError() != ERROR_FILE_NOT_FOUND) {
			return GetLastError();
		}
	}

	return 0;
}

int SetDirectoryTimesRecursive(wchar_t *directory, SYSTEMTIME time, int depth)
{
	DWORD rc = ERROR_SUCCESS;
	BOOL searched = FALSE;
	WIN32_FIND_DATAW find_data = {0};
	size_t len = wcslen(directory) + 5;

	if (depth > 32 || len >= FS_MAX_PATH) {
		return ERROR_SUCCESS;
	}

	wchar_t *firstFile = calloc(len, sizeof(wchar_t));
	if (!firstFile) {
		return ERROR_SUCCESS;
	}

	swprintf_s(firstFile, FS_MAX_PATH, L"%s\\*.*", directory);

	HANDLE file = FindFirstFileW(firstFile, &find_data);
	if (file != INVALID_HANDLE_VALUE) {
		do {
			if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if (wcscmp(find_data.cFileName, L".") && wcscmp(find_data.cFileName, L"..")) {
					size_t len = wcslen(directory) + wcslen(find_data.cFileName) + 32;
					wchar_t *nextDirectory = calloc(len, sizeof(wchar_t));
					if (nextDirectory) {
						swprintf_s(nextDirectory, len, L"%s\\%s", directory, find_data.cFileName);
						rc = SetDirectoryTimesRecursive(nextDirectory, time, depth + 1);
						free(nextDirectory);
					}
				}
			} else if (!searched) {
				rc = SetDirectoryTimes(directory, time);
				searched = TRUE;
			}
		} while (FindNextFileW(file, &find_data) != 0);

		FindClose(file);

	} else {
		if (GetLastError() != ERROR_FILE_NOT_FOUND) {
			rc = GetLastError();
		}
	}

	free(firstFile);
	return rc;
}

DWORD request_fs_get_file_mace(Remote *remote, Packet *packet)
{
	SYSTEMTIME lt;
	Packet *response = met_api->packet.create_response(packet);
	HANDLE file = FileOpen(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_FS_FILE_PATH));

	if (file == NULL) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto err;
	}

	FILE_BASIC_INFORMATION fbi;
	struct {
		LARGE_INTEGER *ft;
		unsigned long tlv;
	} fields[] = {
		{ &fbi.LastWriteTime, TLV_TYPE_FS_FILE_MODIFIED },
		{ &fbi.LastAccessTime, TLV_TYPE_FS_FILE_ACCESSED },
		{ &fbi.CreationTime, TLV_TYPE_FS_FILE_CREATED },
		{ &fbi.ChangeTime, TLV_TYPE_FS_FILE_EMODIFIED },
	};

	if (GetFileBasicInfo(file, &fbi) != 0) {
		goto err;
	}

	for (int i = 0; i < 4; i++) {
		time_t epoch = 0;

		if (LargeIntegerToSystemTime(&lt, *fields[i].ft) == 0) {
			SystemTimeToEpochTime(&lt, &epoch);
			met_api->packet.add_tlv_uint(response, fields[i].tlv, (UINT)epoch);
		}
	}

	SetLastError(ERROR_SUCCESS);

err:
	FileClose(file);
	met_api->packet.transmit_response(GetLastError(), remote, response);
	return ERROR_SUCCESS;
}

DWORD request_fs_set_file_mace(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);

	HANDLE file = FileOpen(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_FS_FILE_PATH));
	if (!file) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto out;
	}

	FILE_BASIC_INFORMATION fbi;
	if (GetFileBasicInfo(file, &fbi) != 0) {
		goto out;
	}

	struct {
		LARGE_INTEGER *ft;
		unsigned long tlv;
	} fields[] = {
		{ &fbi.LastWriteTime,  TLV_TYPE_FS_FILE_MODIFIED  },
		{ &fbi.LastAccessTime, TLV_TYPE_FS_FILE_ACCESSED  },
		{ &fbi.CreationTime,   TLV_TYPE_FS_FILE_CREATED   },
		{ &fbi.ChangeTime,     TLV_TYPE_FS_FILE_EMODIFIED },
	};
	for (int i = 0; i < 4; i++) {
		time_t epoch = met_api->packet.get_tlv_value_uint(packet, (TlvType)fields[i].tlv);
		if (epoch) {
			SYSTEMTIME st;
			EpochTimeToSystemTime(epoch, &st);
			SystemTimeToLargeInteger(st, fields[i].ft);
		}
	}

	if (SetFileBasicInfo(file, &fbi)) {
		goto out;
	}

	SetLastError(ERROR_SUCCESS);

out:
	FileClose(file);
	met_api->packet.transmit_response(GetLastError(), remote, response);
	return ERROR_SUCCESS;
}

DWORD request_fs_set_file_mace_from_file(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);

	HANDLE tgtFile = FileOpen(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_FS_FILE_PATH));
	HANDLE srcFile = FileOpen(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_FS_SRC_FILE_PATH));
	if (tgtFile == NULL || srcFile == NULL) {
		goto out;
	}

	FILE_BASIC_INFORMATION fbi;
	if (GetFileBasicInfo(tgtFile, &fbi) != 0) {
		goto out;
	}

	ULONG attributes = fbi.FileAttributes;

	if (GetFileBasicInfo(srcFile, &fbi) != 0) {
		goto out;
	}

	fbi.FileAttributes = attributes;

	if (SetFileBasicInfo(tgtFile, &fbi) != 0) {
		goto out;
	}

	SetLastError(ERROR_SUCCESS);

out:
	FileClose(srcFile);
	FileClose(tgtFile);

	met_api->packet.transmit_response(GetLastError(), remote, response);
	return ERROR_SUCCESS;
}

static SYSTEMTIME epoch = {
	.wYear = 1601,
	.wMonth = 1,
	.wDayOfWeek = 0,
	.wDay = 1,
	.wHour = 0,
	.wMinute = 0,
	.wSecond = 0,
	.wMilliseconds = 0
};

DWORD request_fs_blank_file_mace(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);

	HANDLE file = FileOpen(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_FS_FILE_PATH));
	if (!file) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto out;
	}

	if (SetFileTimes(file, epoch) != 0) {
		goto out;
	}

	SetLastError(ERROR_SUCCESS);

out:
	FileClose(file);
	met_api->packet.transmit_response(GetLastError(), remote, response);
	return ERROR_SUCCESS;
}

DWORD request_fs_blank_directory_mace(Remote *remote, Packet *packet)
{
	Packet *response = met_api->packet.create_response(packet);
	wchar_t *filePath = met_api->string.utf8_to_wchar(met_api->packet.get_tlv_value_string(packet, TLV_TYPE_FS_FILE_PATH));

	if (filePath == NULL) {
		SetLastError(ERROR_INVALID_PARAMETER);
		goto out;
	}

	if (SetDirectoryTimesRecursive(filePath, epoch, 0) != 0) {
		goto out;
	}

	SetLastError(ERROR_SUCCESS);

out:
	free(filePath);
	met_api->packet.transmit_response(GetLastError(), remote, response);
	return ERROR_SUCCESS;
}
