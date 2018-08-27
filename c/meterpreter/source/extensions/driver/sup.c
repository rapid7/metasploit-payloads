/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2016
*
*  TITLE:       SUP.C
*
*  VERSION:     1.00
*
*  DATE:        01 Feb 2016
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"

/*
* supGetSystemInfo
*
* Purpose:
*
* Wrapper for NtQuerySystemInformation.
*
*/
PVOID supGetSystemInfo(
	_In_ SYSTEM_INFORMATION_CLASS InfoClass
	)
{
	INT         c = 0;
	PVOID       Buffer = NULL;
	ULONG		Size = 0x1000;
	NTSTATUS    status;
	ULONG       memIO;
	PVOID       hHeap = NtCurrentPeb()->ProcessHeap;

	do {
		Buffer = RtlAllocateHeap(hHeap, HEAP_ZERO_MEMORY, (SIZE_T)Size);
		if (Buffer != NULL) {
			status = NtQuerySystemInformation(InfoClass, Buffer, Size, &memIO);
		}
		else {
			return NULL;
		}
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			RtlFreeHeap(hHeap, 0, Buffer);
			Size *= 2;
			c++;
			if (c > 100) {
				status = STATUS_SECRET_TOO_LONG;
				break;
			}
		}
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (NT_SUCCESS(status)) {
		return Buffer;
	}

	if (Buffer) {
		RtlFreeHeap(hHeap, 0, Buffer);
	}
	return NULL;
}

/*
* supGetNtOsBase
*
* Purpose:
*
* Return ntoskrnl base address.
*
*/
ULONG_PTR supGetNtOsBase(
	VOID
	)
{
	PRTL_PROCESS_MODULES   miSpace;
	ULONG_PTR              NtOsBase = 0;

	miSpace = supGetSystemInfo(SystemModuleInformation);
	while (miSpace != NULL) {
		NtOsBase = (ULONG_PTR)miSpace->Modules[0].ImageBase;
		RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, miSpace);
		break;
	}
	return NtOsBase;
}

/*
* supQueryResourceData
*
* Purpose:
*
* Load resource by given id (win32 FindResource, SizeofResource, LockResource).
*
*/
PBYTE supQueryResourceData(
	_In_ ULONG_PTR ResourceId,
	_In_ PVOID DllHandle,
	_In_ PULONG DataSize
	)
{
	NTSTATUS                    status;
	ULONG_PTR                   IdPath[3];
	IMAGE_RESOURCE_DATA_ENTRY  *DataEntry;
	PBYTE                       Data = NULL;
	ULONG                       SizeOfData = 0;

	if (DllHandle != NULL) {

		IdPath[0] = (ULONG_PTR)RT_RCDATA; //type
		IdPath[1] = ResourceId;           //id
		IdPath[2] = 0;                    //lang

		status = LdrFindResource_U(DllHandle, (ULONG_PTR*)&IdPath, 3, &DataEntry);
		if (NT_SUCCESS(status)) {
			status = LdrAccessResource(DllHandle, DataEntry, &Data, &SizeOfData);
			if (NT_SUCCESS(status)) {
				if (DataSize) {
					*DataSize = SizeOfData;
				}
			}
		}
	}
	DbgPrint("[+] Exiting scmQueryResourceData SizeOfData: %d\n", SizeOfData);
	return Data;
}

/*
* supBackupVBoxDrv
*
* Purpose:
*
* Backup virtualbox driver file if it already installed.
*
*/
BOOL supBackupVBoxDrv(
	_In_ BOOL bRestore
	)
{
	BOOL  bResult = FALSE;
	WCHAR szOldDriverName[MAX_PATH * 2];
	WCHAR szNewDriverName[MAX_PATH * 2];
	WCHAR szDriverDirName[MAX_PATH * 2];

	if (!GetSystemDirectory(szDriverDirName, MAX_PATH)) {
		return FALSE;
	}

	_strcat(szDriverDirName, TEXT("\\drivers\\"));

	if (bRestore) {
		_strcpy(szOldDriverName, szDriverDirName);
		_strcat(szOldDriverName, TEXT("VBoxDrv.backup"));
		if (PathFileExists(szOldDriverName)) {
			_strcpy(szNewDriverName, szDriverDirName);
			_strcat(szNewDriverName, TEXT("VBoxDrv.sys"));
			bResult = MoveFileEx(szOldDriverName, szNewDriverName,
				MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
		}
	}
	else {
		_strcpy(szOldDriverName, szDriverDirName);
		_strcat(szOldDriverName, TEXT("VBoxDrv.sys"));
		_strcpy(szNewDriverName, szDriverDirName);
		_strcat(szNewDriverName, TEXT("VBoxDrv.backup"));
		bResult = MoveFileEx(szOldDriverName, szNewDriverName,
			MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
	}
	return bResult;
}

/*
* supWriteBufferToFile
*
* Purpose:
*
* Create new file (or open existing) and write (append) buffer to it.
*
*/
SIZE_T supWriteBufferToFile(
	_In_ PWSTR lpFileName,
	_In_ PVOID Buffer,
	_In_ SIZE_T Size,
	_In_ BOOL Flush,
	_In_ BOOL Append
	)
{
	NTSTATUS           Status;
	DWORD              dwFlag;
	HANDLE             hFile = NULL;
	OBJECT_ATTRIBUTES  attr;
	UNICODE_STRING     NtFileName;
	IO_STATUS_BLOCK    IoStatus;
	LARGE_INTEGER      Position;
	ACCESS_MASK        DesiredAccess;
	PLARGE_INTEGER     pPosition = NULL;
	ULONG_PTR          nBlocks, BlockIndex;
	ULONG              BlockSize, RemainingSize;
	PBYTE              ptr = (PBYTE)Buffer;
	SIZE_T             BytesWritten = 0;

	if (RtlDosPathNameToNtPathName_U(lpFileName, &NtFileName, NULL, NULL) == FALSE)
		return 0;

	DesiredAccess = FILE_WRITE_ACCESS | SYNCHRONIZE;
	dwFlag = FILE_OVERWRITE_IF;

	if (Append == TRUE) {
		DesiredAccess |= FILE_READ_ACCESS;
		dwFlag = FILE_OPEN_IF;
	}

	InitializeObjectAttributes(&attr, &NtFileName, OBJ_CASE_INSENSITIVE, 0, NULL);

	__try {
		Status = NtCreateFile(&hFile, DesiredAccess, &attr,
			&IoStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, dwFlag,
			FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);

		if (!NT_SUCCESS(Status))
			__leave;

		pPosition = NULL;

		if (Append == TRUE) {
			Position.LowPart = FILE_WRITE_TO_END_OF_FILE;
			Position.HighPart = -1;
			pPosition = &Position;
		}

		if (Size < 0x80000000) {
			BlockSize = (ULONG)Size;
			Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, BlockSize, pPosition, NULL);
			if (!NT_SUCCESS(Status))
				__leave;

			BytesWritten += IoStatus.Information;
		}
		else {
			BlockSize = 0x7FFFFFFF;
			nBlocks = (Size / BlockSize);
			for (BlockIndex = 0; BlockIndex < nBlocks; BlockIndex++) {

				Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, BlockSize, pPosition, NULL);
				if (!NT_SUCCESS(Status))
					__leave;

				ptr += BlockSize;
				BytesWritten += IoStatus.Information;
			}
			RemainingSize = Size % BlockSize;
			if (RemainingSize != 0) {
				Status = NtWriteFile(hFile, 0, NULL, NULL, &IoStatus, ptr, RemainingSize, pPosition, NULL);
				if (!NT_SUCCESS(Status))
					__leave;
				BytesWritten += IoStatus.Information;
			}
		}
	}
	__finally {
		if (hFile != NULL) {
			if (Flush == TRUE) NtFlushBuffersFile(hFile, &IoStatus);
			NtClose(hFile);
		}
		RtlFreeUnicodeString(&NtFileName);
	}
	return BytesWritten;
}

/*
* supDetectObjectCallback
*
* Purpose:
*
* Comparer callback routine used in objects enumeration.
*
*/
NTSTATUS NTAPI supDetectObjectCallback(
	_In_ POBJECT_DIRECTORY_INFORMATION Entry,
	_In_ PVOID CallbackParam
	)
{
	POBJSCANPARAM Param = (POBJSCANPARAM)CallbackParam;

	if (Entry == NULL) {
		return STATUS_INVALID_PARAMETER_1;
	}

	if (CallbackParam == NULL) {
		return STATUS_INVALID_PARAMETER_2;
	}

	if (Param->Buffer == NULL || Param->BufferSize == 0) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	if (Entry->Name.Buffer) {
		if (_strcmpi_w(Entry->Name.Buffer, Param->Buffer) == 0) {
			return STATUS_SUCCESS;
		}
	}
	return STATUS_UNSUCCESSFUL;
}

/*
* supEnumSystemObjects
*
* Purpose:
*
* Lookup object by name in given directory.
*
*/
NTSTATUS NTAPI supEnumSystemObjects(
	_In_opt_ LPWSTR pwszRootDirectory,
	_In_opt_ HANDLE hRootDirectory,
	_In_ PENUMOBJECTSCALLBACK CallbackProc,
	_In_opt_ PVOID CallbackParam
	)
{
	BOOL                cond = TRUE;
	ULONG               ctx, rlen;
	HANDLE              hDirectory = NULL;
	NTSTATUS            status;
	NTSTATUS            CallbackStatus;
	OBJECT_ATTRIBUTES   attr;
	UNICODE_STRING      sname;

	POBJECT_DIRECTORY_INFORMATION    objinf;

	if (CallbackProc == NULL) {
		return STATUS_INVALID_PARAMETER_4;
	}

	status = STATUS_UNSUCCESSFUL;

	__try {

		// We can use root directory.
		if (pwszRootDirectory != NULL) {
			RtlSecureZeroMemory(&sname, sizeof(sname));
			RtlInitUnicodeString(&sname, pwszRootDirectory);
			InitializeObjectAttributes(&attr, &sname, OBJ_CASE_INSENSITIVE, NULL, NULL);
			status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &attr);
			if (!NT_SUCCESS(status)) {
				return status;
			}
		}
		else {
			if (hRootDirectory == NULL) {
				return STATUS_INVALID_PARAMETER_2;
			}
			hDirectory = hRootDirectory;
		}

		// Enumerate objects in directory.
		ctx = 0;
		do {

			rlen = 0;
			status = NtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &ctx, &rlen);
			if (status != STATUS_BUFFER_TOO_SMALL)
				break;

			objinf = RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, rlen);
			if (objinf == NULL)
				break;

			status = NtQueryDirectoryObject(hDirectory, objinf, rlen, TRUE, FALSE, &ctx, &rlen);
			if (!NT_SUCCESS(status)) {
				RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, objinf);
				break;
			}

			CallbackStatus = CallbackProc(objinf, CallbackParam);

			RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, objinf);

			if (NT_SUCCESS(CallbackStatus)) {
				status = STATUS_SUCCESS;
				break;
			}

		} while (cond);

		if (hDirectory != NULL) {
			NtClose(hDirectory);
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = STATUS_ACCESS_VIOLATION;
	}

	return status;
}

/*
* supIsObjectExists
*
* Purpose:
*
* Return TRUE if the given object exists, FALSE otherwise.
*
*/
BOOL supIsObjectExists(
	_In_ LPWSTR RootDirectory,
	_In_ LPWSTR ObjectName
	)
{
	OBJSCANPARAM Param;

	if (ObjectName == NULL) {
		return FALSE;
	}

	Param.Buffer = ObjectName;
	Param.BufferSize = (ULONG)_strlen(ObjectName);

	return NT_SUCCESS(supEnumSystemObjects(RootDirectory, NULL, supDetectObjectCallback, &Param));
}
