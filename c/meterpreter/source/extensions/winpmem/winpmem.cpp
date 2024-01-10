/*
  Copyright 2012-2014 Michael Cohen <scudette@gmail.com>

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  */

/********************************************************************
   This is a single binary memory imager for Windows.

   Supported systems:
   - Windows XPSP2 to Windows 8 inclusive, both 32 bit and 64 bit.

   *********************************************************************/
#include "winpmem.h"
#include <stdio.h>
#include <time.h>

#ifndef min
#define min(x,y) ((x)<(y)?(x):(y))
#endif

int WinPmem::pad(uint64_t length)
{
	uint64_t start = 0;
	int result = 1;

	ZeroMemory(buffer_, buffer_size_);

	do
	{
		while (start < length) {
			DWORD to_write = (DWORD)min(buffer_size_, length - start);
			DWORD bytes_written;

			if (!WriteFile(out_fd_, buffer_,
				to_write, &bytes_written, NULL) ||
				bytes_written != to_write) {
				dprintf("[WINPMEM] Failed to write padding");
				result = 0;
				break;
			};

			out_offset += bytes_written;

			start += bytes_written;
		};
	} while (0);

	return result;
};

int WinPmem::copy_memory(uint64_t start, uint64_t end)
{
	int result = 0;
	LARGE_INTEGER large_start;

	if (start > max_physical_memory_) {
		return result;
	};

	// Clamp the region to the top of physical memory.
	if (end > max_physical_memory_) {
		end = max_physical_memory_;
	};

	do
	{
		while (start < end) {
			DWORD to_write = (DWORD)min(buffer_size_, end - start);
			DWORD bytes_read = 0;
			DWORD bytes_written = 0;

			large_start.QuadPart = start;

			if (0xFFFFFFFF == SetFilePointerEx(
				fd_, large_start, NULL, FILE_BEGIN)) {
				dprintf("[WINPMEM] Failed to seek in the pmem device.");
				break;
			};

			if (!ReadFile(fd_, buffer_, to_write, &bytes_read, NULL) ||
				bytes_read != to_write) {
				dprintf("[WINPMEM] Failed to Read memory.");
				break;
			};

			if (!WriteFile(out_fd_, buffer_, bytes_read,
				&bytes_written, NULL) ||
				bytes_written != bytes_read) {
				dprintf("[WINPMEM] Failed to write image file");
				break;
			};

			out_offset += bytes_written;

			start += to_write;
		};
		result = 1;
	} while (0);

	return result;
};


// Turn on write support in the driver.
int WinPmem::set_write_enabled(void)
{
	UINT mode;
	DWORD size;

	if (!DeviceIoControl(fd_, PMEM_WRITE_ENABLE, &mode, 4, NULL, 0,
		&size, NULL)) {
		dprintf("[WINPMEM] Failed to set write mode. Maybe these drivers do not support this mode?");
		return -1;
	};

	dprintf("[WINPMEM] Write mode enabled! Hope you know what you are doing.");
	return 1;
};


void WinPmem::print_mode_(unsigned __int32 mode)
{
	switch (mode) {
	case PMEM_MODE_IOSPACE:
		dprintf("[WINPMEM] MMMapIoSpace");
		break;

	case PMEM_MODE_PHYSICAL:
		dprintf("[WINPMEM] \\\\.\\PhysicalMemory");
		break;

	case PMEM_MODE_PTE:
		dprintf("[WINPMEM] PTE Remapping");
		break;

	case PMEM_MODE_PTE_PCI:
		dprintf("[WINPMEM] PTE Remapping with PCI introspection");
		break;

	default:
		dprintf("[WINPMEM] Unknown");
	};
};


// Display information about the memory geometry.
void WinPmem::print_memory_info()
{
	struct PmemMemoryInfo info;
	DWORD size;

	do
	{
		// Get the memory ranges.
		if (!DeviceIoControl(fd_, PMEM_INFO_IOCTRL, NULL, 0, (char*)&info, sizeof(info), &size, NULL))
		{
			dprintf("[WINPMEM] Failed to get memory geometry,");
			break;
		};

		dprintf("[WINPMEM] CR3: 0x%010llX\n %d memory ranges:", info.CR3.QuadPart, info.NumberOfRuns);

		max_physical_memory_ = 0;

		for (int64_t i = 0; i < info.NumberOfRuns.QuadPart; i++)
		{
			dprintf("[WINPMEM] Start 0x%08llX - Length 0x%08llX", info.Run[i].start, info.Run[i].length);
			max_physical_memory_ = info.Run[i].start + info.Run[i].length;
		};

		// When using the pci introspection we dont know the maximum physical memory,
		// we therefore make a guess based on the total ram in the system.
		dprintf("[WINPMEM] Acquisition mode ");
		print_mode_(mode_);

		if (mode_ == PMEM_MODE_PTE_PCI)
		{
			ULONGLONG installed_memory = 0;
			MEMORYSTATUSEX statusx;

			statusx.dwLength = sizeof(statusx);

			if (GlobalMemoryStatusEx(&statusx))
			{
				max_physical_memory_ = (size_t)(statusx.ullTotalPhys * 3 / 2);
				dprintf("[WINPMEM] Max physical memory guessed at 0x%08llX", max_physical_memory_);

			}
			else
			{
				dprintf("[WINPMEM] Unable to guess max physical memory. Just Ctrl-C when done.");
			};
		};
	} while (0);
};

int WinPmem::set_acquisition_mode(unsigned __int32 mode)
{
	DWORD size;

	if (mode == PMEM_MODE_AUTO)
	{
		mode = default_mode_;
	}

	// Set the acquisition mode.
	if (!DeviceIoControl(fd_, PMEM_CTRL_IOCTRL, &mode, 4, NULL, 0, &size, NULL))
	{
		dprintf("[WINPMEM] Failed to set acquisition mode %lu ", mode);
		print_mode_(mode);
		return -1;
	};

	mode_ = mode;
	return 1;
};

int WinPmem::create_output_file(TCHAR *output_filename)
{
	int status = 1;

	do
	{
		// The special file name of - means we should use stdout.
		if (!_tcscmp(output_filename, TEXT("-")))
		{
			out_fd_ = GetStdHandle(STD_OUTPUT_HANDLE);
			break;
		}

		// Create the output file.
		out_fd_ = CreateFile(output_filename,
			GENERIC_WRITE,
			FILE_SHARE_READ,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (out_fd_ == INVALID_HANDLE_VALUE) {
			dprintf("[WINPMEM] Unable to create output file.");
			status = -1;
			break;
		};
	} while (0);

	return status;
}

int WinPmem::write_coredump()
{
	// Somewhere to store the info from the driver;
	struct PmemMemoryInfo info;
	DWORD size;
	int status = -1;

	do
	{
		if (out_fd_ == INVALID_HANDLE_VALUE)
		{
			dprintf("[WINPMEM] Must open an output file first.");
			break;
		};

		RtlZeroMemory(&info, sizeof(info));

		// Get the memory ranges.
		if (!DeviceIoControl(fd_, PMEM_INFO_IOCTRL, NULL, 0, (char*)&info,
			sizeof(info), &size, NULL)) {
			dprintf("[WINPMEM] Failed to get memory geometry,");
			break;
		};

		dprintf("[WINPMEM] Will write an elf coredump.");
		print_memory_info();

		if (!write_coredump_header_(&info)) {
			break;
		};

		for (int64_t i = 0; i < info.NumberOfRuns.QuadPart; i++)
		{
			copy_memory((size_t)info.Run[i].start, (size_t)(info.Run[i].start + info.Run[i].length));
		};

		// Remember where we wrote the last metadata header.
		last_header_offset_ = out_offset;

		if (!WriteFile(out_fd_, metadata_, metadata_len_, &metadata_len_, NULL))
		{
			dprintf("[WINPMEM] Can not write metadata.");
		}

		out_offset += metadata_len_;

		if (pagefile_path_)
		{
			write_page_file();
		};

	} while (0);

	if (out_fd_ != NULL && out_fd_ != INVALID_HANDLE_VALUE)
	{
		CloseHandle(out_fd_);
	}
	out_fd_ = INVALID_HANDLE_VALUE;
	return status;
};


void WinPmem::CreateChildProcess(TCHAR *command, HANDLE stdout_wr)
{
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE;

	// Set up members of the PROCESS_INFORMATION structure.
	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

	// Set up members of the STARTUPINFO structure.
	// This structure specifies the STDIN and STDOUT handles for redirection.
	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdInput = NULL;
	siStartInfo.hStdOutput = stdout_wr;
	siStartInfo.hStdError = stdout_wr;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	dprintf("[WINPMEM] Launching %s", command);

	// Create the child process.
	bSuccess = CreateProcess(NULL,
		command,       // command line
		NULL,          // process security attributes
		NULL,          // primary thread security attributes
		TRUE,          // handles are inherited
		0,             // creation flags
		NULL,          // use parent's environment
		NULL,          // use parent's current directory
		&siStartInfo,  // STARTUPINFO pointer
		&piProcInfo);  // receives PROCESS_INFORMATION

	// If an error occurs, exit the application.
	if (!bSuccess) {
		dprintf("[WINPMEM] Unable to launch process.");
		return;
	}

	// Close handles to the child process and its primary thread.
	// Some applications might keep these handles to monitor the status
	// of the child process, for example.
	CloseHandle(piProcInfo.hProcess);
	CloseHandle(piProcInfo.hThread);
	CloseHandle(stdout_wr);
}


// Copy the pagefile to the current place in the output file.
void WinPmem::write_page_file()
{
	unsigned __int64 pagefile_offset = out_offset;
	TCHAR path[MAX_PATH + 1];
	TCHAR filename[MAX_PATH + 1];

	do
	{
		if (!GetTempPath(MAX_PATH, path))
		{
			dprintf("[WINPMEM] Unable to determine temporary path.");
			break;
		}

		// filename is now the random path.
		GetTempFileName(path, L"fls", 0, filename);

		dprintf("[WINPMEM] Extracting fcat to %s", filename);
		if (extract_file_(WINPMEM_FCAT_EXECUTABLE, filename) < 0)
		{
			break;
		};

		SECURITY_ATTRIBUTES saAttr;
		HANDLE stdout_rd = NULL;
		HANDLE stdout_wr = NULL;

		saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
		saAttr.bInheritHandle = TRUE;
		saAttr.lpSecurityDescriptor = NULL;

		// Create a pipe for the child process's STDOUT.
		if (!CreatePipe(&stdout_rd, &stdout_wr, &saAttr, 0))
		{
			dprintf("[WINPMEM] StdoutRd CreatePipe");
			break;
		};

		// Ensure the read handle to the pipe for STDOUT is not inherited.
		SetHandleInformation(stdout_rd, HANDLE_FLAG_INHERIT, 0);
		WCHAR command_line[1000];
		swprintf(command_line, 1000, L"%s %s \\\\.\\%s", filename, &pagefile_path_[3], pagefile_path_);

		CreateChildProcess(command_line, stdout_wr);
		dprintf("[WINPMEM] Preparing to read pagefile.");
		int running = 1;
		while (running)
		{
			DWORD bytes_read = buffer_size_;
			DWORD bytes_written = 0;

			if (!ReadFile(stdout_rd, buffer_, bytes_read, &bytes_read, NULL))
			{
				break;
			};

			if (!WriteFile(out_fd_, buffer_, bytes_read, &bytes_written, NULL) ||
				bytes_written != bytes_read) {
				dprintf("[WINPMEM] Failed to write image file");
				running = 0;
				break;
			};

			out_offset += bytes_written;
		};
	} while (0);

	// Write another metadata header.
	{
		char metadata[1000];
	    _snprintf_s(metadata, sizeof(metadata), _TRUNCATE,
				"# PMEM\n"
				"---\n"
				"PreviousHeader: %#llx\n"
				"PagefileOffset: %#llx\n"
				"PagefileSize: %#llx\n"
				"...\n",
			last_header_offset_,
			pagefile_offset,
			out_offset - pagefile_offset
		);

		DWORD metadata_len = (DWORD)strlen(metadata);
		DWORD bytes_written = 0;

		if (!WriteFile(out_fd_, metadata, metadata_len, &bytes_written, NULL) || bytes_written != metadata_len)
		{
			dprintf("[WINPMEM] Failed to write image file");
		};

		out_offset += bytes_written;
	};

	DeleteFile(filename);
};

int WinPmem::write_raw_image()
{
	// Somewhere to store the info from the driver;
	struct PmemMemoryInfo info;
	DWORD size;
	int status = -1;

	do
	{
		if (out_fd_ == INVALID_HANDLE_VALUE)
		{
			dprintf("[WINPMEM] Must open an output file first.");
			break;
		};

		RtlZeroMemory(&info, sizeof(info));

		// Get the memory ranges.
		if (!DeviceIoControl(fd_, PMEM_INFO_IOCTRL, NULL, 0, (char*)&info,
			sizeof(info), &size, NULL)) {
			dprintf("[WINPMEM] Failed to get memory geometry,");
			break;
		};

		dprintf("[WINPMEM] Will generate a RAW image");
		print_memory_info();

		int64_t offset = 0;
		int failed = 0;
		for (int64_t i = 0; i < info.NumberOfRuns.QuadPart; i++)
		{
			if (info.Run[i].start > offset)
			{
				dprintf("[WINPMEM] Padding from 0x%08llX to 0x%08llX", offset, info.Run[i].start);
				if (!pad((size_t)(info.Run[i].start - offset)))
				{
					failed = 1;
					break;
				}
			};

			copy_memory((size_t)info.Run[i].start, (size_t)(info.Run[i].start + info.Run[i].length));
			offset = info.Run[i].start + info.Run[i].length;
		};

		if (!failed)
		{
			// All is well.
			status = 1;
		}
	} while (0);

	if (out_fd_ != NULL && out_fd_ != INVALID_HANDLE_VALUE)
	{
		CloseHandle(out_fd_);
	}
	out_fd_ = INVALID_HANDLE_VALUE;
	return status;
};

WinPmem::WinPmem()
	: fd_(INVALID_HANDLE_VALUE),
	  buffer_size_(1024 * 1024),
	  buffer_(NULL),
	  service_name(PMEM_SERVICE_NAME),
	  max_physical_memory_(0),
	  mode_(PMEM_MODE_AUTO),
	  default_mode_(PMEM_MODE_AUTO),
	  metadata_(NULL),
	  metadata_len_(0),
	  driver_filename_(NULL),
	  driver_is_tempfile_(false),
	  out_offset(0),
	  pagefile_path_(NULL)
{
	buffer_ = new char[buffer_size_];
}

WinPmem::~WinPmem()
{
	if (fd_ != INVALID_HANDLE_VALUE)
	{
		CloseHandle(fd_);
	};

	if (buffer_)
	{
		delete[] buffer_;
	}

	if (driver_filename_ && driver_is_tempfile_)
	{
		free(driver_filename_);
	}
}

int WinPmem::extract_file_(__int64 resource_id, TCHAR *filename)
{
	int result = -1;

	// Locate the driver resource in the .EXE file.
	HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(resource_id), L"FILE");
	do
	{
		if (hRes == NULL)
		{
			dprintf("[WINPMEM] Could not locate driver resource.");
			break;
		}

		HGLOBAL hResLoad = LoadResource(NULL, hRes);
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

		DWORD size = SizeofResource(NULL, hRes);

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

		result = 1;
	} while (0);

	if (out_fd_ != NULL && out_fd_ != INVALID_HANDLE_VALUE)
	{
		CloseHandle(out_fd_);
	}

	return result;
};

void WinPmem::set_driver_filename(TCHAR *driver_filename)
{
	DWORD res;

	if (driver_filename_)
	{
		free(driver_filename_);
		driver_filename_ = NULL;
	};

	if (driver_filename)
	{
		driver_filename_ = (TCHAR *)malloc(MAX_PATH * sizeof(TCHAR));
		if (driver_filename_)
		{
			res = GetFullPathName(driver_filename, MAX_PATH, driver_filename_, NULL);
		};
	};
}

void WinPmem::set_pagefile_path(TCHAR *path)
{
	DWORD res;

	if (pagefile_path_)
	{
		free(pagefile_path_);
		pagefile_path_ = NULL;
	};

	if (path)
	{
		pagefile_path_ = (TCHAR *)malloc(MAX_PATH * sizeof(TCHAR));
		if (pagefile_path_)
		{
			res = GetFullPathName(path, MAX_PATH, pagefile_path_, NULL);
		};

		// Split at the drive letter. C:\pagefile.sys
		pagefile_path_[2] = 0;
	};
};

int WinPmem::install_driver()
{
	SC_HANDLE scm, service;
	int status = -1;

	do
	{
		// Try to load the driver from the resource section.
		if (extract_driver() < 0)
		{
			break;
		}

		uninstall_driver();

		scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
		if (!scm)
		{
			dprintf("[WINPMEM] Can not open SCM. Are you administrator?\n");
			break;
		}

		service = CreateService(scm,
			service_name,
			service_name,
			SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER,
			SERVICE_DEMAND_START,
			SERVICE_ERROR_NORMAL,
			driver_filename_,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL);

		if (GetLastError() == ERROR_SERVICE_EXISTS) {
			service = OpenService(scm, service_name, SERVICE_ALL_ACCESS);
		}

		if (!service)
		{
			break;
		};

		if (!StartService(service, 0, NULL))
		{
			if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
			{
				dprintf("[WINPMEM] Error: StartService(), Cannot start the driver.\n");
				break;
			}
		}

		dprintf("[WINPMEM] Loaded Driver %s.\n", driver_filename_);

		fd_ = CreateFile(TEXT("\\\\.\\") TEXT(PMEM_DEVICE_NAME),
			// Write is needed for IOCTL.
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (fd_ == INVALID_HANDLE_VALUE) {
			dprintf("[WINPMEM] Can not open raw device.");
			break;
		};

		status = 1;
	} while (0);

	if (service != NULL)
	{
		CloseServiceHandle(service);
	}

	if (scm != NULL)
	{
		CloseServiceHandle(scm);
	}

	// Only remove the driver file if it was a temporary file.
	if (driver_is_tempfile_)
	{
		dprintf("[WINPMEM] Deleting %S", driver_filename_);
		DeleteFile(driver_filename_);
	};

	return status;
}

int WinPmem::uninstall_driver()
{
	SC_HANDLE scm, service;
	SERVICE_STATUS ServiceStatus;

	scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);

	if (!scm) return 0;

	service = OpenService(scm, service_name, SERVICE_ALL_ACCESS);

	if (service)
	{
		ControlService(service, SERVICE_CONTROL_STOP, &ServiceStatus);
		DeleteService(service);
		CloseServiceHandle(service);
		dprintf("[WINPMEM] Driver Unloaded.");
		return 1;
	};

	return 0;
}

/* Create a YAML file describing the image encoded into a null terminated
   string. Caller will own the memory.
   */
char *store_metadata_(struct PmemMemoryInfo *info)
{
	SYSTEM_INFO sys_info;

	char *arch = NULL;

	// Get basic architecture information (Note that we always write ELF64 core
	// dumps - even on 32 bit platforms).
	ZeroMemory(&sys_info, sizeof(sys_info));
	GetNativeSystemInfo(&sys_info);

	switch (sys_info.wProcessorArchitecture)
	{
	case PROCESSOR_ARCHITECTURE_AMD64:
		arch = "AMD64";
		break;

	case PROCESSOR_ARCHITECTURE_INTEL:
		arch = "I386";
		break;

	default:
		arch = "Unknown";
	}

	char *buffer = (char *)malloc(1000);
	_snprintf_s(buffer, 1000, _TRUNCATE,
		// A YAML File describing metadata about this image.
		"# PMEM\n"
		"---\n"   // The start of the YAML file.
		"acquisition_tool: 'WinPMEM " PMEM_VERSION "'\n"
		"CR3: %#llx\n"
		"NtBuildNumber: %#llx\n"
		"NtBuildNumberAddr: %#llx\n"
		"KernBase: %#llx\n"
		"Arch: %s\n"
		"...\n",  // This is the end of a YAML file.
		info->CR3.QuadPart,
		info->NtBuildNumber.QuadPart,
		info->NtBuildNumberAddr.QuadPart,
		info->KernBase.QuadPart,
		arch
	);

	return buffer;
};


// WinPmem64 - A 64 bit implementation of the imager.
__int64 WinPmem::write_coredump_header_(struct PmemMemoryInfo *info)
{
	Elf64_Ehdr header;
	DWORD header_size;
	Elf64_Phdr pheader;
	int i;

	if (!metadata_) {
		metadata_ = store_metadata_(info);
		if (!metadata_) return 0;

		metadata_len_ = (DWORD)strlen(metadata_);
	};

	// Where we start writing data.
	uint64 file_offset = (
		sizeof(Elf64_Ehdr) +
		// One Phdr for each run and one for the metadata.
		(info->NumberOfRuns.QuadPart + 1) * sizeof(Elf64_Phdr));

	// All values that are unset will be zero
	RtlZeroMemory(&header, sizeof(Elf64_Ehdr));

	// We create a 64 bit core dump file with one section
	// for each physical memory segment.
	header.ident[0] = ELFMAG0;
	header.ident[1] = ELFMAG1;
	header.ident[2] = ELFMAG2;
	header.ident[3] = ELFMAG3;
	header.ident[4] = ELFCLASS64;
	header.ident[5] = ELFDATA2LSB;
	header.ident[6] = EV_CURRENT;
	header.type = ET_CORE;
	header.machine = EM_X86_64;
	header.version = EV_CURRENT;
	header.phoff = sizeof(Elf64_Ehdr);
	header.ehsize = sizeof(Elf64_Ehdr);
	header.phentsize = sizeof(Elf64_Phdr);

	// One more header for the metadata.
	header.phnum = (uint32)info->NumberOfRuns.QuadPart + 1;
	header.shentsize = sizeof(Elf64_Shdr);
	header.shnum = 0;

	header_size = sizeof(header);
	if (!WriteFile(out_fd_, &header, header_size, &header_size, NULL))
	{
		dprintf("[WINPMEM] Failed to write header");
		return 0;
	};

	out_offset += header_size;

	for (i = 0; i < info->NumberOfRuns.QuadPart; i++) {
		PHYSICAL_MEMORY_RANGE range = info->Run[i];

		RtlZeroMemory(&pheader, sizeof(Elf64_Phdr));

		pheader.type = PT_LOAD;
		pheader.paddr = range.start;
		pheader.memsz = range.length;
		pheader.align = PAGE_SIZE;
		pheader.flags = PF_R;
		pheader.off = file_offset;
		pheader.filesz = range.length;

		// Move the file offset by the size of this run.
		file_offset += range.length;

		header_size = sizeof(pheader);
		if (!WriteFile(out_fd_, &pheader, header_size, &header_size, NULL)) {
			dprintf("[WINPMEM] Failed to write header");
			return 0;
		};

		out_offset += header_size;

	};

	// Add a header for the metadata so it can be easily found in the file.
	RtlZeroMemory(&pheader, sizeof(Elf64_Phdr));
	pheader.type = PT_PMEM_METADATA;

	// The metadata section will be written at the end of the
	pheader.off = file_offset;
	pheader.filesz = metadata_len_;

	header_size = sizeof(pheader);
	if (!WriteFile(out_fd_, &pheader, header_size, &header_size, NULL)) {
		dprintf("[WINPMEM] Failed to write header");
		return 0;
	};

	out_offset += header_size;

	return 1;
};

int WinPmem::extract_driver(TCHAR *driver_filename)
{
	set_driver_filename(driver_filename);
	return extract_driver();
};

int WinPmem64::extract_driver()
{
	// 64 bit drivers use PTE acquisition by default.
	default_mode_ = PMEM_MODE_PTE;

	if (!driver_filename_) {
		TCHAR path[MAX_PATH + 1];
		TCHAR filename[MAX_PATH + 1];

		// Gets the temp path env string (no guarantee it's a valid path).
		if (!GetTempPath(MAX_PATH, path)) {
			dprintf("[WINPMEM] Unable to determine temporary path.");
			return -1;
		}

		GetTempFileName(path, service_name, 0, filename);
		set_driver_filename(filename);

		driver_is_tempfile_ = true;
	};

	dprintf("[WINPMEM] Extracting driver to %S", driver_filename_);

	return extract_file_(WINPMEM_64BIT_DRIVER, driver_filename_);
}

int WinPmem32::extract_driver()
{
	// 32 bit acquisition defaults to physical device.
	default_mode_ = PMEM_MODE_PHYSICAL;

	if (!driver_filename_)
	{
		TCHAR path[MAX_PATH + 1];
		TCHAR filename[MAX_PATH + 1];

		// Gets the temp path env string (no guarantee it's a valid path).
		if (!GetTempPath(MAX_PATH, path)) {
			dprintf("[WINPMEM] Unable to determine temporary path.");
			return -1;
		}

		GetTempFileName(path, service_name, 0, filename);
		set_driver_filename(filename);

		driver_is_tempfile_ = true;
	};

	dprintf("[WINPMEM] Extracting driver to %S", driver_filename_);

	return extract_file_(WINPMEM_32BIT_DRIVER, driver_filename_);
}
