#include "windows.h"
#include "stdio.h"
#include "tchar.h"
#include <stdint.h>
#include "elf.h"
#include <stdio.h>
#include <stdarg.h>
#include <varargs.h>

// Executable version.
#define PMEM_VERSION "1.6.2"
#define PMEM_DEVICE_NAME "pmem"
#define PMEM_SERVICE_NAME TEXT("pmem")

static TCHAR version[] = TEXT(PMEM_VERSION) TEXT(" ") TEXT(__DATE__);

// These numbers are set in the resource editor for the FILE resource.
#define WINPMEM_64BIT_DRIVER 104
#define WINPMEM_32BIT_DRIVER 105
#define WINPMEM_FCAT_EXECUTABLE 106

#define PAGE_SIZE 0x1000

// We use this special section to mark the beginning of the pmem metadata
// region. Note that the metadata region extends past the end of this physical
// header - it is guaranteed to be the last section. This allows users to simply
// add notes by appending them to the end of the file (e.g. with a hex editor).
#define PT_PMEM_METADATA (PT_LOOS + 0xd656d70)


class WinPmem {
 public:
  WinPmem();
  virtual ~WinPmem();

  virtual __int64 install_driver();
  virtual __int64 uninstall_driver();
  virtual __int64 set_write_enabled();
  virtual __int64 set_acquisition_mode(unsigned __int32 mode);
  virtual void set_driver_filename(TCHAR *driver_filename);
  virtual void set_pagefile_path(TCHAR *pagefile_path);
  virtual void write_page_file();
  virtual void print_memory_info();

  // In order to create an image:

  // 1. Create an output file with create_output_file()
  // 2. Select either write_raw_image() or write_crashdump().
  // 3. When this object is deleted, the file is closed.
  virtual __int64 create_output_file(TCHAR *output_filename);
  virtual __int64 write_raw_image();
  virtual __int64 write_coredump();

  // This is set if output should be suppressed (e.g. if we pipe the
  // image to the STDOUT).
  __int64 suppress_output;
  TCHAR last_error[1024];

  virtual __int64 extract_driver() = 0;
  virtual __int64 extract_driver(TCHAR *driver_filename);

 protected:
  void CreateChildProcess(TCHAR *command, HANDLE g_hChildStd_OUT_Wr);

  __int64 extract_file_(__int64 resource_id, TCHAR *filename);
  virtual __int64 write_coredump_header_(struct PmemMemoryInfo *info);

  virtual void LogError(TCHAR *message);
  virtual void Log(const TCHAR *message, ...);
  virtual void LogLastError(TCHAR *message);

  __int64 pad(__int64 length);
  __int64 copy_memory(unsigned __int64 start, unsigned __int64 end);

  // The file handle to the pmem device.
  HANDLE fd_;

  // The file handle to the image file.
  HANDLE out_fd_;
  TCHAR *service_name;
  char *buffer_;
  size_t buffer_size_;
  TCHAR *driver_filename_;
  bool driver_is_tempfile_;

  // This is the maximum size of memory calculated.
  unsigned __int64 max_physical_memory_;

  // Current offset in output file (Total bytes written so far).
  unsigned __int64 out_offset;

  // The current acquisition mode.
  unsigned __int32 mode_;
  unsigned __int32 default_mode_;

  // The pagefile name to acquire.
  TCHAR *pagefile_path_;

 private:
  void print_mode_(unsigned __int32 mode);
  char *metadata_;
  DWORD metadata_len_;

  // The offset of the previous metadata header.
  unsigned __int64 last_header_offset_;
};

class WinPmem32: public WinPmem {
  virtual __int64 extract_driver();
};

class WinPmem64: public WinPmem {
  virtual __int64 extract_driver();
};


// ioctl to get memory ranges from our driver.
#define PMEM_CTRL_IOCTRL CTL_CODE(0x22, 0x101, 0, 3)
#define PMEM_WRITE_ENABLE CTL_CODE(0x22, 0x102, 0, 3)
#define PMEM_INFO_IOCTRL CTL_CODE(0x22, 0x103, 0, 3)

// Available modes
#define PMEM_MODE_IOSPACE 0
#define PMEM_MODE_PHYSICAL 1
#define PMEM_MODE_PTE 2
#define PMEM_MODE_PTE_PCI 3

#define PMEM_MODE_AUTO 99

#pragma pack(push, 2)
typedef struct pmem_info_runs {
  __int64 start;
  __int64 length;
} PHYSICAL_MEMORY_RANGE;

struct PmemMemoryInfo {
  LARGE_INTEGER CR3;
  LARGE_INTEGER NtBuildNumber; // Version of this kernel.
  LARGE_INTEGER KernBase;  // The base of the kernel image.
  LARGE_INTEGER KDBG;  // The address of KDBG

  // Support up to 32 processors for KPCR.
  LARGE_INTEGER KPCR[32];

  LARGE_INTEGER PfnDataBase;
  LARGE_INTEGER PsLoadedModuleList;
  LARGE_INTEGER PsActiveProcessHead;

  // The address of the NtBuildNumber integer - this is used to find the kernel
  // base quickly.
  LARGE_INTEGER NtBuildNumberAddr;

  // As the driver is extended we can add fields here maintaining
  // driver alignment..
  LARGE_INTEGER Padding[0xfe];

  LARGE_INTEGER NumberOfRuns;

  // A Null terminated array of ranges.
  PHYSICAL_MEMORY_RANGE Run[100];
};

#pragma pack(pop)

char *asprintf(const char *fmt, ...);
TCHAR *aswprintf(const TCHAR *fmt, ...);
