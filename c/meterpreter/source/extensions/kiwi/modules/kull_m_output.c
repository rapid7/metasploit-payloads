#include "kull_m_output.h"
#include "../debug.h"

#define PRINT_BUFFER_SIZE 2048

static FILE * logfile = NULL;
static output_writer currentwriter = NULL;
static wchar_t printbuffer[PRINT_BUFFER_SIZE];

VOID kull_m_output_set_writer(output_writer writer)
{
	currentwriter = writer;
}

void kprintf(PCWCHAR format, ...)
{
	va_list args;
	va_start(args, format);

	if (currentwriter)
	{
		vswprintf_s(printbuffer, PRINT_BUFFER_SIZE, format, args);
		currentwriter(printbuffer);
	}
	else
	{
		vwprintf(format, args);
		fflush(stdout);
	}

	if (logfile)
	{
		vfwprintf(logfile, format, args);
	}
	va_end(args);
	fflush(logfile);
}

BOOL kull_m_output_file(PCWCHAR file)
{
	BOOL status = FALSE;
	FILE * newlog = NULL;
	errno_t result = 0;

	if(file)
		 result = _wfopen_s(&newlog, file, L"a");
	
	if(!result && (newlog || !file))
	{
		if(logfile)
			fclose(logfile);
		logfile = newlog;
	}
	return (!file || (!result && logfile));
}