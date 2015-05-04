#include "kull_m_output.h"
#include "../debug.h"

#define PRINT_BUFFER_SIZE 2048

static output_writer currentwriter = NULL;
static wchar_t printbuffer[PRINT_BUFFER_SIZE];

VOID kull_m_output_set_writer(output_writer writer)
{
	currentwriter = writer;
}

void kprintf(PCWCHAR format, ...)
{
	if (currentwriter)
	{
		va_list args;
		va_start(args, format);

		vswprintf_s(printbuffer, PRINT_BUFFER_SIZE, format, args);
		currentwriter(printbuffer);

		va_end(args);
	}
}
