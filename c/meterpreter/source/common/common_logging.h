#ifndef _METERPRETER_COMMON_LOGGING_H
#define _METERPRETER_COMMON_LOGGING_H

HANDLE init_logging(wchar_t* filePath);
HANDLE get_logging_context();
HANDLE get_lock();
void set_logging_context(HANDLE ctx, HANDLE lock1);
void log_to_file(char* buffer);

#endif
