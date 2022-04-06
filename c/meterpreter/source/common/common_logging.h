#ifndef _METERPRETER_COMMON_LOGGING_H
#define _METERPRETER_COMMON_LOGGING_H
#include "common_config.h"

HANDLE initLogging(wchar_t* filePath);
HANDLE getLoggingContext();
HANDLE getLock();
void setLoggingContext(HANDLE ctx, HANDLE lock1);
void logToFile(char* buffer);

#endif