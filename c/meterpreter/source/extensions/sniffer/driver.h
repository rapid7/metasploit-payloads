#ifndef _METERPRETER_LIB_DRIVER_H
#define _METERPRETER_LIB_DRIVER_H

NTSTATUS driverLoad(PCWSTR driverPath, PCWSTR driverKey);
NTSTATUS driverUnload(PCWSTR driverPath, PCWSTR driverKey);
DWORD dropDriverResource(int name, LPCTSTR rtype, PCWSTR driverPath);
// These functions arent being exported, but for completeness' sake:
int getPrivilege();
int createRegKey(PCWSTR driverPath, PCWSTR driverKey);
int deleteRegKey(PCWSTR driverKey);

#endif