#ifndef _METERPRETER_SOURCE_EXTENSION_EXTAPI_PRIV_SERVER_SYSKEY_H
#define _METERPRETER_SOURCE_EXTENSION_EXTAPI_PRIV_SERVER_SYSKEY_H
BOOL get_syskey_component(HKEY lsaHandle, char subkeyName[255], unsigned char *tmpSysKey);
BOOL get_syskey(unsigned char *sysKey);

#endif
