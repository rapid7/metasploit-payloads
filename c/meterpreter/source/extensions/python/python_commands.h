/*!
 * @file python_commands.h
 * @brief Declarations for the python command functions.
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_PYTHON_PYTHON_COMMANDS
#define _METERPRETER_SOURCE_EXTENSION_PYTHON_PYTHON_COMMANDS

#include "../../common/common.h"

///! @brief List of valid python code types for loading
#define PY_CODE_TYPE_STRING   0
#define PY_CODE_TYPE_PY       1
#define PY_CODE_TYPE_PYC      2

VOID python_prepare_session();
VOID python_destroy_session();
VOID python_execute(CHAR* modName, LPBYTE pythonCode, DWORD codeLength, UINT codeType, CHAR* resultVar, Packet* responsePacket);

DWORD request_python_reset(Remote* remote, Packet* packet);
DWORD request_python_execute(Remote* remote, Packet* packet);

#endif
