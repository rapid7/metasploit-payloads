/*!
 * @file python_commands.h
 * @brief Declarations for the python command functions.
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_PYTHON_PYTHON_COMMANDS
#define _METERPRETER_SOURCE_EXTENSION_PYTHON_PYTHON_COMMANDS

#include "../../common/common.h"

DWORD request_python_execute_string(Remote *remote, Packet *packet);

#endif
