/*!
 * @file powershell_bindings.h
 * @brief Declarations for bindings to meterpreter functions that can be called from Powershell.
 */
#ifndef _METERPRETER_SOURCE_EXTENSION_POWERSHELL_BINDINGS_H
#define _METERPRETER_SOURCE_EXTENSION_POWERSHELL_BINDINGS_H

extern Remote* gRemote;

VOID MeterpreterInvoke(unsigned int isLocal, unsigned char* input, unsigned int inputLength, unsigned char** output, unsigned int* outputLength);

#endif
