/*!
 * @file base.h
 * @brief Declarations, macros and types that apply to almost any Meterpreter component.
 */
#ifndef _METERPRETER_METSRV_BASE_H
#define _METERPRETER_METSRV_BASE_H

#include "core.h"

void command_register_all(Command commands[]);
void command_deregister_all(Command commands[]);
DWORD command_register(Command *command);
DWORD command_deregister(Command *command);
Command* command_locate_extension(UINT commandId);
VOID command_registration_scope_begin(Command* boundary);
DWORD command_registration_scope_error(VOID);
VOID command_registration_scope_rollback(VOID);
VOID command_registration_scope_end(VOID);
VOID command_join_threads( VOID );
BOOL command_handle( Remote *remote, Packet *packet );

Command* register_base_dispatch_routines(void);
void deregister_base_dispatch_routines(void);

#endif
