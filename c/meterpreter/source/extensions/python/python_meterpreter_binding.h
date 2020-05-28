/*!
 * @file python_meterpreter_binding.y
 * @brief Declrations for functions that support meterpreter bindings.
 */

#ifndef PYTHON_METERPRETER_BINDING_H
#define PYTHON_METERPRETER_BINDING_H

VOID binding_startup();
VOID binding_add_command(UINT commandId);
VOID binding_init();

#endif