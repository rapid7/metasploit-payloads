/*!
 * @file ptrace.h
 * @brief Declarations for functions providing ptrace helpers.
 */
#include "common.h"

LONG detach(LONG pid);
LONG attach(LONG pid);
LONG getregs(LONG pid, struct user_regs_struct *regs);
LONG setregs(LONG pid, struct user_regs_struct *regs);
LONG cont(LONG pid);
LONG write_memory(LONG pid, unsigned long addr, unsigned long *contents, UINT size);
LONG read_memory(LONG pid, unsigned long addr, unsigned long *contents, UINT size);	
