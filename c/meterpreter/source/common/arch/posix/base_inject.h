/*!
 * @file posix/base_inject.h
 * @brief Declarations for functions which provide meterpreter library injection.
 * @details These functions are used in order to migrate meterpreter, using 
 *          ptrace to debug the new process host, allocate memory for the 
 *          meterpreter stage and a new stack, and give control. If something
 *          fails while migration, it should be able to restore the new host
 *          process and continue execution. Once migration is completed, the
 *          original process code isn't executed anymore, this could be solved,
 *          maybe, using clone to execute the meterpreter stage in a new LWP.
 */
#include "common.h"

/*! Macro to calculate sizes in order to help when writing and reading memory. */
#define _SIZE_OF(buf) (buf / sizeof(long)) + (buf % 4 > 0 ? 1 : 0)
/*! Length of the mmap code stub. */
#define MMAP_STUB_LENGTH 128
/*! ptrace friendly size of the mmap code stub. */
#define MMAP_STUB_SIZE _SIZE_OF(MMAP_STUB_LENGTH)
/*! Position of the length to mmap in the mmap stub. */
#define MMAP_LENGTH_POS 111
/*! Position of the address to mmap in the mmap stub. */
#define MMAP_ADDR_POS 116
/*! Length of the call code stub. */
#define CALL_STUB_LENGTH 112
/*! ptrace friendly size of the call code stub. */
#define CALL_STUB_SIZE _SIZE_OF(CALL_STUB_LENGTH)
/*! Position of the options flags in the call stub */
#define OPTIONS_POS 91
/*! Position of the library entry point in the call stub */
#define ENTRY_POINT_POS 101
/*! Length of the new stack to allocate */
#define STACK_SIZE 0x200000
/*! Length of the new memory to store code stubs */
#define CODE_SIZE 0x1000

/*! @brief Container struct for a library to inject and execute. */
typedef struct {
	ULONG arch;                ///< Library architecture (x86 => 1)
	PUCHAR data;               ///< Library's raw data
	ULONG length;              ///< Library length
	unsigned long base_addr;   ///< Base address
	unsigned long entry_point; ///< Entry point address
} library;

/*! 
 * @brief Container struct for a process data.
 * @details Memory and registers which needs to be restored if library
 *          injection fails.
 */
typedef struct {
	struct user_regs_struct regs;         ///< Process registers.
	unsigned long memory[MMAP_STUB_SIZE];	///< Code memory to restore.
} state;
	
LONG save_state(LONG pid, state *s);
LONG restore_state(LONG pid, state *s, int only_memory);
BOOL wait_trap(LONG pid);
LONG execute_stub(LONG pid, unsigned long addr, unsigned long *stub, ULONG stub_size);
LONG allocate(LONG pid, struct user_regs_struct *regs, unsigned long addr, size_t length);
LONG call(LONG pid, struct user_regs_struct *regs, unsigned long addr);
LONG inject_library(LONG pid, library *l);
