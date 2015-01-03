/*!
 * @file ptrace.c
 * @brief Definitions for functions providing ptrace helpers.
 */
#include "ptrace.h"

/*!
 * @brief Detaches from the debugged process and restarts it.
 * @param pid Process identifier to dettach.
 * @returns Indication of success or failure.
 * @retval 0 Indicates success.
 */
LONG
detach(LONG pid) {
	dprintf("[PTRACE] Dettaching from pid %d", pid);
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
		dprintf("[PTRACE] DETACH failed");
		return errno;
	}

	return 0;
}

/*!
 * @brief Attaches to a process to debug it.
 * @param pid Process identifier to attach.
 * @returns Indication of success or failure.
 * @retval 0 Indicates success.
 */
LONG
attach(LONG pid) {
	dprintf("[PTRACE] Attaching to pid: %d", pid);
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
		dprintf("[PTRACE] PTRACE_ATTACH failed");
		return errno;
	}

	return 0;
}

/*!
 * @brief Get registers of the debugged process.
 * @param pid Process identifier of the debugged process.
 * @param regs Pointer to \c user_regs_struct to store the registers.
 * @returns Indication of success or failure.
 * @retval 0 Indicates success.
 */
LONG
getregs(LONG pid, struct user_regs_struct *regs) {
	dprintf("[PTRACE] Getting registers");

	if (regs == NULL) {
		return ERROR_INVALID_PARAMETER;
	}

	if (ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1) {
		dprintf("[PTRACE] PTRACE_GETREGS failed");
		return errno;
	}

	return 0;	
}

/*!
 * @brief Set registers of the debugged process.
 * @param pid Process identifier of the debugged process.
 * @param regs Pointer to \c user_regs_struct with the registers.
 * @returns Indication of success or failure.
 * @retval 0 Indicates success.
 */
LONG
setregs(LONG pid, struct user_regs_struct *regs) {
	dprintf("[PTRACE] Setting registers");

	if (regs == NULL) {
		return ERROR_INVALID_PARAMETER;
	}

	if (ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1) {
		dprintf("[PTRACE] PRACE_SETREGS failed");
		return errno;
	}

	return 0;	
}

/*!
 * @brief Continues execution of the debugged process.
 * @param pid Process identifier of the debugged process.
 * @returns Indication of success or failure.
 * @retval 0 Indicates success.
 */
LONG
cont(LONG pid) {
	LONG result = 0;

	dprintf("[PTRACE] Executing");
	result = ptrace(PTRACE_CONT, pid, NULL, NULL);
	if (result == -1) {
		dprintf("[PTRACE] PTRACE_CONT failed");
		return errno;
	}
	
	return 0;
}

/*!
 * @brief Writes data to the debugged process memory.
 * @param pid Process identifier of the debugged process.
 * @param addr Address of the debugged process to write the contents.
 * @param contents Pointer to the data to write.
 * @param size Lenght of contents / \c sizeof(long)
 * @returns Indication of success or failure.
 * @retval 0 Indicates success.
 */
LONG
write_memory(LONG pid, unsigned long addr, unsigned long *contents, UINT size) {
	LONG i = 0;

	if (size == 0 || contents == NULL)
		return ERROR_INVALID_PARAMETER;

	dprintf("[PTRACE] Writing memory");	
	for (i = 0; i < size; i++) {
		//dprintf("[PTRACE] Writting %x to %x", contents[i], (addr + (i * sizeof(void *))));
		if (ptrace(PTRACE_POKETEXT, pid, (void *)(addr + (i * sizeof(void *))), (void *)contents[i]) == -1) {
			dprintf("[PTRACE] PTRACE_POKETEXT failed");
			return errno;
		}
	}

	return 0;
}

/*!
 * @brief Reads data from the debugged process memory.
 * @param pid Process identifier of the debugged process.
 * @param addr Address of the debugged process to read data from.
 * @param contents Pointer to the space reserved to store the contents.
 * @param size Lenght of data to read / \c sizeof(long)
 * @returns Indication of success or failure.
 * @retval 0 Indicates success.
 */
LONG
read_memory(LONG pid, unsigned long addr, unsigned long *contents, UINT size) {
	LONG i = 0;

	if (size == 0 || contents == NULL)
		return ERROR_INVALID_PARAMETER;

	dprintf("[PTRACE] Reading memory");
	for (i = 0; i < size; i++) {
		contents[i] = ptrace(PTRACE_PEEKTEXT, pid, (void *)(addr + (i * sizeof(void *))), NULL);
		if (contents[i] == -1) {
			dprintf("[PTRACE] PTRACE_PEEKTEXT failed");
			return errno;
		}
	}

	return 0;
}
