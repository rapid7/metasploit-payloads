package com.metasploit.meterpreter.command;

import com.metasploit.TLVPacket;
import com.metasploit.meterpreter.CommandManager;
import com.metasploit.meterpreter.Meterpreter;

/**
 * A command that can be executed inside meterpreter. Each command has a name and can be registered using the {@link CommandManager#registerCommand(int commandId, Class commandClass)} command.
 *
 * @author mihi
 */
public interface Command {

    /**
     * Status code representing a successful run of the command.
     */
    public static final int ERROR_SUCCESS = 0;

    /**
     * Status code representing a failed run of the command.
     */
    public static final int ERROR_FAILURE = 1;

    /**
     * Status code indicating a clean dispatch loop exit.
     */
    public static final int EXIT_DISPATCH = 2;

    /**
     * Execute this command.
     *
     * @param request     request packet
     * @param response    response packet
     * @param meterpreter Meterpreter to write errors to
     * @return a status code (usually {@link #ERROR_SUCCESS} or {@link #ERROR_FAILURE})
     * @throws Exception any exception, which will be mapped to an error stream output and an {@link #ERROR_FAILURE} status code.
     */
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception;
}
