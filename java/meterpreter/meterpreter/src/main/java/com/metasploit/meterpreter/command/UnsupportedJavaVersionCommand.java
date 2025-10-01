package com.metasploit.meterpreter.command;

import com.metasploit.TLVPacket;
import com.metasploit.meterpreter.ExtensionLoader;
import com.metasploit.meterpreter.Meterpreter;

/**
 * A command that represents a command that is implemented, but not for the current Java version.
 *
 * @author mihi
 */
public class UnsupportedJavaVersionCommand implements Command {

    private final int command;
    private final int version;

    /**
     * Create a new instance of that command.
     *
     * @param command ID of the command
     * @param version Version required
     */
    public UnsupportedJavaVersionCommand(int command, int version) {
        this.command = command;
        this.version = version;
    }

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        meterpreter.getErrorStream().println("Command " + command + " requires at least Java 1." + (version - ExtensionLoader.V1_2 + 2));
        return ERROR_FAILURE;
    }
}
