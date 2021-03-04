package com.metasploit.meterpreter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.command.NotYetImplementedCommand;
import com.metasploit.meterpreter.command.UnsupportedJavaVersionCommand;

/**
 * A registry for supported commands. Extensions will register their commands here.
 *
 * @author mihi
 */
public class CommandManager {

    private final int javaVersion;
    private Map/* <int,Command> */registeredCommands = new HashMap();
    private Vector/* <int> */newCommands = new Vector();

    protected CommandManager() throws Exception {
        // get the API version, which might be different from the
        // VM version, especially on some application servers
        // (adapted from org.apache.tools.ant.util.JavaEnvUtils).
        Class.forName("java.lang.Void");
        Class.forName("java.lang.ThreadLocal");
        int apiVersion = ExtensionLoader.V1_2;
        try {
            Class.forName("java.lang.StrictMath");
            apiVersion = ExtensionLoader.V1_3;
            Class.forName("java.lang.CharSequence");
            apiVersion = ExtensionLoader.V1_4;
            Class.forName("java.net.Proxy");
            apiVersion = ExtensionLoader.V1_5;
            Class.forName("java.util.ServiceLoader");
            apiVersion = ExtensionLoader.V1_6;
        } catch (Throwable ignored) {
        }
        String javaversion = System.getProperty("java.version");
        if (javaversion != null && javaversion.length() > 2) {
            int vmVersion = javaversion.charAt(2) - '2' + ExtensionLoader.V1_2;
            if (vmVersion >= ExtensionLoader.V1_2 && vmVersion < apiVersion) {
                apiVersion = vmVersion;
            }
        }
        this.javaVersion = apiVersion;

        // load core commands
        new com.metasploit.meterpreter.core.Loader().load(this);
    }

    /**
     * Register a command that can be executed on all Java versions (from 1.2 onward)
     *
     * @param commandId    ID of the command
     * @param commandClass Class that implements the command
     */
    public void registerCommand(int commandId, Class commandClass) throws Exception {
        registerCommand(commandId, commandClass, ExtensionLoader.V1_2);
    }

    /**
     * Register a command that can be executed only on some Java versions
     *
     * @param commandId    ID of the command
     * @param commandClass Stub class for generating the class name that implements the command
     * @param version      Minimum Java version
     */
    public void registerCommand(int commandId, Class commandClass, int version) throws Exception {
        registerCommand(commandId, commandClass, version, version);
    }

    /**
     * Register a command that can be executed only on some Java versions, and has two different implementations for different Java versions.
     *
     * @param commandId     ID of the command
     * @param commandClass  Stub class for generating the class name that implements the command
     * @param version       Minimum Java version
     * @param secondVersion Minimum Java version for the second implementation
     */
    public void registerCommand(int commandId, Class commandClass, int version, int secondVersion) throws Exception {
        if (secondVersion < version) {
            throw new IllegalArgumentException("secondVersion must be larger than version");
        }

        if (javaVersion < version) {
            registeredCommands.put(commandId, new UnsupportedJavaVersionCommand(commandId, version));
            return;
        }

        if (javaVersion >= secondVersion) {
            version = secondVersion;
        }

        if (version != ExtensionLoader.V1_2) {
            commandClass = commandClass.getClassLoader().loadClass(commandClass.getName() + "_V1_" + (version - 10));
        }

        Command cmd = (Command) commandClass.newInstance();
        registeredCommands.put(commandId, cmd);
        Command x = (Command)registeredCommands.get(commandId);

        newCommands.add(commandId);
    }

    /**
     * Get a command for the given ID.
     */
    public Command getCommand(int commandId) {
        Command cmd = (Command) registeredCommands.get(commandId);
        if (cmd == null) {
            cmd = NotYetImplementedCommand.INSTANCE;
        }
        return cmd;
    }

    /**
     * Get a list of commands registered against a specific extension
     */
    public Integer[] getCommandsInRange(Integer start, Integer end) {
        Vector commandIds = new Vector();
        for (Object key : registeredCommands.keySet()) {
            Integer commandId = (Integer)key;
            if (start < commandId && commandId < end) {
                commandIds.add(commandId);
            }
        }
        Integer[] result = new Integer[commandIds.size()];
        return (Integer[])commandIds.toArray(result);
    }

    public int executeCommand(Meterpreter met, TLVPacket request, TLVPacket response) throws IOException {
        int commandId = request.getIntValue(TLVType.TLV_TYPE_COMMAND_ID);
        Command cmd = this.getCommand(commandId);

        int result;
        try {
            result = cmd.execute(met, request, response);
        } catch (Throwable t) {
            t.printStackTrace(met.getErrorStream());
            result = Command.ERROR_FAILURE;
        }

        if (result == Command.EXIT_DISPATCH) {
            response.add(TLVType.TLV_TYPE_RESULT, Command.ERROR_SUCCESS);
        } else {
            response.add(TLVType.TLV_TYPE_RESULT, result);
        }

        return result;
    }

    /**
     * Reset the list of commands loaded by the last core_loadlib call
     */
    public void resetNewCommands() {
        newCommands.clear();
    }

    /**
     * Retrieves the list of command IDs loaded by the last core_loadlib call
     */
    public Integer[] getNewCommandIds() {
        return (Integer[]) newCommands.toArray(new Integer[0]);
    }

    /**
     * Retrieves the list of command IDs
     */
    public Integer[] getCommandsIds() {
        return (Integer[]) registeredCommands.keySet().toArray(new Integer[0]);
    }
}
