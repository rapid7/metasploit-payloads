package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.CommandManager;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class core_enumextcmd implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String command = request.getStringValue(TLVType.TLV_TYPE_STRING);
        CommandManager commandManager = meterpreter.getCommandManager();
        String[] commands = commandManager.getCommands();
        for (String loadedCommand : commands) {
            if (command.equals(loadedCommand.split("_")[0])) {
                response.addOverflow(TLVType.TLV_TYPE_STRING, loadedCommand);
            }
        }
        if ("android".equals(command)) {
             // There are currently no commands prefixed with android but we still want to load the extension
            response.addOverflow(TLVType.TLV_TYPE_STRING, "");
        }
        return ERROR_SUCCESS;
    }
}
