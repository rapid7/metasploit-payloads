package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.CommandManager;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class core_enumextcmd implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String extension = request.getStringValue(TLVType.TLV_TYPE_STRING);
        CommandManager commandManager = meterpreter.getCommandManager();
        String[] commands = commandManager.getCommands();
        for (String command : commands) {
            String prefix = command.split("_")[0];
            if ("webcam".equals(prefix)) {
                prefix = "stdapi";
            }
            if (extension.equals(prefix)) {
                response.addOverflow(TLVType.TLV_TYPE_STRING, command);
            }
        }
        return ERROR_SUCCESS;
    }
}
