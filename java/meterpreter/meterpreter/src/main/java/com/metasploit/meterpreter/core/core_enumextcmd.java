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
        Integer[] commands = commandManager.getCommandsForExtension(extension);
        for (Integer commandId : commands) {
            response.addOverflow(TLVType.TLV_TYPE_UINT, commandId);
        }
        return ERROR_SUCCESS;
    }
}
