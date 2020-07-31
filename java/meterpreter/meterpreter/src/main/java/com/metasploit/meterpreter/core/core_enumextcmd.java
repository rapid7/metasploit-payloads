package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.CommandManager;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class core_enumextcmd implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        Integer start = request.getIntValue(TLVType.TLV_TYPE_UINT);
        Integer end = request.getIntValue(TLVType.TLV_TYPE_LENGTH) + start;
        CommandManager commandManager = meterpreter.getCommandManager();
        Integer[] commands = commandManager.getCommandsInRange(start, end);
        for (Integer commandId : commands) {
            response.addOverflow(TLVType.TLV_TYPE_UINT, commandId);
        }
        return ERROR_SUCCESS;
    }
}
