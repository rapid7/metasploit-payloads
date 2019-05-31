package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.*;
import com.metasploit.meterpreter.command.Command;

public class stdapi_sys_process_close implements Command {
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        long handle = request.getLongValue(TLVType.TLV_TYPE_HANDLE);
        Channel channel = meterpreter.getChannel((int)handle, false);
        if (channel instanceof ProcessChannel) {
            channel.close();
        }
        return ERROR_SUCCESS;
    }
}
