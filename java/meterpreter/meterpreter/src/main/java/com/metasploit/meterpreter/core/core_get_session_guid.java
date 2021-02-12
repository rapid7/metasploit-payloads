package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class core_get_session_guid implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        response.add(TLVType.TLV_TYPE_SESSION_GUID, meterpreter.getSessionGUID());
        return ERROR_SUCCESS;
    }
}
