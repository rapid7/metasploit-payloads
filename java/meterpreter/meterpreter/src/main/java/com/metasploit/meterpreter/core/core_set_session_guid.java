package com.metasploit.meterpreter.core;

import com.metasploit.TLVPacket;
import com.metasploit.TLVType;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.command.Command;

public class core_set_session_guid implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        byte[] newGuid = request.getRawValue(TLVType.TLV_TYPE_SESSION_GUID, null);
        if (newGuid != null) {
            meterpreter.setSessionGUID(newGuid);
        }
        return ERROR_SUCCESS;
    }
}
