package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class core_set_uuid implements Command {
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        byte[] newUuid = request.getRawValue(TLVType.TLV_TYPE_UUID, null);
        if (newUuid != null) {
            meterpreter.setUUID(newUuid);
        }
        return ERROR_SUCCESS;
    }
}
