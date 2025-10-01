package com.metasploit.meterpreter.core;

import com.metasploit.TLVPacket;
import com.metasploit.TLVType;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.command.Command;

public class core_patch_uuid implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String patchUuid = request.getStringValue(TLVType.TLV_TYPE_C2_UUID);
        if (meterpreter.getTransports().current().patchUuid(patchUuid)) {
            return EXIT_DISPATCH;
        } else {
            return ERROR_FAILURE;
        }
    }
}
