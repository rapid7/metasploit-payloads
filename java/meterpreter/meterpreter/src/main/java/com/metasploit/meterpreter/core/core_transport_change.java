package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;

public class core_transport_change extends core_transport_add {

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        int result = super.execute(meterpreter, request, response);

        if (result == ERROR_SUCCESS) {
            // transport added as a previous element, switch it
            meterpreter.getTransports().setNext(meterpreter.getTransports().current().getPrev(), 0);
            result = EXIT_DISPATCH;
        }

        return result;
    }
}

