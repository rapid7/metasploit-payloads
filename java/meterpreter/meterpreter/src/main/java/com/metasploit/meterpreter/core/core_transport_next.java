package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class core_transport_next implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        meterpreter.getTransports().setNext(meterpreter.getTransports().current().getNext(), 0);

        return EXIT_DISPATCH;
    }
}

