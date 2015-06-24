package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

import java.io.IOException;

public class core_shutdown implements Command {
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        System.out.println("msf : Shutdown requested, exiting dispatch");
        return EXIT_DISPATCH;
    }
}
