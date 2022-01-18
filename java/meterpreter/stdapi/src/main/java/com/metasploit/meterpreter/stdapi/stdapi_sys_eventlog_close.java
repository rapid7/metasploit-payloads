package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;
import com.sun.jna.Pointer;

public class stdapi_sys_eventlog_close extends stdapi_sys_eventlog implements Command {
    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        try
        {
            Pointer handle = Pointer.createConstant(request.getLongValue(TLVType.TLV_TYPE_EVENT_HANDLE));
            AdvAPILibrary.INSTANCE.CloseEventLog(handle);
            return ERROR_SUCCESS;
        }
        catch (Throwable e)
        {
            return ERROR_FAILURE;
        }
    }
}