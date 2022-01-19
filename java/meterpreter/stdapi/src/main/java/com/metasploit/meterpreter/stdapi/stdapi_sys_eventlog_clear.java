package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;
import com.sun.jna.Pointer;

public class stdapi_sys_eventlog_clear extends stdapi_sys_eventlog implements Command {
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        try
        {
            final Pointer handle = Pointer.createConstant(request.getLongValue(TLVType.TLV_TYPE_EVENT_HANDLE));
            final Boolean success = AdvAPILibrary.INSTANCE.ClearEventLog(handle, null);
            if (!success)
            {
                return Kernel32Library.INSTANCE.GetLastError();
            }
            return ERROR_SUCCESS;
        }
        catch (Throwable e)
        {
            return ERROR_FAILURE;
        }
    }
}