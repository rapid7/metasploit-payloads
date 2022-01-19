package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import com.sun.jna.Pointer;

public class stdapi_sys_eventlog_open extends stdapi_sys_eventlog implements Command {
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String sourceName = request.getStringValue(TLVType.TLV_TYPE_EVENT_SOURCENAME);

        try
        {
            final Pointer handle = AdvAPILibrary.INSTANCE.OpenEventLog(null, sourceName);
            if (handle == Pointer.NULL)
            {
                return Kernel32Library.INSTANCE.GetLastError();
            }
            // Remember to cast the native value to Pointer later.
            response.add(TLVType.TLV_TYPE_EVENT_HANDLE, Pointer.nativeValue(handle));
            return ERROR_SUCCESS;
        }
        catch (Throwable e)
        {
            return ERROR_FAILURE;
        }
    }
}