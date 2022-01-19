package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;

public class stdapi_sys_eventlog_numrecords extends stdapi_sys_eventlog implements Command {
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        try
        {
            final Pointer handle = Pointer.createConstant(request.getLongValue(TLVType.TLV_TYPE_EVENT_HANDLE));
            IntByReference numberOfRecords = new IntByReference();
            final Boolean successful = AdvAPILibrary.INSTANCE.GetNumberOfEventLogRecords(handle, numberOfRecords);
            if (!successful)
            {
                return Kernel32Library.INSTANCE.GetLastError();
            }
            response.add(TLVType.TLV_TYPE_EVENT_NUMRECORDS, numberOfRecords.getValue());
            return ERROR_SUCCESS;
        }
        catch (Throwable e)
        {
            return ERROR_FAILURE;
        }
    }
}
