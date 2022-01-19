package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;

public class stdapi_sys_eventlog_oldest implements Command {
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        try
        {
            final Pointer handle = Pointer.createConstant(request.getLongValue(TLVType.TLV_TYPE_EVENT_HANDLE));
            IntByReference recordReference = new IntByReference(0);
            stdapi_sys_eventlog.AdvAPILibrary.INSTANCE.GetOldestEventLogRecord(handle, recordReference);
            response.add(TLVType.TLV_TYPE_EVENT_RECORDNUMBER, recordReference.getValue());
        }
        catch (Throwable e)
        {
            return ERROR_FAILURE;
        }
        return 0;
    }
}
