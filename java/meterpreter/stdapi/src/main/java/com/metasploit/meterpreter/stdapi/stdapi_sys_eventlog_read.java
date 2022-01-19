package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;
import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;

public class stdapi_sys_eventlog_read extends stdapi_sys_eventlog implements Command {
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        try
        {
            final Pointer handle = Pointer.createConstant(request.getLongValue(TLVType.TLV_TYPE_EVENT_HANDLE));
            final int flags = request.getIntValue(TLVType.TLV_TYPE_EVENT_READFLAGS);
            final int offset = request.getIntValue(TLVType.TLV_TYPE_EVENT_RECORDOFFSET);

            IntByReference bytesRead = new IntByReference(0);
            IntByReference bytesNeeded = new IntByReference(0);

            if (AdvAPILibrary.INSTANCE.ReadEventLog(handle, flags, offset, bytesRead, 0, bytesRead, bytesNeeded))
            {
                return Kernel32Library.INSTANCE.GetLastError();
            }

            // There are no events
            if (bytesNeeded.getValue() == 0)
            {
                return ERROR_FAILURE;
            }

            final int bufferSize = bytesNeeded.getValue();
            Pointer buffer = new Memory(bufferSize);
            final boolean readEventsSuccess = AdvAPILibrary.INSTANCE.ReadEventLog(handle, flags, offset, buffer, bufferSize, bytesRead, bytesNeeded);

            if (!readEventsSuccess)
            {
                final int returnCode =  Kernel32Library.INSTANCE.GetLastError();
                final int ERROR_HANDLE_EOF = 38;
                if (returnCode != ERROR_HANDLE_EOF)
                {
                    return returnCode;
                }
            }

            stdapi_sys_eventlog_record_struct record = new stdapi_sys_eventlog_record_struct(buffer);

            response.add(TLVType.TLV_TYPE_EVENT_RECORDNUMBER, record.RecordNumber);
            response.add(TLVType.TLV_TYPE_EVENT_TIMEGENERATED, record.TimeGenerated);
            response.add(TLVType.TLV_TYPE_EVENT_TIMEWRITTEN, record.TimeWritten);
            response.add(TLVType.TLV_TYPE_EVENT_ID, record.EventID);
            response.add(TLVType.TLV_TYPE_EVENT_TYPE, record.EventType);
            response.add(TLVType.TLV_TYPE_EVENT_CATEGORY, record.EventCategory);

            byte[] eventData = new byte[record.DataLength];
            // Arrays.copyOfRange fails Java 1.5 check, so we use System.arrcopy instead
            System.arraycopy(buffer.getByteArray(record.DataOffset, record.DataLength), 0, eventData, 0, record.DataLength);
            response.add(TLVType.TLV_TYPE_EVENT_DATA, eventData);

            final byte[] eventStringBytes = buffer.getByteArray(record.StringOffset, bufferSize - record.StringOffset);
            StringBuilder eventString = new StringBuilder();
            for (byte i : eventStringBytes)
            {
                if (i != 0)
                {
                    eventString.append((char) i);
                }
            }
            response.add(TLVType.TLV_TYPE_EVENT_STRING, eventString.toString());

            return ERROR_SUCCESS;
        }
        catch (Throwable e)
        {
            System.out.println(e.getMessage());
            return ERROR_FAILURE;
        }
    }
}
