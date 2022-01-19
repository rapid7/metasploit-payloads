package com.metasploit.meterpreter.stdapi;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-eventlogrecord
@Structure.FieldOrder({"Length", "Reserved", "RecordNumber", "TimeGenerated", "TimeWritten",
                        "EventID", "EventType", "NumStrings", "EventCategory", "ReservedFlags",
                        "ClosingRecordNumber", "StringOffset", "UserSidLength", "UserSidOffset",
                        "DataLength", "DataOffset"})
public class stdapi_sys_eventlog_record_struct extends Structure {
    public int Length;
    public int Reserved;
    public int RecordNumber;
    public int TimeGenerated;
    public int TimeWritten;
    public int EventID;
    public short EventType;
    public short NumStrings;
    public short EventCategory;
    public short ReservedFlags;
    public int ClosingRecordNumber;
    public int StringOffset;
    public int UserSidLength;
    public int UserSidOffset;
    public int DataLength;
    public int DataOffset;

    public stdapi_sys_eventlog_record_struct() {
        super();
    }

    public stdapi_sys_eventlog_record_struct(Pointer p) {
        super(p);
        read();
    }
}
