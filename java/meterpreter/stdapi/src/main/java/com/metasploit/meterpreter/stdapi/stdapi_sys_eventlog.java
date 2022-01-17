package com.metasploit.meterpreter.stdapi;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.Platform;
import com.sun.jna.ptr.IntByReference;

import com.sun.jna.win32.W32APIOptions;

// Empty dummy class
public class stdapi_sys_eventlog {
    interface Libraries extends Library {
        // Native.loadLibrary is deprecated
        stdapi_sys_eventlog.Libraries AdvAPILibrary = Native.load(
                (Platform.isWindows() ? "Advapi32" : "THIS SHOULD NEVER BE CALLED."), stdapi_sys_eventlog.Libraries.class, W32APIOptions.DEFAULT_OPTIONS);
        Pointer OpenEventLog(String lpUNCServerName, String lpSourceName);
        // Close an event log
        Boolean CloseEventLog(Pointer hEventLog);
        // Clear an event log
        Boolean ClearEventLog(Pointer hEventLog, String lpBackupFileName);
        Boolean GetNumberOfEventLogRecords(Pointer hEventLog, IntByReference NumberOfRecords);

        stdapi_sys_eventlog.Libraries Kernel32Library = Native.load(
                (Platform.isWindows() ? "Kernel32.dll" : "THIS SHOULD NEVER BE CALLED."), stdapi_sys_eventlog.Libraries.class, W32APIOptions.DEFAULT_OPTIONS);
        Integer GetLastError();
    }
}