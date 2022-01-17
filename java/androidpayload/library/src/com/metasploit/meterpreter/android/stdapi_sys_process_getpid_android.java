package com.metasploit.meterpreter.android;

import android.os.Process;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.stdapi.stdapi_sys_process_getpid;

public class stdapi_sys_process_getpid_android extends stdapi_sys_process_getpid implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        int pid = Process.myPid();
        response.add(TLVType.TLV_TYPE_PID, pid);
        return ERROR_SUCCESS;

    }
}
