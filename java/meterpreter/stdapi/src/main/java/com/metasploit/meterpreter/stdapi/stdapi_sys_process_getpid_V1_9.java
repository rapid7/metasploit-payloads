package com.metasploit.meterpreter.stdapi;

import java.lang.reflect.Method;

import com.metasploit.TLVPacket;
import com.metasploit.TLVType;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.command.Command;

public class stdapi_sys_process_getpid_V1_9 extends stdapi_sys_process_getpid_V1_5 implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        if (classExists("java.lang.ProcessHandle"))
        {
            Class<?> processHandleClass = Class.forName("java.lang.ProcessHandle");
            Method getCurrentProcessHandleMethod = processHandleClass.getMethod("current");
            Object currentProcessHandle = getCurrentProcessHandleMethod.invoke(null);
            Object pidObject = processHandleClass.getMethod("pid").invoke(currentProcessHandle);
            Long pid = (Long) pidObject;
            response.add(TLVType.TLV_TYPE_PID, pid.intValue());
            return ERROR_SUCCESS;
        }
        else
        {
            return ERROR_FAILURE;
        }
    }
}
