package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import java.lang.reflect.Method;

public class stdapi_sys_process_getpid_V1_5 extends stdapi_sys_process_getpid implements Command {

    protected static boolean classExists(String className) {
        try {
            Class.forName(className);
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        if (classExists("java.lang.management.ManagementFactory") && classExists("java.lang.management.RuntimeMXBean"))
        {
            Class<?> managementFactory = Class.forName("java.lang.management.ManagementFactory");
            Method runtimeBeanMethod = managementFactory.getMethod("getRuntimeMXBean");
            Object runtimeBean = runtimeBeanMethod.invoke(null);
            Class<?> runtimeBeanClass = Class.forName("java.lang.management.RuntimeMXBean");
            Method nameMethod = runtimeBeanClass.getMethod("getName");
            Object nameObj = nameMethod.invoke(runtimeBean);
            String name = (String) nameObj;
            Integer pid = Integer.parseInt(name.substring(0, name.indexOf("@")));
            response.add(TLVType.TLV_TYPE_PID, pid);
            return ERROR_SUCCESS;
        }
        else
        {
            return ERROR_FAILURE;
        }
    }
}
