package com.metasploit.meterpreter.stdapi;

import java.util.Locale;

import com.metasploit.TLVPacket;
import com.metasploit.TLVType;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.Utils;
import com.metasploit.meterpreter.command.Command;

public class stdapi_sys_config_sysinfo implements Command {

    protected String getOsName() throws Exception {
        return System.getProperty("os.name");
    }

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        response.add(TLVType.TLV_TYPE_COMPUTER_NAME, Utils.getHostname());
        response.add(TLVType.TLV_TYPE_OS_NAME, getOsName() + " " + System.getProperty("os.version") + " (" + System.getProperty("os.arch") + ")");
        String arch = Utils.getNormalizedArch();
        if (arch != null) {
            response.add(TLVType.TLV_TYPE_ARCHITECTURE, arch);
        }
        response.add(TLVType.TLV_TYPE_LANG_SYSTEM, Locale.getDefault().toString());
        return ERROR_SUCCESS;
    }
}
