package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.Utils;
import com.metasploit.meterpreter.command.Command;

import java.util.Locale;

public class stdapi_sys_config_sysinfo implements Command {

    private static String normalizeArch(String arch) {
        if (arch.equals("i386") || arch.equals("i486")  || arch.equals("i586") || arch.equals("i686")) {
            return "x86";
        }
        if (arch.equals("amd64") || arch.equals("x86_64")) {
            return "x64";
        }
        if (arch.equals("arm") || arch.equals("arm32")) {
            return "armle";
        }
        if (arch.equals("arm64")) {
            return "aarch64";
        }
        return arch;
    }

    protected String getOsName() throws Exception {
        return System.getProperty("os.name");
    }

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String arch = System.getProperty("os.arch");
        response.add(TLVType.TLV_TYPE_COMPUTER_NAME, Utils.getHostname());
        response.add(TLVType.TLV_TYPE_OS_NAME, getOsName() + " " + System.getProperty("os.version") + " (" + arch + ")");
        if (arch != null) {
            response.add(TLVType.TLV_TYPE_ARCHITECTURE, normalizeArch(arch));
        }
        response.add(TLVType.TLV_TYPE_LANG_SYSTEM, Locale.getDefault().toString());
        return ERROR_SUCCESS;
    }
}
