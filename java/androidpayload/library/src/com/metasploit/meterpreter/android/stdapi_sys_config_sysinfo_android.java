package com.metasploit.meterpreter.android;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.Utils;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.stdapi.stdapi_sys_config_sysinfo;

import android.os.Build;

public class stdapi_sys_config_sysinfo_android extends
        stdapi_sys_config_sysinfo implements Command {

    protected String getOsName() throws Exception {
        String androidOS = Utils.runCommand("getprop ro.build.version.release").replace("\n", "");
        return "Android " + androidOS + " - " + System.getProperty("os.name");
    }
}
