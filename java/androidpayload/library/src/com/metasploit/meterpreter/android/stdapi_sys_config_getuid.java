package com.metasploit.meterpreter.android;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.Utils;
import com.metasploit.meterpreter.command.Command;

public class stdapi_sys_config_getuid implements Command {
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String line = Utils.runCommand("id");
        if (line == null) {
            return ERROR_FAILURE;
        }

        String parts[] = line.split(" ");
        if (parts.length < 2) {
            return ERROR_FAILURE;
        }

        String userName = "unknown";

        for (String part : parts) {
            String parts2[] = part.split("=");
            if (parts2.length < 2) {
                return ERROR_FAILURE;
            }
            if (parts2[0].equals("uid")) {
                String parts3[] = parts2[1].split("[\\(\\)]");

                if (parts3.length > 1) {
                    userName = parts3[1];
                    break;
                }
            }
        }

        response.add(TLVType.TLV_TYPE_USER_NAME, userName);
        return ERROR_SUCCESS;
    }
}
