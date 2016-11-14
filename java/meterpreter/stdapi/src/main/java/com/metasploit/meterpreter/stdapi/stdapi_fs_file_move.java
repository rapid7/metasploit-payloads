package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import java.io.File;
import java.io.IOException;

public class stdapi_fs_file_move implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String oldpath = request.getStringValue(TLVType.TLV_TYPE_FILE_NAME);
        String path = request.getStringValue(TLVType.TLV_TYPE_FILE_PATH);
        File file = Loader.expand(oldpath);
        File dest = Loader.expand(path);
        if (!file.exists() || !file.isFile()) {
            throw new IOException("File not found: " + path);
        }
        if (!file.renameTo(dest)) {
            throw new IOException("Cannot move " + file.getCanonicalPath() + " to " + dest.getCanonicalPath());
        }
        return ERROR_SUCCESS;
    }
}
