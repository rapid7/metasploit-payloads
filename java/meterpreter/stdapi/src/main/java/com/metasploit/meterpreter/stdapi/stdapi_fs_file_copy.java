package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import java.io.*;

public class stdapi_fs_file_copy implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String oldpath = request.getStringValue(TLVType.TLV_TYPE_FILE_NAME);
        String path = request.getStringValue(TLVType.TLV_TYPE_FILE_PATH);
        File file = Loader.expand(oldpath);
        File dest = Loader.expand(path);
        if (!file.exists() || !file.isFile()) {
            throw new IOException("File not found: " + path);
        }

        InputStream in = new FileInputStream(file);
        OutputStream out = new FileOutputStream(dest);
        byte[] buf = new byte[4096];
        int len;
        while ((len = in.read(buf)) > 0) {
            out.write(buf, 0, len);
        }
        in.close();
        out.close();
        return ERROR_SUCCESS;
    }
}
