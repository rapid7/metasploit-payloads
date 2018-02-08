package com.metasploit.meterpreter.stdapi;

import java.io.File;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.command.NotYetImplementedCommand;

public class stdapi_fs_file_expand_path implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String path = request.getStringValue(TLVType.TLV_TYPE_FILE_PATH);
        if (path.equals("%COMSPEC%")) {
            response.add(TLVType.TLV_TYPE_FILE_PATH, getShellPath());
            return ERROR_SUCCESS;
        } else {
            /*
             * TODO this should also do shell word expansion
             */
            File f = new File(path);
            response.add(TLVType.TLV_TYPE_FILE_PATH, f.getCanonicalPath());
            return ERROR_SUCCESS;
        }
    }

    protected String getShellPath() {
        if (File.pathSeparatorChar == ';')
            return "cmd.exe";
        else
            return "/bin/sh";
    }
}
