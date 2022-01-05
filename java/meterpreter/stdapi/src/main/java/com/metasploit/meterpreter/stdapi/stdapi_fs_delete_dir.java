package com.metasploit.meterpreter.stdapi;

import java.io.File;
import java.io.IOException;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_fs_delete_dir implements Command {
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String path = request.getStringValue(TLVType.TLV_TYPE_DIRECTORY_PATH);
        File file = Loader.expand(path);
        if (isSymlink(file)) {
            if (!file.delete()) {
                throw new IOException("Cannot delete symbolic link " + file.getCanonicalPath());
            }
        } else if (file.isDirectory()) {
            rmtree(file);
        } else {
            throw new IOException("Directory not found: " + path);
        }
        return ERROR_SUCCESS;
    }

    private static boolean isSymlink(File file) throws IOException {
        File canon;
        if (file.getParent() == null) {
            canon = file;
        } else {
            File canonDir = file.getParentFile().getCanonicalFile();
            canon = new File(canonDir, file.getName());
        }
        return !canon.getCanonicalFile().equals(canon.getAbsoluteFile());
    }

    private void rmtree(File file) throws IOException {
        for (File subFile : file.listFiles()) {
            if (isSymlink(subFile)) {
                subFile.delete();
            } else if (subFile.isDirectory()) {
                rmtree(subFile);
            } else {
                subFile.delete();
            }
        }
        file.delete();
        return;
    }
}
