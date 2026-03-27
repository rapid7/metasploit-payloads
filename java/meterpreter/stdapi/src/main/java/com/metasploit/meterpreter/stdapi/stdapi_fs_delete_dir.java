package com.metasploit.meterpreter.stdapi;

import java.io.File;
import java.io.IOException;

import com.metasploit.TLVPacket;
import com.metasploit.TLVType;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.command.Command;

public class stdapi_fs_delete_dir implements Command {
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String path = request.getStringValue(TLVType.TLV_TYPE_DIRECTORY_PATH);
        File file = Loader.expand(path);
        if (FsUtils.isSymlink(file)) {
            if (!deleteSymlink(file)) {
                throw new IOException("Cannot delete symbolic link " + file.getCanonicalPath());
            }
        } else if (file.isDirectory()) {
            if (!rmtree(file)) {
                throw new IOException("Cannot delete " + file.getCanonicalPath());
            }
        } else {
            throw new IOException("Directory not found: " + path);
        }
        return ERROR_SUCCESS;
    }

    protected boolean deleteSymlink(File file) throws IOException {
        return file.delete();
    }

    private boolean rmtree(File file) throws IOException {
        boolean ret = true;
        for (File subFile : file.listFiles()) {
            if (FsUtils.isSymlink(subFile)) {
                ret = ret && deleteSymlink(subFile);
            } else if (subFile.isDirectory()) {
                ret = ret && rmtree(subFile);
            } else {
                ret = ret && subFile.delete();
            }
        }
        ret = ret && file.delete();
        return ret;
    }
}
