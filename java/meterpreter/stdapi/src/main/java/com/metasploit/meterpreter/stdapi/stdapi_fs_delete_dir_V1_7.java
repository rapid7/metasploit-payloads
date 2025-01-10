package com.metasploit.meterpreter.stdapi;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class stdapi_fs_delete_dir_V1_7 extends stdapi_fs_delete_dir {
    @Override
    protected boolean deleteSymlink(File file) throws IOException {
        String osName = System.getProperty("os.name");
        if (osName != null && osName.toLowerCase().contains("windows")) {
            Files.delete(file.toPath());
            return true;
        }
        return file.delete();
    }
}
