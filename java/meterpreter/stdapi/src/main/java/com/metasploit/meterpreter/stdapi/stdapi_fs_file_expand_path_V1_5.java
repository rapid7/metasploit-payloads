package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Utils;

public class stdapi_fs_file_expand_path_V1_5 extends stdapi_fs_file_expand_path {

    @Override
    protected String getShellPath() {
        String result;
        if (Utils.isWindows()) {
            result = System.getenv("COMSPEC");
        } else {
            result = System.getenv("SHELL");
        }
        if (result == null || result.length() == 0) {
            result = super.getShellPath();
        }
        return result;
    }
}
