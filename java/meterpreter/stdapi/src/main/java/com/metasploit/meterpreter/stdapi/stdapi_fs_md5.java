package com.metasploit.meterpreter.stdapi;

public class stdapi_fs_md5 extends HashCommand {
    @Override
    protected String getAlgorithm() {
        return "MD5";
    }
}
