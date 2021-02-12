package com.metasploit.meterpreter.stdapi;

import java.io.File;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_fs_file_expand_path implements Command {

    /**
     * Pattern for capturing variables. Either $xyz, ${xyz} or ${a.b} but not $a.b, while ignoring "$$"
      */
    private static final Pattern VARIABLE = Pattern.compile("\\$([A-Za-z0-9_]+|\\{[A-Za-z0-9_.]+\\}|\\%[A-Za-z0-9_.]+\\%|\\$)");

    private static String expandPath(String s) {
        int idx=0;
        while (true) {
            Matcher m = VARIABLE.matcher(s);
            if (!m.find(idx)) {
                return s;
            }

            String key = m.group().substring(1);
            String value;
            if (key.charAt(0) == '$') {
                value = "$";
            } else {
                if (key.charAt(0) == '{' || key.charAt(0) == '%') {
                    key = key.substring(1,key.length()-1);
                }
                value = System.getenv(key);
            }

            if (value == null) {
                value = "";
            }

            s = s.substring(0, m.start()) + value + s.substring(m.end());
            idx = m.start() + value.length();
        }
    }

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String path = request.getStringValue(TLVType.TLV_TYPE_FILE_PATH);
        if (path.equals("%COMSPEC%")) {
            response.add(TLVType.TLV_TYPE_FILE_PATH, getShellPath());
            return ERROR_SUCCESS;
        } else if (path.equals("%TEMP%")) {
            response.add(TLVType.TLV_TYPE_FILE_PATH, System.getenv("TEMP"));
            return ERROR_SUCCESS;
        } else {
            response.add(TLVType.TLV_TYPE_FILE_PATH, expandPath(path));
            return ERROR_SUCCESS;
        }
    }

    protected String getShellPath() {
        if (File.pathSeparatorChar == ';') {
            return "cmd.exe";
        } else {
            return "/bin/sh";
        }
    }
}
