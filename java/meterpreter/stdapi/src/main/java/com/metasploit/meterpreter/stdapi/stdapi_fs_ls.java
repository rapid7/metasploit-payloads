package com.metasploit.meterpreter.stdapi;

import java.io.File;
import java.util.List;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;
import com.metasploit.meterpreter.command.CommandId;

public class stdapi_fs_ls implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        stdapi_fs_stat statCommand = (stdapi_fs_stat) meterpreter.getCommandManager().getCommand(CommandId.STDAPI_FS_STAT);
        String pathString = request.getStringValue(TLVType.TLV_TYPE_DIRECTORY_PATH);
        File path = Loader.expand(pathString);
        if (pathString.contains("*")) {
            String root = path.getParent();
            String match = path.getName();
            List entries = stdapi_fs_search.findFiles(root, match, false, null, null);
            for (int i = 0; i < entries.size(); i++) {
                String entry = entries.get(i).toString();
                if (entry.equals(".") || entry.equals("..")) {
                    continue;
                }
                File f = new File(entry);
                String pathEntry = entry;
                if (pathEntry.startsWith(root)) {
                    pathEntry = pathEntry.substring(root.length() + 1);
                }
                response.addOverflow(TLVType.TLV_TYPE_FILE_NAME, f.getName());
                response.addOverflow(TLVType.TLV_TYPE_FILE_PATH, pathEntry);
                response.addOverflow(TLVType.TLV_TYPE_STAT_BUF, statCommand.stat(f));
            }
            return ERROR_SUCCESS;
        }
        String[] entries = path.list();
        for (int i = 0; i < entries.length; i++) {
            if (entries[i].equals(".") || entries[i].equals("..")) {
                continue;
            }
            File f = new File(path, entries[i]);
            response.addOverflow(TLVType.TLV_TYPE_FILE_NAME, entries[i]);
            response.addOverflow(TLVType.TLV_TYPE_FILE_PATH, f.getCanonicalPath());
            response.addOverflow(TLVType.TLV_TYPE_STAT_BUF, statCommand.stat(f));
        }
        return ERROR_SUCCESS;
    }
}
