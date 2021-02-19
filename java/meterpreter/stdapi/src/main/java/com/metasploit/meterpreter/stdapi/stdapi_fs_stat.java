package com.metasploit.meterpreter.stdapi;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class stdapi_fs_stat implements Command {

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String path = request.getStringValue(TLVType.TLV_TYPE_FILE_PATH);
        if (path.equals("...")) {
            long length = meterpreter.getErrorBufferLength();
            if (length != -1) {
                response.add(TLVType.TLV_TYPE_STAT_BUF, stat(0444 | 0100000, length, System.currentTimeMillis()));
                return ERROR_SUCCESS;
            }
        }
        File file = new File(path);
        if (!file.exists()) {
            file = Loader.expand(path);
        }
        if (!file.exists()) {
            throw new IOException("File/directory does not exist: " + path);
        }
        response.add(TLVType.TLV_TYPE_STAT_BUF, stat(file));
        return ERROR_SUCCESS;
    }

    public byte[] stat(File file) throws IOException {
        int mode = (file.canRead() ? 0444 : 0)
                | (file.canWrite() ? 0222 : 0)
                | (canExecute(file) ? 0110 : 0)
                // File objects have a prefix (which is something like "C:\\" on Windows
                // and always "/" on Linux) and a name. If we're talking about the root
                // directory, the name will be an empty string which triggers a bug in gcj
                // where isHidden() blows up when calling charAt(0) on an empty string.
                // Work around it by always treating / as unhidden.
                | (!file.getAbsolutePath().equals("/") && file.isHidden() ? 1 : 0)
                | (file.isDirectory() ? 040000 : 0)
                | (file.isFile() ? 0100000 : 0);
        return stat(mode, file.length(), file.lastModified());
    }

    private byte[] stat(int mode, long length, long lastModified) throws IOException {
        ByteArrayOutputStream statbuf = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(statbuf);
        dos.writeInt(le(0)); // dev
        dos.writeInt(le(mode)); // mode
        dos.writeInt(le(1)); // nlink
        dos.writeInt(le(65535)); // uid
        dos.writeInt(le(65535)); // gid
        dos.writeInt(le(0)); // rdev
        dos.writeLong(long_le(0)); // ino
        dos.writeLong(long_le(length)); // size
        long mtime = lastModified / 1000;
        dos.writeLong(long_le(mtime)); // atime
        dos.writeLong(long_le(mtime)); // mtime
        dos.writeLong(long_le(mtime)); // ctime
        dos.writeInt(le(1024)); // blksize
        dos.writeInt(le((int) ((length + 1023) / 1024))); // blocks
        return statbuf.toByteArray();
    }

    /**
     * Check whether a file can be executed.
     */
    protected boolean canExecute(File file) {
        return false;
    }

    /**
     * Convert an integer to little endian.
     */
    private static int le(int value) {
        return ((value & 0xff) << 24) | ((value & 0xff00) << 8) | ((value & 0xff0000) >> 8) | (int) ((value & 0xff000000L) >> 24);
    }

    /**
     * Convert a short to little endian.
     */
    private static int short_le(int value) {
        return ((value & 0xff) << 8) | ((value & 0xff00) >> 8);
    }

    /**
     * Convert a long to little endian.
     */
    private static long long_le(long value) {
        ByteBuffer buf = ByteBuffer.allocate(8);
        buf.order(ByteOrder.BIG_ENDIAN);
        buf.putLong(value);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        return buf.getLong(0);
    }
}
