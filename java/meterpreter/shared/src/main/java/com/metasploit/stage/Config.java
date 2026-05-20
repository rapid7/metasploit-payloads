package com.metasploit.stage;

import java.util.LinkedList;
import java.util.List;

public class Config {

    public static final int FLAG_STAGELESS = 1;
    public static final int FLAG_DEBUG = 2;
    public static final int FLAG_WAKELOCK = 4;
    public static final int FLAG_HIDE_APP_ICON = 8;

    // See metasploit-framework/lib/rex/payloads/meterpreter/config.rb
    public byte[] rawConfig;

    public int flags;
    public long session_expiry;
    public byte[] uuid;
    public byte[] session_guid;
    public String debug_log;

    public List<TransportConfig> transportConfigList = new LinkedList<TransportConfig>();

    // Raw extension jar bytes from any TLV_TYPE_EXTENSION groups in the
    // config block (EXTENSIONS=). Hot-loaded after Meterpreter starts so
    // commands are registered before the first C2 dispatch.
    public List<byte[]> extensions = new LinkedList<byte[]>();

}
