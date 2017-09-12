package com.metasploit.stage;

import java.util.LinkedList;
import java.util.List;

public class Config {

    // See metasploit-framework/lib/rex/payloads/meterpreter/config.rb
    public byte[] rawConfig;

    public long session_expiry;
    public byte[] uuid;
    public byte[] session_guid;

    public List<TransportConfig> transportConfigList = new LinkedList<TransportConfig>();

}
