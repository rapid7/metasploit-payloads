package com.metasploit.stage;

public class TransportConfig {

    public String url;
    public long comm_timeout;
    public long retry_total;
    public long retry_wait;

    // HTTP only
    public String proxy;
    public String proxy_user;
    public String proxy_pass;
    public String user_agent;
    public byte[] cert_hash;
    public String custom_headers;

}
