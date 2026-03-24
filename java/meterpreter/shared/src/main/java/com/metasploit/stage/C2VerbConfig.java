package com.metasploit.stage;

public class C2VerbConfig {

    public String uri;
    public int enc;              // 0=None, 1=Base64, 2=Base64URL
    public byte[] prefix;
    public byte[] suffix;
    public int prefixSkip;
    public int suffixSkip;
    public String uuidGet;
    public String uuidHeader;
    public String uuidCookie;

}
