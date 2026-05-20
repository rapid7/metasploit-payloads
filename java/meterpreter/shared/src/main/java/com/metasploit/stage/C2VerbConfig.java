package com.metasploit.stage;

public class C2VerbConfig {

    public String uri;
    public int encInbound;       // server->client (response body) encoding
    public int encOutbound;      // client->server (request body, POST only) encoding
    public int encUuid;          // encoding applied to the UUID before placement
    public byte[] prefix;
    public byte[] suffix;
    public String uuidPrefix;    // string prepended to the (encoded) UUID
    public String uuidSuffix;    // string appended to the (encoded) UUID
    public int prefixSkip;
    public int suffixSkip;
    public String uuidGet;
    public String uuidHeader;
    public String uuidCookie;

}
