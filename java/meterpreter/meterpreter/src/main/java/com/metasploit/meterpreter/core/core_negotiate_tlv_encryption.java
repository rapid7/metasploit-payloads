package com.metasploit.meterpreter.core;

import javax.xml.bind.DatatypeConverter;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.lang.String;
import javax.crypto.Cipher;

import com.metasploit.meterpreter.Transport;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.Utils;
import com.metasploit.meterpreter.command.Command;

public class core_negotiate_tlv_encryption implements Command {

    private static final SecureRandom sr = new SecureRandom();

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
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
