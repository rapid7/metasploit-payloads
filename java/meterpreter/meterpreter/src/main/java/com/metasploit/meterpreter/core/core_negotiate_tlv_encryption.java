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

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        String pem = request.getStringValue(TLVType.TLV_TYPE_RSA_PUB_KEY);

        SecureRandom sr = new SecureRandom();
        byte[] aesKey = new byte[32];
        sr.nextBytes(aesKey);

        try
        {
            PublicKey pubKey = getPublicKey(pem);
            Cipher cipher = Cipher.getInstance("RSA");
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

    private PublicKey getPublicKey(String pem) {
        String[] lines = pem.trim().split("\n", -1);
        String b64 = "";
        
        for (int i = 1; i < lines.length - 1; ++i) {
            b64 = String.join("", b64, lines[i]);
        }

        return getPublicKey(DatatypeConverter.parseBase64Binary(b64));
    }

    // This is here for when we move over to using DER instead of PEM
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
