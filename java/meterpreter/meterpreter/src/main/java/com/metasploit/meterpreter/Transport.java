package com.metasploit.meterpreter;

import java.io.DataInputStream;
import java.io.OutputStream;
import java.io.IOException;

public abstract class Transport {
    public static final long MS = 1000L;

    private Transport prev;
    private Transport next;

    protected String url;
    protected long commTimeout;
    protected long retryTotal;
    protected long retryWait;

    protected abstract boolean tryConnect(Meterpreter met) throws IOException;

    public abstract int parseConfig(byte[] configuration, int offset);
    public abstract void bind(DataInputStream in, OutputStream rawOut);
    public abstract void disconnect();
    public abstract boolean dispatch(Meterpreter met);
    public abstract void writePacket(TLVPacket packet, int type) throws IOException;
    public abstract TLVPacket readPacket() throws IOException;
    public abstract boolean switchUri(String uri);

    protected Transport(String url) {
        this.url = url;
    }

    protected int parseTimeouts(byte[] configuration, int offset) {
        // starts with the comms timeout
        this.commTimeout = MS * Meterpreter.unpack32(configuration, offset);
        offset += 4;

        // then we have the retry total
        this.retryTotal = MS * Meterpreter.unpack32(configuration, offset);
        offset += 4;

        // then we have the retry wait
        this.retryWait = MS * Meterpreter.unpack32(configuration, offset);
        offset += 4;

        return offset;
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

        while (System.currentTimeMillis() < lastAttempt + this.retryTotal) {
            try {
                if (this.tryConnect(met)) {
                    return true;
                }
            } catch (Exception e) {
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

