package com.metasploit.meterpreter;

public class TransportList {
    private Transport transport = null;
    private Transport nextTransport = null;
    private long wait = 0;

    public boolean isEmpty() {
        return this.transport == null;
    }

    public Transport current() {
        return this.transport;
    }

    public boolean changeRequested() {
        return this.nextTransport != null;
    }

    public void moveNext(Meterpreter met) {
        if (this.wait > 0) {
            met.sleep(this.wait);
            this.wait = 0;
        }

        if (this.nextTransport == null) {
            this.transport = this.transport.getNext();
        } else {
            this.transport = this.nextTransport;
            this.nextTransport = null;
        }
    }

    public void setNext(Transport t, long wait) {
        this.wait = wait;
        this.nextTransport = t;
    }

    public void add(Transport t) {
        if (this.transport == null) {
            // first transport, point it at itself
            t.setNext(t);
            t.setPrev(t);
            this.transport = t;
        } else {
            // wire it into the end of the circular list
            this.transport.getPrev().setNext(t);
            t.setPrev(this.transport.getPrev());
            t.setNext(this.transport);
            this.transport.setPrev(t);
        }
    }

    public void remove(Transport t) {
        if (this.transport == this.transport.getNext()) {
            // removing the last one
            this.transport = null;
        } else {
            // move to the next if the current one is being removed
            if (this.transport == t) {
                this.transport = this.transport.getNext();
            }

            // pointer juggle
            t.getPrev().setNext(t.getNext());
            t.getNext().setPrev(t.getPrev());
        }
    }
}

