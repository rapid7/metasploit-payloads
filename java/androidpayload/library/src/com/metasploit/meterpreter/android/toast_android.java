package com.metasploit.meterpreter.android;

import android.widget.Toast;
import android.content.Context;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class toast_android implements Command {
  
  private static final int TLV_EXTENSIONS = 20000;
  private static final int TLV_TYPE_TOAST_STRING = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9001);
  private static final int TLV_TYPE_TOAST_SR = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9021);
  
   @Override
    public int execute(Meterpreter meterpreter, TLVPacket request,
                       TLVPacket response) throws Exception {
        String message = request.getStringValue(TLV_TYPE_TOAST_STRING);
        String TOAST_SUCCESS = "SUCCESS";
        AndroidMeterpreter androidMeterpreter = (AndroidMeterpreter) meterpreter;
        final Context context = androidMeterpreter.getContext();
        Toast.makeText(context,message,Toast.LENGTH_LONG).show();
        response.addOverflow(TLV_TYPE_TOAST_SR, TOAST_SUCCESS);
        return ERROR_SUCCESS;
    }
  

}
