//
// Created by Simon Janusz on 25/01/2022.
//

#include "com_metasploit_meterpreter_stdapi_stdapi_railgun_api.h"
#include <windows.h>

typedef ULONG_PTR (__stdcall* STDCALL_FUNC_00)( VOID );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_01)( ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_02)( ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_03)( ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_04)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_05)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_06)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_07)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_08)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_09)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_10)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_11)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_12)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_13)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_14)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_15)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_16)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_17)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_18)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_19)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_20)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_21)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_22)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_23)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_24)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__stdcall* STDCALL_FUNC_25)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );

typedef ULONG_PTR (__cdecl* CDECL_FUNC_00)( VOID );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_01)( ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_02)( ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_03)( ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_04)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_05)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_06)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_07)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_08)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_09)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_10)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_11)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_12)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_13)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_14)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_15)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_16)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_17)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_18)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_19)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_20)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_21)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_22)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_23)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_24)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );
typedef ULONG_PTR (__cdecl* CDECL_FUNC_25)( ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR, ULONG_PTR );

#define function(i) ((STDCALL_FUNC_##i)pFuncAddr)
#define cdecl_func(i)	((CDECL_FUNC_##i)pFuncAddr)
#define p(i)		(ULONG_PTR)pStack[i]

typedef unsigned __int64 QWORD;

JNIEXPORT void JNICALL Java_com_metasploit_meterpreter_stdapi_stdapi_1railgun_1api_railgunCaller(JNIEnv* env, jobject thisObject, jint sizeOut, jbyteArray stackBlobIn, jbyteArray bufferBlobIn, jbyteArray bufferBlobInOut, jstring libName, jstring funcName, jstring callConv, jbyteArray bufferBlobOut, jintArray errorCode, jbyteArray errorMessage, jlongArray returnValue)
{
    HMODULE hDLL = 0;
    VOID* pFuncAddr = 0;
    QWORD qwReturnValue = 0;

    // Get DLL name
    const char* dllName = env->GetStringUTFChars(libName, 0);
    hDLL = LoadLibraryA(dllName);

    const char* functionName = env->GetStringUTFChars(funcName, 0);
    pFuncAddr = (VOID*)GetProcAddress(hDLL, functionName);

    const char* callingConvention = env->GetStringUTFChars(funcName, 0);

    // error message out
    jbyte* jErrorMessage = (jbyte*)env->GetByteArrayElements(errorMessage, 0);
    char* errorMessageOut = (char*)jErrorMessage;

    // Buffer in
    jbyte* jBufferIn = (jbyte*)env->GetByteArrayElements(bufferBlobIn, 0);
    byte* bufferIn = (byte*)jBufferIn;

    // Buffer out
    // https://stackoverflow.com/questions/5231599/is-there-any-way-to-pass-a-java-array-to-c-through-jni-without-making-a-copy-of
    // One consideration might be to use GetPrimitiveArrayCritical or GetArrayElements when your data is an output of your Java code and an input of your C code.
    // You would use GetDirectBufferAddress when your data flows the other way.
    // GetDirectBufferAccess
    byte* bufferOut = (byte*) env->GetDirectBufferAddress(bufferBlobOut);

    // Buffer inout
    jbyte* jBufferInOut = (jbyte*)env->GetByteArrayElements(bufferBlobInOut, 0);
    byte* bufferInOut = (byte*)jBufferInOut;

    // Get the stack blob
    jbyte* jStackBlob = (jbyte*) env->GetByteArrayElements(stackBlobIn, 0);
    byte* stackBlob = (byte*)jStackBlob;

    DWORD dwStackSizeInElements = env->GetArrayLength(stackBlobIn) / (2 * sizeof(ULONG_PTR));

    ULONG_PTR* pStackDescriptorBuffer = (ULONG_PTR*) stackBlob;

    ULONG_PTR* pStack = (ULONG_PTR*) malloc(dwStackSizeInElements * sizeof(ULONG_PTR));

    for (DWORD i = 0; i < dwStackSizeInElements; i++)
    {
        ULONG_PTR item = pStackDescriptorBuffer[(i * 2) + 1];
        switch(pStackDescriptorBuffer[i * 2])
        {
            case 0: // do nothing. item is a literal value
                pStack[i] = item;
                break;

            case 1: // relative ptr to pBufferIN. Convert to absolute Ptr
                pStack[i] = item + ((ULONG_PTR) bufferIn);
                break;

            case 2: // relative ptr to pBufferOUT. Convert to absolute Ptr
                pStack[i] = item + ((ULONG_PTR) bufferOut);
                break;

            case 3: // relative ptr to pBufferINOUT. Convert to absolute Ptr
                pStack[i] = item + ((ULONG_PTR) bufferInOut );
                break;

            default:
                break;
        }
    }

    if (strcmp(callingConvention, "cdecl") == 0)
    {
        switch(dwStackSizeInElements)
        {
        	case  0: qwReturnValue = cdecl_func( 00 )(); break;
        	case  1: qwReturnValue = cdecl_func( 01 )( p(0) ); break;
        	case  2: qwReturnValue = cdecl_func( 02 )( p(0), p(1) ); break;
        	case  3: qwReturnValue = cdecl_func( 03 )( p(0), p(1), p(2) ); break;
        	case  4: qwReturnValue = cdecl_func( 04 )( p(0), p(1), p(2), p(3) );break;
        	case  5: qwReturnValue = cdecl_func( 05 )( p(0), p(1), p(2), p(3), p(4) );break;
        	case  6: qwReturnValue = cdecl_func( 06 )( p(0), p(1), p(2), p(3), p(4), p(5) );break;
       		case  7: qwReturnValue = cdecl_func( 07 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6) );break;
     		case  8: qwReturnValue = cdecl_func( 08 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7) );break;
        	case  9: qwReturnValue = cdecl_func( 09 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8) );break;
        	case 10: qwReturnValue = cdecl_func( 10 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9) );break;
        	case 11: qwReturnValue = cdecl_func( 11 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10) );break;
        	case 12: qwReturnValue = cdecl_func( 12 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11) );break;
        	case 13: qwReturnValue = cdecl_func( 13 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12) );break;
        	case 14: qwReturnValue = cdecl_func( 14 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13) );break;
        	case 15: qwReturnValue = cdecl_func( 15 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14) );break;
        	case 16: qwReturnValue = cdecl_func( 16 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15) );break;
        	case 17: qwReturnValue = cdecl_func( 17 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16) );break;
        	case 18: qwReturnValue = cdecl_func( 18 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17) );break;
        	case 19: qwReturnValue = cdecl_func( 19 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18) );break;
        	case 20: qwReturnValue = cdecl_func( 20 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19) );break;
        	case 21: qwReturnValue = cdecl_func( 21 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19), p(20) );break;
        	case 22: qwReturnValue = cdecl_func( 22 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19), p(20), p(21) );break;
        	case 23: qwReturnValue = cdecl_func( 23 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19), p(20), p(21), p(22) );break;
        	case 24: qwReturnValue = cdecl_func( 24 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19), p(20), p(21), p(22), p(23) );break;
        	case 25: qwReturnValue = cdecl_func( 25 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19), p(20), p(21), p(22), p(23), p(24) );break;

        	default:
        		qwReturnValue = -1;
        		SetLastError(ERROR_INVALID_PARAMETER);
        		break;
        }
    }
    else
    {
        switch(dwStackSizeInElements)
        {
        	case  0: qwReturnValue = function( 00 )(); break;
        	case  1: qwReturnValue = function( 01 )( p(0) ); break;
        	case  2: qwReturnValue = function( 02 )( p(0), p(1) ); break;
        	case  3: qwReturnValue = function( 03 )( p(0), p(1), p(2) ); break;
        	case  4: qwReturnValue = function( 04 )( p(0), p(1), p(2), p(3) );break;
        	case  5: qwReturnValue = function( 05 )( p(0), p(1), p(2), p(3), p(4) );break;
        	case  6: qwReturnValue = function( 06 )( p(0), p(1), p(2), p(3), p(4), p(5) );break;
        	case  7: qwReturnValue = function( 07 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6) );break;
        	case  8: qwReturnValue = function( 08 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7) );break;
        	case  9: qwReturnValue = function( 09 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8) );break;
        	case 10: qwReturnValue = function( 10 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9) );break;
        	case 11: qwReturnValue = function( 11 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10) );break;
        	case 12: qwReturnValue = function( 12 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11) );break;
        	case 13: qwReturnValue = function( 13 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12) );break;
        	case 14: qwReturnValue = function( 14 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13) );break;
        	case 15: qwReturnValue = function( 15 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14) );break;
        	case 16: qwReturnValue = function( 16 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15) );break;
        	case 17: qwReturnValue = function( 17 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16) );break;
        	case 18: qwReturnValue = function( 18 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17) );break;
        	case 19: qwReturnValue = function( 19 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18) );break;
        	case 20: qwReturnValue = function( 20 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19) );break;
        	case 21: qwReturnValue = function( 21 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19), p(20) );break;
        	case 22: qwReturnValue = function( 22 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19), p(20), p(21) );break;
        	case 23: qwReturnValue = function( 23 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19), p(20), p(21), p(22) );break;
        	case 24: qwReturnValue = function( 24 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19), p(20), p(21), p(22), p(23) );break;
        	case 25: qwReturnValue = function( 25 )( p(0), p(1), p(2), p(3), p(4), p(5), p(6), p(7), p(8), p(9), p(10), p(11), p(12), p(13), p(14), p(15), p(16), p(17), p(18), p(19), p(20), p(21), p(22), p(23), p(24) );break;

        	default:
        		qwReturnValue = -1;
        		SetLastError(ERROR_INVALID_PARAMETER);
        		break;
        }
    }

    jlong* jReturnValue = (jlong*)env->GetLongArrayElements(returnValue, 0);
    long* toReturnValue = (long*)jReturnValue;
    toReturnValue[0] = (long) qwReturnValue;

    jint* jErrorCode = (jint*)env->GetIntArrayElements(errorCode, 0);
    int* returnErrorCode = (int*)jErrorCode;
    returnErrorCode[0] = (int)GetLastError();

    char* outMsgBuffer = 0;
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS,
        0,    // unused with FORMAT_MESSAGE_FROM_SYSTEM
        returnErrorCode[0], MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &outMsgBuffer,  // output
        0, // minimum size for output buffer
        0);

    for (int i = 0; i < 1024 && i < strlen(outMsgBuffer); i++)
    {
        errorMessageOut[i] = outMsgBuffer[i];
    }

    // Free the stuffs.
    free(pStack);
    FreeLibrary(hDLL);
    env->ReleaseStringUTFChars(libName, dllName);
    env->ReleaseStringUTFChars(funcName, functionName);
    env->ReleaseByteArrayElements(bufferBlobIn, jBufferIn, 0);
    env->ReleaseByteArrayElements(bufferBlobInOut, jBufferInOut, 0);
    env->ReleaseByteArrayElements(stackBlobIn, jStackBlob, 0);
    env->ReleaseLongArrayElements(returnValue, jReturnValue, 0);
    env->ReleaseIntArrayElements(errorCode, jErrorCode, 0);
    env->ReleaseStringUTFChars(callConv, callingConvention);
    env->ReleaseByteArrayElements(errorMessage, jErrorMessage, 0);
    LocalFree(outMsgBuffer);
}
