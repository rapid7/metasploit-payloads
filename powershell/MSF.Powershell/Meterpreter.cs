using System;
using System.Runtime.InteropServices;
using System.Text;

namespace MSF.Powershell
{
    public static class Meterpreter
    {
        private delegate void MeterpreterInvoke(uint isLocal, byte[] input, uint inputSize, ref IntPtr output, ref uint outputSize);

        private static MeterpreterInvoke _callback = null;

        public static void SetInvocationPointer(Int64 callbackPointer)
        {
            _callback = (MeterpreterInvoke)Marshal.GetDelegateForFunctionPointer(new IntPtr(callbackPointer), typeof(MeterpreterInvoke));
        }

        public static string RandomString(int length)
        {
            var r = new Random();
            var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var bytes = new byte[length];
            for (int i = 0; i < length; ++i)
            {
                bytes[i] = (byte)chars[r.Next(chars.Length)];
            }

            return Encoding.ASCII.GetString(bytes);
        }

        internal static byte[] InvokeMeterpreterBinding(bool isLocal, byte[] input)
        {
            if (_callback != null)
            {

                IntPtr output = IntPtr.Zero;
                try
                {
                    uint outputLength = 0;
                    _callback(isLocal ? 1U : 0U, input, (uint)input.Length, ref output, ref outputLength);

                    var result = new byte[outputLength];
                    Marshal.Copy(output, result, 0, result.Length);

                    return result;
                }
                finally
                {
                    if (output != IntPtr.Zero)
                    {
                        Marshal.FreeCoTaskMem(output);
                    }
                }
            }

            return null;
        }
    }
}
