using System;
using System.Runtime.InteropServices;
using System.Text;

namespace MSF.Powershell.Meterpreter
{
    public static class Core
    {
        private delegate void MeterpreterInvoke(uint isLocal, byte[] input, uint inputSize, ref IntPtr output, ref uint outputSize);

        private static MeterpreterInvoke _callback = null;

        public static void SetInvocationPointer(Int64 callbackPointer)
        {
            System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] Callback pointer being set to 0x{0:X}", callbackPointer));
            _callback = (MeterpreterInvoke)Marshal.GetDelegateForFunctionPointer(new IntPtr(callbackPointer), typeof(MeterpreterInvoke));
            System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] _callback is {0}null", _callback == null ? "" : "not "));
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

                    if (output != IntPtr.Zero && outputLength > 0)
                    {
                        var result = new byte[outputLength];
                        Marshal.Copy(output, result, 0, result.Length);

                        return result;
                    }
                }
                finally
                {
                    if (output != IntPtr.Zero)
                    {
                        System.Diagnostics.Debug.Write(string.Format("[PSH BINDINGS] Freeing up memory allocated from the C++ Binding: {0:X}", output));
                        Marshal.FreeCoTaskMem(output);
                    }
                }
            }

            return null;
        }
    }
}
