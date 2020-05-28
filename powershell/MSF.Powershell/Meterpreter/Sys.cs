using System.Collections.Generic;

namespace MSF.Powershell.Meterpreter
{
    public static class Sys
    {
        public class ProcessInfo
        {
            public string Architecture { get; set; }
            public int Pid { get; set; }
            public int ParentPid { get; set; }
            public string Name { get; set; }
            public string Path { get; set; }
            public int Session { get; set; }
            public string Username { get; set; }
        }

        public class SysInfo
        {
            public string Host { get; set; }
            public string OperatingSystem { get; set; }
            public string Architecture { get; set; }
            public string Language { get; set; }
            public string Domain { get; set; }
            public int LoggedOnUsers { get; set; }
        }

        public static SysInfo Info()
        {
            Tlv tlv = new Tlv();

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(CommandId.StdapiSysConfigSysinfo));

            if (result != null)
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] Info result returned");
                var responseTlv = Tlv.FromResponse(result);
                if (responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0)
                {
                    System.Diagnostics.Debug.Write("[PSH BINDING] Info succeeded");

                    return new SysInfo
                    {
                        Host = Tlv.GetValue<string>(responseTlv, TlvType.ComputerName, string.Empty),
                        OperatingSystem = Tlv.GetValue<string>(responseTlv, TlvType.OsName, string.Empty),
                        Architecture = Tlv.GetValue<string>(responseTlv, TlvType.Architecture, string.Empty),
                        Language = Tlv.GetValue<string>(responseTlv, TlvType.LangSystem, string.Empty),
                        Domain = Tlv.GetValue<string>(responseTlv, TlvType.Domain, string.Empty),
                        LoggedOnUsers = Tlv.GetValue<int>(responseTlv, TlvType.LoggedOnUserCount)
                    };
                }
                System.Diagnostics.Debug.Write("[PSH BINDING] ShowMount failed");
            }
            else
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] ShowMount result was null");
            }

            return null;
        }

        public static List<ProcessInfo> ProcessList()
        {
            Tlv tlv = new Tlv();

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(CommandId.StdapiSysProcessGetProcesses));

            if (result != null)
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] ProcessList result returned");
                var responseTlv = Tlv.FromResponse(result);
                if (responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0)
                {
                    System.Diagnostics.Debug.Write("[PSH BINDING] ProcessList succeeded");
                    var processes = new List<ProcessInfo>();

                    foreach (var processObj in responseTlv[TlvType.ProcessGroup])
                    {
                        var processDict = (Dictionary<TlvType, List<object>>)processObj;
                        var process = new ProcessInfo
                        {
                            Architecture = Tlv.GetValue<int>(processDict, TlvType.ProcessArch) == 1 ? "x86" : "x86_64",
                            Name = Tlv.GetValue<string>(processDict, TlvType.ProcessName, string.Empty),
                            Username = Tlv.GetValue<string>(processDict, TlvType.UserName, string.Empty),
                            Pid = Tlv.GetValue<int>(processDict, TlvType.Pid),
                            ParentPid = Tlv.GetValue<int>(processDict, TlvType.ParentPid),
                            Path = Tlv.GetValue<string>(processDict, TlvType.ProcessPath, string.Empty),
                            Session = Tlv.GetValue<int>(processDict, TlvType.ProcessSession)
                        };
                        processes.Add(process);
                    }

                    return processes;
                }
                System.Diagnostics.Debug.Write("[PSH BINDING] ProcessList failed");
            }
            else
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] ProcessList result was null");
            }

            return null;
        }
    }
}
