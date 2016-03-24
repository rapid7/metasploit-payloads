using System.Collections.Generic;

namespace MSF.Powershell.Meterpreter
{
    public static class Sys
    {
        public class ProcessInfo
        {
            public string Architecture { get; private set; }
            public int Pid { get; private set; }
            public int ParentPid { get; private set; }
            public string Name { get; private set; }
            public string Path { get; private set; }
            public int Session { get; private set; }
            public string Username { get; private set; }

            public ProcessInfo(string architcutre, int pid, int parentPid, string name,
                string path, int session, string username)
            {
                Architecture = architcutre;
                Pid = pid;
                ParentPid = parentPid;
                Name = name;
                Path = path;
                Session = session;
                Username = username;
            }
        }

        public class SysInfo
        {
            public string Host { get; private set; }
            public string OperatingSystem { get; private set; }
            public string Architecture { get; private set; }
            public string Language { get; private set; }
            public string Domain { get; private set; }
            public int LoggedOnUsers { get; private set; }

            public SysInfo(string host, string operatingSystem, string architecture, string language,
                string domain, int loggedOnUsers)
            {
                Host = host;
                OperatingSystem = operatingSystem;
                Architecture = architecture;
                Language = language;
                Domain = domain;
                LoggedOnUsers = loggedOnUsers;
            }
        }

        public static SysInfo Info()
        {
            Tlv tlv = new Tlv();

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest("stdapi_sys_config_sysinfo"));

            if (result != null)
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] Info result returned");
                var responseTlv = Tlv.FromResponse(result);
                if (responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0)
                {
                    System.Diagnostics.Debug.Write("[PSH BINDING] Info succeeded");

                    var host = Tlv.GetValue<string>(responseTlv, TlvType.ComputerName, string.Empty);
                    var os = Tlv.GetValue<string>(responseTlv, TlvType.OsName, string.Empty);
                    var arch = Tlv.GetValue<string>(responseTlv, TlvType.Architecture, string.Empty);
                    var lang = Tlv.GetValue<string>(responseTlv, TlvType.LangSystem, string.Empty);
                    var domain = Tlv.GetValue<string>(responseTlv, TlvType.Domain, string.Empty);
                    var loggedOn = Tlv.GetValue<int>(responseTlv, TlvType.LoggedOnUserCount);

                    return new SysInfo(host, os, arch, lang, domain, loggedOn);
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

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest("stdapi_sys_process_get_processes"));

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
                        var arch = Tlv.GetValue<int>(processDict, TlvType.ProcessArch) == 1 ? "x86" : "x86_64";
                        var name = Tlv.GetValue<string>(processDict, TlvType.ProcessName, string.Empty);
                        var user = Tlv.GetValue<string>(processDict, TlvType.UserName, string.Empty);
                        var pid = Tlv.GetValue<int>(processDict, TlvType.Pid);
                        var parentPid = Tlv.GetValue<int>(processDict, TlvType.ParentPid);
                        var path = Tlv.GetValue<string>(processDict, TlvType.ProcessPath, string.Empty);
                        var session = Tlv.GetValue<int>(processDict, TlvType.ProcessSession);
                        processes.Add(new ProcessInfo(arch, pid, parentPid, name, path, session, user));
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
