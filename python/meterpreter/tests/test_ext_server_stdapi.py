# coding=utf-8

import unittest
import code
import sys
import socket
import os

if sys.version_info >= (3, 3):
    from unittest import mock
else:
    import mock

ERROR_SUCCESS = 0

is_windows = sys.platform.startswith("win")
windows_only_test_reason = "Windows only test"


def create_meterpreter_context():
    with open("meterpreter.py", "rb") as file:
        # Read and patch out the Meterpreter socket connection logic side effect onwards
        source = file.read()
        source_without_socket_connection = source[
            0 : source.index(b"# PATCH-SETUP-ENCRYPTION #")
        ]

        context = {}
        exec(source_without_socket_connection, context, context)
    return context


def create_ext_server_stdapi_context(meterpreter, meterpreter_context):
    with open("ext_server_stdapi.py", "rb") as file:
        extension_content = file.read()

        context = {}
        context.update(meterpreter_context["EXPORTED_SYMBOLS"])
        context["meterpreter"] = meterpreter
        exec(extension_content, context, context)
    return context


class MockMeterpreter:
    def __init__(self):
        self.extension_functions = {}

    def register_extension(self, extension_name):
        pass

    def register_function(self, func):
        self.extension_functions[func.__name__] = func
        return func


class ExtServerStdApiTest(unittest.TestCase):
    def setUp(self):
        self.mock_meterpreter = MockMeterpreter()
        self.meterpreter_context = create_meterpreter_context()

        self.ext_server_stdapi = create_ext_server_stdapi_context(
            self.mock_meterpreter, self.meterpreter_context
        )

    def assertMethodErrorSuccess(self, method_name, request, response):
        result = self.ext_server_stdapi[method_name](request, response)
        self.assertErrorSuccess(result)

        return result

    def assertErrorSuccess(self, result):
        self.assertEqual(result[0], ERROR_SUCCESS)
        self.assertIsInstance(result[1], bytes)

    def assertRegex(self, text, regexp, msg=None):
        if hasattr(super(self.__class__.__bases__[0], self), 'assertRegex'):
            super(self.__class__.__bases__[0], self).assertRegex(text, regexp, msg)
        else:
            # Python 2.7 fallback
            self.assertRegexpMatches(text, regexp, msg)


class ExtServerStdApiNetworkTest(ExtServerStdApiTest):
    def test_stdapi_net_config_get_interfaces(self):
        request = bytes()
        response = bytes()
        self.assertMethodErrorSuccess(
            "stdapi_net_config_get_interfaces", request, response
        )

    def test_stdapi_net_config_get_routes(self):
        request = bytes()
        response = bytes()
        self.assertMethodErrorSuccess("stdapi_net_config_get_routes", request, response)

    def test_stdapi_sys_process_get_processes(self):
        request = bytes()
        response = bytes()
        self.assertMethodErrorSuccess(
            "stdapi_sys_process_get_processes", request, response
        )

    @mock.patch("subprocess.Popen")
    def test_stdapi_net_config_get_routes_via_osx_netstat(self, mock_popen):
        command_result = b"""
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            10.79.0.1          UGScg          en0
192.168.1          link#6             UCS            en0      !

Internet6:
Destination                             Gateway                         Flags         Netif Expire
default                                 fe80::%utun0                    UGcIg         utun0
fe80::e8fa:527d:5e1a:1122%en5           f3:3a:1c:c6:f7:75               UHLI            lo0
fe80::e8fa:527d:5e1a:ae4c%bridge100     f3.3a.1c.c6.f7.75               UHLI            lo0
""".lstrip()

        process_mock = mock.Mock()
        attrs = {
            "communicate.return_value": (command_result, b""),
            "wait.return_value": ERROR_SUCCESS,
        }
        process_mock.configure_mock(**attrs)
        mock_popen.return_value = process_mock

        result = self.ext_server_stdapi[
            "stdapi_net_config_get_routes_via_osx_netstat"
        ]()

        expected = [
            {
                "gateway": b"\nO\x00\x01",
                "iface": "en0",
                "metric": 0,
                "netmask": b"\x00\x00\x00\x00",
                "subnet": b"\x00\x00\x00\x00",
            },
            {
                "gateway": b"\x00\x00\x00\x00",
                "iface": "en0",
                "metric": 0,
                "netmask": b"\xff\xff\xff\xff",
                "subnet": b"\xc0\xa8\x01\x00",
            },
            {
                "gateway": b"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "iface": "utun0",
                "metric": 0,
                "netmask": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "subnet": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            },
            {
                "gateway": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "iface": "lo0",
                "metric": 0,
                "netmask": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00",
                "subnet": b'\xfe\x80\x00\x00\x00\x00\x00\x00\xe8\xfaR}^\x1a\x11"',
            },
            {
                "gateway": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "iface": "lo0",
                "metric": 0,
                "netmask": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00",
                "subnet": b"\xfe\x80\x00\x00\x00\x00\x00\x00\xe8\xfaR}^\x1a\xaeL",
            },
        ]

        self.assertEqual(result, expected)

    @mock.patch("subprocess.Popen")
    def test_stdapi_net_config_get_interfaces_via_osx_ifconfig(self, mock_popen):
        command_result = b"""
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        options=400<CHANNEL_IO>
        ether 11:22:33:44:55:66
        inet 192.168.1.166 netmask 0xffffff00 broadcast 192.168.1.255
        media: autoselect
        status: active
""".lstrip()

        process_mock = mock.Mock()
        attrs = {
            "communicate.return_value": (command_result, b""),
            "wait.return_value": ERROR_SUCCESS,
        }
        process_mock.configure_mock(**attrs)
        mock_popen.return_value = process_mock

        result = self.ext_server_stdapi[
            "stdapi_net_config_get_interfaces_via_osx_ifconfig"
        ]()

        expected = [
            {
                "addrs": [
                    (
                        socket.AF_INET,
                        b"\xc0\xa8\x01\xa6",
                        b"\xff\xff\xff\x00",
                    )
                ],
                "flags": 8863,
                "flags_str": "UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST",
                "hw_addr": '\x11"3DUf',
                "index": 0,
                "mtu": 1500,
                "name": "en0",
            }
        ]

        self.assertEqual(result, expected)


class ExtServerStdApiFileSystemTest(ExtServerStdApiTest):
    def test_stdapi_fs_stat(self):
        request = bytes()
        request += self.meterpreter_context["tlv_pack"](
            self.ext_server_stdapi["TLV_TYPE_FILE_PATH"],
            os.path.dirname(os.path.abspath(__file__)),
        )
        response = bytes()
        self.assertMethodErrorSuccess("stdapi_fs_stat", request, response)

    # Older versions of Python on Windows return invalid/negative values for st_rdev
    # https://github.com/python/cpython/commit/a10c1f221a5248cedf476736eea365e1dfc84910#diff-b419a047f587ec3afef8493e19dbfc142624bf278f3298bfc74729abd89e311d
    @mock.patch("os.stat")
    @mock.patch("sys.platform")
    def test_stdapi_fs_stat_with_negative_st_rdev_on_windows(
        self, mock_sys_platform, mock_os_stat
    ):
        os_stat_result = mock.MagicMock()
        os_stat_result.configure_mock(
            **{
                "st_mode": 33206,
                "st_ino": 281474976726344,
                "st_dev": 3323847249,
                "st_nlink": 1,
                "st_uid": 0,
                "st_gid": 0,
                "st_size": 9884,
                "st_rdev": -1910224650,
                "st_atime": 1686079301.2200336,
                "st_mtime": 1686079301.2200336,
                "st_ctime": 1686079301.2200336,
            }
        )

        mock_os_stat.return_value = os_stat_result
        mock_sys_platform.return_value = "win32"

        request = bytes()
        request += self.meterpreter_context["tlv_pack"](
            self.ext_server_stdapi["TLV_TYPE_FILE_PATH"], "/mock/path"
        )
        response = bytes()
        self.assertMethodErrorSuccess("stdapi_fs_stat", request, response)


class ExtServerStdApiSysProcess(ExtServerStdApiTest):
    def test_stdapi_sys_process_get_processes(self):
        request = bytes()
        response = bytes()
        result = self.assertMethodErrorSuccess(
            "stdapi_sys_process_get_processes", request, response
        )

        self.assertErrorSuccess(result)

    @mock.patch("subprocess.Popen")
    def test_stdapi_sys_process_get_processes_via_ps(self, mock_popen):
        command_result = b"""
  PID  PPID USER             COMMAND
    1     0 root             /sbin/launchd
   88     1 root             /usr/sbin/syslogd
   89     1 root             /usr/libexec/UserEventAgent (System)
""".lstrip()

        process_mock = mock.Mock()
        attrs = {
            "communicate.return_value": (command_result, b""),
            "wait.return_value": ERROR_SUCCESS,
        }
        process_mock.configure_mock(**attrs)
        mock_popen.return_value = process_mock

        request = bytes()
        response = bytes()
        result = self.ext_server_stdapi["stdapi_sys_process_get_processes_via_ps"](
            request, response
        )

        self.assertErrorSuccess(result)


class ExtServerStdApiSystemConfigTest(ExtServerStdApiTest):
    def test_stdapi_sys_config_getuid(self):
        request = bytes()
        response = bytes()
        _result_code, result_tlvs = self.assertMethodErrorSuccess(
            "stdapi_sys_config_getuid", request, response
        )

        user_name = self.meterpreter_context["packet_get_tlv"](
            result_tlvs, self.ext_server_stdapi["TLV_TYPE_USER_NAME"]
        ).get("value")
        self.assertRegex(user_name, ".+")

    @unittest.skipUnless(is_windows, windows_only_test_reason)
    def test_stdapi_sys_config_getsid(self):
        request = bytes()
        response = bytes()
        _result_code, result_tlvs = self.assertMethodErrorSuccess(
            "stdapi_sys_config_getsid", request, response
        )

        sid = self.meterpreter_context["packet_get_tlv"](
            result_tlvs, self.ext_server_stdapi["TLV_TYPE_SID"]
        ).get("value")
        self.assertRegex(sid, "S-1-5-.*")


if __name__ == "__main__":
    unittest.main()
