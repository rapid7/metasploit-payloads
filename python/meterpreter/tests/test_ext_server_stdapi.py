# coding=utf-8

import unittest
import code
import sys
import socket

if sys.version_info >= (3, 3):
    from unittest import mock
else:
    import mock

ERROR_SUCCESS = 0


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


class TestExtServerStdApi(unittest.TestCase):
    def setUp(self):
        self.ext_server_stdapi = create_ext_server_stdapi_context(
            MockMeterpreter(), create_meterpreter_context()
        )

    @mock.patch("subprocess.Popen")
    def test_stdapi_net_config_get_routes_via_osx_netstat(self, mock_popen):
        command_result = b"""
Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            10.79.0.1          UGScg          en0

Internet6:
Destination                             Gateway                         Flags         Netif Expire
default                                 fe80::%utun0                    UGcIg         utun0
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
                "gateway": b"\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "iface": "utun0",
                "metric": 0,
                "netmask": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                "subnet": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
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

    def assertMethodErrorSuccess(self, method_name, request, response):
        request = bytes()
        response = bytes()
        result = self.ext_server_stdapi[method_name](request, response)

        self.assertErrorSuccess(result)

        return result

    def assertErrorSuccess(self, result):
        self.assertEqual(result[0], ERROR_SUCCESS)
        self.assertIsInstance(result[1], bytes)


if __name__ == "__main__":
    unittest.main()
