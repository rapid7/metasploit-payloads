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
    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    else:
      socket_protocol = socket.ntohs(3)
    sniffer.bind((host, 0))
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) # turning on promiscous mode for windows

    while capture:
        raw_buffer, addr = sniffer.recvfrom(65565)
        eth = ethernet_head(raw_data)
        src_mac = eth[0]
        dst_mac = eth[1]
        protocol = eth[2]
      
        if eth[2] == 8:
            ipv4 = ipv4_head(eth[3])
            ip_version = ipv4[0]
            ip_header_length = ipv4[1]
            ip_ttl = ipv4[2]
            ip_proto = ipv4[3]
            ip_src_address = get_ip(ipv4[4])
            ip_dst_address = get_ip(ipv4[5])
            if ipv4[3] == 6:
                tcp = tcp_head(ipv4[6])
                src_port = tcp[0]
                dst_port = tcp[1]
                seq = tcp[2]
                ack = tcp[3]
            elif ipv4[3] == 1:
              # ICMP packet
            elif ipv4[3] == 17:
              # UDP packet



def request_sniffer_capture_stop(request, response):
    capture = false
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF) # turning of the promiscous mode in case of windows

def request_sniffer_interfaces(request, response):
  addrs = psutil.net_if_addrs()
  response = tlv_pack(TLV_TYPE_SNIFFER_INTERFACES, addrs.keys())
  return ERROR_SUCCESS, response

meterpreter.register_extension('sniffer')

def ethernet_head(raw_data):
  dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
  #dest_mac = get_mac_addr(dest)
 # src_mac = get_mac_addr(src)
  proto = socket.htons(prototype)
  data = raw_data[14:]
  return dest, src, proto, data

def get_mac(addr):
  mac_int = int.from_bytes(addr, "big")
  mac_hex = "{:012x}".format(mac_int)
  mac_str = ":".join(mac_hex[i:i+2] for i in range(0, len(mac_hex), 2))
  
def ipv4_head(raw_data):
 version_header_length = raw_data[0]
 version = version_header_length >> 4
 header_length = (version_header_length & 15) * 4
 ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
 data = raw_data[header_length:]
 return version, header_length, ttl, proto, src, target, data

def tcp_head( raw_data):
 (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', raw_data[:14])
 offset = (offset_reserved_flags >> 12) * 4
 flag_urg = (offset_reserved_flags & 32) >> 5
 flag_ack = (offset_reserved_flags & 16) >> 4
 flag_psh = (offset_reserved_flags & 8) >> 3
 flag_rst = (offset_reserved_flags & 4) >> 2
 flag_syn = (offset_reserved_flags & 2) >> 1
 flag_fin = offset_reserved_flags & 1
 data = raw_data[offset:]
 return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

def get_ip(addr):
 return '.'.join(map(str, addr))
