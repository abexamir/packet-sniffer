import struct
import time
from utilities import *


class Pcap:
    def __init__(self, filename, link_type=1):
        self.pcap_file = open(filename, 'wb')
        self.pcap_file.write(struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

    def write(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        self.pcap_file.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close(self):
        self.pcap_file.close()


def ether(data):
    dst_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return mac_format(dst_mac), mac_format(src_mac), proto, data[14:]


def arp(data):
    hw_type, protocol, hw_addr_length, proto_address_length, opcode, src_mac, src_ip, dst_mac, dst_ip = struct.unpack(
        '2s 2s 1s 1s 2s 6s 4s 6s 4s', data[:28])
    return mac_format(hw_type), protocol, hw_addr_length, proto_address_length, mac_format(opcode), mac_format(
        src_mac), ip_format(src_ip), mac_format(dst_mac), ip_format(dst_ip)


def ip(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 0xF) * 4
    ttl, proto, src_ip, dst_ip = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ip_format(src_ip), ip_format(dst_ip), data[header_length:]


def icmp(data):
    icmp_type, icmp_code, icmp_checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, icmp_code, icmp_checksum, data[4:]


def tcp(data):
    (src_port, dst_port, sequence, acknowledgement, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    return src_port, dst_port, sequence, acknowledgement, \
           flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, \
           data[offset:]


def http(data):
    try:
        http_data = data.decode('utf-8')
    except:
        http_data = data
    return http_data


def udp(data):
    (src_prt, dst_port, length, checksum) = struct.unpack('! H H H H', data[:8])
    return src_prt, dst_port, length, checksum, data[8:]


def dns(data):
    (identification, flags, number_queries, number_response, number_authority, number_additional) = struct.unpack(
        '!H H H H H H', data[:12])
    qr = (flags & 32768) != 0
    opcode = (flags & 30720) >> 11
    aa = (flags & 1024) != 0
    tc = (flags & 512) != 0
    rd = (flags & 256) != 0
    ra = (flags & 128) != 0
    z = (flags & 112) >> 4
    rcode = flags & 15
    return identification, flags, number_queries, number_response, + \
        number_authority, number_additional, qr, opcode, aa, tc, + \
               rd, ra, z, rcode
