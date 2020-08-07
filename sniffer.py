#! /usr/bin/python3

# sniffer.py - Python3 based packet sniffer to sniff and log different kind of packets.
# It can sniff Ethernet Frames, ARP Packets, IPv4 packets, TCP and UDP segments, ICMP, HTTP and DNS protocols.
# Saves the capture logs in a file named log.pcap in the same directory as the program.
# Libraries used: socket, struct, time, os, textwrap.
# Must be run as root.
# Python Virtual Environment included.

# A project for Computer Networks I Course 98-2 semester at Isfahan University of Technology.
# Instructor: Dr. Manshaei.
# Programmed by Mohammad Serati Aligudarzi - Student. No: 9427363 - E-Mail: abexamir@gmail.com.

import socket
import struct
import time
import os
import textwrap

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '


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


def is_root():
    return os.geteuid() == 0


def multi_line_format(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


def mac_format(raw_mac):
    byte_str = map('{:02x}'.format, raw_mac)
    mac_addr = ':'.join(byte_str).upper()
    return mac_addr


def ip_format(raw_ip):
    return '.'.join(map(str, raw_ip))


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


def sniff():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    log = Pcap('log.pcap')

    while True:
        data, address = conn.recvfrom(65535)
        dst_mac, src_mac, eth_proto, data = ether(data)
        print('\nEthernet Frame:')
        print('\t Destination: {}, Source: {}, Protocol: {}'.format(dst_mac, src_mac, eth_proto))

        # ARP
        if eth_proto == 0x0806:
            (hw_type, protocol, hw_addr_length, proto_address_length, opcode, arp_src_mac, arp_src_ip, arp_dst_mac,
             arp_dst_ip) = arp(
                data)
            print("\t ARP Packet: ")
            print(("\t\t Hardware Type: {}, Opcode:{}".format(hw_type, opcode)))
            print(("\t\t Source MAC: {}, Source IP:{}".format(arp_src_mac, arp_src_ip)))
            print(("\t\t Destination MAC: {}, Destination IP:{}".format(arp_dst_mac, arp_dst_ip)))


        # IP
        elif eth_proto == 0x0800:
            (ip_version, ip_header_length, ttl, ip_protocol, src_ip, dst_ip, data) = ip(data)
            print("\t IPv4 Packet:")
            print("\t\t Version: {}, Header Length: {}, TTL: {}".format(ip_version, ip_header_length, ttl))
            print("\t\t Protocol: {}, Source: {}, Destination: {}".format(ip_protocol, src_ip, dst_ip))

            # ICMP
            if ip_protocol == 1:
                icmp_type, icmp_code, icmp_checksum, data = icmp(data)
                print('\t ICMP Packet:')
                print('\t\t Type: {}, Code:{}, Checksum: {},'.format(icmp_type, icmp_code, icmp_checksum))
                print(multi_line_format(DATA_TAB_3, data))



            # TCP
            elif ip_protocol == 6:
                tcp_src_port, tcp_dst_port, tcp_sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp(
                    data)
                print('\t TCP Segment:')
                print('\t\t Source Port: {}, Destination Port: {}'.format(tcp_src_port, tcp_dst_port))
                print('\t\t Sequence: {}, Acknowledgment: {}'.format(tcp_sequence, acknowledgment))
                print('\t\t Flags:')
                print('\t\t URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh))
                print('\t\t RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin))

                if len(data) > 0:
                    # HTTP
                    if tcp_src_port == 80 or tcp_dst_port == 80:
                        print('\t\t HTTP Data:')
                        try:
                            http_data = http(data)
                            http_info = str(http_data).split('\n')
                            for line in http_info:
                                print(DATA_TAB_3 + str(line))
                        except:
                            print(multi_line_format(DATA_TAB_3, data))
                    else:
                        print('\t\t TCP Data:')
                        print(multi_line_format(DATA_TAB_3, data))

            # UDP
            if ip_protocol == 17:
                udp_src_port, udp_dst_port, udp_size, udp_checksum, data = udp(data)
                print('\t UDP Segment:')
                print('\t\t Source Port: {}, Destination Port: {}'.format(udp_src_port, udp_dst_port))
                print('\t\t Size: {}, Checksum: {}'.format(udp_size, udp_checksum))

                # DNS
                if udp_src_port == 53 or udp_src_port == 53:
                    identification, flags, number_queries, \
                    number_response, number_authority, number_additional, \
                    qr, opcode, aa, tc, rd, ra, z, rcode = dns(data)
                    print("\t DNS Packet:")
                    print("\t\tdentification: {}".format(identification))
                    print("\t\tFlags : {}".format(flags))
                    print("\t\tnumber_queries : {}".format(number_queries))
                    print("\t\tnumber_response : {}".format(number_response))
                    print("\t\tnumber_authority : {}".format(number_authority))
                    print("\t\tnumber_additional : {}".format(number_additional))
                    print("\t\tQr : {}".format(qr))
                    print("\t\tOpcode : {}".format(opcode))
                    print("\t\tAA : {}".format(aa))
                    print("\t\tTC : {}".format(tc))
                    print("\t\tRD : {}".format(rd))
                    print("\t\tRA : {}".format(ra))
                    print("\t\tZ : {}".format(z))
                    print("\t\tRCODE : {}".format(rcode))


if is_root():
    sniff()

else:
    print("root access is necessary")
