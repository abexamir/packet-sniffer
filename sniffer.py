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
from networking import *


def sniff(conn):
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
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    log = Pcap('log.pcap')
    while True:
        try:
            sniff(connection)
        except KeyboardInterrupt:
            print("[+] Keyboard Interrupt Detected, Closing ...")
            break
    log.close()
    connection.close()
else:
    print("Please run the sniffer as root")
