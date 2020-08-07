import os
import textwrap


DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

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

