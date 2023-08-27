import socket#importing socket module to work with sockets
import os
import struct#provides funtionality to work with variable-lenght binary data records
from ctypes import *#ctypes provides c compatible data types

class IP(Structure):#declaring new class which inherits from "structures" in ctypes
    #_fields attribute used for defining the fields of the structure(name and types)
    _fields=[
        ('ihl', c_ubyte, 4)#Internet Header Lenght(length of ip header), c_ubyte represents unsigned byte, 4 indicates 4 bits
        ('version', c_ubyte, 4),#version of ip(IPv4/IPv6), occupies 4 bits
        ('tos', c_ubyte),#type of service
        ('len', c_ushort),#len represents the entire packet size, c_ushort represents 2bytes or 16 bits
        ('id', c_ushort),#"Identification" field, used for uniquely identifying fragments of an original IP datagram
        ('offset', c_ushort),#"Fragment Offset" field, used to indicate where a fragment belongs in the original IP datagram.
        ('ttl', c_ubyte),#time to live, counter that gets decremented at each hop in the network until it reaches 0 and packet is discared
        ('protocol_num', c_ubyte)#indicates the number of the protocol used
        ('sum', c_ushort),#header checksum, used for error checking the header
        ('src', c_uint32),#represents the source ip address(where the packet is coming from)
        ('dst', c_uint32)#represents the dst ip address(where the packet is going)
    ]