import socket#importing socket module to work with sockets
import os
import struct#provides funtionality to work with variable-lenght binary data records
from ctypes import *#ctypes provides c compatible data types

class IP(Structure):#declaring new class which inherits from "structures" in ctypes
    #_fields attribute used for defining the fields of the structure(name and types)
    _fields=[
        ('ihl', c_ubyte, 4),#Internet Header Lenght(length of ip header), c_ubyte represents unsigned byte, 4 indicates 4 bits
        ('version', c_ubyte, 4),#version of ip(IPv4/IPv6), occupies 4 bits
        ('tos', c_ubyte),#type of service
        ('len', c_ushort),#len represents the entire packet size, c_ushort represents 2bytes or 16 bits
        ('id', c_ushort),#"Identification" field, used for uniquely identifying fragments of an original IP datagram
        ('offset', c_ushort),#"Fragment Offset" field, used to indicate where a fragment belongs in the original IP datagram.
        ('ttl', c_ubyte),#time to live, counter that gets decremented at each hop in the network until it reaches 0 and packet is discared
        ('protocol_num', c_ubyte),#indicates the number of the protocol used
        ('sum', c_ushort),#header checksum, used for error checking the header
        ('src', c_uint32),#represents the source ip address(where the packet is coming from)
        ('dst', c_uint32)#represents the destination ip address(where the packet is going)
    ]

    #method for creating new instance of class
    def __new__(self, socket_buffer=None):
        return self.from_buffer_copy(socket_buffer)#returning a copy of the binary data, ensuring integrity of the binary data
    
    #method to initialize the instance of the class
    """def __init__(self, socket_buffer=None):
        self.protocol_map={1: "ICMP", 6: "TCP", 17:"UDP"}#dictionary to map the protocols and their numbers
        #translating source IP address from binary to standard dotted-quad string representation
        self.src_address=socket.inet_ntoa(struct.pack("<L", self.src))
        #same functionality as above line, except its used for destination address
        self.dst_address=socket.inet_ntoa(struct.pack("<L", self.dst))
        try:
            #fetching the protocols string representation
            self.protocol = self.protocol_map.get(self.protocol_num, str(self.protocol_num))
        except:
            #if protocol doesn't exist in above dictionary, it fetches the protocol number
            self.protocol=str(self.protocol_num)"""
    
    def __init__(self, socket_buffer=None):
        self.protocol_map={1: "ICMP", 6: "TCP", 17:"UDP"} #dictionary to map the protocols and their numbers

        # Unpacking the IP header fields from the socket buffer
        iph = struct.unpack('!BBHHHBBH4s4s', socket_buffer)
        self.version_ihl = iph[0]
        self.tos = iph[1]
        self.len = iph[2]
        self.id = iph[3]
        self.offset = iph[4]
        self.ttl = iph[5]
        self.protocol_num = iph[6]
        self.sum = iph[7]
        self.src = iph[8]  # Storing the packed IP source address
        self.dst = iph[9]  # Storing the packed IP dest address

        # Version is the first 4 bits of version_ihl
        self.version = self.version_ihl >> 4
        # IHL is the last 4 bits of version_ihl
        self.ihl = self.version_ihl & 0xF

        # Translate the packed IP addresses to dotted-quad strings
        self.src_address = socket.inet_ntoa(self.src)
        self.dst_address = socket.inet_ntoa(self.dst)

        self.protocol = self.protocol_map.get(self.protocol_num, str(self.protocol_num))

def main():
    #checking if operting system is windows
    if os.name=="nt":
        #if windows, socket protocol is set to "socket.IPROTO_IP" meaning sniffer will capture all IP packets
        socket_protocol=socket.IPPROTO_IP
    else:
        socket_protocol=socket.IPPROTO_ICMP
    #creating a new sniffer socket
    #socket.AF_INET-> specifies its an IPv4 packet
    #socket.SOCK_RAW-> meaning that it captures all packets and not only payload data
    sniffer=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    #sniffer socket is bound to this IP address, meaning it captures all packets from and to this machine
    sniffer.bind(("192.168.1.23", 0))

    #checking if operating system is windows
    if os.name=="nt":
        #making sure it captures all the data
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    
    try:
        while True:
            #capturing all packets from socket
            #rcvfrom returns a tuple of data and address ut we only fetch data[0]
            raw_buffer=sniffer.recvfrom(65565)[0]

            #extracting the first 20 bytes from the packet, representing IP header
            ip_header=IP(raw_buffer[0:20])

            #printing the protocol, source address and destination address
            print(f"protocol: {ip_header.protocol} {ip_header.src_address} -> {ip_header.dst_address}")
    #exception for when user interrupts program
    except KeyboardInterrupt:
        if os.name=="nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

#running the main funtion
if __name__=="__main__":
    main()