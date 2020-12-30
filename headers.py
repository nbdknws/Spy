import socket
import struct 
from ctypes import BigEndianStructure, create_string_buffer, c_ubyte, c_uint8, \
    c_uint16, c_uint32, sizeof

#create a proto class for all possible headers
class Header(BigEndianStructure):
    _pack_ = 1
    #takes in a raw buffer and forms a structure from it
    def __new__(cls, data):
        return cls.from_buffer_copy(data)
    #when __init__ is called __new__ is already finished processining the buffer 
    def __init__(self, *args):
        super().__init__()
        #set encapsulated protocol flag
        self.encapsulated = None
    #creates C char arrays
    def __str__(self):
        return create_string_buffer(sizeof(self))[:]
    #converts MAC adress in bytes to proper addess string with : separator
    def bytes_to_addr(self, bytes_addr):

        return ':'.join(map('{:02x}'.format, bytes_addr)).upper()
    #formats to hex value
    def hex_format(self, value, str_length=6): 
        return format(value, '#0{}x'.format(str_length))



class Ethernet(Header):
    #define _fields_ structure for mapping bytes to attributes
    _fields_ = [
        ('dst', c_ubyte * 6),
        ('src', c_ubyte * 6),
        ('type', c_uint16)
    ]
    #set header length
    header_length = 14
    #set encapsulated protocols types
    types = { '0x0806': 'ARP', '0x0800': 'IPv4', '0x86dd': 'IPv6'}

    def __init__(self, data):
        super().__init__(data)
        #format dst and src MAC and ethernet type
        self.dest = self.bytes_to_addr(self.dst)
        self.source = self.bytes_to_addr(self.src)
        self.ethtype = self.hex_format(self.type, 6)
        
        self.encapsulated = self.types[self.ethtype]
    



class IPv4(Header):
    #define _fields_ structure for mapping bytes to attributes
    _fields_ = [
        ("version", c_uint8, 4),  
        ("header_len", c_uint8, 4),      
        ("dscp", c_uint8, 6),      
        ("ecn", c_uint8, 2),      
        ("total_length", c_uint16),       
        ("id", c_uint16),         
        ("flags", c_uint16, 3),    
        ("fragment_offset", c_uint16, 13),  
        ("ttl", c_uint8),          
        ("proto", c_uint8),        
        ("cheksum", c_uint16),      
        ("src", c_ubyte * 4),      
        ("dst", c_ubyte * 4)       
    ]
    #set header length
    header_length = 20
    types = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}


    def __init__(self, packet):
        #format src and dst IP
        super().__init__(packet)
        self.source = socket.inet_ntop(socket.AF_INET, self.src)
        self.dest = socket.inet_ntop(socket.AF_INET, self.dst)
        #set encapsulated proto if possible
        if self.proto in self.types:
            self.encapsulated = self.types[self.proto]
        else:
            self.encapsulated = None



class IPv6(Header):
    #define _fields_ structure for mapping bytes to attributes
    _fields_ = [
        ("version", c_uint32, 4), 
        ("traffic_class", c_uint32, 8),
        ("flow_label", c_uint32, 20),
        ("payload_len", c_uint16),
        ("next_hdr", c_uint8),
        ("hop_limit", c_uint8),
        ("src", c_ubyte * 16), #128 bits
        ("dst", c_ubyte * 16),
    ]
    #set header length
    header_length=40


    def __init__(self, packet):
        super().__init__(packet)
        #format src and dst IP 
        self.source = socket.inet_ntop(socket.AF_INET6, self.src)
        self.dest = socket.inet_ntop(socket.AF_INET6, self.dst)
    


    

class ARP(Header):
    #define _fields_ structure for mapping bytes to attributes
    _fields_ = [
        ('hardware_type', c_uint16), 
        ('protocol_type', c_uint16),
        ('hardware_address_length', c_uint8),
        ('protocol_address_length', c_uint8),
        ('operation', c_uint16), 
        ('sender_hardware_address', c_ubyte * 6),
        ('sender_protocol_address', c_ubyte * 4),
        ('target_hardware_address', c_ubyte * 6),
        ('target_protocol_address', c_ubyte * 4),
    ]
    #set header length
    header_length = 28

    def __init__(self, packet):
        super().__init__(packet)
        #format protocol type and src, dst MAC/IP addrs
        self.proto = self.hex_format(self.protocol_type, 6)
        self.src_mac = self.bytes_to_addr(self.sender_hardware_address)
        self.dst_mac = self.bytes_to_addr(self.target_hardware_address)
        self.src_ip = socket.inet_ntop(socket.AF_INET, bytes(self.sender_protocol_address))
        self.dst_ip = socket.inet_ntop(socket.AF_INET, bytes(self.target_protocol_address))

    

class TCP(Header):
    #define _fields_ structure for mapping bytes to attributes
    _fields_ = [
        ('source_port', c_uint16),
        ('destination_port', c_uint16),
        ('sequence_number', c_uint32),
        ('acknowledgement', c_uint32),
        ('data_offset', c_uint16, 4),
        ('reserved', c_uint16, 3),
        ('flags', c_uint16, 9),
        ('window_size', c_uint16),
        ('cheksum', c_uint16),
        ('urgent_pointer', c_uint16)
    ]
    #set header length
    header_length = 32 

    def __init__(self, packet):
        super().__init__(packet)
        #create flag string from flags
        self.flags_str = self.parse_flags()
    
    def parse_flags(self):
        names = ['NS', 'CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN']
        bits = format(self.flags, '09b')
        
        parsed = ''

        for i in range(len(names)):
            parsed += names[i] + ':' + bits[i] + ' '
        
        return parsed
    



class UDP(Header):
    #define _fields_ structure for mapping bytes to attributes
    _fields_ = [
        ('source_port', c_uint16),
        ('destination_port', c_uint16),
        ('length', c_uint16),
        ('cheksum', c_uint16),
    ]
    #set header length
    header_length = 8

    def __init__(self, packet):
        super().__init__(packet)
    


class ICMP(Header):
    #define _fields_ structure for mapping bytes to attributes
    _fields_ = [
        ('type', c_uint8),
        ('code', c_uint8),
        ('checksum', c_uint16),
        ('rest_of_header', c_ubyte * 4),
    ]
    #set header length
    header_length = 8
    #types of messeges
    types = { 
        0:'Echo reply', 
        3:'Destination unreachable', 
        4: 'Source Quench', 
        5:'Redirect Message', 
        8:'Echo request', 
        9:'Router advertisment', 
        10:'Router Solicitation',
        11:'Time Exceeded',
        12:'Parameter Poblem; Bad IP Header',
        13:'Timestamp',
        14:'Timestamp Reply',
        15:'Information Request',
        16:'Information Reply',
        17:'Address Mask Request',
        18:'Address Mask Reply',
        30:'Traceroute',
        42:'Extended Echo Request',

        }

    def __init__(self, packet):
        super().__init__(packet)
        #create type messege string if possible
        if self.type in self.types:
            self.type_str = self.types[self.type]
        else:
            self.type_str = 'Unknown type'
