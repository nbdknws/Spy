from socket import socket, AF_PACKET, PF_PACKET, SOCK_RAW, htons, INADDR_ANY
import sys
import os
import struct 
import time
import codecs
import argparse
import headers

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class Sniffer:
    
    def __init__(self, packet):
        self.data = packet
        self.queue = ["Ethernet"]
        self.to_screen = False
        self.hide_data = False
        
    def CollectHeaders(self):
        for header_name in self.queue:
            header_class = getattr(headers, header_name)
            start = 0
            end = start + header_class.header_length
            header = header_class(self.data[start:end])

            setattr(self, header_name.lower(), header)
            
            if header.encapsulated is None:
                break
            
            self.queue.append(header.encapsulated)
            start = end
            self.data = self.data[end:]
    
    def GiveHeaders(self):
        packet = ''
        for header_name in self.queue:
            
            packet += header_name +'\n'
            packet += getattr(self, 'print_{}_header'.format(header_name.lower()))()
        if not self.hide_data:
            packet += self.display_header_data()
        return packet
        
    def PrintHeaders(self):
        for header_name in self.queue:
            print(bcolors.OKGREEN + header_name + bcolors.ENDC + '\n')
            print(getattr(self, 'print_{}_header'.format(header_name.lower()))())
        if not self.hide_data:
            print(self.display_header_data())
    
    def print_header_attrs(self, header, attrs):
        attributes = ''
        if self.to_screen:
            color1, color2 = bcolors.OKCYAN, bcolors.ENDC
        else:
            color1, color2 = '', ''

        for attr in attrs.keys():
            attributes += ('    '+ color1 + attrs[attr] + color2 + ' : ' + str(getattr(header,attr)) + '\n')
        return attributes

    
    def print_ethernet_header(self):
        attrs = {'source':'Source MAC', 'dest': 'Destination MAC', 'ethtype':'Ethrnet Type'}
        return self.print_header_attrs(self.ethernet, attrs)

    def print_ipv4_header(self):
        attrs = {'version':'Version', 'header_len':'Header Length', 'dscp': 'DSCP','ecn':'ECN','total_length': 'Total Length', 'id': 'ID', 'fragment_offset': 'Fragment Offset', 'ttl':'TTL', 'proto':'Protocol', 'source':'Source IP', 'dest':'Target IP'}
        return self.print_header_attrs(self.ipv4, attrs)

    def print_ipv6_header(self):
        attrs = {"version" :"Version", "traffic_class":"Traffic Class", "flow_label":"Flow Label", "payload_len": "Payload Length", "next_hdr":"Next Header", "hop_limit":"Hop Limit", "source":"Source IP", "dest":"Destination IP"}
        return self.print_header_attrs(self.ipv6, attrs)
    
    def print_arp_header(self):
        attrs = {'hardware_type':'Hardware Type', 'proto':'Protocol Type', 'operation':'Operation', 'src_mac':'Sender Hardware Address', 'dst_mac':'Target Hardware Address', 'src_ip' :'Sender Protocol address', 'dst_ip':'Target Protocol Address'}
        return self.print_header_attrs(self.arp, attrs)
    
    def print_tcp_header(self):
        attrs = {'source_port':'Source Port', 'destination_port':'Destination Port', 'sequence_number':"Sequence number", 'acknowledgement': 'Acknowledgement', 'flags_str':'Flags'}
        return self.print_header_attrs(self.tcp, attrs)
        
        

    def print_icmp_header(self):
        attrs = {'type_str':'Type', 'code':'Code', 'cheksum' :'Checksum', 'rest_of_header':'Rest of Header'}
        return self.print_header_attrs(self.icmp, attrs)
    
    def print_udp_header(self):
        attrs = {'source_port':'Source Port', 'destination_port' :'Destination Port', 'length':'Length', 'cheksum':'Cheksum'}
        return self.print_header_attrs(self.udp, attrs)

    def display_header_data(self):
        ending = codecs.decode(bytes(self.data), 'utf-8', errors='ignore')      
        j = 0
        end_str = '\n'
        
        
        for i in range(len(ending) - 1):
            j += 1
            end_str += ending[i]
            
            if j == 80:
                end_str += '\n'
                j = 0
        
        return end_str +'\n'
            




def main():

    if len(sys.argv) == 1:
        print(bcolors.WARNING + 'Use -h or --help flag to get information about commands.'+ bcolors.ENDC)
    

    
    parser = argparse.ArgumentParser()
    parser.add_argument('--sniff-to-screen', '-ss', dest='screen', action='store_true', help='starts sniffing and directs output to screen')
    parser.add_argument('--sniff-to-file', '-sf', dest='file', type=argparse.FileType('w'), action='store', help='starts sniffing and directs the output to a file name of your choice')
    parser.add_argument('--speed', '-spd', dest='speed', type=int, choices=[1, 2, 3, 4, 5],help='defines screen output speed, 1 - the lowest possible value, 5 - the biggest possible value; default speed is set to 5', default=5)
    parser.add_argument('--hide-data', '-hd', dest='hide_data', action='store_true', help='if set, the data will not be displayed')
    args = parser.parse_args()
    
    if args.screen:
        s = (6 - args.speed) * 0.1
        to_screen(s, args.hide_data)
    if args.file:
        to_file(args.file, args.hide_data)
        
    


    
    



def to_screen(speed, hd=False):
    


    conn = socket(PF_PACKET, SOCK_RAW, htons(3))
    counter = 0

    print(bcolors.WARNING + 'Sniffing is starting...' +'\nPress CTRL + C to stop'+bcolors.ENDC)
    try:
        while True:
            counter += 1
            raw_data, addr = conn.recvfrom(655536)
            btw = '_ ' * 40
            print(bcolors.WARNING + btw + '\n'+'\nPacket [{}]:'.format( counter) + bcolors.ENDC)
            s = Sniffer(raw_data)
            s.to_screen = True
            s.hide_data = hd
            s.CollectHeaders()
            s.PrintHeaders()
            time.sleep(speed)
    except KeyboardInterrupt:
        print('\n' +bcolors.WARNING +'Sniffing finished' + bcolors.ENDC)


def to_file(f, hd=False):
    conn = socket(PF_PACKET, SOCK_RAW, htons(3))
    counter = 0
    print(bcolors.WARNING + 'Sniffing is starting...' +'\nPress CTRL + C to stop'+bcolors.ENDC)
    try:
        while True:
            counter += 1
            raw_data, addr = conn.recvfrom(655536)
            btw = '_ ' * 40
            f.write('\n'+'\nPacket [{}]:'.format( counter)+'\n')
            s = Sniffer(raw_data)
            s.hide_data = hd
            s.CollectHeaders()
            f.write(s.GiveHeaders())
    except KeyboardInterrupt:
        print('\n' + bcolors.WARNING +'Sniffing finished. Check {}'.format(f.name) + bcolors.ENDC)
        f.close()




if __name__ == '__main__':
    try:
        main()
    except PermissionError:
        print(bcolors.WARNING + 'You need root permissions to use the script!'+ bcolors.ENDC)




