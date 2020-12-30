from socket import socket, AF_PACKET, PF_PACKET, SOCK_RAW, htons, INADDR_ANY
import sys
import struct 
import time
import codecs
import argparse
import headers

#colors for console output decoration
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

#main sniffer class - parses, collects, prints headers and data for current packet
class Sniffer:
    
    def __init__(self, packet):
        self.data = packet #raw packet data
        self.queue = ["Ethernet"] #stores all encapsulated header names
        self.to_screen = False #flag for file/screen output
        self.hide_data = False #flag for hiding/displaying packet data in output
    
    #parses all encapsulated packet headers and stores them as class attributes
    def CollectHeaders(self):
        for header_name in self.queue:
            #find corresponding header class in headers module
            header_class = getattr(headers, header_name)
            #set where data bytes of current header start and end 
            start = 0
            end = header_class.header_length
            #cut header data bytes and send them to the header class for parsing
            header = header_class(self.data[start:end])
            #store header as class attribute
            setattr(self, header_name.lower(), header)
            #stop if there are no encapsulated headers
            if header.encapsulated is None:
                break
            #if there is an encapsulated header -> add it to the headers queue
            self.queue.append(header.encapsulated)
            #update current data
            self.data = self.data[end:]
    #returns packet headers string for file output
    def ReturnHeaders(self):
        packet = ''
        #read encapsulated packet headers one by one 
        #and call corresponding get_header function for each of them
        for header_name in self.queue:
            packet += header_name +'\n'
            packet += getattr(self, 'get_{}_header'.format(header_name.lower()))()
        #if --hide-data flag is set -> do not display data
        if not self.hide_data:
            packet += self.display_header_data()
        return packet
    
    #prints headers in console 
    def PrintHeaders(self):
        #read encapsulated packet headers one by one 
        #and call corresponding get_header function for each of them
        for header_name in self.queue:
            print(bcolors.OKGREEN + header_name + bcolors.ENDC + '\n')
            print(getattr(self, 'get_{}_header'.format(header_name.lower()))())
        #if --hide-data flag is set -> do not display data
        if not self.hide_data:
            print(self.display_header_data())
    #takes header and selected attributes
    #returns header string with selected attributes
    def get_header_attrs(self, header, attrs):
        attributes = ''
        #if -ss flag is selected -> set colors for console output decoration
        if self.to_screen:
            color1, color2 = bcolors.OKCYAN, bcolors.ENDC
        #if -sf flag is selected -> don't use colors
        else:
            color1, color2 = '', ''

        for attr in attrs.keys():
            attributes += ('    '+ color1 + attrs[attr] + color2 + ' : ' + str(getattr(header,attr)) + '\n')
        return attributes
    #get header functions for all possible headers
    #each defines attributes to be shown in resulting header string
    #returns header string
    def get_ethernet_header(self):
        attrs = {'source':'Source MAC', 'dest': 'Destination MAC', 'ethtype':'Ethrnet Type'}
        return self.get_header_attrs(self.ethernet, attrs)

    def get_ipv4_header(self):
        attrs = {'version':'Version', 'header_len':'Header Length', 'dscp': 'DSCP','ecn':'ECN','total_length': 'Total Length', 'id': 'ID', 'fragment_offset': 'Fragment Offset', 'ttl':'TTL', 'proto':'Protocol', 'source':'Source IP', 'dest':'Target IP'}
        return self.get_header_attrs(self.ipv4, attrs)

    def get_ipv6_header(self):
        attrs = {"version" :"Version", "traffic_class":"Traffic Class", "flow_label":"Flow Label", "payload_len": "Payload Length", "next_hdr":"Next Header", "hop_limit":"Hop Limit", "source":"Source IP", "dest":"Destination IP"}
        return self.get_header_attrs(self.ipv6, attrs)
    
    def get_arp_header(self):
        attrs = {'hardware_type':'Hardware Type', 'proto':'Protocol Type', 'operation':'Operation', 'src_mac':'Sender Hardware Address', 'dst_mac':'Target Hardware Address', 'src_ip' :'Sender Protocol address', 'dst_ip':'Target Protocol Address'}
        return self.get_header_attrs(self.arp, attrs)
    
    def get_tcp_header(self):
        attrs = {'source_port':'Source Port', 'destination_port':'Destination Port', 'sequence_number':"Sequence number", 'acknowledgement': 'Acknowledgement', 'flags_str':'Flags'}
        return self.get_header_attrs(self.tcp, attrs)      

    def get_icmp_header(self):
        attrs = {'type_str':'Type', 'code':'Code', 'cheksum' :'Checksum', 'rest_of_header':'Rest of Header'}
        return self.get_header_attrs(self.icmp, attrs)
    
    def get_udp_header(self):
        attrs = {'source_port':'Source Port', 'destination_port' :'Destination Port', 'length':'Length', 'cheksum':'Cheksum'}
        return self.get_header_attrs(self.udp, attrs)
    #decodes and returns unparsed packet data
    def display_header_data(self):
        ending = codecs.decode(bytes(self.data), 'utf-8', errors='ignore')      
        #split data string into lines
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
    #if no flags where set -> show help messege
    if len(sys.argv) == 1:
        print(bcolors.WARNING + 'Use -h or --help flag to get information about commands.'+ bcolors.ENDC)
    
    #argument parser for console flags interface
    parser = argparse.ArgumentParser()
    #add screen output flag
    parser.add_argument('--sniff-to-screen', '-ss', dest='screen', action='store_true', help='starts sniffing and directs output to screen')
    #add file output flag
    parser.add_argument('--sniff-to-file', '-sf', dest='file', type=argparse.FileType('w'), action='store', help='starts sniffing and directs the output to a file name of your choice')
    #add speed(time delay) of output control flag
    parser.add_argument('--speed', '-spd', dest='speed', type=int, choices=[1, 2, 3, 4, 5],help='defines screen output speed, 1 - the lowest possible value, 5 - the biggest possible value; default speed is set to 5', default=5)
    #add hide data flag
    parser.add_argument('--hide-data', '-hd', dest='hide_data', action='store_true', help='if set, the data will not be displayed')
    args = parser.parse_args()
    #if screen output selected -> call to_screen finction 
    if args.screen:
        #calculate time delay
        s = (6 - args.speed) * 0.1
        to_screen(s, args.hide_data)
    #if file output flag was selected -> call to_file function
    if args.file:
        to_file(args.file, args.hide_data)
        
    
#screen output function
def to_screen(speed, hd=False):
    #create socket
    #PF_PACKET: low-level interface directly to network devices; PF for Linux OS family
    #SOCK_RAW: packets are passed from the device driver without any changes 
    #htons(3): ETH_P_ALL all protocols are recieved
    conn = socket(PF_PACKET, SOCK_RAW, htons(3))
    #packets counter
    counter = 0
    #print starting messege 
    print(bcolors.WARNING + 'Sniffing is starting...' +'\nPress CTRL + C to stop'+bcolors.ENDC)
    #while possible - recieve packets
    try:
        while True:
            counter += 1
            #recieve data from socket
            raw_data, addr = conn.recvfrom(655536)
            #string separator 
            btw = '_ ' * 40
            #print packet and it's number
            print(bcolors.WARNING + btw + '\n'+'\nPacket [{}]:'.format( counter) + bcolors.ENDC)
            #create a sniffer and send him raw packet data 
            s = Sniffer(raw_data)
            #set sniffer's screen output flag to be True
            s.to_screen = True
            #set sniffer's hide data flag
            s.hide_data = hd
            #ask sniffer to parse and collect all packet headers
            s.CollectHeaders()
            #print collected headers to console
            s.PrintHeaders()
            #set time delay before next packet 
            time.sleep(speed)
    #ctrl + c pressed -> stop sniffer
    except KeyboardInterrupt:
        print('\n' +bcolors.WARNING +'Sniffing finished' + bcolors.ENDC)

#file output function
def to_file(f, hd=False):
    #create socket
    #PF_PACKET: low-level interface directly to network devices; PF for Linux OS family
    #SOCK_RAW: packets are passed from the device driver without any changes 
    #htons(3): ETH_P_ALL all protocols are recieved
    conn = socket(PF_PACKET, SOCK_RAW, htons(3))
    #packets counter
    counter = 0
    #print starting messege 
    print(bcolors.WARNING + 'Sniffing is starting...' +'\nPress CTRL + C to stop'+bcolors.ENDC)
    #while possible - recieve packets
    try:
        while True:
            counter += 1
            #recieve data from socket
            raw_data, addr = conn.recvfrom(655536)
            #string separator
            btw = '_ ' * 40
            #print packet and it's number
            f.write('\n'+'\nPacket [{}]:'.format( counter)+'\n')
    
            #create a sniffer and send him raw packet data 
            s = Sniffer(raw_data)
            #set sniffer's hide data flag
            s.hide_data = hd
            #ask sniffer to parse and collect all packet headers
            s.CollectHeaders()
            #output collected headers to selected file
            f.write(s.ReturnHeaders())
     #ctrl + c pressed -> stop sniffer
    except KeyboardInterrupt:
        print('\n' + bcolors.WARNING +'Sniffing finished. Check {}'.format(f.name) + bcolors.ENDC)
        #f.close()




if __name__ == '__main__':
    #if user is not root -> print warning messege
    try:
        main()
    except PermissionError:
        print(bcolors.FAIL + 'You need root permissions to use the script!'+ bcolors.ENDC)




