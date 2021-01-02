# S.py
 
 A very simple packet sniffer for Linux OS. Captures, parses and displays network packets' information for current machine.
 Requires root permissions.
 
 # Usage
 ```
 usage: s.py [-h] [--sniff-to-screen] [--sniff-to-file FILE] [--speed {1,2,3,4,5}] [--hide-data]

 optional arguments:
  -h, --help            show this help message and exit
  --sniff-to-screen, -ss
                        starts sniffing and directs output to screen
  --sniff-to-file FILE, -sf FILE
                        starts sniffing and directs output to a file name of your choice
  --speed {1,2,3,4,5}, -spd {1,2,3,4,5}
                        defines screen output speed, 1 - the lowest possible value, 5 - the biggest
                        possible value; default speed is set to 5
  --hide-data, -hd      if set, only packet headers will be displayed
```
# Output example

```
_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ 
                                                                                                       
Packet [54]:                                                                                           
Ethernet

    Source MAC : 54:67:51:DC:97:5D
    Destination MAC : 00:0C:29:91:5D:75
    Ethrnet Type : 0x0800

IPv4

    Version : 4
    Header Length : 5
    DSCP : 0
    ECN : 0
    Total Length : 1400
    ID : 49325
    Fragment Offset : 0
    TTL : 224
    Protocol : 6
    Source IP : 52.95.123.41
    Target IP : 192.168.0.129

TCP

    Source Port : 443
    Destination Port : 56998
    Sequence number : 3795295803
    Acknowledgement : 3419068698
    Flags : NS:0 CWR:0 ECE:0 URG:0 ACK:1 PSH:0 RST:0 SYN:0 FIN:0 

_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
```
