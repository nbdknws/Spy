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
                        starts sniffing and directs the output to a file name of your choice
  --speed {1,2,3,4,5}, -spd {1,2,3,4,5}
                        defines screen output speed, 1 - the lowest possible value, 5 - the biggest
                        possible value; default speed is set to 5
  --hide-data, -hd      if set, the data will not be displayed
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


7;▒P*;);?p7(0
             ѿB_▒V{/$z<2Y=տu(KQ&Jl
U}d*!Ze;LRn1VftP]N+=0[Z
!ơS]04\@+9<<nU!my
ѧ▒Mu
    ;X5 Ԇ݌▒#3[e
%bsM0I01Ww޲S2[V&s4V
0       *H
091
U  0    UUS10
15102n10UAmazon Root CA 10
251019000000Z0F1
U               0       UUS10
Amazon10U

         Server CA 1B1
0Amazon0*H
Ngμj7Z:0(H)nSգ9▒wpkqm˦*N
<
9
ĵXV%>Rz)nP_1Jb>G' 5_Mk7P>DZf~jU5uNXU}Sk
kB+
   SgЈ:s_r~0c*z-▒2>
hӈJeJ.LU;07000U0UYfR{<'t[=
0U#▒0▒4
       YǲN
0+o0m0+0#http://ocsp.rootca1.amazont
rust.com0+0.http://crt.rootca1.amazontrust.com/rootca1.cer0?U80604
20.http://crl.rootca1.amazontrust.com/rootca1.crl0U 
                                                    0
g
 0      *H

ma7{XQ(Ovf.) `HSe5kQ@UW_▒">/1
I'8HR6O-h5r}Wy7{`-w
    vRȼAxpmJx-^L`Gx-R9,/3ڔ00z

_ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _
```
