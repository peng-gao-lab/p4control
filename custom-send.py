#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct
import re
import binascii
from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IntField, ShortField, LongField, BitField, IP, UDP, TCP, Raw
from scapy.all import bind_layers

class p4control(Packet):
    name = "p4control"
    fields_desc = [BitField("label", 0, 64), BitField("tracker", 0, 64)]

bind_layers(TCP, p4control)

# Update with your interface
def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if re.search("veth.", i):
            iface=i
            break;
    if not iface:
        print("Cannot find veth interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<4:
        print('pass 4 arguments: <destination> <label> <tracker> "<message>"')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    
    # hex_value = int(sys.argv[2])
    label_tag = int(sys.argv[2])
    id_tag = int(sys.argv[3])

    print(("sending on interface %s to %s" % (iface, str(addr))))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt /IP(dst=addr, flags='evil') / TCP(dport=1234, sport=49153)/ p4control(trust=label_tag, id = id_tag) / sys.argv[4]
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
