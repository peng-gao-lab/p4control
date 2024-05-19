#!/usr/bin/env python3
import sys
import struct
import os
import re
from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, TCP, UDP, Raw
from scapy.all import bind_layers
from scapy.layers.inet import _IPOption_HDR

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

def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 1234:
        print("got a packet")
        pkt.show2()
    #    hexdump(pkt)
        sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'veth' in i]
    iface = ifaces[0]
    print(("sniffing on %s, port 1234" % iface))
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()