#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports

from __future__ import print_function
from bcc import BPF
from bcc.containers import filter_by_containers
from bcc.utils import ArgString, printb
import bcc.utils as utils
import argparse
import re
import time
import pwd
from collections import defaultdict
from time import strftime
import sqlite3
import argparse as ap
import socket
from struct import pack
from scapy.all import *
from ctypes import *
import pyroute2

# initialize BPF
b = BPF(src_file="host_agent_ebpf.c")


execve_fnname = b.get_syscall_fnname("execve")
b.attach_kretprobe(event=execve_fnname, fn_name="do_ret_sys_execve")

event_name = b.get_syscall_fnname("clone")
b.attach_kretprobe(event=event_name, fn_name ="syscall_clone")

b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_v4_connect_entry")
# b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_tcp_v4_connect_return")

# b.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")

# b.attach_kprobe(event="vfs_create", fn_name="trace_create")
# b.attach_kprobe(event="vfs_open", fn_name="trace_open")

# b.attach_kprobe(event="vfs_read", fn_name="trace_read")
# if BPF.get_kprobe_functions(b"security_inode_create"):
    # b.attach_kprobe(event="security_inode_create", fn_name="trace_security_inode_create")


# Mellanox nic definitions
nic_list = socket.if_nameindex()
for i in nic_list:
    if "enp0s3" in i:
        device = "enp0s3"
    else:
        device = "enp8s0f0np0"

print("USING NIC " + device)
fn = b.load_func("handle_ingress", BPF.XDP)
b.attach_xdp(device, fn, 0)

f_egress = b.load_func("handle_egress", BPF.SCHED_CLS)
ipr = pyroute2.IPRoute()
eth = ipr.link_lookup(ifname=device)[0]
ipr.tc("add", "clsact", eth)
ipr.tc("add-filter", "bpf", eth, ":1", fd=f_egress.fd, name=f_egress.name,
           parent="ffff:fff3", classid=1, direct_action=True)



while 1:
    try:
        b.trace_print()
        # b.perf_buffer_poll()
    except KeyboardInterrupt:
        b.remove_xdp(device, 0)   
        exit()
# tc qdisc del dev enp1s0f0np0 clsact
# tc qdisc del dev enp0s31f6 clsact
